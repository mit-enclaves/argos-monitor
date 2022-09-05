//! Linux Guest

use core::slice;

use crate::acpi::AcpiInfo;
use crate::debug::info;
use crate::guests;
use crate::guests::boot_params::{
    BootParams, E820Types, EBDA_START, KERNEL_BOOT_FLAG_MAGIC, KERNEL_HDR_MAGIC,
    KERNEL_LOADER_OTHER, KERNEL_MIN_ALIGNMENT_BYTES,
};
use crate::guests::elf_program::{ElfMapping, ElfProgram};
use crate::mmu::eptmapper::EptMapper;
use crate::mmu::frames::RangeFrameAllocator;
use crate::mmu::ioptmapper::{IoPtFlag, IoPtMapper};
use crate::mmu::FrameAllocator;
use crate::println;
use crate::qemu;
use crate::vmx;
use crate::vmx::bitmaps::EptEntryFlags;
use crate::vmx::fields;
use crate::vmx::{GuestPhysAddr, HostPhysAddr, HostVirtAddr, Register};
use crate::vtd::{ContextEntry, Iommu, RootEntry};

use super::Guest;
use super::HandlerResult;

#[cfg(feature = "guest_linux")]
const LINUXBYTES: &'static [u8] = include_bytes!("../../../../linux-image/images/vmlinux");
#[cfg(not(feature = "guest_linux"))]
const LINUXBYTES: &'static [u8] = &[0; 10];

#[allow(dead_code)]
const LINUX_MASK: u64 = 0xffffffff82000000;
// Offset of setup_header within the boot_params structure as specified in:
// linux/arch/x86/include/uapi/asm/bootparam.h
#[allow(dead_code)]
const SETUP_HDR: u64 = 0x1f1;
const HIGH_MEM_START: u64 = 0x0010_0000; // 1 Mb
const APIC_BASE: usize = 0xfee0_0000;

// WARNING: Don't forget that the command line must be null terminated ('\0')!
static COMMAND_LINE: &'static [u8] = b"apic=debug\0";

pub struct Linux {}

pub const LINUX: Linux = Linux {};

impl Guest for Linux {
    unsafe fn instantiate<'vmx>(
        &self,
        vmxon: &'vmx vmx::Vmxon,
        acpi: &AcpiInfo,
        allocator: &impl FrameAllocator,
    ) -> vmx::VmcsRegion<'vmx> {
        let mut linux_prog = ElfProgram::new(LINUXBYTES);
        linux_prog.set_mapping(ElfMapping::Identity);

        let virtoffset = allocator.get_physical_offset();
        // Create a bumper allocator with 1GB of RAM.
        let guest_ram_size = 2 * guests::ONEGB;
        let guest_ram = allocator
            .allocate_range(guest_ram_size)
            .expect("Unable to allocate 2GB");

        // Storing the guest ram start address for debugging.
        info::tyche_hook_set_guest_start(guest_ram.start.as_u64());
        let guest_allocator = RangeFrameAllocator::new(guest_ram.start, guest_ram.end, virtoffset);

        // Setup the EPT first.
        let (start, end) = guest_allocator.get_boundaries();
        let ept_root = allocator
            .allocate_frame()
            .expect("EPT root allocation")
            .zeroed();
        let iopt_root = allocator
            .allocate_frame()
            .expect("I/O PT root allocation")
            .zeroed();
        let mut ept_mapper = EptMapper::new(virtoffset.as_usize(), ept_root.phys_addr);
        let mut iopt_mapper = IoPtMapper::new(virtoffset.as_usize(), iopt_root.phys_addr);

        // Map guest memory
        ept_mapper.map_range(
            allocator,
            GuestPhysAddr::new(0),
            HostPhysAddr::new(start),
            end - start,
            EptEntryFlags::READ | EptEntryFlags::WRITE | EptEntryFlags::SUPERVISOR_EXECUTE,
        );
        iopt_mapper.map_range(
            allocator,
            GuestPhysAddr::new(0),
            HostPhysAddr::new(start),
            end - start,
            IoPtFlag::WRITE,
        );

        // Maps guest APIC mmio to host, giving complete control over APIC configuration.
        ept_mapper.map_range(
            allocator,
            GuestPhysAddr::new(APIC_BASE),
            HostPhysAddr::new(APIC_BASE),
            0x1000,
            EptEntryFlags::READ | EptEntryFlags::WRITE,
        );

        // Load guest into memory.
        let mut loaded_linux = linux_prog
            .load(guest_ram, virtoffset)
            .expect("Failed to load guest");

        // Setup I/O MMU
        if let Some(iommus) = &acpi.iommu {
            let iommu_addr = HostVirtAddr::new(
                iommus[0].base_address.as_usize() + allocator.get_physical_offset().as_usize(),
            );
            let mut iommu = Iommu::new(iommu_addr);
            let root_addr = setup_iommu_context(iopt_mapper.get_root(), allocator);
            iommu.set_root_table_addr(root_addr.as_u64() | (0b00 << 10)); // Set legacy mode
            iommu.update_root_table_addr();
            iommu.enable_translation();
        }

        // Build the boot params
        let mut boot_params = build_bootparams(guest_ram_size as u64);
        let command_line = loaded_linux.add_payload(COMMAND_LINE);
        let command_line_addr_low = (command_line.as_usize() & 0xFFFF_FFFF) as u32;
        let command_line_addr_high = (command_line.as_usize() >> 32) as u32;
        boot_params.ext_cmd_line_ptr = command_line_addr_high;
        boot_params.hdr.cmd_line_ptr = command_line_addr_low;
        boot_params.hdr.cmdline_size = COMMAND_LINE.len() as u32;
        let boot_params = loaded_linux.add_payload(boot_params.as_bytes());

        // Setup the vmcs.
        let frame = allocator.allocate_frame().expect("Failed to allocate VMCS");
        let mut vmcs = match vmxon.create_vm(frame) {
            Err(err) => {
                println!("VMCS:   Err({:?})", err);
                qemu::exit(qemu::ExitCode::Failure);
            }
            Ok(vmcs) => {
                println!("VMCS:   Ok(())");
                vmcs
            }
        };

        {
            // VMCS is active in this block
            let mut vcpu = vmcs.set_as_active().expect("Failed to activate VMCS");
            guests::default_vmcs_config(&mut vcpu, false);

            // Configure MSRs
            let frame = allocator
                .allocate_frame()
                .expect("Failed to allocate MSR bitmaps");
            let msr_bitmaps = vcpu
                .initialize_msr_bitmaps(frame)
                .expect("Failed to install MSR bitmap");
            msr_bitmaps.allow_all();

            // Setup the roots.
            vcpu.set_ept_ptr(ept_mapper.get_root()).unwrap();
            let entry_point = linux_prog.phys_entry;
            vcpu.set_nat(fields::GuestStateNat::Rip, entry_point.as_usize())
                .unwrap();
            vcpu.set_nat(fields::GuestStateNat::Cr3, loaded_linux.pt_root.as_usize())
                .unwrap();
            vcpu.set_nat(fields::GuestStateNat::Rsp, 0).unwrap();

            // Zero out the gdt and idt
            vcpu.set_nat(fields::GuestStateNat::GdtrBase, 0x0).unwrap();
            vcpu.set_nat(fields::GuestStateNat::IdtrBase, 0x0).unwrap();

            // Setup control registers
            let vmxe = 1 << 13; // VMXE flags, required during VMX operations.
            let cr4 = 0xA0 | vmxe;
            vcpu.set_nat(fields::GuestStateNat::Cr4, cr4).unwrap();
            vcpu.set_cr4_mask(vmxe).unwrap();
            vcpu.set_cr4_shadow(vmxe).unwrap();

            // Setup boot_params
            vcpu.set(Register::Rsi, boot_params.as_u64());

            vmx::check::check().expect("check error");
        }
        vmcs
    }

    unsafe fn vmcall_handler(
        &self,
        _vcpu: &mut vmx::ActiveVmcs,
    ) -> Result<HandlerResult, vmx::VmxError> {
        crate::println!("Linux: VMCall - exiting...");
        Ok(HandlerResult::Exit)
    }
}

fn build_bootparams(guest_ram_size: u64) -> BootParams {
    let mut boot_params = BootParams::default();
    boot_params.hdr.type_of_loader = KERNEL_LOADER_OTHER;
    boot_params.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
    boot_params.hdr.header = KERNEL_HDR_MAGIC;
    //boot_params.hdr.cmd_line_ptr = cmdline_addr.raw_value() as u32;
    //boot_params.hdr.cmdline_size = cmdline_size as u32;
    boot_params.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;

    // The initramfs is embedded so not sure we need to do any of that
    //boot_params.hdr.ramdisk_image = ramdisk addr;
    //boot_params.hdr.ramdisk_size = ramdisk size;
    boot_params
        .add_e820_entry(GuestPhysAddr::new(0), EBDA_START, E820Types::Ram)
        .expect("VGA region");
    boot_params
        .add_e820_entry(
            GuestPhysAddr::new(HIGH_MEM_START as usize),
            guest_ram_size as u64 - HIGH_MEM_START,
            E820Types::Ram,
        )
        .expect("High memory");

    boot_params
}

fn setup_iommu_context(iopt_root: HostPhysAddr, allocator: &impl FrameAllocator) -> HostPhysAddr {
    let ctx_frame = allocator
        .allocate_frame()
        .expect("I/O MMU context frame")
        .zeroed();
    let root_frame = allocator
        .allocate_frame()
        .expect("I/O MMU root frame")
        .zeroed();
    let ctx_entry = ContextEntry {
        upper: 0b010, // 4 lvl pages
        lower: iopt_root.as_u64(),
    };
    let root_entry = RootEntry {
        reserved: 0,
        entry: ctx_frame.phys_addr.as_u64() | 0b1, // Mark as present
    };

    unsafe {
        let ctx_array = slice::from_raw_parts_mut(ctx_frame.virt_addr as *mut ContextEntry, 256);
        let root_array = slice::from_raw_parts_mut(root_frame.virt_addr as *mut RootEntry, 256);

        for entry in ctx_array {
            *entry = ctx_entry;
        }
        for entry in root_array {
            *entry = root_entry;
        }
    }

    root_frame.phys_addr
}
