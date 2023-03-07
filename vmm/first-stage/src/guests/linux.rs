//! Linux Guest

use super::Guest;
use super::HandlerResult;
use crate::acpi::AcpiInfo;
use crate::elf::{ElfMapping, ElfProgram};
use crate::guests::boot_params::{
    BootParams, E820Types, KERNEL_BOOT_FLAG_MAGIC, KERNEL_HDR_MAGIC, KERNEL_LOADER_OTHER,
    KERNEL_MIN_ALIGNMENT_BYTES,
};
use crate::guests::common::setup_iommu_context;
use crate::guests::ManifestInfo;
use crate::mmu::MemoryMap;
use crate::println;
use crate::vmx;
use crate::vmx::{GuestPhysAddr, GuestVirtAddr, HostVirtAddr};
use bootloader::boot_info::MemoryRegionKind;
use mmu::{IoPtFlag, IoPtMapper, PtFlag, RangeAllocator};
use stage_two_abi::GuestInfo;
use vmx::HostPhysAddr;
use vtd::Iommu;

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

// WARNING: Don't forget that the command line must be null terminated ('\0')!
#[cfg(not(feature = "bare_metal"))]
static COMMAND_LINE: &'static [u8] =
    b"root=/dev/sdb2 apic=debug earlyprintk=serial,ttyS0 console=ttyS0\0";
#[cfg(feature = "bare_metal")]
static COMMAND_LINE: &'static [u8] =
    b"root=/dev/sdb2 apic=debug earlyprintk=serial,ttyS0,115200 console=ttyS0,115200 nr_cpus=2\0";

pub struct Linux {}

pub const LINUX: Linux = Linux {};

impl Guest for Linux {
    unsafe fn instantiate(
        &self,
        acpi: &AcpiInfo,
        host_allocator: &impl RangeAllocator,
        guest_allocator: &impl RangeAllocator,
        memory_map: MemoryMap,
        rsdp: u64,
    ) -> ManifestInfo {
        let mut manifest = ManifestInfo::default();
        let mut linux_prog = ElfProgram::new(LINUXBYTES);
        linux_prog.set_mapping(ElfMapping::Identity);

        let virtoffset = host_allocator.get_physical_offset();
        let iopt_root = host_allocator
            .allocate_frame()
            .expect("I/O PT root allocation")
            .zeroed();
        let mut iopt_mapper = IoPtMapper::new(virtoffset.as_usize(), iopt_root.phys_addr);
        let host_range = memory_map.host;
        iopt_mapper.map_range(
            host_allocator,
            GuestPhysAddr::new(0),
            HostPhysAddr::new(0),
            host_range.start.as_usize(),
            IoPtFlag::WRITE | IoPtFlag::READ | IoPtFlag::EXECUTE,
        );

        // Load guest into memory.
        let mut loaded_linux = linux_prog
            .load::<GuestPhysAddr, GuestVirtAddr>(guest_allocator, virtoffset)
            .expect("Failed to load guest");

        // Setup I/O MMU
        if let Some(iommus) = &acpi.iommu {
            if cfg!(not(feature = "bare_metal")) {
                let iommu_addr = HostVirtAddr::new(
                    iommus[0].base_address.as_usize()
                        + host_allocator.get_physical_offset().as_usize(),
                );
                let mut iommu = Iommu::new(iommu_addr);
                let root_addr = setup_iommu_context(iopt_mapper.get_root(), host_allocator);
                iommu.set_root_table_addr(root_addr.as_u64() | (0b00 << 10)); // Set legacy mode
                iommu.update_root_table_addr();
                iommu.enable_translation();
                manifest.iommu = iommus[0].base_address.as_u64();
                println!("I/O MMU: {:?}", iommu.get_global_status());
                println!("I/O MMU Fault: {:?}", iommu.get_fault_status());
            }
        }

        // FIXME: Linux reserves the first 1MiB for real-mode address space
        loaded_linux.pt_mapper.map_range(
            guest_allocator,
            GuestVirtAddr::new(0x0),
            GuestPhysAddr::new(0x0),
            1 << 20,
            PtFlag::PRESENT | PtFlag::WRITE,
        );

        // Build the boot params
        let mut boot_params = build_bootparams(&memory_map);
        let command_line = loaded_linux.add_payload(COMMAND_LINE, guest_allocator);
        let command_line_addr_low = (command_line.as_usize() & 0xFFFF_FFFF) as u32;
        let command_line_addr_high = (command_line.as_usize() >> 32) as u32;
        boot_params.ext_cmd_line_ptr = command_line_addr_high;
        boot_params.hdr.cmd_line_ptr = command_line_addr_low;
        boot_params.hdr.cmdline_size = COMMAND_LINE.len() as u32;
        boot_params.acpi_rsdp_addr = rsdp;
        let boot_params = loaded_linux.add_payload(boot_params.as_bytes(), guest_allocator);
        let entry_point = linux_prog.phys_entry;
        let mut info = GuestInfo::default();
        info.cr3 = loaded_linux.pt_root.as_usize();
        info.rip = entry_point.as_usize();
        info.rsp = 0;
        info.rsi = boot_params.as_usize();
        info.loaded = true;
        manifest.guest_info = info;

        manifest
    }

    unsafe fn vmcall_handler(
        &self,
        _vcpu: &mut vmx::ActiveVmcs,
    ) -> Result<HandlerResult, vmx::VmxError> {
        crate::println!("Linux: VMCall - exiting...");
        Ok(HandlerResult::Exit)
    }
}

fn build_bootparams(memory_map: &MemoryMap) -> BootParams {
    let mut boot_params = BootParams::default();
    boot_params.hdr.type_of_loader = KERNEL_LOADER_OTHER;
    boot_params.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
    boot_params.hdr.header = KERNEL_HDR_MAGIC;
    boot_params.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;

    // The initramfs is embedded so not sure we need to do any of that
    //boot_params.hdr.ramdisk_image = ramdisk addr;
    //boot_params.hdr.ramdisk_size = ramdisk size;
    for region in memory_map.guest {
        let addr = GuestPhysAddr::new(region.start as usize);
        let size = region.end - region.start;
        let kind = match region.kind {
            MemoryRegionKind::Usable => E820Types::Ram,
            MemoryRegionKind::Bootloader => E820Types::Ram,
            MemoryRegionKind::UnknownUefi(_) => E820Types::Reserved,
            MemoryRegionKind::UnknownBios(_) => E820Types::Reserved,
            _ => todo!("Add missing kind when updating bootloader crate"),
        };
        boot_params
            .add_e820_entry(addr, size, kind)
            .expect("Failed to add region");
    }

    boot_params
}
