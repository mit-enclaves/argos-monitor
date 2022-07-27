//! Linux Guest
use crate::guests;
use crate::guests::elf_program::{ElfMapping, ElfProgram};
use crate::mmu::eptmapper::EptMapper;
use crate::mmu::frames::RangeFrameAllocator;
use crate::mmu::FrameAllocator;
use crate::println;
use crate::qemu;
use crate::vmx;
use crate::vmx::bitmaps::EptEntryFlags;
use crate::vmx::fields;

use super::Guest;
use super::HandlerResult;

#[cfg(feature = "guest_linux")]
const LINUXBYTES: &'static [u8] = include_bytes!("../../linux-image/vmlinux");
#[cfg(not(feature = "guest_linux"))]
const LINUXBYTES: &'static [u8] = &[0; 10];

pub struct Linux {}

pub const LINUX: Linux = Linux {};

impl Guest for Linux {
    unsafe fn instantiate<'vmx>(
        &self,
        vmxon: &'vmx vmx::Vmxon,
        allocator: &impl FrameAllocator,
    ) -> vmx::VmcsRegion<'vmx> {
        let mut linux_prog = ElfProgram::new(LINUXBYTES);
        linux_prog.set_mapping(ElfMapping::Identity);

        let virtoffset = allocator.get_physical_offset();
        // Create a bumper allocator with 1GB of RAM.
        let guest_ram = allocator
            .allocate_range(guests::ONEGB)
            .expect("Unable to allocate 1GB");
        let guest_allocator = RangeFrameAllocator::new(guest_ram.start, guest_ram.end, virtoffset);

        // Setup the EPT first.
        let (start, end) = guest_allocator.get_boundaries();
        let ept_root = allocator
            .allocate_frame()
            .expect("EPT root allocation")
            .zeroed();
        let mut ept_mapper =
            EptMapper::new(virtoffset.as_u64() as usize, start, ept_root.phys_addr);

        ept_mapper.map_range(
            allocator,
            vmx::GuestPhysAddr::new(0),
            vmx::HostPhysAddr::new(start),
            end - start,
            EptEntryFlags::READ | EptEntryFlags::WRITE | EptEntryFlags::SUPERVISOR_EXECUTE,
        );

        // Load guest into memory.
        let pt_root = linux_prog
            .load(guest_ram, virtoffset, None)
            .expect("Failed to load guest");

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
            let mut vmcs = vmcs.set_as_active().expect("Failed to activate VMCS");
            guests::default_vmcs_config(&mut vmcs, false);

            // Configure MSRs
            let frame = allocator
                .allocate_frame()
                .expect("Failed to allocate MSR bitmaps");
            let msr_bitmaps = vmcs
                .initialize_msr_bitmaps(frame)
                .expect("Failed to install MSR bitmap");
            msr_bitmaps.allow_all();

            // Setup the roots.
            vmcs.set_ept_ptr(ept_mapper.get_root()).unwrap();
            let entry_point = linux_prog.phys_entry;
            let vcpu = vmcs.get_vcpu_mut();
            vcpu.set_nat(fields::GuestStateNat::Rip, entry_point.as_usize())
                .unwrap();
            vcpu.set_nat(fields::GuestStateNat::Cr3, pt_root.as_usize())
                .unwrap();
            vcpu.set_nat(fields::GuestStateNat::Rsp, 0).unwrap();

            // Zero out the gdt and idt
            vcpu.set_nat(fields::GuestStateNat::GdtrBase, 0x0).unwrap();
            vcpu.set_nat(fields::GuestStateNat::IdtrBase, 0x0).unwrap();

            // Setup control registers
            let vmxe = 1 << 13; // VMXE flags, required during VMX operations.
            let cr4 = 0xA0 | vmxe;
            vcpu.set_nat(fields::GuestStateNat::Cr4, cr4).unwrap();
            vmcs.set_cr4_mask(vmxe).unwrap();
            vmcs.set_cr4_shadow(vmxe).unwrap();

            vmx::check::check().expect("check error");
        }
        vmcs
    }

    unsafe fn vmcall_handler(&self, _vcpu: &mut vmx::VCpu) -> Result<HandlerResult, vmx::VmxError> {
        crate::println!("Linux: VMCall - exiting...");
        Ok(HandlerResult::Exit)
    }
}
