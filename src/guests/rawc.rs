use crate::guests;
use crate::guests::elf_program::ElfProgram;
use crate::mmu::frames::RangeFrameAllocator;
use crate::mmu::{EptMapper, FrameAllocator};
use crate::println;
use crate::qemu;
use crate::vmx;
use crate::vmx::bitmaps::EptEntryFlags;
use crate::vmx::fields;
use crate::GuestVirtAddr;

use super::Guest;
use super::HandlerResult;

const RAWCBYTES: &'static [u8] = include_bytes!("../../guest/rawc");
const STACK: u64 = 0x7ffffffdd000;

/// A datastructure to represent the program.
/// `start` is the start address of the program.
/// `offset` is the .text section offset in the raw bytes.
pub struct RawcBytes {}

pub const RAWC: RawcBytes = RawcBytes {};

impl Guest for RawcBytes {
    /// Creates a VM from the rawc file bytes and jumps.
    /// This small guest sets rax to 0x666 and performs a vmcall.
    /// It is a proof of concept on the path to instantiate a full linux vm.
    ///
    /// The strategy to instantiate it is the following:
    /// 1. Allocate page tables with one pml4 and one level 3 mapping of 1GB.
    /// 2. Copy the program rawc to this memory region.
    /// 3. Generate the EPT mappings with hpa == gpa.
    /// 4. Set the EPT and return the vmcs.
    unsafe fn instantiate<'vmx>(
        &self,
        vmxon: &'vmx vmx::Vmxon,
        allocator: &impl FrameAllocator,
    ) -> vmx::VmcsRegion<'vmx> {
        let rawc_prog = ElfProgram::new(RAWCBYTES);
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
        let mut ept_mapper = EptMapper::new(
            virtoffset.as_u64() as usize,
            start as usize,
            ept_root.phys_addr,
        );

        ept_mapper.map_range(
            allocator,
            vmx::GuestPhysAddr::new(0),
            vmx::HostPhysAddr::new(start as usize),
            (end - start) as usize,
            EptEntryFlags::READ | EptEntryFlags::WRITE | EptEntryFlags::SUPERVISOR_EXECUTE,
        );

        // Load guest into memory.
        let pt_root = rawc_prog
            .load(
                guest_ram,
                virtoffset,
                Some((GuestVirtAddr::new(STACK as usize), 0x1000)),
            )
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

            // Setup the roots.
            vmcs.set_ept_ptr(ept_mapper.get_root()).ok();
            vmx::check::check().expect("check error");
            let entry_point = rawc_prog.entry;
            let vcpu = vmcs.get_vcpu_mut();
            vcpu.set_nat(fields::GuestStateNat::Rip, entry_point.as_usize())
                .ok();
            vcpu.set_nat(fields::GuestStateNat::Cr3, pt_root.as_usize())
                .ok();
            vcpu.set_nat(
                fields::GuestStateNat::Rsp,
                (STACK + guests::ONEPAGE) as usize,
            )
            .ok();

            // Zero out the gdt and idt
            vcpu.set_nat(fields::GuestStateNat::GdtrBase, 0x0).ok();
            vcpu.set_nat(fields::GuestStateNat::IdtrBase, 0x0).ok();
        }
        vmcs
    }

    unsafe fn exit_handler(&self, vcpu: &mut vmx::VCpu) -> HandlerResult {
        let rax = vcpu[vmx::Register::Rax];
        if rax == 0x777 {
            return HandlerResult::Exit;
        }
        if rax == 0x888 {
            return HandlerResult::Resume;
        }
        HandlerResult::Crash
    }
}
