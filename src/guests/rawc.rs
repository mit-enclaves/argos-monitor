use crate::debug::info;
use crate::guests;
use crate::guests::elf_program::ElfProgram;
use crate::mmu::frames::RangeFrameAllocator;
use crate::mmu::{EptMapper, FrameAllocator};
use crate::println;
use crate::qemu;
use crate::vmx;
use crate::vmx::bitmaps::EptEntryFlags;
use crate::vmx::{fields, Register};
use crate::GuestVirtAddr;

use super::Guest;
use super::HandlerResult;

#[cfg(feature = "guest_rawc")]
const RAWCBYTES: &'static [u8] = include_bytes!("../../guest/rawc");
#[cfg(not(feature = "guest_rawc"))]
const RAWCBYTES: &'static [u8] = &[0; 10];

const STACK: usize = 0x7ffffffdd000;

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
        let mut rawc_prog = ElfProgram::new(RAWCBYTES);
        rawc_prog.add_stack(GuestVirtAddr::new(STACK), 0x1000);

        let virtoffset = allocator.get_physical_offset();
        // Create a bumper allocator with 1GB of RAM.
        let guest_ram = allocator
            .allocate_range(guests::ONEGB)
            .expect("Unable to allocate 1GB");
        // Storing the guest ram start address for debugging.
        info::tyche_hook_set_guest_start(guest_ram.start.as_u64());

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
        let pt_root = rawc_prog
            .load(guest_ram, virtoffset)
            .expect("Failed to load guest")
            .pt_root;

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
            vcpu.set_ept_ptr(ept_mapper.get_root()).ok();
            let entry_point = rawc_prog.entry;
            vcpu.set_nat(fields::GuestStateNat::Rip, entry_point.as_usize())
                .ok();
            vcpu.set_nat(fields::GuestStateNat::Cr3, pt_root.as_usize())
                .ok();
            vcpu.set_nat(fields::GuestStateNat::Rsp, STACK + guests::ONEPAGE)
                .ok();
            // Zero out the gdt and idt
            vcpu.set_nat(fields::GuestStateNat::GdtrBase, 0x0).ok();
            vcpu.set_nat(fields::GuestStateNat::IdtrBase, 0x0).ok();

            // Setup control registers
            let vmxe = 1 << 13; // VMXE flags, required during VMX operations.
            let cr4 = 0xA0 | vmxe;
            vcpu.set_nat(fields::GuestStateNat::Cr4, cr4).unwrap();
            vcpu.set_cr4_mask(vmxe).unwrap();
            vcpu.set_cr4_shadow(vmxe).unwrap();

            vmx::check::check().expect("check error");
        }
        vmcs
    }

    unsafe fn vmcall_handler(
        &self,
        vcpu: &mut vmx::ActiveVmcs,
    ) -> Result<HandlerResult, vmx::VmxError> {
        let rip = vcpu.get(Register::Rip);
        let rax = vcpu.get(Register::Rax);

        // Move to next instruction
        vcpu.set(Register::Rip, rip + 3);

        // Interpret VMCall
        if rax == 0x777 {
            return Ok(HandlerResult::Exit);
        }
        if rax == 0x888 {
            return Ok(HandlerResult::Resume);
        }
        Ok(HandlerResult::Crash)
    }
}
