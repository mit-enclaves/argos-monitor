use crate::guests;
use crate::guests::elf_program::ElfProgram;
use crate::mmu::eptmapper::EptMapper;
use crate::mmu::frames::RangeFrameAllocator;
use crate::mmu::ptmapper::PtFlag;
use crate::mmu::ptmapper::PtMapper;
use crate::mmu::FrameAllocator;
use crate::println;
use crate::qemu;
use crate::vmx;
use crate::vmx::bitmaps::EptEntryFlags;
use crate::vmx::fields;

use super::Guest;
use super::HandlerResult;

const RAWCBYTES: &'static [u8] = include_bytes!("../../guest/rawc");
const ONEGB: u64 = 1 << 30;
const ONEPAGE: u64 = 1 << 12;
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
        let ram = allocator
            .allocate_range(ONEGB)
            .expect("Unable to allocate 2GB");
        let bumper = RangeFrameAllocator::new(ram.start, ram.end, virtoffset);

        // Setup the EPT first.
        let (start, end) = bumper.get_boundaries();
        let ept_root = bumper
            .allocate_frame()
            .expect("EPT root allocation")
            .zeroed();
        let mut ept_mapper = EptMapper::new(
            bumper.get_physical_offset().as_u64() as usize,
            start as usize,
            ept_root.phys_addr,
        );

        ept_mapper.map_range(
            &bumper,
            vmx::GuestPhysAddr::new(0),
            vmx::HostPhysAddr::new(start as usize),
            (end - start) as usize,
            EptEntryFlags::READ | EptEntryFlags::WRITE | EptEntryFlags::SUPERVISOR_EXECUTE,
        );

        // Setup the page tables.
        let pt_root = bumper.allocate_frame().expect("Root alloc").zeroed();
        let mut pt_mapper = PtMapper::new(
            virtoffset.as_u64() as usize,
            start as usize,
            vmx::GuestPhysAddr::new((pt_root.phys_addr.as_u64() - start) as usize),
        );
        rawc_prog.load(&bumper, &mut pt_mapper);

        // setup a stack.
        let (bstart, _) = bumper.get_boundaries();
        let stack = bumper.allocate_range(ONEPAGE).expect("stack");
        pt_mapper.map_range(
            &bumper,
            vmx::GuestVirtAddr::new(STACK as usize),
            vmx::GuestPhysAddr::new((stack.start.as_u64() - bstart) as usize),
            ONEPAGE as usize,
            PtFlag::WRITE | PtFlag::PRESENT | PtFlag::EXEC_DISABLE | PtFlag::USER,
        );

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
            vcpu.set_nat(fields::GuestStateNat::Rip, entry_point as usize)
                .ok();
            vcpu.set_nat(
                fields::GuestStateNat::Cr3,
                (pt_root.phys_addr.as_u64() - start) as usize,
            )
            .ok();
            vcpu.set_nat(fields::GuestStateNat::Rsp, (STACK + ONEPAGE) as usize)
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
