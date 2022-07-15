use crate::guests;
use crate::mmu::eptmapper::EptMapper;
use crate::mmu::ptmapper::{PtFlag, PtMapper};
use crate::mmu::FrameAllocator;
use crate::println;
use crate::qemu;
use crate::vmx;
use crate::vmx::bitmaps::EptEntryFlags;
use crate::vmx::fields;
use crate::vmx::{GuestPhysAddr, GuestVirtAddr};

use super::Guest;

const RAWCBYTES: &'static [u8] = include_bytes!("../../guest/rawc");

pub struct RawcBytes {
    pub start: u64,
    pub offset: u64,
}

pub const RAWC: RawcBytes = RawcBytes {
    start: 0x401000,
    offset: 0x1000,
};

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
    unsafe fn instantiate(&self, allocator: &impl FrameAllocator) -> vmx::VmcsRegion {
        let pml4 = allocator
            .allocate_zeroed_frame()
            .expect("Unable to allocate root");
        // 2. Allocate 2GB so that we can find a 1Gb aligned address;
        let gb = 1 << 30;
        let backed = allocator
            .allocate_range(2 * gb)
            .expect("Unable to allocate 2GB");
        let aligned = backed.start.as_u64() / gb + gb;
        assert!(
            aligned % gb == 0 && aligned > backed.start.as_u64() && aligned < backed.end.as_u64()
        );
        let mut mapper = PtMapper::new(
            allocator.get_physical_offset().as_u64() as usize,
            0,
            GuestPhysAddr::new(pml4.phys_addr.as_usize()),
        );
        let frames = mapper
            .map_range(
                allocator,
                GuestVirtAddr::new(0),
                GuestPhysAddr::new(aligned as usize),
                gb as usize,
                PtFlag::PRESENT | PtFlag::WRITE | PtFlag::USER,
            )
            .expect("Error building page tables");

        // Copying the program.
        let virtoffset = allocator.get_physical_offset().as_u64();
        let offset_aligned = aligned - backed.start.as_u64();
        let addr = backed.start.as_u64() + virtoffset + offset_aligned;
        let start = self.offset as usize;
        if start >= RAWCBYTES.len() {
            panic!("The offset is too big");
        }
        let target = core::slice::from_raw_parts_mut(
            (addr + self.start) as *mut u8,
            RAWCBYTES.len() - start,
        );
        target.copy_from_slice(&RAWCBYTES[start..]);

        let mut vmcs = match vmx::VmcsRegion::new(allocator) {
            Err(err) => {
                println!("VMCS:   Err({:?})", err);
                qemu::exit(qemu::ExitCode::Failure);
            }
            Ok(vmcs) => {
                println!("VMCS:   Ok(())");
                vmcs
            }
        };

        println!("LOAD:   {:?}", vmcs.set_as_active());
        guests::default_vmcs_config(&mut vmcs, false);
        let root = allocator.allocate_zeroed_frame().expect("Allocate frame");
        let mut ept_mapper = EptMapper::new(
            allocator.get_physical_offset().as_u64() as usize,
            0,
            root.phys_addr,
        );

        // Let's map stuff
        ept_mapper.map_range(
            allocator,
            vmx::GuestPhysAddr::new(pml4.phys_addr.as_usize()),
            pml4.phys_addr,
            0x1000,
            EptEntryFlags::READ | EptEntryFlags::WRITE | EptEntryFlags::SUPERVISOR_EXECUTE,
        );
        ept_mapper.map_range(
            allocator,
            vmx::GuestPhysAddr::new(frames[0].phys_addr.as_usize()),
            frames[0].phys_addr,
            0x1000,
            EptEntryFlags::READ | EptEntryFlags::WRITE | EptEntryFlags::SUPERVISOR_EXECUTE,
        );
        ept_mapper.map_range(
            allocator,
            vmx::GuestPhysAddr::new(backed.start.as_u64() as usize),
            vmx::HostPhysAddr::new(backed.start.as_u64() as usize),
            backed.size(),
            EptEntryFlags::READ | EptEntryFlags::WRITE | EptEntryFlags::SUPERVISOR_EXECUTE,
        );

        println!("EPTP:   {:?}", vmcs.set_ept_ptr(ept_mapper.get_root()));
        println!("Check:  {:?}", vmx::check::check());
        let entry_point = self.start + 0x4;
        vmcs.vcpu
            .set_nat(fields::GuestStateNat::Rip, entry_point as usize)
            .ok();
        vmcs.vcpu
            .set_nat(fields::GuestStateNat::Cr3, pml4.phys_addr.as_usize())
            .ok();
        // Zero out the gdt and idt
        vmcs.vcpu.set_nat(fields::GuestStateNat::GdtrBase, 0x0).ok();
        vmcs.vcpu.set_nat(fields::GuestStateNat::IdtrBase, 0x0).ok();
        vmcs
    }
}
