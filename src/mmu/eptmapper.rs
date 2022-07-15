use super::{
    walker::{Level, WalkNext, Walker},
    FrameAllocator,
};
use crate::vmx::{
    bitmaps::EptEntryFlags,
    ept::{GIANT_PAGE_SIZE, HUGE_PAGE_SIZE},
};
use crate::vmx::{GuestPhysAddr, HostPhysAddr, HostVirtAddr};

pub struct EptMapper {
    host_offset: usize,
    _offset: usize,
    root: HostPhysAddr,
}

pub const EPT_PRESENT: EptEntryFlags = EptEntryFlags::READ
    .union(EptEntryFlags::WRITE)
    .union(EptEntryFlags::SUPERVISOR_EXECUTE);

unsafe impl Walker for EptMapper {
    type PhysAddr = HostPhysAddr;
    type VirtAddr = GuestPhysAddr;

    fn translate(&self, phys_addr: Self::PhysAddr) -> HostVirtAddr {
        HostVirtAddr::new(phys_addr.as_usize() + self.host_offset)
    }

    fn root(&mut self) -> (Self::PhysAddr, Level) {
        (self.root, Level::L4)
    }
}

impl EptMapper {
    pub fn new(host_offset: usize, offset: usize, root: HostPhysAddr) -> Self {
        Self {
            host_offset,
            _offset: offset,
            root,
        }
    }

    pub fn map_range(
        &mut self,
        allocator: &impl FrameAllocator,
        gpa: GuestPhysAddr,
        hpa: HostPhysAddr,
        size: usize,
        prot: EptEntryFlags,
    ) {
        unsafe {
            self.walk_range(
                gpa,
                GuestPhysAddr::new(gpa.as_usize() + size),
                &mut |addr, entry, level| {
                    if (*entry & EPT_PRESENT.bits()) != 0 {
                        return WalkNext::Continue;
                    }

                    let end = gpa.as_usize() + size;
                    let hphys = hpa.as_usize() + (addr.as_usize() - gpa.as_usize());

                    if level == Level::L3 {
                        if addr.as_usize() + GIANT_PAGE_SIZE <= end {
                            assert!(hphys % GIANT_PAGE_SIZE == 0);
                            *entry = hphys as u64 | EptEntryFlags::PAGE.bits() | prot.bits();
                            return WalkNext::Leaf;
                        }
                    }
                    if level == Level::L2 {
                        if addr.as_usize() + HUGE_PAGE_SIZE <= end {
                            assert!(hphys % HUGE_PAGE_SIZE == 0);
                            *entry = hphys as u64 | EptEntryFlags::PAGE.bits() | prot.bits();
                            return WalkNext::Leaf;
                        }
                    }
                    if level == Level::L1 {
                        *entry = hphys as u64 | prot.bits();
                        return WalkNext::Leaf;
                    }
                    let frame = allocator
                        .allocate_zeroed_frame()
                        .expect("map_range: unable to allocate page table entry");
                    *entry = frame.phys_addr.as_u64() | prot.bits();
                    WalkNext::Continue
                },
            )
            .expect("Failed to map EPTs");
        }
    }

    pub fn get_root(&self) -> HostPhysAddr {
        let memory_kind = 6 << 0; // write-back usize
        let walk_length = 3 << 3; // walk length of 4 usize

        HostPhysAddr::new(self.root.as_usize() | memory_kind | walk_length)
    }
}
