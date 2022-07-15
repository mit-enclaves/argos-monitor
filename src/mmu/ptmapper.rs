use super::walker::{Level, WalkNext, Walker};
use super::FrameAllocator;
use crate::vmx::{GuestPhysAddr, GuestVirtAddr, HostVirtAddr};
use bitflags::bitflags;

pub struct PtMapper {
    host_offset: usize,
    offset: usize,
    root: GuestPhysAddr,
}

bitflags! {
    pub struct PtFlag: u64 {
        const PRESENT = 1;
        const WRITE = 1 << 1;
        const USER = 1 << 2;
        const PAGE_WRITE_THROUGH = 1 << 3;
        const PAGE_CACHE_DISABLE = 1 << 4;
        const ACCESS = 1 << 5;
        const PSIZE = 1 << 7;
        const HALT = 1 << 11;
        const EXEC_DISABLE = 1 << 63;
    }

    pub struct PageSize: usize {
        const GIANT = 1 << 30;
        const HUGE = 1 << 21;
        const NORMAL = 1 << 12;
    }
}

unsafe impl Walker for PtMapper {
    type PhysAddr = GuestPhysAddr;
    type VirtAddr = GuestVirtAddr;
    fn translate(&self, phys_addr: Self::PhysAddr) -> HostVirtAddr {
        HostVirtAddr::new(phys_addr.as_usize() + self.offset + self.host_offset)
    }

    fn root(&mut self) -> (Self::PhysAddr, Level) {
        (self.root, Level::L4)
    }
}

impl PtMapper {
    pub fn new(host_offset: usize, offset: usize, root: GuestPhysAddr) -> Self {
        Self {
            host_offset,
            offset,
            root,
        }
    }

    pub fn map_range(
        &mut self,
        allocator: &impl FrameAllocator,
        gva: GuestVirtAddr,
        gpa: GuestPhysAddr,
        size: usize,
        prot: PtFlag,
    ) {
        //TODO check alignment
        let offset = self.offset;
        unsafe {
            self.walk_range(
                gva,
                GuestVirtAddr::new(gva.as_usize() + size),
                &mut |addr, entry, level| {
                    if (*entry & PtFlag::PRESENT.bits()) != 0 {
                        return WalkNext::Continue;
                    }
                    let end = gva.as_usize() + size;
                    let phys = gpa.as_u64() + (addr.as_u64() - gva.as_u64());
                    // Opportunity to map a 1GB region
                    if level == Level::L3 {
                        if (addr.as_usize() + PageSize::GIANT.bits() <= end)
                            && (phys % (PageSize::GIANT.bits() as u64) == 0)
                        {
                            *entry = phys | PtFlag::PSIZE.bits() | prot.bits();
                            return WalkNext::Leaf;
                        }
                    }
                    // Opportunity to map a 2MB region.
                    if level == Level::L2 {
                        if (addr.as_usize() + PageSize::HUGE.bits() <= end)
                            && (phys % (PageSize::HUGE.bits() as u64) == 0)
                        {
                            *entry = phys | PtFlag::PSIZE.bits() | prot.bits();
                            return WalkNext::Leaf;
                        }
                    }
                    if level == Level::L1 {
                        assert!(phys % (PageSize::NORMAL.bits() as u64) == 0);
                        *entry = phys | prot.bits();
                        return WalkNext::Leaf;
                    }
                    // Create an entry
                    let frame = allocator
                        .allocate_zeroed_frame()
                        .expect("map_range: unable to allocate page table entry.");
                    assert!(frame.phys_addr.as_u64() >= offset as u64);
                    *entry = frame.phys_addr.as_u64() - (offset as u64) | prot.bits();
                    WalkNext::Continue
                },
            )
            .expect("Failed to map PTs");
        }
    }
}
