use super::walker::{Address, Level, WalkNext, Walker};
use super::FrameAllocator;
use crate::HostVirtAddr;
use bitflags::bitflags;
use core::marker::PhantomData;

pub struct PtMapper<PhysAddr, VirtAddr> {
    /// Offset between host physical memory and virtual memory.
    host_offset: usize,
    /// Offset between host physical and guest physical.
    offset: usize,
    root: PhysAddr,
    _virt: PhantomData<VirtAddr>,
}

bitflags! {
    pub struct PtFlag: u64 {
        const PRESENT = 1 << 0;
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

pub const DEFAULT_PROTS: PtFlag = PtFlag::PRESENT.union(PtFlag::WRITE).union(PtFlag::USER);

unsafe impl<PhysAddr, VirtAddr> Walker for PtMapper<PhysAddr, VirtAddr>
where
    PhysAddr: Address,
    VirtAddr: Address,
{
    type PhysAddr = PhysAddr;
    type VirtAddr = VirtAddr;

    fn translate(&self, phys_addr: Self::PhysAddr) -> HostVirtAddr {
        HostVirtAddr::new(phys_addr.as_usize() + self.offset + self.host_offset)
    }

    fn root(&mut self) -> (Self::PhysAddr, Level) {
        (self.root, Level::L4)
    }
}

impl<PhysAddr, VirtAddr> PtMapper<PhysAddr, VirtAddr>
where
    PhysAddr: Address,
    VirtAddr: Address,
{
    pub fn new(host_offset: usize, offset: usize, root: PhysAddr) -> Self {
        Self {
            host_offset,
            offset,
            root,
            _virt: PhantomData,
        }
    }

    pub fn map_range(
        &mut self,
        allocator: &impl FrameAllocator,
        virt_addr: VirtAddr,
        phys_addr: PhysAddr,
        size: usize,
        prot: PtFlag,
    ) {
        //TODO check alignment
        let offset = self.offset;
        unsafe {
            self.walk_range(
                virt_addr,
                VirtAddr::from_usize(virt_addr.as_usize() + size),
                &mut |addr, entry, level| {
                    // TODO(aghosn) handle rewrite of access rights.
                    if (*entry & PtFlag::PRESENT.bits()) != 0 {
                        return WalkNext::Continue;
                    }
                    let end = virt_addr.as_usize() + size;
                    let phys = phys_addr.as_u64() + (addr.as_u64() - virt_addr.as_u64());
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
                        .allocate_frame()
                        .expect("map_range: unable to allocate page table entry.")
                        .zeroed();
                    assert!(frame.phys_addr.as_u64() >= offset as u64);
                    *entry = (frame.phys_addr.as_u64() - (offset as u64))
                        | DEFAULT_PROTS.bits();
                    WalkNext::Continue
                },
            )
            .expect("Failed to map PTs");
        }
    }
}
