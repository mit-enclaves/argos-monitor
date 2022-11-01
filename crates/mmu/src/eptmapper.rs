//! EPT mapper implementation

use crate::frame_allocator::FrameAllocator;
use crate::walker::{Level, WalkNext, Walker};
use utils::{GuestPhysAddr, HostPhysAddr, HostVirtAddr};
use vmx::{
    bitmaps::EptEntryFlags,
    ept::{GIANT_PAGE_SIZE, HUGE_PAGE_SIZE, PAGE_SIZE},
};

pub struct EptMapper {
    host_offset: usize,
    root: HostPhysAddr,
}

pub const EPT_PRESENT: EptEntryFlags = EptEntryFlags::READ
    .union(EptEntryFlags::WRITE)
    .union(EptEntryFlags::SUPERVISOR_EXECUTE);

pub const EPT_ROOT_FLAGS: usize = (6 << 0) | (3 << 3);

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
    pub fn new(host_offset: usize, root: HostPhysAddr) -> Self {
        Self { host_offset, root }
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
                        if (level == Level::L3 || level == Level::L2)
                            && ((*entry & EptEntryFlags::PAGE.bits()) != 0)
                        {
                            return WalkNext::Leaf;
                        }
                        return WalkNext::Continue;
                    }

                    let end = gpa.as_usize() + size;
                    let hphys = hpa.as_usize() + (addr.as_usize() - gpa.as_usize());
                    if level == Level::L3 {
                        if (addr.as_usize() + GIANT_PAGE_SIZE <= end)
                            && (hphys % GIANT_PAGE_SIZE == 0)
                        {
                            *entry = hphys as u64 | EptEntryFlags::PAGE.bits() | prot.bits();
                            return WalkNext::Leaf;
                        }
                    }
                    if level == Level::L2 {
                        if (addr.as_usize() + HUGE_PAGE_SIZE <= end)
                            && (hphys % HUGE_PAGE_SIZE == 0)
                        {
                            *entry = hphys as u64 | EptEntryFlags::PAGE.bits() | prot.bits();
                            return WalkNext::Leaf;
                        }
                    }
                    if level == Level::L1 {
                        assert!(hphys % PAGE_SIZE == 0);
                        *entry = hphys as u64 | prot.bits();
                        return WalkNext::Leaf;
                    }
                    let frame = allocator
                        .allocate_frame()
                        .expect("map_range: unable to allocate page table entry")
                        .zeroed();
                    *entry = frame.phys_addr.as_u64() | prot.bits();
                    WalkNext::Continue
                },
            )
            .expect("Failed to map EPTs");
        }
    }

    pub fn unmap_range(
        &mut self,
        allocator: &impl FrameAllocator,
        gpa: GuestPhysAddr,
        size: usize,
        root: HostPhysAddr,
        offset: usize,
    ) {
        //TODO once the allocator is fixed, we should free pages.
        unsafe {
            self.walk_range(
                gpa,
                GuestPhysAddr::new(gpa.as_usize() + size),
                &mut |addr, entry, level| {
                    if (*entry & EPT_PRESENT.bits()) == 0 {
                        return WalkNext::Continue;
                    }

                    let end = gpa.as_usize() + size;
                    let mut needs_remap = false;
                    let mut big_size: usize = 0;
                    let mut aligned_addr = addr.as_usize();

                    // We have a big entry
                    if level == Level::L3 && (*entry & EptEntryFlags::PAGE.bits()) != 0 {
                        aligned_addr = addr.as_usize() & (level.mask() as usize);
                        // Easy case, the entire entry is to be removed.
                        if gpa.as_usize() <= aligned_addr && (aligned_addr + GIANT_PAGE_SIZE <= end)
                        {
                            *entry = 0;
                            return WalkNext::Leaf;
                        }
                        // Harder case, we need to break the entry.
                        *entry = 0;
                        needs_remap = true;
                        big_size = GIANT_PAGE_SIZE;
                    }
                    if level == Level::L2 && (*entry & EptEntryFlags::PAGE.bits()) != 0 {
                        aligned_addr = addr.as_usize() & (level.mask() as usize);
                        // Easy case, the entire entry is to be removed.
                        if gpa.as_usize() <= aligned_addr && (aligned_addr + GIANT_PAGE_SIZE <= end)
                        {
                            *entry = 0;
                            return WalkNext::Leaf;
                        }
                        // Harder case, we need to break the entry.
                        *entry = 0;
                        needs_remap = true;
                        big_size = HUGE_PAGE_SIZE;
                    }
                    if needs_remap {
                        // Harder case for huge entries.
                        let mut mapper = EptMapper::new(offset, root);
                        // Some mapping on the left.
                        if aligned_addr < gpa.as_usize() {
                            let n_size = gpa.as_usize() - aligned_addr;
                            mapper.map_range(
                                allocator,
                                GuestPhysAddr::new(aligned_addr),
                                HostPhysAddr::new(aligned_addr),
                                n_size,
                                EptEntryFlags::READ
                                    | EptEntryFlags::WRITE
                                    | EptEntryFlags::USER_EXECUTE
                                    | EPT_PRESENT,
                            );
                        }
                        // Some mapping on the left.
                        if gpa.as_usize() + size < aligned_addr + big_size {
                            let n_size = aligned_addr + big_size - gpa.as_usize() - size;
                            mapper.map_range(
                                allocator,
                                gpa + size,
                                HostPhysAddr::new(gpa.as_usize() + size),
                                n_size,
                                EptEntryFlags::READ
                                    | EptEntryFlags::WRITE
                                    | EptEntryFlags::USER_EXECUTE
                                    | EPT_PRESENT,
                            );
                        }
                        return WalkNext::Leaf;
                    }
                    if level == Level::L1 {
                        *entry = 0;
                        return WalkNext::Leaf;
                    }
                    WalkNext::Continue
                },
            )
            .expect("Failed to unmap EPTs");
        }
    }

    pub fn get_root(&self) -> HostPhysAddr {
        //let memory_kind = 6 << 0; // write-back usize
        //let walk_length = 3 << 3; // walk length of 4 usize

        HostPhysAddr::new(self.root.as_usize() | EPT_ROOT_FLAGS)
    }
}
