//! Memory object representation
use core::cell::RefCell;

use arena::{ArenaItem, Handle};
use bitflags::bitflags;
use utils::HostPhysAddr;

use crate::access::AccessRights;
use crate::error::ErrorCode;
use crate::{Capability, CapabilityType, Object, Ownership, Pool};

bitflags! {
    pub struct MemoryFlags: u64 {
        const NONE = 0;
        /// Read the memory.
        const READ = 1 << 0;
        /// Write to the memory.
        const WRITE = 1 << 1;
        /// Execute code held in memory.
        const EXEC = 1 << 2;
        /// Super code hosted in this memory.
        const SUPER = 1 << 3;
        /// Share the region further.
        const SHARE = 1 << 4;
    }
}

pub const ALL_RIGHTS: MemoryFlags = MemoryFlags::READ
    .union(MemoryFlags::WRITE)
    .union(MemoryFlags::EXEC)
    .union(MemoryFlags::SUPER)
    .union(MemoryFlags::SHARE);

pub const SHARE_USER: MemoryFlags = MemoryFlags::READ
    .union(MemoryFlags::WRITE)
    .union(MemoryFlags::EXEC)
    .union(MemoryFlags::SHARE);

pub const NO_SHARE_USER: MemoryFlags = MemoryFlags::READ
    .union(MemoryFlags::WRITE)
    .union(MemoryFlags::EXEC);

#[derive(Copy, Clone, Debug)]
pub struct MemoryAccess {
    /// New bounds.
    pub start: HostPhysAddr,
    pub end: HostPhysAddr,

    /// Access rights
    pub flags: MemoryFlags,
}

/// MemoryRegion represents a segment of memory.
/// All memory regions are organized as a linked list of non overlapping segments.
/// A capability can span 1 or several memory regions.
/// The spans are exact, i.e., capability.start and capability.end should correspond
/// to a region.start and a (potentially other) region.end.
/// MemoryRegions are split with capability operations (dup).
///             Capa __
///             |      \
///             v       v
/// |head| <-> |1| <-> |3| <-> |1|
#[derive(Debug)]
pub struct MemoryRegion {
    /// Bounds for the region.
    pub start: HostPhysAddr,
    pub end: HostPhysAddr,

    /// Reference count for this region.
    pub ref_count: usize,

    // Linked List.
    pub prev: Option<Handle<Self>>,
    pub next: Option<Handle<Self>>,
}

/// Empty memory region.
pub const EMPTY_MEMORY_REGION: RefCell<MemoryRegion> = RefCell::new(MemoryRegion {
    start: HostPhysAddr::new(0),
    end: HostPhysAddr::new(0),
    ref_count: usize::MAX,
    prev: None,
    next: None,
});

/// Empty memory region capability.
pub const EMPTY_MEMORY_REGION_CAPA: RefCell<Capability<MemoryRegion>> = RefCell::new(Capability {
    owner: Ownership::Empty,
    capa_type: CapabilityType::Resource,
    access: MemoryAccess {
        start: HostPhysAddr::new(0),
        end: HostPhysAddr::new(0),
        flags: MemoryFlags::NONE,
    },
    handle: Handle::new_unchecked(0),
    left: Handle::null(),
    right: Handle::null(),
});

impl AccessRights for MemoryAccess {
    fn is_null(&self) -> bool {
        self.start == self.end || self.flags == MemoryFlags::NONE
    }
    fn is_subset(&self, other: &Self) -> bool {
        // If the other is null.
        if other.is_null() {
            return true;
        }
        // Prevent sharing
        if self.flags & MemoryFlags::SHARE == MemoryFlags::NONE {
            return false;
        }
        if other.start < self.start || other.start >= self.end {
            return false;
        }
        if other.end <= self.start || other.end > self.end {
            return false;
        }
        (self.flags ^ other.flags) & other.flags == MemoryFlags::NONE
    }

    /// A valid dup for a memory region requires:
    /// 1) The supplied regions must be contained within the region.
    /// 2) The access rights must be smaller or equal to original ones.
    fn is_valid_dup(&self, op1: &Self, op2: &Self) -> bool {
        self.is_subset(op1) && self.is_subset(op2)
    }

    fn get_null() -> Self {
        Self {
            start: HostPhysAddr::new(0),
            end: HostPhysAddr::new(0),
            flags: MemoryFlags::NONE,
        }
    }
}

impl MemoryRegion {
    pub fn new(
        pool: &impl Pool<Self>,
        start: usize,
        end: usize,
    ) -> Result<Handle<Self>, ErrorCode> {
        if start >= end {
            return Err(ErrorCode::MalformedRegion);
        }
        let region_handle = pool.allocate()?;
        let mut region = pool.get_mut(region_handle);
        region.start = HostPhysAddr::new(start);
        region.end = HostPhysAddr::new(end);
        region.ref_count = 1;
        region.next = None;
        region.prev = None;
        Ok(region_handle)
    }
    fn insert(
        orig: &Capability<Self>,
        pool: &impl Pool<Self>,
        op: &MemoryAccess,
    ) -> Result<Handle<Self>, ErrorCode> {
        // Check for errors or perfect overlap.
        {
            // Check we start from the right region.
            if op.start < orig.access.start || op.start >= orig.access.end {
                return Err(ErrorCode::MemoryRegionOutOfBounds);
            }
            // Easy-case, perfect overlap.
            if orig.access.start == op.start && orig.access.end == op.end {
                return Ok(orig.handle);
            }
        }
        // Find the correct start.
        let handle: Handle<MemoryRegion> = {
            let mut curr_handle = orig.handle;
            loop {
                let obj = pool.get(curr_handle);
                if obj.start <= op.start && obj.end > op.start {
                    break;
                }
                match obj.next {
                    Some(h) => curr_handle = h,
                    _ => {
                        return Err(ErrorCode::Debug);
                    }
                }
            }
            curr_handle
        };

        // Handle the start.
        let start: Handle<Self> = {
            let mut curr = pool.get_mut(handle);
            if curr.start == op.start {
                handle
            } else {
                // Create a new region.
                let region_handle = pool.allocate()?;
                let mut region = pool.get_mut(region_handle);
                region.start = op.start;
                region.end = curr.end;
                region.ref_count = curr.ref_count;
                curr.end = region.start;
                region.prev = Some(handle);
                region.next = curr.next;
                curr.next = Some(region_handle);
                // Fix the next.prev.
                match region.next {
                    Some(n) => {
                        let mut next = pool.get_mut(n);
                        next.prev = Some(region_handle);
                    }
                    _ => {}
                }
                region_handle
            }
        };
        // Handle the end.
        let mut curr_handle = handle;
        {
            loop {
                let curr = pool.get(curr_handle);
                if op.end > curr.start && op.end <= curr.end {
                    // Found it;
                    break;
                }
                // uh-oh we have a malformed region.
                if op.end < curr.start {
                    return Err(ErrorCode::MemoryRegionOutOfBounds);
                }
                match curr.next {
                    Some(h) => curr_handle = h,
                    _ => return Err(ErrorCode::MemoryRegionOutOfBounds),
                }
            }
        }
        let mut end = pool.get_mut(curr_handle);
        // Need a split.
        if op.end != end.end {
            let region_handle = pool.allocate()?;
            let mut region = pool.get_mut(region_handle);
            region.start = op.end;
            region.end = end.end;
            end.end = op.end;
            region.prev = Some(curr_handle);
            region.next = end.next;
            end.next = Some(region_handle);
            region.ref_count = end.ref_count;
            // Fix the next.prev.
            match region.next {
                Some(n) => {
                    let mut next = pool.get_mut(n);
                    next.prev = Some(region_handle);
                }
                _ => {}
            }
        }
        Ok(start)
    }

    pub fn overlap(s1: HostPhysAddr, e1: HostPhysAddr, s2: HostPhysAddr, e2: HostPhysAddr) -> bool {
        (s1 >= s2 && s1 < e2)
            || (e1 > s2 && e1 <= e2)
            || (s2 >= s1 && s2 < e1)
            || (e2 > s1 && e2 <= e1)
    }

    pub fn merge(&mut self, nb: usize, pool: &impl Pool<Self>, capa: &Capability<Self>) {
        if self.ref_count != nb {
            return;
        }
        let mut next = self.next;
        loop {
            match next {
                Some(n) => {
                    // Let's merge it
                    let elem = pool.get(n);
                    if elem.ref_count == nb && elem.start == self.end && elem.end <= capa.access.end
                    {
                        self.end = elem.end;
                        self.next = elem.next;
                        // Fix the prev pointer
                        match self.next {
                            Some(nn) => {
                                let mut next_next = pool.get_mut(nn);
                                next_next.prev = elem.prev;
                            }
                            _ => {}
                        }
                        // Clean the region.
                        pool.free(n);
                        // Move to the next
                        next = self.next;
                    } else {
                        // Stop here.
                        return;
                    }
                }
                _ => {
                    return;
                }
            }
        }
    }
}

impl Object for MemoryRegion {
    type Access = MemoryAccess;

    fn from_bits(start: usize, end: usize, flags: usize) -> Self::Access {
        MemoryAccess {
            start: HostPhysAddr::new(start),
            end: HostPhysAddr::new(end),
            flags: MemoryFlags::from_bits_truncate(flags as u64),
        }
    }

    fn incr_ref(&mut self, pool: &impl Pool<Self>, capa: &Capability<Self>) {
        self.ref_count += 1;
        let mut curr = self.next;
        loop {
            match curr {
                Some(n) => {
                    let mut next = pool.get_mut(n);
                    if MemoryRegion::overlap(
                        capa.access.start,
                        capa.access.end,
                        next.start,
                        next.end,
                    ) {
                        next.ref_count += 1;
                        curr = next.next;
                    } else {
                        break;
                    }
                }
                _ => break,
            }
        }
    }

    fn decr_ref(&mut self, pool: &impl Pool<Self>, capa: &Capability<Self>) {
        self.ref_count -= 1;
        let mut curr = self.next;
        loop {
            match curr {
                Some(n) => {
                    let mut next = pool.get_mut(n);
                    if MemoryRegion::overlap(
                        capa.access.start,
                        capa.access.end,
                        next.start,
                        next.end,
                    ) {
                        next.ref_count -= 1;
                        curr = next.next;
                    } else {
                        break;
                    }
                }
                _ => break,
            }
        }
    }

    fn get_ref(&self, pool: &impl Pool<Self>, capa: &Capability<Self>) -> usize {
        // Find the max of all the overlaps
        let mut max_ref = self.ref_count;
        let mut curr = self.next;
        loop {
            match curr {
                Some(n) => {
                    let next = pool.get(n);
                    if MemoryRegion::overlap(
                        capa.access.start,
                        capa.access.end,
                        next.start,
                        next.end,
                    ) {
                        if max_ref < next.ref_count {
                            max_ref = next.ref_count;
                        }
                        curr = next.next;
                    } else {
                        break;
                    }
                }
                _ => break,
            }
        }
        max_ref
    }

    fn create_from(
        pool: &impl Pool<Self>,
        capa: &Capability<Self>,
        op: &Self::Access,
    ) -> Result<Handle<Capability<Self>>, ErrorCode>
    where
        Self: Sized,
    {
        if capa.owner == Ownership::Empty {
            return Err(ErrorCode::NotOwnedCapability);
        }
        // Nothing to do,
        if op.is_null() {
            return Ok(Handle::null());
        }
        // Check again access rights.
        if !capa.access.is_subset(op) {
            return Err(ErrorCode::IncreasingAccessRights);
        }
        // Insert the correct region.
        let handle = MemoryRegion::insert(capa, pool, op)?;
        let capa_handle = pool.allocate_capa()?;
        {
            let mut capa = pool.get_capa_mut(capa_handle);
            capa.capa_type = CapabilityType::Resource;
            capa.access = *op;
            capa.handle = handle;
            capa.left = Handle::null();
            capa.right = Handle::null();
        }
        // Increment the reference count.
        {
            let mut obj = pool.get_mut(handle);
            let capa = pool.get_capa(capa_handle);
            obj.incr_ref(pool, &capa);
        }
        if let Ownership::Domain(dom, _) = capa.owner {
            pool.set_owner_capa(capa_handle, dom)?;
        }
        Ok(capa_handle)
    }

    /*
    fn install(&mut self, pool: &impl Pool<Self>, capa: &Capability<Self>) -> Result<(), ErrorCode>
    where
        Self: Sized,
        P: Pool<Self>,
    {
        self.merge(1, pool, capa);
        // Call the backend.
        pool.apply(capa)
    }

    fn uninstall<P>(
        &mut self,
        pool: &P,
        capa: &Capability<Self>,
    ) -> Result<(), Error<<P::B as Backend>::Error>>
    where
        Self: Sized,
        P: Pool<Self>,
    {
        self.merge(0, pool, capa);
        pool.apply(capa)
    }
    */
}

// ———————————————————————— Capability<MemoryRegion> ———————————————————————— //

impl Capability<MemoryRegion> {
    pub fn new_with_region(
        pool: &impl Pool<MemoryRegion>,
        access: MemoryAccess,
    ) -> Result<Handle<Self>, ErrorCode> {
        let region_handle =
            MemoryRegion::new(pool, access.start.as_usize(), access.end.as_usize())?;
        let capa_handle = pool.allocate_capa()?;
        let mut capa = pool.get_capa_mut(capa_handle);
        capa.capa_type = CapabilityType::Resource;
        capa.handle = region_handle;
        capa.access = access;
        capa.left = Handle::null();
        capa.right = Handle::null();
        Ok(capa_handle)
    }
}

// ——————————————————————— Arena Trait Implementation ——————————————————————— //
impl ArenaItem for MemoryRegion {
    type Error = ErrorCode;
    const OUT_OF_BOUND_ERROR: Self::Error = ErrorCode::OutOfBound;
    const ALLOCATION_ERROR: Self::Error = ErrorCode::AllocationError;
}
