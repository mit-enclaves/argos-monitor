//! Memory Mapings
//!
//! This module provides abstractions for manipulating virtual memory mappings (i.e. page tables).

use crate::vmx::{GuestPhysAddr, GuestVirtAddr, HostPhysAddr, HostVirtAddr};
use core::slice;

/// Number of entries per page.
const NB_ENTRIES: usize = 512;
/// Size of a single page.
const PAGE_SIZE: u64 = 0x1000;
/// A mask for extracting an address from a page table entry.
const ADDRESS_MASK: u64 = 0x7fffffffff000;
/// Mask for the last 9 bits, corresponding to the size of page table indexes.
const PAGE_TABLE_INDEX_MASK: u64 = 0b111111111;

// —————————————————————————————— Page Levels ——————————————————————————————— //

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    L4,
    L3,
    L2,
    L1,
}

impl Level {
    /// Returns the next level (i.e. the level of pages pointed by the entries of the current
    /// level)
    fn next(self) -> Option<Self> {
        match self {
            Level::L4 => Some(Level::L3),
            Level::L3 => Some(Level::L2),
            Level::L2 => Some(Level::L1),
            Level::L1 => None,
        }
    }

    /// Returns the size of the memory region controlled by each entry of this level.
    fn area_size(self) -> u64 {
        match self {
            Level::L4 => PAGE_SIZE << 27,
            Level::L3 => PAGE_SIZE << 18,
            Level::L2 => PAGE_SIZE << 9,
            Level::L1 => PAGE_SIZE,
        }
    }

    fn mask(self) -> u64 {
        match self {
            Level::L4 => !((1 << 39) - 1),
            Level::L3 => !((1 << 30) - 1),
            Level::L2 => !((1 << 21) - 1),
            Level::L1 => !((1 << 12) - 1),
        }
    }
}

// ——————————————————————————————— Addresses ———————————————————————————————— //

pub trait Address: Sized + Copy + Ord {
    fn from_u64(addr: u64) -> Self;
    fn as_u64(self) -> u64;
    fn from_usize(addr: usize) -> Self;
    fn as_usize(self) -> usize;

    /// Adds an offset to the current address.
    #[inline]
    fn add(self, offset: u64) -> Option<Self> {
        match self.as_u64().checked_add(offset) {
            None => None,
            Some(val) => Some(Self::from_u64(val)),
        }
    }

    /// Apply a mask to the address (binary and).
    #[inline]
    fn mask(self, mask: u64) -> Self {
        Self::from_u64(self.as_u64() & mask)
    }

    /// Returns this address' L4 index.
    #[inline]
    fn l4_index(self) -> usize {
        ((self.as_u64() >> 39) & PAGE_TABLE_INDEX_MASK) as usize
    }

    /// Returns this address' L3 index.
    #[inline]
    fn l3_index(self) -> usize {
        ((self.as_u64() >> 30) & PAGE_TABLE_INDEX_MASK) as usize
    }

    /// Returns this address' L2 index.
    #[inline]
    fn l2_index(self) -> usize {
        ((self.as_u64() >> 21) & PAGE_TABLE_INDEX_MASK) as usize
    }

    /// Returns this address' L1 index.
    #[inline]
    fn l1_index(self) -> usize {
        ((self.as_u64() >> 12) & PAGE_TABLE_INDEX_MASK) as usize
    }

    /// Returns this address index for a given level.
    fn index(self, level: Level) -> usize {
        match level {
            Level::L4 => self.l4_index(),
            Level::L3 => self.l3_index(),
            Level::L2 => self.l2_index(),
            Level::L1 => self.l1_index(),
        }
    }
}

macro_rules! addr_impl {
    ($name:ty) => {
        impl Address for $name {
            #[inline]
            fn from_u64(addr: u64) -> Self {
                Self::new(addr as usize)
            }

            #[inline]
            fn as_u64(self) -> u64 {
                Self::as_u64(self)
            }

            #[inline]
            fn from_usize(addr: usize) -> Self {
                Self::new(addr)
            }

            #[inline]
            fn as_usize(self) -> usize {
                Self::as_usize(self)
            }
        }
    };
}

addr_impl!(GuestPhysAddr);
addr_impl!(GuestVirtAddr);
addr_impl!(HostPhysAddr);
addr_impl!(HostVirtAddr);

// ————————————————————————————————— Walker ————————————————————————————————— //

/// How to continue the walk.
pub enum WalkNext {
    /// Continue to the next page.
    Continue,
    /// Reached a leaf.
    Leaf,
    /// Abort the walk.
    Abort,
}

pub unsafe trait Walker {
    type PhysAddr: Address;
    type VirtAddr: Address;

    /// Translates a physical address in the appropriate context (host or guest) into an host
    /// virtual address.
    fn translate(&self, phys_addr: Self::PhysAddr) -> HostVirtAddr;

    /// Returns the physical address of the root page (L4).
    fn root(&mut self) -> (Self::PhysAddr, Level);

    /// Walk the page tables controlling given address' mapping.
    unsafe fn walk<F>(&mut self, addr: Self::VirtAddr, callback: &mut F) -> Result<(), ()>
    where
        F: FnMut(&mut u64, Level) -> WalkNext,
    {
        let (mut phys_addr, mut level) = self.root();

        loop {
            // Find entry and call callback
            let page = self.as_page(self.translate(phys_addr));
            let idx = addr.index(level);
            let entry = &mut page[idx];
            match callback(entry, level) {
                WalkNext::Abort => return Err(()),
                WalkNext::Leaf => return Ok(()),
                _ => (),
            };

            // Move to next level, if any
            level = if let Some(next) = level.next() {
                next
            } else {
                return Ok(());
            };
            phys_addr = Self::PhysAddr::from_u64(*entry & ADDRESS_MASK);
        }
    }

    /// Walk the page tables entries spanning the range between `start`and ènd`.
    unsafe fn walk_range<F>(
        &mut self,
        start: Self::VirtAddr,
        end: Self::VirtAddr,
        callback: &mut F,
    ) -> Result<(), ()>
    where
        F: FnMut(Self::VirtAddr, &mut u64, Level) -> WalkNext,
    {
        let (phys_addr, level) = self.root();
        let page = as_page(self, self.translate(phys_addr));
        walk_range_rec(self, page, level, start, end, callback)
    }

    unsafe fn as_page(&mut self, addr: HostVirtAddr) -> &mut [u64] {
        let ptr = addr.as_usize() as *mut u64;
        slice::from_raw_parts_mut(ptr, NB_ENTRIES)
    }
}

unsafe fn walk_range_rec<VirtAddr, PhysAddr, W, F>(
    walker: &mut W,
    page: &mut [u64],
    level: Level,
    start: VirtAddr,
    end: VirtAddr,
    callback: &mut F,
) -> Result<(), ()>
where
    VirtAddr: Address,
    PhysAddr: Address,
    W: Walker<VirtAddr = VirtAddr, PhysAddr = PhysAddr> + ?Sized,
    F: FnMut(VirtAddr, &mut u64, Level) -> WalkNext,
{
    let mut idx = start.index(level);
    let mut addr = start;
    let next_level = level.next();
    let level_offset = level.area_size();
    let level_mask = level.mask();

    while addr < end && idx < NB_ENTRIES {
        // Process entry
        let entry = &mut page[idx];
        match callback(addr, entry, level) {
            WalkNext::Continue => {
                // Recursively process next level entries, if any
                if let Some(next) = next_level {
                    let phys_addr = PhysAddr::from_u64(*entry & ADDRESS_MASK);
                    let page = as_page(walker, walker.translate(phys_addr));
                    walk_range_rec(walker, page, next, addr, end, callback)?;
                }
            }
            WalkNext::Leaf => (), // Proceed to the next entry at the same level
            WalkNext::Abort => return Err(()), // Abort walk
        }

        // Move to next entry
        // @warning: mask must be applied before the add to avoid overflowing op.
        addr = match addr.mask(level_mask).add(level_offset) {
            None => break,
            Some(addr) => addr,
        };
        idx += 1;
    }

    Ok(())
}

unsafe fn as_page<'a, 'b, W>(_walker: &'a mut W, addr: HostVirtAddr) -> &'b mut [u64]
where
    'b: 'a,
    W: Walker + ?Sized,
{
    let ptr = addr.as_usize() as *mut u64;
    slice::from_raw_parts_mut(ptr, NB_ENTRIES)
}
