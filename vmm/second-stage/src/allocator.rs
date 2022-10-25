//! A simple bump allocator based on a static bss array.
//! This should be replaced with a verified implementation.

use core::cell::RefCell;

use mmu::{frame_allocator::PhysRange, FrameAllocator};
use utils::{Frame, HostPhysAddr, HostVirtAddr};

use crate::statics::NB_PAGES;

pub const PAGE_SIZE: u64 = 0x1000;

#[derive(Copy, Clone)]
#[repr(C, align(0x1000))]
pub struct Page {
    pub data: [u8; PAGE_SIZE as usize],
}

pub struct BumpInfo {
    curr: usize,
    phys_offset: u64,
    virt_offset: u64,
    pages: &'static mut [Page],
}

impl BumpInfo {
    pub fn new(phys: u64, virt: u64, pages: &'static mut [Page]) -> Self {
        Self {
            curr: 0,
            phys_offset: phys,
            virt_offset: virt,
            pages,
        }
    }
}

impl BumpInfo {
    fn allocate_frame(&mut self) -> Option<Frame> {
        if self.curr == self.pages.len() {
            return None;
        }
        let curr = self.curr;
        self.curr += 1;
        let addr = &self.pages[curr] as *const _ as *mut u8;
        let phys_addr = (addr as u64) - self.virt_offset + self.phys_offset;
        return Some(Frame {
            phys_addr: HostPhysAddr::new(phys_addr as usize),
            virt_addr: addr,
        });
    }

    fn get_boundaries(&self) -> (usize, usize) {
        let addr = &self.pages[0] as *const _ as *mut u8;
        let start_addr = (addr as u64) - self.virt_offset + self.phys_offset;
        let end = &self.pages[NB_PAGES - 1] as *const _ as *mut u8;
        let end_addr = (end as u64) - self.virt_offset + self.phys_offset;
        return (start_addr as usize, end_addr as usize);
    }

    fn get_physical_offset(&self) -> HostVirtAddr {
        return HostVirtAddr::new(self.phys_offset as usize);
    }

    fn allocate_range(&mut self, size: usize) -> Option<PhysRange> {
        if self.curr + size >= self.pages.len() {
            return None;
        }
        let curr = self.curr;
        self.curr += size;
        let saddr = &self.pages[curr] as *const _ as u64;
        let phys_saddr = saddr - self.virt_offset + self.phys_offset;

        let eaddr = &self.pages[self.curr] as *const _ as u64;
        let phys_eaddr = eaddr - self.virt_offset + self.phys_offset;

        return Some(PhysRange {
            start: HostPhysAddr::new(phys_saddr as usize),
            end: HostPhysAddr::new(phys_eaddr as usize),
        });
    }
}

pub struct BumpAllocator {
    alloc: RefCell<BumpInfo>,
}

impl BumpAllocator {
    pub fn new(phys: u64, virt: u64, pages: &'static mut [Page]) -> Self {
        Self {
            alloc: RefCell::new(BumpInfo::new(phys, virt, pages)),
        }
    }
}

unsafe impl FrameAllocator for BumpAllocator {
    fn allocate_frame(&self) -> Option<Frame> {
        let mut inner = self.alloc.borrow_mut();
        inner.allocate_frame()
    }

    fn allocate_range(&self, size: usize) -> Option<PhysRange> {
        let mut inner = self.alloc.borrow_mut();
        inner.allocate_range(size)
    }

    fn get_boundaries(&self) -> (usize, usize) {
        let inner = self.alloc.borrow();
        inner.get_boundaries()
    }

    fn get_physical_offset(&self) -> HostVirtAddr {
        let inner = self.alloc.borrow();
        inner.get_physical_offset()
    }
}
