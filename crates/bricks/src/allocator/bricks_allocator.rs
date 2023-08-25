use core::cell::{RefCell, UnsafeCell};

use x86_64::VirtAddr;

use super::page_allocator;
pub const NUM_PAGES: usize = 16;
pub struct BricksAllocator {
    pub pages: [u64; NUM_PAGES],
    pub allocated: [bool; NUM_PAGES],
}

impl BricksAllocator {
    pub fn kmalloc(&mut self, num_bytes: u64) -> (bool, VirtAddr) {
        let (res, addr) = page_allocator::alloc_page();
        if res {
            for i in 0..NUM_PAGES {
                if !self.allocated[i] {
                    self.allocated[i] = true;
                    self.pages[i] = addr.as_u64();
                    return (res, addr);
                }
            }
            return (false, VirtAddr::new(0)); // should never happen ?
        }
        (res, addr)
    }

    pub fn kfree(&mut self, addr: VirtAddr) -> bool {
        for i in 0..NUM_PAGES {
            if self.allocated[i] && self.pages[i] == addr.as_u64() {
                self.allocated[i] = false;
                return true;
            }
        }

        false
    }

    pub fn new() -> Self {
        BricksAllocator {
            pages: [0; NUM_PAGES],
            allocated: [false; NUM_PAGES],
        }
    }
}
