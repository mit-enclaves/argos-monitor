//! A simple bump allocator based on a static bss array.
//! This should be replaced with a verified implementation.

use vmx::{Frame, HostPhysAddr};

const PAGE_SIZE: u64 = 0x1000;
const NB_PAGES: usize = 40;

#[derive(Copy, Clone)]
#[repr(C, align(0x1000))]
pub struct Page {
    pub data: [u8; PAGE_SIZE as usize],
}

static mut MEMORY_PAGES: [Page; NB_PAGES] = [Page {
    data: [0; PAGE_SIZE as usize],
}; NB_PAGES];

pub struct FrameAllocator {
    curr: usize,
    phys_offset: u64,
    virt_offset: u64,
}

impl FrameAllocator {
    pub fn new(phys: u64, virt: u64) -> Self {
        Self {
            curr: 0,
            phys_offset: phys,
            virt_offset: virt,
        }
    }
    pub fn allocate_frame(&mut self) -> Option<Frame> {
        unsafe {
            if self.curr == MEMORY_PAGES.len() {
                return None;
            }
            let curr = self.curr;
            self.curr += 1;
            let addr = &MEMORY_PAGES[curr] as *const _ as *mut u8;
            let phys_addr = (addr as u64) - self.virt_offset + self.phys_offset;
            return Some(Frame {
                phys_addr: HostPhysAddr::new(phys_addr as usize),
                virt_addr: addr,
            });
        }
    }
}
