//! Linked list allocator
//! Inpired from allocator.rs from aghosn_stage2 branch and https://os.phil-opp.com/allocator-designs/

// TODO check for safe static operations

use vmx::{Frame, HostPhysAddr};

const PAGE_SIZE: u64 = 0x1000;
pub const NB_PAGES: usize = 40;

#[derive(Copy, Clone)]
#[repr(C, align(0x1000))]
pub struct Page {
    pub data: [u8; PAGE_SIZE as usize],
}

#[derive(Clone, Copy)]
pub struct PageInfo {
    pub next_free: Option<usize>,
}

static mut MEMORY_PAGES: [Page; NB_PAGES] = [Page {
    data: [0; PAGE_SIZE as usize],
}; NB_PAGES];

// Linked list stored as an array
static mut LINKED_LIST_FREE_PAGES: [PageInfo; NB_PAGES] = [PageInfo {
    next_free: Some(0),
}; NB_PAGES];

pub struct FrameAllocator {
    head: Option<usize>,
    phys_offset: u64,
    virt_offset: u64,
}

impl FrameAllocator {
    pub fn new(phys: u64, virt: u64) -> Self {
        Self::init();
        Self {
            head: Some(0),
            phys_offset: phys,
            virt_offset: virt,
        }
    }

    pub fn init() {
        unsafe {
            for i in 0..NB_PAGES - 1 {
                LINKED_LIST_FREE_PAGES[i] = PageInfo {
                    next_free: Some(i + 1),
                }
            }
            LINKED_LIST_FREE_PAGES[NB_PAGES - 1] = PageInfo {
                next_free: None,
            }
        }
    }

    fn allocate_frame_get_id(&mut self) -> Option<usize> {
        let curr_head = self.head;
        unsafe {
            match curr_head {
                Some(x) => {
                    self.head = LINKED_LIST_FREE_PAGES[x].next_free; // Move head to the next free page
                    Some(x)
                }
                None => None,
            }
        }
    }

    pub fn allocate_frame(&mut self) -> Option<Frame> {
        let id = Self::allocate_frame_get_id(self);
        unsafe {
            match id {
                Some(x) => {
                    let addr = &MEMORY_PAGES[x] as *const _ as *mut u8;
                    let phys_addr = (addr as u64) - self.virt_offset + self.phys_offset;
                    return Some(Frame {
                        phys_addr: HostPhysAddr::new(phys_addr as usize),
                        virt_addr: addr,
                    });
                }
                None => None,
            }
        }
    }

    pub unsafe fn deallocate_frame(&mut self, frame: Frame) {
        let id = (frame.virt_addr as *const _ as usize) - (&MEMORY_PAGES[0] as *const _ as usize);
        if id >= NB_PAGES {
            // Simply return if index is out of bounds
            return;
        }

        // Replace the head with the new freed frame
        let old_head = self.head;
        // TODO: how to put back the new free block in the linked list? For now I use
        // the fact that we have a 1 1 mapping between MEMORY_PAGES and LINKED_LIST_FREE_PAGES.
        self.head = Some(id);
        LINKED_LIST_FREE_PAGES[id as usize].next_free = old_head;
    }
}
