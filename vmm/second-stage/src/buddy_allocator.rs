//! Revisited buddy allocator

use core::arch::asm;
use vmx::{Frame, HostPhysAddr};

const PAGE_SIZE: u64 = 0x1; // TODO change that
const NB_GB: usize = 2; // 2Gb memory
const NB_PAGES: usize = 512 * 512 * NB_GB;
const TREE_4KB_SIZE: usize = 8209;
//const TREE_2MB_SIZE: usize = 17;
const TREE_1GB_SIZE: usize = 1; // TODO change that to upper log64(x)

#[derive(Copy, Clone)]
//#[repr(C, align(0x1000))]
pub struct Page {
    pub data: [u8; PAGE_SIZE as usize],
}

static mut MEMORY_PAGES: [Page; NB_PAGES] = [Page {
    data: [0; PAGE_SIZE as usize],
}; NB_PAGES];

static mut TREE_4KB: [u64; TREE_4KB_SIZE] = [0xFFFFFFFFFFFFFFFF; TREE_4KB_SIZE];
//static mut TREE_2MB: [u64; TREE_2MB_SIZE] = [0xFFFFFFFFFFFFFFFF; TREE_2MB_SIZE];
//static mut TREE_1GB: [u64; TREE_1GB_SIZE] = [0xFFFFFFFFFFFFFFFF; TREE_1GB_SIZE];

pub struct BuddyAllocator {
    phys_offset: u64,
    virt_offset: u64,
}

impl BuddyAllocator {
    pub fn new(phys: u64, virt: u64) -> Self {
        Self::init();
        Self {
            phys_offset: phys,
            virt_offset: virt,
        }
    }

    pub fn init() {}

    fn bsf(input: u64) -> usize {
        assert!(input > 0);
        let mut pos: usize;
        unsafe {
            asm! {
                "bsf {pos}, {input}",
                input = in(reg) input,
                pos = out(reg) pos,
                options(nomem, nostack, preserves_flags),
            };
        };
        assert!(pos < 64);
        pos
    }

    pub fn allocate_frame(&mut self) -> Option<Frame> {
        unsafe {
            // First level search
            if TREE_4KB[0] == 0 {
                return None;
            }
            let l1_idx = Self::bsf(TREE_4KB[0]);
            if l1_idx >= NB_GB {
                assert!(false);
                return None;
            }

            // Second level search
            let first_block_l2 = TREE_1GB_SIZE + 8 * l1_idx;
            let mut block_chosen_l2 = 8;
            for i in 0..8 {
                if TREE_4KB[first_block_l2 + i] != 0 {
                    block_chosen_l2 = i;
                    break;
                }
            }
            assert!(block_chosen_l2 < 8);
            assert!(TREE_4KB[first_block_l2 + block_chosen_l2] != 0u64);
            let l2_idx =
                Self::bsf(TREE_4KB[first_block_l2 + block_chosen_l2]) + 64 * block_chosen_l2;

            // Third level search
            let first_block_l3 = TREE_1GB_SIZE + 8 * NB_GB + 512 * 8 * l1_idx + 8 * l2_idx;
            let mut block_chosen_l3 = 8;
            for j in 0..8 {
                if TREE_4KB[first_block_l3 + j] != 0u64 {
                    block_chosen_l3 = j;
                    break;
                }
            }
            assert!(block_chosen_l3 < 8);
            assert!(TREE_4KB[first_block_l3 + block_chosen_l3] != 0);
            let l3_idx =
                Self::bsf(TREE_4KB[first_block_l3 + block_chosen_l3]) + 64 * block_chosen_l3;

            // Set bits to 0
            TREE_4KB[first_block_l3 + block_chosen_l3] &= !(1u64 << (l3_idx % 64));
            // if block is full set upper level to 0
            if l3_idx == 511 {
                TREE_4KB[first_block_l2 + block_chosen_l2] &= !(1u64 << (l2_idx % 64));
                if l2_idx == 511 {
                    TREE_4KB[0] &= !(1u64 << l1_idx);
                }
            }
            // TODO need to switch other bits from TREE_1GB and TREE_2MB

            let final_idx = 512 * 512 * l1_idx + 512 * l2_idx + l3_idx;
            let addr = &MEMORY_PAGES[final_idx] as *const _ as *mut u8;
            let phys_addr = (addr as u64) - self.virt_offset + self.phys_offset;
            return Some(Frame {
                phys_addr: HostPhysAddr::new(phys_addr as usize),
                virt_addr: addr,
            });
        }
    }

    pub unsafe fn deallocate_frame(&mut self, frame: Frame) {
        let mut id =
            (frame.virt_addr as *const _ as usize) - (&MEMORY_PAGES[0] as *const _ as usize);

        let l3_block_idx = id & 0x1FF;
        id >>= 9;
        let l2_block_idx = id & 0x1FF;
        id >>= 9;
        let l1_block_idx = id & 0x1FF;

        // TODO check that frame was previously allocated
        let l1_tree_idx = 0; // assume l1_block_idx is between 0 and 63
        TREE_4KB[l1_tree_idx] |= 1u64 << l1_block_idx;
        let l2_tree_idx = TREE_1GB_SIZE + 8 * l1_block_idx + l2_block_idx / 64;
        TREE_4KB[l2_tree_idx] |= 1u64 << (l2_block_idx % 64);
        let l3_tree_idx = TREE_1GB_SIZE
            + 8 * NB_GB
            + 512 * 8 * l1_block_idx
            + 8 * l2_block_idx
            + l3_block_idx / 64;
        TREE_4KB[l3_tree_idx] |= 1u64 << (l3_block_idx % 64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alloc_works() {
        let mut frame_alloc = BuddyAllocator::new(0, 0);
        let new_frame = frame_alloc.allocate_frame();
        assert!(new_frame.is_some());
    }

    #[test]
    fn test_alloc_when_full() {
        let mut frame_alloc = BuddyAllocator::new(0, 0);
        for _ in 0..NB_PAGES {
            let new_frame = frame_alloc.allocate_frame();
            assert!(new_frame.is_some());
        }
        let new_frame = frame_alloc.allocate_frame();
        assert!(new_frame.is_none());
    }

    #[test]
    fn test_alloc_and_dealloc_several_times() {
        let mut frame_alloc = BuddyAllocator::new(0, 0);
        for _ in 0..NB_PAGES * 10 {
            let new_frame = frame_alloc.allocate_frame();
            assert!(new_frame.is_some());
            unsafe { frame_alloc.deallocate_frame(new_frame.unwrap()) };
        }
    }

    #[test]
    fn test_two_allocated_frame_are_diff() {
        let mut frame_alloc = BuddyAllocator::new(0, 0);
        let frame1 = frame_alloc.allocate_frame();
        assert!(frame1.is_some());
        let frame2 = frame_alloc.allocate_frame();
        assert!(frame2.is_some());

        assert_ne!(
            frame1.as_ref().unwrap().phys_addr,
            frame2.as_ref().unwrap().phys_addr
        );
        assert_ne!(
            frame1.as_ref().unwrap().virt_addr,
            frame2.as_ref().unwrap().virt_addr
        );
    }

    fn bsf(input: u64) -> u64 {
        let mut pos: u64;
        // "bsf %1, %0" : "=r" (pos) : "rm" (input),
        unsafe {
            asm! {
                "bsf {pos}, {input}",
                input = in(reg) input,
                pos = out(reg) pos,
                options(nomem, nostack, preserves_flags),
            };
        };
        pos
    }

    #[test]
    fn test_speed_bsf() {
        let x = 0x8000000000000000u64;

        assert_eq!(bsf(x), 63);
    }
}
