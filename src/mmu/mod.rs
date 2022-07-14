//! Memory Management unit

pub mod frames;
pub mod walker;

pub use frames::{init, SharedFrameAllocator};

use crate::vmx::{GuestPhysAddr, GuestVirtAddr, HostVirtAddr};
use walker::{Level, WalkNext, Walker};

// ——————————————————————————— Page Table Walker ———————————————————————————— //

/// Page Table Walker
pub struct PtWalker {
    offset: usize,
    root: GuestPhysAddr,
}

impl PtWalker {
    pub fn new(root: GuestPhysAddr, offset: usize) -> Self {
        Self { root, offset }
    }

    pub fn debug_print(&mut self) -> Result<(), ()> {
        use crate::println;

        println!("Walking page tables:");
        unsafe {
            self.walk_range(
                GuestVirtAddr::new(0),
                GuestVirtAddr::new(0x1000000000000),
                |addr, entry, level| {
                    if Self::is_leaf(*entry, level) {
                        WalkNext::Leaf
                    } else {
                        println!("{:?} - 0x{:x} - 0x{:x}", level, addr.as_u64(), *entry);
                        WalkNext::Continue
                    }
                },
            )
        }
    }

    fn is_leaf(entry: u64, level: Level) -> bool {
        if level != Level::L4 && (entry & (1 << 7)) != 0 {
            // Huge page
            true
        } else {
            // Present flag
            entry & 0b1 == 0
        }
    }
}

unsafe impl Walker for PtWalker {
    type PhysAddr = GuestPhysAddr;
    type VirtAddr = GuestVirtAddr;

    fn translate(&self, phys_addr: Self::PhysAddr) -> HostVirtAddr {
        HostVirtAddr::new(phys_addr.as_usize() + self.offset)
    }

    fn root(&mut self) -> (Self::PhysAddr, Level) {
        (self.root, Level::L4)
    }
}
