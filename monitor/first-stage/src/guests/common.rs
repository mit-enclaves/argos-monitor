use core::slice;

use mmu::FrameAllocator;
use vtd::{ContextEntry, RootEntry};

use crate::HostPhysAddr;

/// Setups the I/O MMU context, i.e. a root and context frame for which all entries points to the
/// given I/O page tables.
pub fn setup_iommu_context(
    iopt_root: HostPhysAddr,
    allocator: &impl FrameAllocator,
) -> HostPhysAddr {
    let ctx_frame = allocator
        .allocate_frame()
        .expect("I/O MMU context frame")
        .zeroed();
    let root_frame = allocator
        .allocate_frame()
        .expect("I/O MMU root frame")
        .zeroed();
    let ctx_entry = ContextEntry {
        upper: 0b010, // 4 lvl pages
        lower: iopt_root.as_u64() | 0b0001,
    };
    let root_entry = RootEntry {
        reserved: 0,
        entry: ctx_frame.phys_addr.as_u64() | 0b1, // Mark as present
    };

    unsafe {
        let ctx_array = slice::from_raw_parts_mut(ctx_frame.virt_addr as *mut ContextEntry, 256);
        let root_array = slice::from_raw_parts_mut(root_frame.virt_addr as *mut RootEntry, 256);

        for entry in ctx_array {
            *entry = ctx_entry;
        }
        for entry in root_array {
            *entry = root_entry;
        }
    }

    root_frame.phys_addr
}
