//! # Heap Allocator

use crate::mmu::frames::FrameAllocator;
use crate::mmu::{PtFlag, PtMapper};
use crate::{HostPhysAddr, HostVirtAddr};
use alloc::alloc::GlobalAlloc;
use core::sync::atomic::{AtomicBool, Ordering};
use x86_64::instructions::tlb;

mod fallback;
mod global;
mod utils;

pub use fallback::FallbackAllocator;

pub const HEAP_START: usize = 0x4444_4444_0000;
pub const HEAP_SIZE: usize = 20 * 0x1000;

static IS_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initializes the kernel heap.
pub fn init_heap(
    mapper: &mut PtMapper<HostPhysAddr, HostVirtAddr>,
    frame_allocator: &impl FrameAllocator,
) -> Result<(), ()> {
    if IS_INITIALIZED.swap(true, Ordering::SeqCst) {
        // Already initialized
        return Ok(());
    }

    // Find space for the heap and create the mappings
    let heap_range = frame_allocator
        .allocate_range(HEAP_SIZE)
        .expect("Could not allocate kernel heap");
    mapper.map_range(
        frame_allocator,
        HostVirtAddr::new(HEAP_START),
        heap_range.start,
        HEAP_SIZE,
        PtFlag::PRESENT | PtFlag::WRITE | PtFlag::EXEC_DISABLE,
    );

    // SAFETY: We check that the method is called only once and the heap is valid (mappings are
    // created just above).
    unsafe {
        tlb::flush_all(); // Update page table to prevent #PF
        GLOBAL_ALLOC.lock().init(HEAP_START, HEAP_SIZE);
    }

    Ok(())
}

// —————————————————————————— The Global Allocator —————————————————————————— //

#[global_allocator]
static GLOBAL_ALLOC: utils::Locked<global::GlobalAllocator> =
    utils::Locked::new(global::GlobalAllocator::new());

unsafe impl GlobalAlloc for utils::Locked<global::GlobalAllocator> {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        self.lock().alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        self.lock().dealloc(ptr, layout)
    }
}
