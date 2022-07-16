use alloc::sync::Arc;
use core::cell::Cell;
use core::ops::DerefMut;

use bootloader::boot_info::{MemoryRegion, MemoryRegionKind};
use spin::Mutex;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::frame::PhysFrame;
use x86_64::structures::paging::page_table::PageTable;
use x86_64::structures::paging::OffsetPageTable;
use x86_64::{PhysAddr, VirtAddr};

use crate::allocator;
use crate::vmx;

const PAGE_SIZE: usize = 0x1000;

// ————————————————————————— Re-export definitions —————————————————————————— //

pub use x86_64::structures::paging::page::Size4KiB;

pub unsafe trait FrameAllocator {
    /// Allocates a frame.
    fn allocate_frame(&self) -> Option<vmx::Frame>;

    /// Allocates a range of physical memory.
    fn allocate_range(&self, size: u64) -> Option<PhysRange>;

    /// Returns the boundaries of usable physical memory.
    fn get_boundaries(&self) -> (u64, u64);

    /// Returns the offset between physical and virtual addresses.
    fn get_physical_offset(&self) -> VirtAddr;
}

// ————————————————————————— Memory Initialization —————————————————————————— //

/// Initializes the memory subsystem.
///
/// After success, the memory subsystem is operationnal, meaning that the global allocator is
/// availables (and thus heap allocated values such as `Box` and `Vec` can be used).
///
/// SAFETY: This function must be called **at most once**, and the boot info must contain a valid
/// mapping of the physical memory.
pub unsafe fn init(
    physical_memory_offset: VirtAddr,
    regions: &'static [MemoryRegion],
) -> Result<impl FrameAllocator, ()> {
    let level_4_table = active_level_4_table(physical_memory_offset);

    // Initialize the frame allocator and the memory mapper.
    let mut mapper = OffsetPageTable::new(level_4_table, physical_memory_offset);
    let mut frame_allocator = BootInfoFrameAllocator::init(regions);

    // Initialize the heap.
    allocator::init_heap(&mut mapper, &mut frame_allocator).map_err(|_| ())?;
    let frame_allocator = SharedFrameAllocator::new(frame_allocator, physical_memory_offset);

    Ok(frame_allocator)
}

/// This function is unsafe because the caller must guarantee that the
/// complete physical memory is mapped to virtual memory at the passed
/// `physical_memory_offset`. Also, this function must be only called once
/// to avoid aliasing `&mut` references (which is undefined behavior).
unsafe fn active_level_4_table(physical_memory_offset: VirtAddr) -> &'static mut PageTable {
    let (level_4_table_frame, _) = Cr3::read();

    let phys = level_4_table_frame.start_address();
    let virt = physical_memory_offset + phys.as_u64();
    let page_table: *mut PageTable = virt.as_mut_ptr();

    &mut *page_table
}

// ———————————————————————————— Frame Allocator ————————————————————————————— //

/// A range of physical memory.
pub struct PhysRange {
    /// Start of the physical range (inclusive).
    pub start: PhysAddr,
    /// End of the physical range (exclusive).
    pub end: PhysAddr,
}

impl PhysRange {
    pub fn size(&self) -> usize {
        (self.end.as_u64() - self.start.as_u64()) as usize
    }
}

/// A FrameAllocator that returns usable frames from the bootloader's memory map.
pub struct BootInfoFrameAllocator {
    memory_map: &'static [MemoryRegion],
    region_idx: usize,
    next_frame: u64,
}

impl BootInfoFrameAllocator {
    /// Create a FrameAllocator from the passed memory map.
    ///
    /// This function is unsafe because the caller must guarantee that the passed
    /// memory map is valid. The main requirement is that all frames that are marked
    /// as `USABLE` in it are really unused.
    pub unsafe fn init(memory_map: &'static [MemoryRegion]) -> Self {
        let region_idx = 0;
        let next_frame = memory_map[region_idx].start;
        let mut allocator = BootInfoFrameAllocator {
            memory_map,
            next_frame,
            region_idx,
        };

        // If first region is not usable, we need to move to the next usable one
        if allocator.memory_map[allocator.region_idx].kind != MemoryRegionKind::Usable {
            allocator
                .goto_next_region()
                .expect("No usable memory region");
        }
        allocator
    }

    /// Allocates a single frame.
    pub fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let region = self.memory_map[self.region_idx];
        if self.next_frame >= region.end {
            if self.goto_next_region().is_ok() {
                // Retry allocation
                self.allocate_frame()
            } else {
                // All the memory is exhausted
                None
            }
        } else {
            let frame = PhysFrame::containing_address(PhysAddr::new(self.next_frame));
            self.next_frame += PAGE_SIZE as u64;
            Some(frame)
        }
    }

    /// Allocates a range of physical memory
    pub fn allocate_range(&mut self, size: u64) -> Option<PhysRange> {
        let region = self.memory_map[self.region_idx];
        if self.next_frame + size > region.end {
            if self.goto_next_region().is_ok() {
                // Retry allocation
                self.allocate_range(size)
            } else {
                // All the memory is exhausted
                None
            }
        } else {
            let start = PhysAddr::new(self.next_frame);
            let end = PhysAddr::new(self.next_frame + size);
            let nb_pages = bytes_to_pages(size as usize);
            self.next_frame = self.next_frame + (nb_pages * PAGE_SIZE) as u64;
            Some(PhysRange { start, end })
        }
    }

    /// Move the cursor to the next memory region
    fn goto_next_region(&mut self) -> Result<(), ()> {
        while self.region_idx + 1 < self.memory_map.len() {
            self.region_idx += 1;

            // Check if usable
            if self.memory_map[self.region_idx].kind == MemoryRegionKind::Usable {
                self.next_frame = self.memory_map[self.region_idx].start;
                return Ok(());
            }
        }

        // All the memory is exhausted
        self.next_frame = self.memory_map[self.region_idx].end;
        Err(())
    }

    pub fn get_boundaries(&self) -> PhysRange {
        let first_region = self.memory_map[0];
        let last_region = self.memory_map[self.memory_map.len() - 1];
        let start = PhysAddr::new(first_region.start);
        let end = PhysAddr::new(last_region.end);
        PhysRange { start, end }
    }
}

unsafe impl x86_64::structures::paging::FrameAllocator<Size4KiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        Self::allocate_frame(self)
    }
}

// ————————————————————————— Shared Frame Allocator ————————————————————————— //

#[derive(Clone)]
pub struct SharedFrameAllocator {
    alloc: Arc<Mutex<BootInfoFrameAllocator>>,
    physical_memory_offset: VirtAddr,
}

impl SharedFrameAllocator {
    pub fn new(alloc: BootInfoFrameAllocator, physical_memory_offset: VirtAddr) -> Self {
        Self {
            alloc: Arc::new(Mutex::new(alloc)),
            physical_memory_offset,
        }
    }
}

unsafe impl FrameAllocator for SharedFrameAllocator {
    fn allocate_frame(&self) -> Option<vmx::Frame> {
        let mut inner = self.alloc.lock();
        let frame = inner.allocate_frame()?;

        Some(vmx::Frame {
            phys_addr: vmx::HostPhysAddr::new(frame.start_address().as_u64() as usize),
            virt_addr: (frame.start_address().as_u64() + self.physical_memory_offset.as_u64())
                as *mut u8,
        })
    }

    fn allocate_range(&self, size: u64) -> Option<PhysRange> {
        let mut inner = self.alloc.lock();
        inner.allocate_range(size)
    }

    fn get_boundaries(&self) -> (u64, u64) {
        let mut inner = self.alloc.lock();
        let inner = inner.deref_mut();
        let range = inner.get_boundaries();
        (range.start.as_u64(), range.end.as_u64())
    }

    fn get_physical_offset(&self) -> VirtAddr {
        self.physical_memory_offset
    }
}

// ————————————————————————— Range Frame Allocator —————————————————————————— //

pub struct RangeFrameAllocator {
    range_start: PhysAddr,
    range_end: PhysAddr,
    cursor: Cell<PhysAddr>,
    physical_memory_offset: VirtAddr,
}

impl RangeFrameAllocator {
    pub unsafe fn new(
        range_start: PhysAddr,
        range_end: PhysAddr,
        physical_memory_offset: VirtAddr,
    ) -> Self {
        let range_start = range_start.align_up(PAGE_SIZE as u64);
        let range_end = range_end.align_down(PAGE_SIZE as u64);
        Self {
            range_start,
            range_end,
            cursor: Cell::new(range_start),
            physical_memory_offset,
        }
    }
}

unsafe impl FrameAllocator for RangeFrameAllocator {
    fn allocate_frame(&self) -> Option<vmx::Frame> {
        let cursor = self.cursor.get();
        if cursor < self.range_end {
            self.cursor
                .set(PhysAddr::new(cursor.as_u64() + PAGE_SIZE as u64));
            Some(vmx::Frame {
                phys_addr: vmx::HostPhysAddr::new(cursor.as_u64() as usize),
                virt_addr: (cursor.as_u64() + self.physical_memory_offset.as_u64()) as *mut u8,
            })
        } else {
            None
        }
    }

    fn allocate_range(&self, size: u64) -> Option<PhysRange> {
        let cursor = self.cursor.get();
        if cursor + size < self.range_end {
            let new_cursor = (cursor + size).align_up(PAGE_SIZE as u64);
            self.cursor.set(new_cursor);
            Some(PhysRange {
                start: cursor,
                end: new_cursor,
            })
        } else {
            None
        }
    }

    fn get_boundaries(&self) -> (u64, u64) {
        (self.range_start.as_u64(), self.range_end.as_u64())
    }

    fn get_physical_offset(&self) -> VirtAddr {
        self.physical_memory_offset
    }
}

// ———————————————————————————— Helper Functions ———————————————————————————— //

/// Returns the number of pages to add in order to grow by at least `n` bytes.
fn bytes_to_pages(n: usize) -> usize {
    let page_aligned = (n + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    page_aligned / PAGE_SIZE
}

// ————————————————————————————————— Tests —————————————————————————————————— //

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn bytes_to_pages() {
        assert_eq!(super::bytes_to_pages(0), 0);
        assert_eq!(super::bytes_to_pages(1), 1);
        assert_eq!(super::bytes_to_pages(PAGE_SIZE - 1), 1);
        assert_eq!(super::bytes_to_pages(PAGE_SIZE), 1);
        assert_eq!(super::bytes_to_pages(PAGE_SIZE + 1), 2);
    }
}
