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
const NB_PTE_ENTRIES: usize = 512;

// ————————————————————————— Re-export definitions —————————————————————————— //

pub use x86_64::structures::paging::page::Size4KiB;

pub trait FrameAllocator: x86_64::structures::paging::FrameAllocator<Size4KiB> {}

impl FrameAllocator for BootInfoFrameAllocator {}

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
) -> Result<SharedFrameAllocator, ()> {
    let level_4_table = active_level_4_table(physical_memory_offset);

    // Initialize the frame allocator and the memory mapper.
    let mut frame_allocator = BootInfoFrameAllocator::init(regions);
    let mut mapper = OffsetPageTable::new(level_4_table, physical_memory_offset);

    // Initialize the heap.
    allocator::init_heap(&mut mapper, &mut frame_allocator).map_err(|_| ())?;

    Ok(SharedFrameAllocator::new(
        frame_allocator,
        physical_memory_offset,
    ))
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

pub struct SharedFrameAllocator {
    alloc: Mutex<BootInfoFrameAllocator>,
    physical_memory_offset: VirtAddr,
}

impl SharedFrameAllocator {
    pub fn new(alloc: BootInfoFrameAllocator, physical_memory_offset: VirtAddr) -> Self {
        Self {
            alloc: Mutex::new(alloc),
            physical_memory_offset,
        }
    }

    pub fn allocate_range(&self, size: u64) -> Option<PhysRange> {
        let mut inner = self.alloc.lock();
        inner.allocate_range(size)
    }

    pub fn get_boundaries(&self) -> (u64, u64) {
        let mut inner = self.alloc.lock();
        let inner = inner.deref_mut();
        let range = inner.get_boundaries();
        (range.start.as_u64(), range.end.as_u64())
    }
}

// TODO: comment about safety
// For now our frame allocator never re-use frames, so that's all good.
unsafe impl vmx::FrameAllocator for SharedFrameAllocator {
    fn allocate_frame(&self) -> Option<vmx::Frame> {
        let mut inner = self.alloc.lock();
        let frame = inner.allocate_frame()?;

        Some(vmx::Frame {
            phys_addr: vmx::HostPhysAddr::new(frame.start_address().as_u64() as usize),
            virt_addr: (frame.start_address().as_u64() + self.physical_memory_offset.as_u64())
                as *mut u8,
        })
    }
}

// ——————————————————————————— Virtual Memory Map ——————————————————————————— //

/// A map of used & available chunks of an address space.
///
/// TODO: For now the memory map does not enable virtual addresses re-use. This was done for
/// simplicity of the initial implementation.
pub struct VirtualMemoryMap {
    // Next available address.
    cursor: VirtAddr,

    // End of the valid virtual address range.
    end_at: VirtAddr,
}

impl VirtualMemoryMap {
    /// Creates a mapping of the virtual memory map from the page tables.
    ///
    /// SAFETY: the page table must be a valid level 4 page table.
    pub unsafe fn new_from_mapping(level_4_table: &PageTable) -> Self {
        let (last_used_index, _) = level_4_table
            .iter()
            .enumerate()
            .filter(|(_idx, entry)| !entry.is_unused())
            .last()
            .unwrap();

        if last_used_index >= NB_PTE_ENTRIES {
            // Return a map with no free aeas
            VirtualMemoryMap {
                cursor: VirtAddr::new(0),
                end_at: VirtAddr::new(0),
            }
        } else {
            let l4_shift = 9 + 9 + 9 + 12; // Shift to get virtual address from L4 index
            let first_unused_index = (last_used_index + 1) as u64;
            let last_available_index = (NB_PTE_ENTRIES - 1) as u64;
            let cursor = VirtAddr::new(first_unused_index << l4_shift);
            let end_at = VirtAddr::new(last_available_index << l4_shift);
            VirtualMemoryMap { cursor, end_at }
        }
    }

    /// Reserves an area in the virtual address space.
    ///
    /// No frames are allocated, but the area is marked as reserved, preventing future collisions
    /// with other areas.
    pub fn reserve_area(&mut self, size: usize) -> Result<VirtAddr, ()> {
        let start_of_area = self.cursor;
        let end_of_area = (start_of_area + size).align_up(PAGE_SIZE as u64);
        if end_of_area > self.end_at {
            return Err(());
        }
        self.cursor = end_of_area;
        Ok(start_of_area)
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
