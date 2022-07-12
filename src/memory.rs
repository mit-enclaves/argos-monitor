use alloc::sync::Arc;
use core::marker::PhantomData;
use core::ops::DerefMut;
use core::ptr::NonNull;

use bootloader::boot_info::{MemoryRegion, MemoryRegionKind};
use spin::{Mutex, MutexGuard};
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::frame::PhysFrame;
use x86_64::structures::paging::page::Page;
use x86_64::structures::paging::page_table::{PageTable, PageTableFlags};
use x86_64::structures::paging::{Mapper, OffsetPageTable};
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
) -> Result<VirtualMemoryAreaAllocator, ()> {
    let level_4_table = active_level_4_table(physical_memory_offset);

    // Initialize the frame allocator and the memory mapper.
    let mut frame_allocator = BootInfoFrameAllocator::init(regions);
    let mut mapper = OffsetPageTable::new(level_4_table, physical_memory_offset);

    // Initialize the heap.
    allocator::init_heap(&mut mapper, &mut frame_allocator).map_err(|_| ())?;

    // Create a memory map once the heap has been allocated.
    let memory_map = VirtualMemoryMap::new_from_mapping(mapper.level_4_table());

    Ok(VirtualMemoryAreaAllocator::new(
        mapper,
        memory_map,
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
// NOTE: this implementation comes from [1], it is simple but don't allow     //
// frame reuse and has an allocation inf O(n) where n is the number of        //
// already allocated framed.                                                  //
//                                                                            //
// [1]: https://os.phil-opp.com/paging-implementation/                        //
// —————————————————————————————————————————————————————————————————————————— //

/// A range of physical memory.
pub struct PhysRange {
    /// Start of the physical range (inclusive).
    pub start: PhysAddr,
    /// End of the physical range (exclusive).
    pub end: PhysAddr,
}

impl PhysRange {
    pub fn size(&self) -> usize {
        (self.start.as_u64() - self.end.as_u64()) as usize
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

// —————————————————————————— Virtual Memory Area ——————————————————————————— //

// TODO: Free the area on drop.
pub struct VirtualMemoryArea {
    ptr: NonNull<u8>,
    nb_pages: usize,
    vma_allocator: VirtualMemoryAreaAllocator,
    marker: PhantomData<u8>,
}

impl VirtualMemoryArea {
    /// Set the given flags for all pages of the virtual memory area.
    ///
    /// WARNING: future accesses to the VMA might cause an exception if the appropriate flags are
    /// not present.
    fn update_flags(&mut self, flags: PageTableFlags) -> Result<(), ()> {
        let mut virt_addr = VirtAddr::from_ptr(self.ptr.as_ptr());
        let mut allocator = self.vma_allocator.lock();
        let mapper = &mut allocator.mapper;

        // The assumption is not necessary for correctness here, but should still hold.
        debug_assert!(virt_addr.is_aligned(PAGE_SIZE as u64));

        for _ in 0..self.nb_pages {
            let page = Page::<Size4KiB>::containing_address(virt_addr);
            unsafe {
                mapper.update_flags(page, flags).map_err(|_| ())?.flush();
            }
            virt_addr += PAGE_SIZE;
        }

        Ok(())
    }

    pub fn set_executable(&mut self) {
        let flags = PageTableFlags::PRESENT;
        self.update_flags(flags)
            .expect("Could not set execute permission");
    }

    pub fn set_write(&mut self) {
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        self.update_flags(flags)
            .expect("Could not set write permission");
    }

    pub fn set_read_only(&mut self) {
        let flags = PageTableFlags::PRESENT | PageTableFlags::NO_EXECUTE;
        self.update_flags(flags)
            .expect("Could not set read-only permission");
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.ptr.as_ptr()
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    /// Physical address of the first frame of this VMA.
    ///
    /// WARNING: There is no guarantee that frames are continuous!
    pub fn as_phys_addr(&self) -> PhysAddr {
        let page = Page::<Size4KiB>::containing_address(VirtAddr::from_ptr(self.as_ptr()));
        let allocator = self.vma_allocator.lock();
        let mapper = &allocator.mapper;
        mapper.translate_page(page).unwrap().start_address()
    }

    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: We rely on the correctness of `self.size()` and the validity of the pointer.
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.size()) }
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: We rely on the correctness of `self.size()` and the validity of the pointer.
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.size()) }
    }

    pub fn size(&self) -> usize {
        self.nb_pages * PAGE_SIZE
    }
}

/// The Virtual Memory Area Allocator, responsible for allocating and managing virtual memory
/// areas.
pub struct VirtualMemoryAreaAllocator(Arc<Mutex<LockedVirtualMemoryAreaAllocator>>);

impl VirtualMemoryAreaAllocator {
    fn lock(&self) -> MutexGuard<LockedVirtualMemoryAreaAllocator> {
        self.0.lock()
    }

    pub fn allocate_range(&mut self, size: u64) -> Option<PhysRange> {
        let mut inner = self.lock();
        inner.frame_allocator.allocate_range(size)
    }
}

impl Clone for VirtualMemoryAreaAllocator {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

// TODO: comment about safety
// For now our frame allocator never re-use frames, so that's all good.
unsafe impl vmx::FrameAllocator for VirtualMemoryAreaAllocator {
    fn allocate_frame(&self) -> Option<vmx::Frame> {
        let mut inner = self.0.lock();
        let frame = inner.frame_allocator.allocate_frame()?;

        Some(vmx::Frame {
            phys_addr: vmx::HostPhysAddr::new(frame.start_address().as_u64() as usize),
            virt_addr: (frame.start_address().as_u64() + inner.physical_memory_offset.as_u64())
                as *mut u8,
        })
    }
}

/// Internal state of the `VirtualMemoryAreaAllocator`.
struct LockedVirtualMemoryAreaAllocator {
    mapper: OffsetPageTable<'static>,
    memory_map: VirtualMemoryMap,
    frame_allocator: BootInfoFrameAllocator,
    physical_memory_offset: VirtAddr,
}

impl VirtualMemoryAreaAllocator {
    pub fn new(
        mapper: OffsetPageTable<'static>,
        memory_map: VirtualMemoryMap,
        frame_allocator: BootInfoFrameAllocator,
        physical_memory_offset: VirtAddr,
    ) -> Self {
        let inner = Arc::new(Mutex::new(LockedVirtualMemoryAreaAllocator {
            mapper,
            memory_map,
            frame_allocator,
            physical_memory_offset,
        }));
        Self(inner)
    }

    // TODO: Free allocated pages on failure.
    pub fn with_capacity(&self, capacity: usize) -> Result<VirtualMemoryArea, ()> {
        let nb_pages = bytes_to_pages(capacity);
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        let mut inner = self.0.lock();
        let inner = inner.deref_mut();
        let mapper = &mut inner.mapper;
        let frame_allocator = &mut inner.frame_allocator;
        let mut virt_addr = inner.memory_map.reserve_area(capacity)?;
        let ptr = NonNull::new(virt_addr.as_mut_ptr()).unwrap();

        for _ in 0..nb_pages {
            unsafe {
                let frame = frame_allocator.allocate_frame().ok_or(())?;
                let page = Page::containing_address(virt_addr);
                mapper
                    .map_to(page, frame, flags, frame_allocator)
                    .map_err(|_| ())?
                    .flush();
                virt_addr += PAGE_SIZE;
            }
        }

        Ok(VirtualMemoryArea {
            ptr,
            nb_pages,
            vma_allocator: self.clone(),
            marker: PhantomData,
        })
    }

    /// Returns the memory boundaries.
    // TODO: make this more efficient when refactoring the allocator.
    pub fn get_boundaries(&self) -> Option<(u64, u64)> {
        let mut inner = self.0.lock();
        let inner = inner.deref_mut();
        let range = inner.frame_allocator.get_boundaries();
        Some((range.start.as_u64(), range.end.as_u64()))
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
