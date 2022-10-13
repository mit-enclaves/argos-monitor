use core::slice;

use crate::mmu::MemoryMap;
use crate::vmx::bitmaps::EptEntryFlags;
use crate::{GuestPhysAddr, HostPhysAddr};
use mmu::{EptMapper, FrameAllocator, IoPtFlag, IoPtMapper};
use vtd::{ContextEntry, RootEntry};

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
        lower: iopt_root.as_u64(),
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

/// Creates the EPT and I/O PT mappings.
///
/// The memory is divided in two regions:
/// - A lower region, used by the guest
/// - An upper region, reserved for host use and not mapped within the EPT and I/O PT
pub fn create_mappings(
    memory_map: &MemoryMap,
    ept_mapper: &mut EptMapper,
    iopt_mapper: &mut IoPtMapper,
    host_allocator: &impl FrameAllocator,
) {
    let host_range = memory_map.host;

    ept_mapper.map_range(
        host_allocator,
        GuestPhysAddr::new(0),
        HostPhysAddr::new(0),
        host_range.start.as_usize(),
        EptEntryFlags::READ | EptEntryFlags::WRITE | EptEntryFlags::SUPERVISOR_EXECUTE,
    );
    iopt_mapper.map_range(
        host_allocator,
        GuestPhysAddr::new(0),
        HostPhysAddr::new(0),
        host_range.start.as_usize(),
        IoPtFlag::WRITE | IoPtFlag::READ | IoPtFlag::EXECUTE,
    );
}
