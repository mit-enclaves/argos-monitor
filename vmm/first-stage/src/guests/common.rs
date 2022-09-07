use core::slice;

use crate::mmu::{EptMapper, FrameAllocator, IoPtFlag, IoPtMapper, MemoryMap};
use crate::vmx::bitmaps::EptEntryFlags;
use crate::vtd::{ContextEntry, RootEntry};
use crate::{GuestPhysAddr, HostPhysAddr};

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
/// The memory is divided in three regions:
/// - A lower region, used by the guest
/// - A middle region, reserved for host use and not mapped within the EPT and I/O PT
/// - A upper region, used by the guest
pub fn create_mappings(
    memory_map: &MemoryMap,
    ept_mapper: &mut EptMapper,
    iopt_mapper: &mut IoPtMapper,
    host_allocator: &impl FrameAllocator,
) {
    let host_range = memory_map.host;
    let max_addr = memory_map.guest.iter().fold(
        0,
        |max, region| if region.end > max { region.end } else { max },
    ) as usize;
    let upper_size = max_addr - host_range.end.as_usize();

    // Before host region (lower region)
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

    // After host region (upper region)
    ept_mapper.map_range(
        host_allocator,
        GuestPhysAddr::new(host_range.end.as_usize()),
        host_range.end,
        upper_size,
        EptEntryFlags::READ | EptEntryFlags::WRITE | EptEntryFlags::SUPERVISOR_EXECUTE,
    );
    iopt_mapper.map_range(
        host_allocator,
        GuestPhysAddr::new(host_range.end.as_usize()),
        host_range.end,
        upper_size,
        IoPtFlag::WRITE | IoPtFlag::READ | IoPtFlag::EXECUTE,
    );
}
