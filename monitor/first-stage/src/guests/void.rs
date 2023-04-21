//! Empty guest

use mmu::FrameAllocator;

use super::{Guest, ManifestInfo};
use crate::acpi::AcpiInfo;
use crate::mmu::MemoryMap;

pub struct VoidGuest {}

pub const VOID_GUEST: VoidGuest = VoidGuest {};

impl Guest for VoidGuest {
    unsafe fn instantiate(
        &self,
        _acpi: &AcpiInfo,
        _host_allocator: &impl FrameAllocator,
        _guest_allocator: &impl FrameAllocator,
        _memory_map: MemoryMap,
        _rsdp: u64,
    ) -> ManifestInfo {
        ManifestInfo::default()
    }
}
