//! Extended Page Table

use super::bitmaps::EptEntryFlags;
use super::{Frame, HostPhysAddr};

pub const GIANT_PAGE_SIZE: usize = 1 << 30;
pub const HUGE_PAGE_SIZE: usize = 1 << 21;
pub const PAGE_SIZE: usize = 1 << 12;
pub const PTE_FLAGS: EptEntryFlags = EptEntryFlags::READ
    .union(EptEntryFlags::WRITE)
    .union(EptEntryFlags::SUPERVISOR_EXECUTE)
    .union(EptEntryFlags::USER_EXECUTE);

// ——————————————————————————————— EPTP List ———————————————————————————————— //

/// An EPTP list, used by the EPTP Switching VM function.
pub struct EptpList {
    frame: Frame,
}

impl EptpList {
    /// Creates a fresh EPTP List with zeroed entries.
    pub fn new(frame: Frame) -> Self {
        Self { frame }
    }

    /// Returns the address of the EPTP list.
    pub fn get_ptr(&self) -> HostPhysAddr {
        self.frame.phys_addr
    }

    /// Sets an entry of the EPTP list.
    ///
    /// SAFETY: the mapping must stay alive for at least as long as the entries is used (i.e. until
    /// it is overriten or the EPTP is never used again).
    pub unsafe fn set_entry(&mut self, index: usize, ept_pointer: HostPhysAddr) {
        self.frame.as_array_page()[index] = ept_pointer.as_u64();
    }

    pub unsafe fn set_entry_raw(&mut self, index: usize, root: u64) {
        self.frame.as_array_page()[index] = root;
    }

    /// Deletes an entry from the EPTP list.
    pub fn delete_entry(&mut self, index: usize) {
        self.frame.as_array_page()[index] = 0;
    }
}
