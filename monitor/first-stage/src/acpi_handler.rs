use crate::HostVirtAddr;
use acpi::{AcpiHandler, PhysicalMapping};
use core::ptr::NonNull;

#[derive(Clone)]
pub struct TycheACPIHandler;

impl AcpiHandler for TycheACPIHandler {
    unsafe fn map_physical_region<T>(
        &self,
        physical_address: usize,
        size: usize,
    ) -> PhysicalMapping<Self, T> {
        // FIXME: ganze schlechte ad-hoc Lösungen... aber funktioniert
        let virtual_address = HostVirtAddr::new(physical_address + 0x18000000000);

        PhysicalMapping::new(
            usize::from(physical_address),
            NonNull::new(virtual_address.as_usize() as *mut _).unwrap(),
            size,
            size,
            TycheACPIHandler,
        )
    }

    fn unmap_physical_region<T>(_region: &PhysicalMapping<Self, T>) {}
}
