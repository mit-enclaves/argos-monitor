use crate::vmx::{HostPhysAddr, HostVirtAddr};
use acpi::platform::interrupt;
use alloc::vec::Vec;
use mmu::{PtFlag, PtMapper, RangeAllocator};
use x86::apic::{ioapic, xapic};

// FIXME: LAPIC address should be parsed from ACPI, but parsing the table occurs after we
//        initialize the BSP...
pub const LAPIC_PHYS_ADDRESS: usize = 0xfee00000;
pub const LAPIC_VIRT_ADDRESS: usize = LAPIC_PHYS_ADDRESS + 0x18000000000;

pub fn allocate(
    lapic_addr: usize,
    allocator: &impl RangeAllocator,
    pt_mapper: &mut PtMapper<HostPhysAddr, HostVirtAddr>,
) {
    let lapic_frame = unsafe {
        vmx::Frame::new(
            HostPhysAddr::new(lapic_addr),
            HostVirtAddr::new(lapic_addr + allocator.get_physical_offset().as_usize()),
        )
    };
    pt_mapper.map_range(
        allocator,
        HostVirtAddr::new(lapic_frame.virt_addr as usize),
        lapic_frame.phys_addr,
        0x1000,
        PtFlag::WRITE | PtFlag::PRESENT | PtFlag::USER | PtFlag::PAGE_CACHE_DISABLE,
    );
}

pub fn lapic_new(lapic_addr: usize) -> xapic::XAPIC {
    // Initialize LAPIC
    unsafe { xapic::XAPIC::new(core::slice::from_raw_parts_mut(lapic_addr as _, 0x1000)) }
}

pub fn lapic_setup(lapic: &mut xapic::XAPIC) {
    lapic.attach();
}

// Only the BSP is responsible for instantiateing the IOAPIC
unsafe fn _ioapic_new(entries: Vec<&interrupt::IoApic>) -> Vec<ioapic::IoApic> {
    entries
        .iter()
        .map(|&entry| {
            let mut ioapic = ioapic::IoApic::new(entry.address as usize);
            ioapic.disable_all();
            ioapic
        })
        .collect()
}
