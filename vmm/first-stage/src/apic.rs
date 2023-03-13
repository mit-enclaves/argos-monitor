use crate::vmx::{HostPhysAddr, HostVirtAddr};
use acpi::platform::interrupt;
use alloc::vec::Vec;
use mmu::{PtFlag, PtMapper, RangeAllocator};
use x86::apic::{ioapic, x2apic};

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

pub fn lapic_new() -> x2apic::X2APIC {
    // Initialize LAPIC
    x2apic::X2APIC::new()
}

pub fn lapic_setup(lapic: &mut x2apic::X2APIC) {
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
