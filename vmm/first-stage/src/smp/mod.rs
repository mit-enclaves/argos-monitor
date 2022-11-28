use crate::println;
use alloc::vec::Vec;

use acpi::platform::interrupt::InterruptModel;
use acpi::platform::PlatformInfo;
use acpi::platform::Processor;

use core::arch::x86_64::_rdtsc;
use x86::apic::{xapic::XAPIC, ApicControl, ApicId};

fn to_virt(addr: u64) -> u64 {
    addr + 0x18000000000
}

// TODO: relax() instead of busy spinning
fn spin(us: u64) {
    const FREQ: u64 = 2_000_000_000u64; // TODO: get cpu frequency
    let end = unsafe { _rdtsc() + FREQ / 1_000_000 * us };
    while unsafe { _rdtsc() < end } {
        core::hint::spin_loop();
    }
}

pub unsafe fn boot(platform_info: PlatformInfo) {
    let apic_info = match platform_info.interrupt_model {
        InterruptModel::Apic(apic) => apic,
        _ => panic!("unable to retrieve apic informaiton"),
    };
    let processor_info = platform_info.processor_info.as_ref().unwrap();
    let bsp: Processor = processor_info.boot_processor;
    let ap: &Vec<Processor> = processor_info.application_processors.as_ref();

    let start_page: u8 = 42;

    // Initialize APIC
    let apic_region =
        core::slice::from_raw_parts_mut(to_virt(apic_info.local_apic_address) as _, 0x1000 / 4);
    let mut lapic = XAPIC::new(apic_region);

    // Check if I am the BSP or not
    assert!(!bsp.is_ap);
    assert!(lapic.id() == bsp.local_apic_id);

    // Intel MP Spec B.4: Universal Start-up Algorithm
    // TODO: check APIC version and make sure it's not 82489DX
    for id in 1..ap.len() as u8 {
        let apic_id = ApicId::XApic(id);
        // BSP sends AP an INIT IPI (Level Interrupt)
        lapic.ipi_init(apic_id);
        spin(200);
        lapic.ipi_init_deassert();
        println!("sent init");
        // BSP delays (10ms)
        spin(10_000);
        // BSP sends AP a STARTUP IPI (1st try)
        // AP should start executing at 000VV000h
        lapic.ipi_startup(apic_id, start_page);
        println!("sent first ipi");
        // BSP delays (200us)
        spin(200);
        // BSP sends AP a STARTUP IPI (2nd try)
        lapic.ipi_startup(apic_id, start_page);
        println!("sent second ipi");
        // BSP delays (200us)
        spin(200);
    }

    // TODO: BSP verifies synchronization with executing AP
}
