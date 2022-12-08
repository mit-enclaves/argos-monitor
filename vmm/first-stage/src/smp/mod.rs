use crate::println;
use alloc::vec::Vec;

use acpi::platform::interrupt::InterruptModel;
use acpi::platform::PlatformInfo;
use acpi::platform::Processor;

use core::arch::global_asm;
use core::arch::x86_64::_rdtsc;
use x86::apic::{ApicControl, ApicId};

use crate::vmx::{HostPhysAddr, HostVirtAddr};
use mmu::{PtFlag, PtMapper, RangeAllocator};

use crate::{apic, gdt, idt};
use core::sync::atomic::*;

global_asm!(include_str!("trampoline.S"));

const START_PAGE: u8 = 7;
const ENTRY_PTR_OFFSET: u64 = 0x0ff0;
const CR3_PTR_OFFSET: u64 = 0x0ff8;
const RSP_PTR_OFFSET: u64 = 0x0fe8;

const CODE_PADDR: u64 = (START_PAGE as usize * 0x1000) as u64;
const ENTRY_PTR_PADDR: u64 = CODE_PADDR + ENTRY_PTR_OFFSET;
const CR3_PTR_PADDR: u64 = CODE_PADDR + CR3_PTR_OFFSET;
const RSP_PTR_PADDR: u64 = CODE_PADDR + RSP_PTR_OFFSET;

const FALSE: AtomicBool = AtomicBool::new(false);
static CPU_STATUS: [AtomicBool; 256] = [FALSE; 256];

const STACK_SIZE: usize = 20 * 0x1000;

extern "C" {
    fn ap_trampoline_start();
    fn ap_trampoline_end();
}

fn spin(us: u64) {
    const FREQ: u64 = 2_000_000_000u64; // TODO: get cpu frequency
    let end = unsafe { _rdtsc() + FREQ / 1_000_000 * us };
    while unsafe { _rdtsc() < end } {
        core::hint::spin_loop();
    }
}

unsafe fn ap_entry() {
    // Setup GDT on the core
    gdt::init();
    // Setup IDT on the core
    idt::init();
    // Signal the AP is ready
    let cpuid = unsafe { core::arch::x86_64::__cpuid(0x01) };
    let apic_id = ((cpuid.ebx & 0xffffffff) >> 24) as usize;
    CPU_STATUS[apic_id].store(true, Ordering::SeqCst);
    println!("Hello World from cpu {}", apic_id);

    loop {}
}

// FIXME: the two allocation functions here uses the same address for physical and virtual address
// for debugging purposes. We should switch to virtual address once we're done
unsafe fn allocate_code_section(
    _allocator: &impl RangeAllocator,
    mapper: &mut PtMapper<HostPhysAddr, HostVirtAddr>,
) -> vmx::Frame {
    // As we **must** have the frame on code_paddr for the AP to boot up,
    // I bypass the memory allocator to directly allocate the memory here
    let frame = vmx::Frame {
        phys_addr: HostPhysAddr::new(CODE_PADDR as usize),
        virt_addr: CODE_PADDR as *mut u8,
    };

    mapper.map_range(
        _allocator,
        HostVirtAddr::new(frame.phys_addr.as_usize()),
        frame.phys_addr,
        0x1000,
        PtFlag::WRITE | PtFlag::PRESENT | PtFlag::USER,
    );

    // Copy the cr3 register to cr3_ptr and share with AP
    (CR3_PTR_PADDR as *mut usize).write(x86::controlregs::cr3() as usize);
    // Copy the entry function pointer and share with AP
    (ENTRY_PTR_PADDR as *mut usize).write(ap_entry as usize);

    // Copy the ap trampoline code to start page
    core::ptr::copy_nonoverlapping(
        ap_trampoline_start as *const u8,
        CODE_PADDR as _,
        ap_trampoline_end as usize - ap_trampoline_start as usize,
    );

    frame
}

unsafe fn allocate_stack_section(
    _cpuid: u8, // seems not important as the allocation is random...
    stack_allocator: &impl RangeAllocator,
    mapper: &mut PtMapper<HostPhysAddr, HostVirtAddr>,
) {
    let stack_range = stack_allocator
        .allocate_range(STACK_SIZE)
        .expect("AP stack frame");

    mapper.map_range(
        stack_allocator,
        HostVirtAddr::new(stack_range.start.as_usize()),
        stack_range.start,
        stack_range.end.as_usize() - stack_range.start.as_usize(),
        PtFlag::WRITE | PtFlag::PRESENT | PtFlag::USER,
    );

    // obviously rsp moves in the opposite direction as I expected x_x...
    (RSP_PTR_PADDR as *mut usize).write(stack_range.end.as_usize());
}

pub unsafe fn boot(
    platform_info: PlatformInfo,
    stage1_allocator: &impl RangeAllocator,
    pt_mapper: &mut PtMapper<HostPhysAddr, HostVirtAddr>,
) {
    let virtoffset = stage1_allocator.get_physical_offset();

    let apic_info = match platform_info.interrupt_model {
        InterruptModel::Apic(apic) => apic,
        _ => panic!("unable to retrieve apic informaiton"),
    };
    let processor_info = platform_info.processor_info.as_ref().unwrap();
    let bsp: Processor = processor_info.boot_processor;
    let ap: &Vec<Processor> = processor_info.application_processors.as_ref();

    // Map the LAPIC's 4k MMIO region to virtual memory
    apic::allocate(
        apic_info.local_apic_address as usize + virtoffset.as_usize(),
        stage1_allocator,
        pt_mapper,
    );

    // TODO: disable PIC (mask all interrupts)

    let lapic = &mut gdt::current().as_mut().unwrap().lapic;

    // Check if I am the BSP or not
    assert!(!bsp.is_ap);
    assert!(lapic.id() == bsp.local_apic_id);

    allocate_code_section(stage1_allocator, pt_mapper);

    // Intel MP Spec B.4: Universal Start-up Algorithm
    for id in 1..(ap.len() + 1) as u8 {
        allocate_stack_section(id, stage1_allocator, pt_mapper);
        let apic_id = ApicId::XApic(id);

        assert!(CPU_STATUS[id as usize].load(Ordering::SeqCst) == false);

        // BSP sends AP an INIT IPI (Level Interrupt)
        lapic.ipi_init(apic_id);
        spin(200);
        lapic.ipi_init_deassert();
        // BSP delays (10ms)
        spin(10_000);
        // BSP sends AP a STARTUP IPI (1st try), AP should start executing at 000VV000h
        lapic.ipi_startup(apic_id, START_PAGE);
        // BSP delays (200us)
        spin(200);
        // BSP sends AP a STARTUP IPI (2nd try)
        lapic.ipi_startup(apic_id, START_PAGE);
        // BSP delays (200us)
        spin(200);
        // Wait for AP to startup
        spin(20000);
        // BSP verifies synchronization with executing AP
        while !CPU_STATUS[id as usize].load(Ordering::SeqCst) {
            core::hint::spin_loop();
        }
    }
}
