use x86_64::instructions::segmentation::{Segment, CS};
use x86_64::instructions::tables::load_tss;
use x86_64::registers::segmentation::{SegmentSelector, SS};
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

use x86::apic::xapic;

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;
pub const MAX_CPU_NUM: usize = 256;
const INITCPU: Option<Cpu> = None;
static mut CPUS: [Option<Cpu>; MAX_CPU_NUM] = [INITCPU; MAX_CPU_NUM];
// FIXME: LAPIC address should be parsed from ACPI, but parsing the table occurs after we
//        initialize the BSP...
const LAPIC_PHYS_ADDRESS: usize = 0xfee00000;
const LAPIC_VIRT_ADDRESS: usize = LAPIC_PHYS_ADDRESS + 0x18000000000;

pub struct Cpu {
    id: usize,
    pub gdt: GlobalDescriptorTable,
    tss: TaskStateSegment,
    pub lapic: xapic::XAPIC,
}

impl Cpu {
    pub fn new(lapic_id: usize) -> Self {
        Self {
            id: lapic_id,
            gdt: GlobalDescriptorTable::new(),
            tss: TaskStateSegment::new(),
            // FIXME: it's amazing that this doesn't crash before the memory allocator is
            //        initialized on CPU0...
            lapic: unsafe {
                xapic::XAPIC::new(core::slice::from_raw_parts_mut(
                    LAPIC_VIRT_ADDRESS as _,
                    0x1000,
                ))
            },
        }
    }

    pub fn setup(&'static mut self) {
        // Setup stack for double fault
        self.tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
            const STACK_SIZE: usize = 4096 * 5;
            static mut STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];

            let stack_start = VirtAddr::new(unsafe { &STACK as *const _ as u64 });
            let stack_end = stack_start + STACK_SIZE;
            stack_end
        };

        let code_selector = self.gdt.add_entry(Descriptor::kernel_code_segment());
        let tss_selector = self.gdt.add_entry(Descriptor::tss_segment(&self.tss));

        self.gdt.load();

        // Reload Code Segment Register and TSS
        unsafe {
            CS::set_reg(code_selector);
            load_tss(tss_selector);

            // Reload SS to ensure it is either 0 or points to a valid segment.
            // Failure to initialize it properly cause `iret` to fail.
            // See: https://github.com/rust-osdev/bootloader/issues/190
            SS::set_reg(SegmentSelector(0));
        }

        self.lapic.attach();
    }

    pub fn gdt(&self) -> &GlobalDescriptorTable {
        &self.gdt
    }
}

pub unsafe fn current() -> &'static mut Option<Cpu> {
    let lapic_id = raw_cpuid::CpuId::new()
        .get_feature_info()
        .unwrap()
        .initial_local_apic_id() as usize;

    return &mut CPUS[lapic_id];
}

pub fn init() {
    let lapic_id = raw_cpuid::CpuId::new()
        .get_feature_info()
        .unwrap()
        .initial_local_apic_id() as usize;

    unsafe {
        match current() {
            Some(_) => panic!("CPU {} already initialized", lapic_id),
            None => {
                CPUS[lapic_id] = Some(Cpu::new(lapic_id));
                CPUS[lapic_id].as_mut().unwrap().setup();
            }
        }
    }
}
