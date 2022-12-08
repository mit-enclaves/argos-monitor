use x86_64::instructions::segmentation::{Segment, CS};
use x86_64::instructions::tables::load_tss;
use x86_64::registers::segmentation::{SegmentSelector, SS};
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

pub struct Gdt {
    pub gdt: GlobalDescriptorTable,
    tss: TaskStateSegment,
}

impl Gdt {
    pub fn new() -> Self {
        Self {
            gdt: GlobalDescriptorTable::new(),
            tss: TaskStateSegment::new(),
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
    }
}
