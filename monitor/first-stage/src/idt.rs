use lazy_static::lazy_static;
use x86_64::registers::control::Cr2;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

use crate::{gdt, getsec, println};

lazy_static! {
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();
        idt.divide_error.set_handler_fn(divide_by_zero_handler);
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        idt.debug.set_handler_fn(debug_handler);
        idt.invalid_opcode.set_handler_fn(invalid_opcode_handler);
        idt.page_fault.set_handler_fn(page_fault_handler);
        idt.invalid_tss.set_handler_fn(invalid_tss_handler);
        idt.machine_check.set_handler_fn(machine_check_handler);
        idt.virtualization.set_handler_fn(virtualization_handler);
        idt.device_not_available
            .set_handler_fn(device_not_available_handler);
        idt.stack_segment_fault
            .set_handler_fn(stack_segment_fault_handler);
        idt.non_maskable_interrupt
            .set_handler_fn(non_maskable_interrupt_handler);
        idt.segment_not_present
            .set_handler_fn(segment_not_present_handler);
        idt.general_protection_fault
            .set_handler_fn(general_protection_fault_handler);
        unsafe {
            idt.double_fault
                .set_handler_fn(double_fault_handler)
                .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);
        }
        // idt[InterruptIndex::Timer.as_usize()].set_handler_fn(timer_interrupt_handler);

        // Override invalid opcode handler to emulate getsec.
        unsafe {
            let opcode_handler_ptr = x86_64::VirtAddr::new((getsec::invalid_opcode as *const ()) as u64);
            idt.invalid_opcode.set_handler_addr(opcode_handler_ptr);
        }

        idt
    };
}

/// Initialize the Interrupt Description Table.
pub fn init() {
    IDT.load();
}

extern "x86-interrupt" fn divide_by_zero_handler(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: DIVIDE BY ZERO\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    println!("EXCEPTION: BREAKPOINT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn general_protection_fault_handler(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) {
    panic!("EXCEPTION: GENERAL PROTECTION FAULT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn debug_handler(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: DEBUG\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn non_maskable_interrupt_handler(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: NON MASKABLE INTERRUPT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn virtualization_handler(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: VIRTUALIZATION\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn device_not_available_handler(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: DEVICE NOT AVAILABLE\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn invalid_tss_handler(stack_frame: InterruptStackFrame, _error_code: u64) {
    panic!("EXCEPTION: INVALID TSS\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn stack_segment_fault_handler(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) {
    panic!("EXCEPTION: STACK SEGMENT FAULT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn segment_not_present_handler(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) {
    panic!("EXCEPTION: SEGMENT NOT PRESENT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn machine_check_handler(stack_frame: InterruptStackFrame) -> ! {
    panic!("EXCEPTION: MACHINE CHECK\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    panic!("EXCEPTION: DOUBLE FAULT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    println!("EXCEPTION: PAGE FAULT");
    println!("Accessed Address: {:?}", Cr2::read());
    println!("Error code:       {:?}", error_code);
    println!("Error code (raw): 0x{:x}", error_code.bits());
    println!("{:#?}", stack_frame);
    panic!();
}

extern "x86-interrupt" fn invalid_opcode_handler(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: INVALID OPCODE\n{:#?}", stack_frame);
}

/*
extern "x86-interrupt" fn timer_interrupt_handler(_stack_frame: InterruptStackFrame) {
    print!(".");

    // TODO
}
*/
