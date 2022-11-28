use lazy_static::lazy_static;
use spin::Mutex;
use x86_64::registers::control::Cr2;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

use crate::gdt;
use crate::getsec;
use crate::mmu;
use crate::print;
use crate::println;

use x2apic::ioapic::IoApic;
use x2apic::lapic::{xapic_base, LocalApic, LocalApicBuilder};

// The 32 first slots are dedicated to CPU exceptions, we reserve the next 15 for the two chained
// PICS (i.e. 32-47).
pub const PIC_1_OFFSET: u8 = 32;
pub const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;

/// Index of a PIC interrupt.
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum InterruptIndex {
    Timer = PIC_1_OFFSET,
    Keyboard = PIC_1_OFFSET + 1,
    Error = PIC_1_OFFSET + 2,
    Spurious = 0xFF,
}

// FIXME: cleanup this
lazy_static! {
    // The physical address of the LAPIC is specified inside the MADT at offset 0x24
    // The virtual address of the LAPIC can be directly determined by adding an offset
    // The spurious vector should have its lowest 4 bits set and must be above 32 (0xFF)
    // We also need to consider:
    //   - ACPI LAPIC NMI Table (Type 4)
    //   - ACPI LAPIC Address Override Table (Type 5)
    // In addition, we need to mask all of the PIC's interrupts
    pub static ref LOCALAPIC: Mutex<LocalApic> = Mutex::new({
        let phys_addr = unsafe { xapic_base() };
        let virtual_addr = phys_addr + mmu::get_physical_memory_offset().as_u64();
        let lapic: LocalApic = LocalApicBuilder::new()
            .timer_vector(InterruptIndex::Timer as usize)
            .error_vector(InterruptIndex::Error as usize)
            .spurious_vector(InterruptIndex::Spurious as usize)
            .set_xapic_base(virtual_addr)
            .build()
            .unwrap_or_else(|err| panic!("{}", err));
        lapic
    });
    // We initialize one IOAPIC instance per ACPI IOAPIC entry (type 0 inside MADT): the base address
    // and the base of GSI is already defined inside the ACPI IOAPIC entry.
    // To setup the Redirection Table, we
    //   1) Check the MADT table and see how legacy IRQs are mapped to the IOAPIC inputs
    //      - Map the IOAPIC Interrupt Source Override Table (Type 2)
    //      - Map the IOAPIC NMI Table (Type 3)
    //      * The Flags field can determine low/high active and if the interrupt is level/edge triggered
    //   2) Use ACPI's AML to determine how PCI devices are connected to the IOAPIC inputs (TODO)
    // XXX: how do we determine the details of the interrupt (e.g., interrupt mode, level/edge
    // triggered, low/high active, mask/non-masked, destination, irq number)
    // pub static ref IOAPIC: Mutex<IoApic> = Mutex::new(unsafe { init_ioapic(4273995776, 0) });
}

pub unsafe fn init_ioapic(address: u64, gsi_base: u8) -> IoApic {
    let mut ioapic = IoApic::new(address + mmu::get_physical_memory_offset().as_u64());
    ioapic.init(gsi_base);

    // let mut entry = RedirectionTableEntry::default();
    // entry.set_mode(IrqMode::Fixed);
    // entry.set_flags(IrqFlags::LEVEL_TRIGGERED | IrqFlags::LOW_ACTIVE | IrqFlags::MASKED);
    // entry.set_dest(dest); // CPU(s)
    // ioapic.set_table_entry(irq_number, entry);

    // ioapic.enable_irq(irq_number);

    ioapic
}

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
        idt[InterruptIndex::Timer.as_usize()].set_handler_fn(timer_interrupt_handler);

        // Override invalid opcode handler to emulate getsec.
        unsafe {
            let opcode_handler_ptr = x86_64::VirtAddr::new((getsec::invalid_opcode as *const ()) as u64);
            idt.invalid_opcode.set_handler_addr(opcode_handler_ptr);
        }

        idt
    };
}

/// Initialize the Interrupt Description Table.
pub fn init_idt() {
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
    error_code: u64,
) {
    panic!(
        "Error code: 0x{:x}\nEXCEPTION: GENERAL PROTECTION FAULT\n{:#?}",
        error_code, stack_frame
    );
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

extern "x86-interrupt" fn stack_segment_fault_handler(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) {
    panic!("EXCEPTION: STACK SEGMENT FAULT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn invalid_tss_handler(stack_frame: InterruptStackFrame, error_code: u64) {
    panic!(
        "EXCEPTION: INVALID TSS\n{:#?}\n Error Code: 0x{:x}",
        stack_frame, error_code
    );
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

extern "x86-interrupt" fn timer_interrupt_handler(_stack_frame: InterruptStackFrame) {
    print!(".");

    unsafe {
        LOCALAPIC.lock().end_of_interrupt();
    }
}

impl InterruptIndex {
    fn as_u8(self) -> u8 {
        self as u8
    }

    fn as_usize(self) -> usize {
        usize::from(self.as_u8())
    }
}
