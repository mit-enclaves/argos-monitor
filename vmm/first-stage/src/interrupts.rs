use crate::mmu;
use lazy_static::lazy_static;
use spin::Mutex;

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

impl InterruptIndex {
    fn as_u8(self) -> u8 {
        self as u8
    }

    fn as_usize(self) -> usize {
        usize::from(self.as_u8())
    }
}
