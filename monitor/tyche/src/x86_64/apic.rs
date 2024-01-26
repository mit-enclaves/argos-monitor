/* Source code taken from https://github.com/gz/rust-x86 */

// Default MMIO address of lapic
const LAPIC_ADDR: usize = 0xfee00000;

/// Error Status Register (ESR). Read/write. See Section 10.5.3.
pub const XAPIC_ESR: u32 = 0x280;

/// Interrupt Command Register (ICR). Read/write. See Figure 10-28 for reserved bits
pub const XAPIC_ICR0: u32 = 0x300;

/// Interrupt Command Register (ICR). Read/write. See Figure 10-28 for reserved bits
pub const XAPIC_ICR1: u32 = 0x310;

/// Specify IPI Delivery Mode
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Eq, PartialEq)]
#[allow(dead_code)]
#[repr(u64)]
pub enum DeliveryMode {
    /// Delivers the interrupt specified in the vector field to the target processor or processors.
    Fixed = 0b000,
    /// Same as fixed mode, except that the interrupt is delivered to the processor executing at the
    /// lowest priority among the set of processors specified in the destination field. The ability
    /// for a processor to send a lowest priority IPI is model specific and should be avoided by
    /// BIOS and operating system software.
    LowestPriority = 0b001,
    /// Delivers an SMI interrupt to the target processor or processors.
    /// The vector field must be programmed to 00H for future compatibility.
    SMI = 0b010,
    /// Reserved
    _Reserved = 0b11,
    /// Delivers an NMI interrupt to the target processor or processors.
    /// The vector information is ignored.
    NMI = 0b100,
    /// Delivers an INIT request to the target processor or processors, which causes them to perform an INIT.
    Init = 0b101,
    /// Sends a special start-up IPI (called a SIPI) to the target processor or processors.
    /// The vector typically points to a start-up routine that is part of the
    /// BIOS boot-strap code (see Section 8.4, Multiple-Processor (MP) Initialization). I
    /// PIs sent with this delivery mode are not automatically retried if the source
    /// APIC is unable to deliver it. It is up to the software to deter- mine if the
    /// SIPI was not successfully delivered and to reissue the SIPI if necessary.
    StartUp = 0b110,
}

/// Specify IPI Destination Mode.
#[derive(Debug, Eq, PartialEq)]
#[allow(dead_code)]
#[repr(u64)]
pub enum DestinationMode {
    Physical = 0,
    Logical = 1,
}

/// Specify Delivery Status
#[derive(Debug, Eq, PartialEq)]
#[allow(dead_code)]
#[repr(u64)]
pub enum DeliveryStatus {
    Idle = 0,
    SendPending = 1,
}

/// IPI Level
#[derive(Debug, Eq, PartialEq)]
#[allow(dead_code)]
#[repr(u64)]
pub enum Level {
    Deassert = 0,
    Assert = 1,
}

/// IPI Trigger Mode
#[derive(Debug, Eq, PartialEq)]
#[allow(dead_code)]
#[repr(u64)]
pub enum TriggerMode {
    Edge = 0,
    Level = 1,
}

/// IPI Destination Shorthand
#[derive(Debug, Eq, PartialEq)]
#[allow(dead_code)]
#[repr(u64)]
pub enum DestinationShorthand {
    NoShorthand = 0b00,
    Myself = 0b01,
    AllIncludingSelf = 0b10,
    AllExcludingSelf = 0b11,
}

/// Abstract the IPI control register
#[derive(Debug, Eq, PartialEq)]
pub struct Icr(u64);

impl Icr {
    fn id_to_xapic_destination(destination: ApicId) -> u64 {
        // XApic destination are encoded in bytes 56--63 in the Icr
        match destination {
            ApicId::XApic(d) => (d as u64) << 56,
            ApicId::X2Apic(_d) => {
                unreachable!("x2APIC IDs are not supported for xAPIC (use the x2APIC controller)")
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        dest_encoder: fn(ApicId) -> u64,
        vector: u8,
        destination: ApicId,
        destination_shorthand: DestinationShorthand,
        delivery_mode: DeliveryMode,
        destination_mode: DestinationMode,
        delivery_status: DeliveryStatus,
        level: Level,
        trigger_mode: TriggerMode,
    ) -> Icr {
        Icr(dest_encoder(destination)
            | (destination_shorthand as u64) << 18
            | (trigger_mode as u64) << 15
            | (level as u64) << 14
            | (delivery_status as u64) << 12
            | (destination_mode as u64) << 11
            | (delivery_mode as u64) << 8
            | (vector as u64))
    }

    /// Get lower 32-bits of the Icr register.
    pub fn lower(&self) -> u32 {
        self.0 as u32
    }

    /// Get upper 32-bits of the Icr register.
    pub fn upper(&self) -> u32 {
        (self.0 >> 32) as u32
    }
}

/// Encodes the id of a core.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[allow(dead_code)]
pub enum ApicId {
    /// A core destination encoded as an xAPIC ID.
    XApic(u8),
    /// A core destination encoded as an x2APIC ID.
    X2Apic(u32),
}

pub unsafe fn ipi_init(core: ApicId) {
    let icr = Icr::new(
        Icr::id_to_xapic_destination,
        0,
        core,
        DestinationShorthand::NoShorthand,
        DeliveryMode::Init,
        DestinationMode::Physical,
        DeliveryStatus::Idle,
        Level::Assert,
        TriggerMode::Level,
    );
    send_ipi(icr);
}

/// Send a generic IPI.
unsafe fn send_ipi(icr: Icr) {
    // 10.6 ISSUING INTERPROCESSOR INTERRUPTS
    write(XAPIC_ICR1, icr.upper());
    write(XAPIC_ICR0, icr.lower());

    loop {
        let icr = read(XAPIC_ICR0);
        if (icr >> 12 & 0x1) == 0 {
            break;
        }
        if read(XAPIC_ESR) > 0 {
            break;
        }
    }
}

/// Read a register from the MMIO region.
fn read(offset: u32) -> u32 {
    assert!(offset as usize % 4 == 0);
    let index = offset as usize / 4;
    let mmio_region: &'static mut [u32] =
        unsafe { core::slice::from_raw_parts_mut(LAPIC_ADDR as _, 0x1000) };
    unsafe { core::ptr::read_volatile(&mmio_region[index]) }
}

/// write a register in the MMIO region.
fn write(offset: u32, val: u32) {
    assert!(offset as usize % 4 == 0);
    let index = offset as usize / 4;
    let mmio_region: &'static mut [u32] =
        unsafe { core::slice::from_raw_parts_mut(LAPIC_ADDR as _, 0x1000) };
    unsafe { core::ptr::write_volatile(&mut mmio_region[index], val) }
}
