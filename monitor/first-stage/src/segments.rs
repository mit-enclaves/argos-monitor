//! x86 Segments & Selectors

use crate::vmx::GuestVirtAddr;
use bitflags::bitflags;

/// A segment selector.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct SegmentSelector(pub u16);

impl SegmentSelector {
    /// Creates a new segment for the given index and requested privilege level.
    pub fn new(index: u16, rpl: u8) -> Self {
        SegmentSelector((index << 3) | (rpl & 0b11) as u16)
    }

    /// Returns the table index.
    pub fn index(self) -> u16 {
        self.0 >> 3
    }

    /// Returns the requested privilege level.
    pub fn rpl(self) -> u8 {
        (self.0 & 0b11) as u8
    }
}

/// A pointer to a descriptor table (GDT or IDT).
///
/// This struct is in a format suitable for loading by `lgdt` and `lidt`.
#[repr(C, packed)]
pub struct DescriptorTablePointer {
    /// Size of the table.
    pub limit: u16,
    /// Pointer to the memory region containing the table.
    pub base: GuestVirtAddr,
}

/// A Global Descriptor Table (GDT).
pub struct GlobalDescriptorTable<const SIZE: usize> {
    table: [u64; SIZE],
    len: usize,
}

impl<const SIZE: usize> GlobalDescriptorTable<SIZE> {
    /// Creates an empty GDT.
    ///
    /// The first selector is automatically created (it must not be used).
    pub const fn new() -> Self {
        Self {
            table: [0; SIZE],
            len: 1,
        }
    }

    /// Adds a descriptor to a table.
    pub fn add_entry(&mut self, entry: DescriptorFlags) -> Result<SegmentSelector, ()> {
        if self.len > self.table.len().saturating_sub(1) {
            return Err(());
        }
        let index = self.push(entry.bits());

        let rpl = if entry.contains(DescriptorFlags::DPL_RING_3) {
            3
        } else {
            0
        };

        Ok(SegmentSelector::new(index as u16, rpl))
    }

    /// Write the table to a given region.
    pub fn write_to(&self, region: &mut [u64]) -> Result<(), ()> {
        if region.len() < self.table.len() {
            return Err(());
        }

        region[0..SIZE].copy_from_slice(&self.table);
        Ok(())
    }

    fn push(&mut self, value: u64) -> usize {
        let index = self.len;
        self.table[index] = value;
        self.len += 1;
        index
    }
}

bitflags! {
    /// Flags for a GDT descriptor. Not all flags are valid for all descriptor types.
    pub struct DescriptorFlags: u64 {
        /// Set by the processor if this segment has been accessed. Only cleared by software.
        /// _Setting_ this bit in software prevents GDT writes on first use.
        const ACCESSED          = 1 << 40;
        /// For 32-bit data segments, sets the segment as writable. For 32-bit code segments,
        /// sets the segment as _readable_. In 64-bit mode, ignored for all segments.
        const WRITABLE          = 1 << 41;
        /// For code segments, sets the segment as “conforming”, influencing the
        /// privilege checks that occur on control transfers. For 32-bit data segments,
        /// sets the segment as "expand down". In 64-bit mode, ignored for data segments.
        const CONFORMING        = 1 << 42;
        /// This flag must be set for code segments and unset for data segments.
        const EXECUTABLE        = 1 << 43;
        /// This flag must be set for user segments (in contrast to system segments).
        const USER_SEGMENT      = 1 << 44;
        /// The DPL for this descriptor is Ring 3. In 64-bit mode, ignored for data segments.
        const DPL_RING_3        = 3 << 45;
        /// Must be set for any segment, causes a segment not present exception if not set.
        const PRESENT           = 1 << 47;
        /// Available for use by the Operating System
        const AVAILABLE         = 1 << 52;
        /// Must be set for 64-bit code segments, unset otherwise.
        const LONG_MODE         = 1 << 53;
        /// Use 32-bit (as opposed to 16-bit) operands. If [`LONG_MODE`][Self::LONG_MODE] is set,
        /// this must be unset. In 64-bit mode, ignored for data segments.
        const DEFAULT_SIZE      = 1 << 54;
        /// Limit field is scaled by 4096 bytes. In 64-bit mode, ignored for all segments.
        const GRANULARITY       = 1 << 55;

        /// Bits `0..=15` of the limit field (ignored in 64-bit mode)
        const LIMIT_0_15        = 0xFFFF;
        /// Bits `16..=19` of the limit field (ignored in 64-bit mode)
        const LIMIT_16_19       = 0xF << 48;
        /// Bits `0..=23` of the base field (ignored in 64-bit mode, except for fs and gs)
        const BASE_0_23         = 0xFF_FFFF << 16;
        /// Bits `24..=31` of the base field (ignored in 64-bit mode, except for fs and gs)
        const BASE_24_31        = 0xFF << 56;
    }
}
