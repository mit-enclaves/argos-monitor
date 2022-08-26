//! ACPI tables definitions

use core::slice;

// —————————————————————————————————— RSDP —————————————————————————————————— //

/// The Root System Description Pointer.
#[repr(C, packed)]
pub struct Rsdp {
    pub signature: [u8; 8],
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub revision: u8,
    pub rsdt_address: u32,

    // These fields are only valid for ACPI Version 2.0 and greater,
    // i.e. revision > 0.
    pub length: u32,
    pub xsdt_address: u64,
    pub ext_checksum: u8,
    pub reserved: [u8; 3],
}

impl Rsdp {
    /// Checks that the RSDP table is valid by computing the checksum.
    pub fn check(&self) -> Result<(), ()> {
        let mut sum: u64 = 0;

        for byte in self.signature {
            sum += byte as u64;
        }
        for byte in self.oem_id {
            sum += byte as u64;
        }
        for byte in self.rsdt_address.to_le_bytes() {
            sum += byte as u64;
        }
        sum += self.checksum as u64;
        sum += self.revision as u64;

        if self.revision > 0 {
            for byte in self.length.to_le_bytes() {
                sum += byte as u64;
            }
            for byte in self.xsdt_address.to_le_bytes() {
                sum += byte as u64;
            }
            for byte in self.reserved {
                sum += byte as u64;
            }
            sum += self.ext_checksum as u64;
        }

        if sum & 0xFF == 0 {
            Ok(())
        } else {
            Err(())
        }
    }
}

// ————————————————————————————— Shared Header —————————————————————————————— //

/// Shared header for System Description Tables.
#[repr(C, packed)]
pub struct SdtHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_revision: u32,
}

impl SdtHeader {
    pub unsafe fn verify_checksum(&self) -> Result<(), ()> {
        // We trust that the table content is valid here, in particular that the length correspond
        // to the real length of the table and therefore entirely reside in accessible memory.
        let table = slice::from_raw_parts((self as *const _) as *const u8, self.length as usize);
        let mut checksum: u64 = 0;
        for byte in table {
            checksum += *byte as u64;
        }

        // The table is valid only if the last 8 bits of the checksum are 0
        match checksum & 0xFF {
            0 => Ok(()),
            _ => Err(()),
        }
    }
}

// —————————————————————————————————— MCFG —————————————————————————————————— //

/// ACPI MCFG table items, describing configuration address spaces of PCIe devices.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct McfgItem {
    /// Base address of the configuration address space.
    pub base_address: u64,
    /// PCI segment group number.
    pub segment_group: u16,
    /// Start PCI bus number decoded by this host bridge.
    pub start_bus: u8,
    /// End PCI bus number decoded by this host bridge.
    pub end_bus: u8,
    // Reserved.
    pub reserved: u32,
}
