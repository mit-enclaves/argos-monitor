//! ACPI Tables Support

mod tables;

use alloc::vec::Vec;
use core::mem;
use core::ptr;

use crate::println;
use crate::vmx::HostVirtAddr;
use tables::{McfgItem, Rsdp, SdtHeader};

#[derive(Default)]
pub struct AcpiInfo {
    /// MCFG table.
    pub mcfg: Option<Vec<McfgItem>>,
}

impl AcpiInfo {
    /// Read ACPI info from the RSDP pointer.
    ///
    /// SAFETY: The pointer must point to a well formed RSDP table.
    pub unsafe fn from_rsdp(rsdp_ptr: u64, physical_memory_offset: HostVirtAddr) -> Self {
        // Get RSDP virtual address
        let rsdp = &*((rsdp_ptr + physical_memory_offset.as_u64()) as *const Rsdp);
        rsdp.check().expect("Invalid RSDP checksum");
        if rsdp.revision == 0 {
            println!("Missing XSDT");
            return AcpiInfo::default();
        }

        // Parse the XSDT
        let xsdt_ptr = (rsdp.xsdt_address + physical_memory_offset.as_u64()) as *const u8;
        let xsdt_header = &*(xsdt_ptr as *const SdtHeader);
        let lenght = xsdt_header.length as usize;
        println!("Lenght:    {}", lenght);
        println!("Nb Items:  {}", lenght - mem::size_of::<SdtHeader>());
        println!("XSDT ptr:  0x{:x}", xsdt_ptr as usize);
        println!(
            "Table ptr: 0x{:x}",
            xsdt_ptr.offset(mem::size_of::<SdtHeader>() as isize) as usize
        );

        // Iterate over table entries
        let mut table_ptr = xsdt_ptr.offset(mem::size_of::<SdtHeader>() as isize);
        let mut acpi_info = AcpiInfo::default();
        while table_ptr < xsdt_ptr.offset(lenght as isize) {
            let table_addr = ptr::read_unaligned(table_ptr as *const u64);
            acpi_info.handle_table(table_addr, physical_memory_offset);
            table_ptr = table_ptr.offset(mem::size_of::<u64>() as isize);
        }

        acpi_info
    }

    unsafe fn handle_table(&mut self, table_addr: u64, physical_memory_offset: HostVirtAddr) {
        let header = &*((table_addr + physical_memory_offset.as_u64()) as *const SdtHeader);
        match &header.signature {
            b"MCFG" => self.handle_mcfg_table(header),
            _ => {
                println!(
                    "ACPI: unknown table '{}'",
                    core::str::from_utf8(&header.signature)
                        .expect("Failed to parse table signature")
                );
            }
        }
    }

    unsafe fn handle_mcfg_table(&mut self, header: &SdtHeader) {
        println!("ACPI: parsing 'MCFG' table");
        header.verify_checksum().expect("Invalid MCFG checksum");

        // Table items start at offset 44.
        // See https://wiki.osdev.org/PCI_Express
        let item_ptr = ((header as *const _) as *const u8).offset(44);
        let mut item_ptr = item_ptr as *const McfgItem;
        let table_end = ((header as *const _) as *const u8).offset(header.length as isize);
        let table_end = table_end as *const McfgItem;
        let mut items = Vec::new();
        while item_ptr < table_end {
            let item = ptr::read_unaligned(item_ptr);
            items.push(item);

            item_ptr = item_ptr.offset(1);
        }

        self.mcfg = Some(items);
    }
}
