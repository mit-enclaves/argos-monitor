//! ACPI Tables Support

mod tables;

use alloc::vec::Vec;
use core::mem;
use core::ptr;

use crate::println;
use crate::vmx::{HostPhysAddr, HostVirtAddr};
use tables::dmar;
use tables::{McfgItem, Rsdp, SdtHeader};

/// Hardware configuration info collected from ACPI tables.
#[derive(Default, Debug)]
pub struct AcpiInfo {
    /// MCFG table.
    pub mcfg: Option<Vec<McfgItem>>,
    /// DMAR table, containing I/O MMU configuration.
    pub iommu: Option<Vec<IommuInfo>>,
}

/// Information about I/O MMU.
#[derive(Debug)]
pub struct IommuInfo {
    /// Base address of the I/O MMU configuration.
    pub base_address: HostPhysAddr,
    /// Size of the I/O MMU configuration, in bytes.
    pub size: usize,
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
            b"DMAR" => self.handle_dmar_table(header),
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

    unsafe fn handle_dmar_table(&mut self, header: &SdtHeader) {
        println!("ACPI: parsing 'DMAR' table");
        header.verify_checksum().expect("Invalid DMAR checksum");

        let table_ptr = (header as *const _) as *const u8;
        let table_end = table_ptr.offset(header.length as isize);
        let mut remap_struct_ptr = table_ptr.offset(mem::size_of::<dmar::Header>() as isize);
        let mut iommus = Vec::new();
        while remap_struct_ptr < table_end {
            let remap_header = &*(remap_struct_ptr as *const dmar::RemappingHeader);
            match remap_header.typ {
                0 => {
                    let iommu = self
                        .handle_dmar_drhd(&*(remap_struct_ptr as *const dmar::DmaRemappingHwUnit));
                    iommus.push(iommu);
                }
                _ => {
                    println!("  Unknown DMAR type: {}", remap_header.typ);
                }
            }

            remap_struct_ptr = remap_struct_ptr.offset(remap_header.length as isize);
        }

        self.iommu = Some(iommus);
    }

    unsafe fn handle_dmar_drhd(&mut self, remap_unit: &dmar::DmaRemappingHwUnit) -> IommuInfo {
        if remap_unit.flags & 0b1 != 0 {
            // All the segment is remapped
            todo!();
        } else {
            // Only the specified devices are remapped.

            let unit_ptr = (remap_unit as *const _) as *const u8;
            let unit_end = unit_ptr.offset(remap_unit.header.length as isize);
            let mut device_scope_ptr =
                unit_ptr.offset(mem::size_of::<dmar::DmaRemappingHwUnit>() as isize);
            while device_scope_ptr < unit_end {
                let device_scope = &*(device_scope_ptr as *const dmar::DeviceScope);
                if device_scope.length != 8 {
                    todo!("Handle arbitrary PCI device path");
                }

                // We assume a single path here
                let path = &*(device_scope_ptr.offset(mem::size_of::<dmar::DeviceScope>() as isize)
                    as *const dmar::Path);
                println!(
                    "  PCI: {:02x}:{:02x}.{} - len: {} - type: {}",
                    device_scope.start_bus,
                    path.device_number,
                    path.function_number,
                    device_scope.length,
                    device_scope.typ
                );

                device_scope_ptr = device_scope_ptr.offset(device_scope.length as isize);
            }

            let base_address = HostPhysAddr::new(remap_unit.base_address as usize);
            let size = 1 << ((remap_unit.size & 0b1111) + 12);
            IommuInfo { base_address, size }
        }
    }
}
