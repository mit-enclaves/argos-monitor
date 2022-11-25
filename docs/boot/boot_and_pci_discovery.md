# Discovering and mapping PCI/PCIe devices

Tyche needs to enumerate, configure, and select which PCIe devices will be exposed to the Linux guest.
It further needs to correctly configure the corresponding IO MMU(s) to protect itself (and enclaves) from the untrusted Linux Guest.  

This article describes all the steps required to correctly configure PCIe devices in our hypervisor.
Hopefully, this gives a complete self-contained overview.

The article is organized as follows:

1. General Overview 
2. What we get at boot-time.
3. Parsing PCIe configurations.
4. IO MMU configuration.

## General Overview 

### PCI - Peripheral Component Interconnect

PCI is a local computer bus to attach hardware devices in a computer.
PCI devices attached to the bus are usually assigned addresses in the processor's address space.
PCI has three address spaces:
1. memory
2. I/O address
3. configuration

Memory addresses can be either 32 or 64 bits. 

I/O addresses are used for compatibility with Intel's x86 I/O port address space.

PCI configuration space holds special per-device configuration registers.
This registers are used to configure devices memory and I/O address ranges.

##### Topology

The PCI/PCIe topology is arranged as a tree, where each node is uniquely
identified by their bus, device, and function identifiers, noted in the
`bus:device.function` format. PCIe introduces segments groups to enable large
system to go beyond the 256 buses limits, in which case the format becomes
`segment:bus:device.function`. For most systems the only segment is segment 0.

The bus is encoded on 8 bits, the node on 5 and function on 3, giving 16 bits of
address space for PCI devices. The segment is encoded on 16 bit itself, raising
this limit to 32 bits on PCIe systems.

Intermediate nodes in the tree are PCI bridges, used to connect two buses. The
incoming bus is called _primary_, the outgoing bus is called _secondary_, and
the highest bus ID that is a descendent of the secondary bus is called the
_subordinate_. Therefore, a bridge is on the path to any buses in the range
[secondary, subordinate].

#### Enumeration

At boot-time, the BIOS scans devices and assigns memory and I/O address ranges.
This is called Bus enumeration and might be done by the Operating System as well.
The enumeration consists in attempting to access all possible configuration spaces (see below).
When a read succeeds, the BIOS or OS writes all ones to its `Base Address Registers`, reads the device's requested memory size, and programs the memory-mapped addresses and I/O port addresses into the device's BAR configuration registers.
Each PCI device function can implement up to 6 BARs, describing between 16 bytes and 2 GB, located below the 4GB address space limit, if bits 2:1 are 0x0, or optionally above in 64 bits mode if bits 2:1 are 0x2.

![CPU_and_PCI](figs/CPU_and_PCI.jpg)

#### Legacy PCI addressing

In Legacy PCI, each device on the bus has a configuration space of 256 bytes, which can be addressed with its 16 bits `B/D/F`:
```
PCI bus: 8 bits | Device: 5 bits | Function: 3 bits  
```

The first 64 bytes of the device configuration are standardized, while the rest is vendor specific.

The configuration of this 256 bytes can be done via I/O addresses via the Configuration Access Mechanism (CAM).
This relies on two registers:

`CONFIG_ADDRESS` (`0xCF8`) holds the destination address:
```
0x80000000 | bus << 16 | device << 11 | function <<  8 | offset
```

`CONFIG_DATA` (`0xCFC`) is a 32 bit register holding the data to be written. 

#### PCIe - PCI Express

PCIe Is the de-facto standard on computers nowadays, it allows high bandwidth
communication with devices.

PCIe extends the configuration space from 256 bytes for PCI to 4096 bytes (i.e.
a full x86 page). The extended space cannot be accessed through the legacy PCI
I/O ports method, but uses memory mapped I/O instead. The beginning of the
configuration region can be found in the system's ACPI `MCFG` table.

#### Links

- [OSDev PCI](https://wiki.osdev.org/Pci)
- [OSDev PCIe](https://wiki.osdev.org/PCI_Express)
- [Wikipedia PCI configuration space](https://en.wikipedia.org/wiki/PCI_configuration_space)
- [PCI BAR size](https://stackoverflow.com/questions/19006632/how-is-a-pci-pcie-bar-size-determined)

## What we get at boot time 

### Rust BootLoader BootInfo 

The rust [bootloader](https://github.com/rust-osdev/bootloader) used by tyche abstracts over the differences between BIOS and UEFI booting to supply the kernel's entry point with [BootInfo](https://github.com/rust-osdev/bootloader/blob/main/src/boot_info.rs).

First, the `memory_regions` displays all the `e820` regions obtained from the BIOS:

```
MemoryRegion { start: 7f0a6000, end: 7f0af000, kind: Usable }
MemoryRegion { start: 7f0af000, end: 7f0b2000, kind: Usable }
MemoryRegion { start: 7f0b2000, end: 7f0b5000, kind: Usable }
MemoryRegion { start: 7f0b5000, end: 7f4bf000, kind: Usable }
MemoryRegion { start: 7f4bf000, end: 7f4c6000, kind: Usable }
MemoryRegion { start: 7f4c6000, end: 7f4c9000, kind: Usable }
MemoryRegion { start: 7f4c9000, end: 7f4d1000, kind: Usable }
MemoryRegion { start: 7f4d1000, end: 7f4d5000, kind: Usable }
MemoryRegion { start: 7f4d5000, end: 7f4dc000, kind: Usable }
MemoryRegion { start: 7f4dc000, end: 7f4dd000, kind: Usable }
MemoryRegion { start: 7f4dd000, end: 7f4e9000, kind: Usable }
MemoryRegion { start: 7f4e9000, end: 7f4ea000, kind: Usable }
MemoryRegion { start: 7f4ea000, end: 7f4ef000, kind: Usable }
MemoryRegion { start: 7f4ef000, end: 7f8ef000, kind: Usable }
MemoryRegion { start: 7f8ef000, end: 7f9ef000, kind: Usable }
MemoryRegion { start: 7f9ef000, end: 7faef000, kind: Usable }
MemoryRegion { start: 7faef000, end: 7fb6f000, kind: UnknownUefi(0) }
MemoryRegion { start: 7fb6f000, end: 7fb7f000, kind: UnknownUefi(9) }
MemoryRegion { start: 7fb7f000, end: 7fbff000, kind: UnknownUefi(a) }
MemoryRegion { start: 7fbff000, end: 7fe00000, kind: Usable }
MemoryRegion { start: 7fe00000, end: 7fed3000, kind: Usable }
MemoryRegion { start: 7fed3000, end: 7fef3000, kind: Usable }
MemoryRegion { start: 7fef3000, end: 7ff23000, kind: Usable }
MemoryRegion { start: 7ff23000, end: 7ff2c000, kind: Usable }
MemoryRegion { start: 7ff2c000, end: 7ff58000, kind: Usable }
MemoryRegion { start: 7ff58000, end: 7ff78000, kind: Usable }
MemoryRegion { start: 7ff78000, end: 80000000, kind: UnknownUefi(a) }
MemoryRegion { start: 100000000, end: 140000000, kind: Usable }
MemoryRegion { start: 140000000, end: 1400cb000, kind: Usable }
MemoryRegion { start: 1400cb000, end: 200000000, kind: Usable }
MemoryRegion { start: b0000000, end: c0000000, kind: UnknownUefi(0) }
```
Another useful information we get from the `BootInfo` is the `rsdp_addr`.
This field points to the BIOS/UEFI RSDP data structure used to find the ACPI tables.
This structure contains a `xsdt` pointer field, i.e., a pointer to entries in a system description table.
We are interested in two types (signature) of headers: `DMAR` and `MCFG`.

`MCFG` entries are tables with potentially multiple items that each describe a PCI-attached device:

```
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
```

`DMAR` entries describe DMA remapping tables, i.e., IO MMUs available as well as the unit they are responsible for.

By parsing tables of both of these types, we should have all the information needed to list all available PCI devices and the corresponding I/O MMUs to properly isolate them.
