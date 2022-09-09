# Discovering and mapping PCI/PCIe devices

Tyche needs to enumerate, configure, and select which PCIe devices will be exposed to the Linux guest.
It further needs to correctly configure the corresponding IO MMU(s) to protect itself (and enclaves) from the untrusted Linux Guest.  

This article describes all the steps required to correctly configure PCIe devices in our hypervisor.
Hopefully, this gives a complete self-contained overview.

The article is organized as follows:

1. Terminology
2. What we get at boot-time.
3. Parsing PCIe configurations.
4. IO MMU configuration.

## Terminology

### PCI - Peripheral Component Interconnect

PCI is a local computer bus to attach hardware devices in a computer.
PCI devices attached to the bus are usually assigned addresses in the processor's address space.
PCI has three address spaces:
1. memory
2. I/O address
3. configuration

Memory addresses can be either 32 or 64 bits. 

I/O addresses are used for compatibility with Intel's x86 I/O port address space (`in` and `out` instructions).

PCI configuration space holds special per-device configuration registers.
This registers are used to configure devices memory and I/O address ranges.
At boot-time, the BIOS scans devices and assigns memory and I/O address ranges.

![CPU_and_PCI](figs/CPU_and_PCI.jpg)

#### Legacy PCI

The configuration space of 256 bytes can be accessed through I/O ports `0xCF8`
and `0xCFC`.

In case the devices uses memory region, those regions can be configured in the
Base Address Registers (BARs). Those registers can hold either 32 bits addresses
(if bits 2:1 are 0x0) or 64 bits addresses (if bits 2:1 are 0x2).


# Rust BootLoader BootInfo 

The rust [bootloader](https://github.com/rust-osdev/bootloader) used by tyche abstracts over the differences between BIOS and UEFI booting to supply the kernel's entry point with the appropriate information. 

