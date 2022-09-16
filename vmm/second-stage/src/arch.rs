//! Architecture specific structures

use core::arch::asm;
use core::mem::size_of;

// —————————————————— Architecture-related Initializations —————————————————— //

pub unsafe fn init() {
    let gdt_desc = DescriptorTablePointer {
        limit: GDT.len() as u16,
        base: GDT.as_ptr() as u64,
    };
    let idt_desc = DescriptorTablePointer {
        limit: 256,
        base: IDT.as_ptr() as u64,
    };
    asm! {
        "lgdt [{gdt}]",
        "lidt [{idt}]",
        gdt = in(reg) &gdt_desc,
        idt = in(reg) &idt_desc,
        options(readonly, nostack, preserves_flags),
    };
}

#[repr(C, packed(2))]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

// —————————————————————————————————— GDT ——————————————————————————————————— //

/// The Global Descriptor Table.
#[used]
#[export_name = "__GDT"]
pub static GDT: [u64; 2] = [0, CODE_SEGMENT];

const CODE_SEGMENT: u64 = 0xaf9b000000ffff;

// —————————————————————————————————— TSS ——————————————————————————————————— //

/// The unique TSS for the second-stage.
#[used]
#[export_name = "__TSS"]
pub static TSS: TaskStateSegment = TaskStateSegment {
    rsp: [0; 3],
    ist: [0; 7],
    io_map: size_of::<TaskStateSegment>() as u16,
    reserved_1: 0,
    reserved_2: 0,
    reservec_3: 0,
    reserved_4: 0,
};

/// TSS layout.
#[repr(C, packed(4))]
pub struct TaskStateSegment {
    reserved_1: u32,
    /// Address of stack pointers (RSP) for rings 0 to 2.
    rsp: [u64; 3],
    reserved_2: u64,
    /// Address of interrupt stack table (IST) pointers.
    ist: [u64; 7],
    reservec_3: u64,
    reserved_4: u16,
    io_map: u16,
}

// —————————————————————————————————— IDT ——————————————————————————————————— //

/// The unique IDT for the second stage.
pub static IDT: [IdtEntry; 256] = [IdtEntry::empty(); 256];

/// An IDT entry.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct IdtEntry {
    ptr_low: u16,
    gdt_selector: u16,
    options: u16,
    ptr_mid: u16,
    ptr_high: u32,
    reserved: u32,
}

impl IdtEntry {
    const fn empty() -> Self {
        IdtEntry {
            ptr_low: 0,
            gdt_selector: 0,
            options: 0,
            ptr_mid: 0,
            ptr_high: 0,
            reserved: 0,
        }
    }
}
