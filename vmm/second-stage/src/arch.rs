//! Architecture specific structures

use core::mem::size_of;

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
