//! GETSEC emulation
//!
//! The Intel SMX extension is not available on KVM, therefore this module enables a simple GETSEC
//! emulation by providing a #UD exception handler that recognise traps on GETSEC and react
//! accordingly.
//!
//! IMPORTANT: When relying on GETSEC emulation, the SMXE bit in CR4 must _not_ be set, otherwhise
//! GETSEC causes a VM exit and KVM will kill the VM.

use core::arch::asm;

const GETSEC_OPCODE: u16 = 0x370F;

// ————————————————————————— Invalid Opcode Handler ————————————————————————— //

/// The interrupt stack frame
#[derive(Debug)]
#[repr(C)]
pub struct StackFrame {
    pub rip: u64,
    pub cs: u64,
    pub eflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

/// The registers used by GETSEC.
#[repr(C)]
pub struct GetsecRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
}

/// The invalid opcode exception handler. Handles the x86 exception handlers calling convention and
/// forward the relevant registers to the inner function.
#[naked]
pub unsafe extern "C" fn invalid_opcode() {
    asm! {
        // Caller-saved registers
        "push rdi",
        "push rsi",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        // GETSEC return values
        "push rdx",
        "push rcx",
        "push rbx",
        "push rax",
        // Call inner function
        "mov rdi, rsp",        // first parameter:  getsec registers
        "lea rsi, [rsp + 80]", // second parameter: interrupt frame
        "call {inner}",
        // Restore GETSEC return values
        "pop rax",
        "pop rbx",
        "pop rcx",
        "pop rdx",
        // Restore caller-saved registers
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rsi",
        "pop rdi",
        // Return from interrupt
        "iretq",
        inner = sym invalid_opcode_inner,
        options(noreturn)
    };
}

// ———————————————————————————— GETSEC Emulation ———————————————————————————— //

/// The Rust function for handling invalid opcodes, responsible for emulating GETSEC.
#[inline]
extern "C" fn invalid_opcode_inner(registers: &mut GetsecRegisters, stack_frame: &mut StackFrame) {
    // Read next 2 bytes after the faulty RIP
    let next_instr = unsafe {
        let rip = stack_frame.rip as *const u16;
        *rip
    };
    if next_instr == GETSEC_OPCODE {
        // TODO: emulate GETSEC
        registers.rax *= 2;
        registers.rbx *= 2;
        registers.rcx *= 2;
        registers.rdx *= 2;

        // Skip GETSEC instruction before resuming execution
        stack_frame.rip += 2;
    } else {
        panic!("EXCEPTION: INVALID OPCODE\n{:#x?}", stack_frame);
    }
}
