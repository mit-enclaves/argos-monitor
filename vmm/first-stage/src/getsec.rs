//! GETSEC emulation
//!
//! The Intel SMX extension is not available on KVM, therefore this module enables a simple GETSEC
//! emulation by providing a #UD exception handler that recognise traps on GETSEC and react
//! accordingly.
//!
//! IMPORTANT: When relying on GETSEC emulation, the SMXE bit in CR4 must _not_ be set, otherwhise
//! GETSEC causes a VM exit and KVM will kill the VM.

use crate::println;
use core::arch::asm;

const GETSEC_OPCODE: u16 = 0x370F;
const CAPABILITIES_CHIPSET: u64 = 1;
const CAPABILITIES_SENTER: u64 = 1 << 4;
const CAPABILITIES_PARAMETERS: u64 = 1 << 6;
const SINIT_BASE: u64 = 45; //TBD//
const SINIT_SIZE: u64 = 45; //TBD//
static TPM_ACCESS_0_ACTIVELOCALITY: u8 = 0;

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
        match registers.rax {
            0 => {
                getsec_capabilities(registers);
            }
            4 => {
                getsec_senter(registers);
            }
            6 => {
                getsec_parameters(registers);
            }
            _ => {
                todo!("INVALID GETSEC LEAF");
            }
        }

        // Skip GETSEC instruction before resuming execution
        stack_frame.rip += 2;
    } else {
        panic!("EXCEPTION: INVALID OPCODE\n{:#x?}", stack_frame);
    }
}

fn getsec_capabilities(registers: &mut GetsecRegisters) {
    if registers.rbx == 0 {
        registers.rax = CAPABILITIES_CHIPSET | CAPABILITIES_PARAMETERS | CAPABILITIES_SENTER;
    } else {
        println!("INVALID RBX VALUE: 0x{:x} ", registers.rbx);
    }
}

fn getsec_senter(registers: &mut GetsecRegisters) {
    // ————————————————— CONDITIONS FOR SENTER LEAF TO BE LAUNCH ————————————————— //
    // TPM.ACCESS_0.activeLocality needs to be clear
    if TPM_ACCESS_0_ACTIVELOCALITY != 0 {
        println!("CANNOT LAUNCH GETSEC[SENTER] => TPM.ACCESS.0.ACTIVELOCALITY BIT IS SET");
    }

    // Unless enumeration by the GETSEC[PARAMETERS] leaf reports otherwise,
    // only a value of zero is supported
    if registers.rdx != 0 {
        println!(
            "CANNOT LAUNCH GETSEC[SENTER] => RDX SHOULD BE 0 BUT IS: 0x{:x} ",
            registers.rdx
        );
    }
    // ————————————————— SENTER LEAF EXECUTION ————————————————— //
    // Verify if loaded SINIT BASE and SIZE are ok
    else if registers.rbx != SINIT_BASE {
        println!(
            "ERROR GETSEC[SENTER] => RBX SHOULD BE EQUAL TO: 0x{:x}, BUT IS: 0x{:x}",
            SINIT_BASE, registers.rbx
        );
    } else if registers.rcx != SINIT_SIZE {
        println!(
            "ERROR GETSEC[SENTER] => RCX SHOULD BE EQUAL TO: 0x{:x}, BUT IS: 0x{:x}",
            SINIT_SIZE, registers.rcx
        );
    }

    // ILP DO SOME STUFFS NEED TO DEFINE WHAT NEEDS TO BE EMULATED OR NOT

    // TODO JUMP TO ACM
}

fn getsec_parameters(registers: &mut GetsecRegisters) {
    //match on RBX
    match registers.rbx {
        0 => {
            todo!("PARAMS RBX 0");
        }
        1 => {
            todo!("PARAMS RBX 1");
        }
        2 => {
            todo!("PARAMS RBX 2");
        }
        3 => {
            todo!("PARAMS RBX 3");
        }
        4 => {
            todo!("PARAMS RBX 4");
        }
        _ => {
            todo!("NOT DEFINED RBX VALUE FOR GETSEC[PARAMETERS]");
        }
    }
}
