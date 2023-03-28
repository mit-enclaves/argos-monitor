use core::arch::asm;

use qemu::println;
use riscv_csrs::*;
use riscv_sbi::ecall::ecall_handler;
use riscv_utils::RegisterState;

// M-mode trap handler
// Saves register state - calls trap_handler - restores register state - mret to intended mode.

#[repr(align(4))]
#[naked]
pub extern "C" fn machine_trap_handler() {
    unsafe {
        asm!(
            "csrrw sp, mscratch, sp
        addi sp, sp, -34*8
        sd ra, 0*8(sp)
        sd a0, 1*8(sp)
        sd a1, 2*8(sp)
        sd a2, 3*8(sp)
        sd a3, 4*8(sp)
        sd a4, 5*8(sp)
        sd a5, 6*8(sp)
        sd a6, 7*8(sp)
        sd a7, 8*8(sp)
        sd t0, 9*8(sp)
        sd t1, 10*8(sp)
        sd t2, 11*8(sp)
        sd t3, 12*8(sp)
        sd t4, 13*8(sp)
        sd t5, 14*8(sp)
        sd t6, 15*8(sp)
        sd zero, 16*8(sp)
        sd gp, 17*8(sp)
        sd tp, 18*8(sp)
        sd s0, 19*8(sp)
        sd s1, 20*8(sp)
        sd s2, 21*8(sp)
        sd s3, 22*8(sp)
        sd s4, 23*8(sp)
        sd s5, 24*8(sp)
        sd s6, 25*8(sp)
        sd s7, 26*8(sp)
        sd s8, 27*8(sp)
        sd s9, 28*8(sp)
        sd s10, 29*8(sp)
        sd s11, 30*8(sp)
        mv a0, sp      //arg to trap_handler
        auipc x1, 0x0
        addi x1, x1, 10
        j {trap_handler}
        ld ra, 0*8(sp)
        ld a0, 1*8(sp)
        ld a1, 2*8(sp)
        ld a2, 3*8(sp)
        ld a3, 4*8(sp)
        ld a4, 5*8(sp)
        ld a5, 6*8(sp)
        ld a6, 7*8(sp)
        ld a7, 8*8(sp)
        ld t0, 9*8(sp)
        ld t1, 10*8(sp)
        ld t2, 11*8(sp)
        ld t3, 12*8(sp)
        ld t4, 13*8(sp)
        ld t5, 14*8(sp)
        ld t6, 15*8(sp)
        ld zero, 16*8(sp)
        ld gp, 17*8(sp)
        ld tp, 18*8(sp)
        ld s0, 19*8(sp)
        ld s1, 20*8(sp)
        ld s2, 21*8(sp)
        ld s3, 22*8(sp)
        ld s4, 23*8(sp)
        ld s5, 24*8(sp)
        ld s6, 25*8(sp)
        ld s7, 26*8(sp)
        ld s8, 27*8(sp)
        ld s9, 28*8(sp)
        ld s10, 29*8(sp)
        ld s11, 30*8(sp)
        addi sp, sp, 34*8
        csrrw sp, mscratch, sp
        mret",
            trap_handler = sym handle_exit,
            options(noreturn)
        )
    }
}

pub extern "C" fn exit_handler_failed() {
    // TODO: Currently, interrupts must be getting redirected here too. Confirm this and then fix
    // it.
    println!("Cannot handle this trap!");
}

// Exit handler - equivalent to x86 handle_exit for its guest.
// In RISC-V, any trap to machine mode will lead to this function being called (via the machine_trap_handler)

pub fn handle_exit(reg_state: &mut RegisterState) {
    let mut ret: usize = 0;
    let mut err: usize = 0;
    let mut mcause: usize;
    let mut mepc: usize;
    let mut mstatus: usize;
    let mut mtval: usize;

    unsafe {
        asm!("csrr {}, mcause", out(reg) mcause);
        asm!("csrr {}, mepc", out(reg) mepc);
        asm!("csrr {}, mstatus", out(reg) mstatus);
        asm!("csrr {}, mtval", out(reg) mtval);
    }

    // print trap related registers
    println!("mcause: {:x}", mcause);
    println!("mepc: {:x}", mepc);
    println!("mstatus: {:x}", mstatus);
    println!("mtval: {:x}", mtval);

    println!(
        "Trap arguments: a0 {:x} a1 {:x} a2 {:x} a3 {:x} a4 {:x} a5 {:x} a6 {:x} a7 {:x} ",
        reg_state.a0,
        reg_state.a1,
        reg_state.a2,
        reg_state.a3,
        reg_state.a4,
        reg_state.a5,
        reg_state.a6,
        reg_state.a7
    );

    // Check which trap it is
    // mcause register holds the cause of the machine mode trap
    match mcause {
        mcause::ILLEGAL_INSTRUCTION => {
            illegal_instruction_handler(mepc, mstatus);
        }
        mcause::ECALL_FROM_SMODE => {
            ecall_handler(&mut ret, &mut err, reg_state.a0, reg_state.a6, reg_state.a7)
        }
        _ => exit_handler_failed(),
        //Default - just print whatever information you can about the trap.
    }
    println!("Ecall handler complete: returning {:x}", ret);

    // Return to the next instruction after the trap.
    // i.e. mepc += 4
    unsafe {
        asm!("csrr t0, mepc");
        asm!("addi t0, t0, 0x4");
        asm!("csrw mepc, t0");
    }

    //Set appropriate return values
    reg_state.a0 = 0x0;
    reg_state.a1 = ret;
}

pub fn illegal_instruction_handler(mepc: usize, mstatus: usize) {
    let mut mepc_instr_opcode: usize = 0;

    // Read the instruction which caused the trap. (mepc points to the VA of this instruction).
    // Need to set mprv before reading the instruction pointed to by mepc (to enable VA to PA
    // translation in M-mode. Reset mprv once done.

    let mut mprv_index: usize = 1 << mstatus::MPRV;

    unsafe {
        asm!("csrs mstatus, {}", in(reg) mprv_index);
        asm!("csrr a0, mepc");
        asm!("lw a1, (a0)");
        asm!("csrc mstatus, {}", in(reg) mprv_index);
        asm!("mv {}, a1", out(reg) mepc_instr_opcode);
    }

    println!(
        "Illegal instruction trap from {} mode, caused by instruction {:x}",
        ((mstatus >> mstatus::MPP_LOW) & mstatus::MPP_MASK),
        mepc_instr_opcode
    );
}
