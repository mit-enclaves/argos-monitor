//! Architecture specific structures

use core::arch::asm;
use riscv_utils::{SUP_STACK_POINTER,TYCHE_STACK_POINTER,SERIAL_PORT_BASE_ADDRESS,PMP_SHIFT,TYCHE_START_ADDRESS,TYCHE_SIZE_NAPOT, ECALL_FROM_UMODE};
use crate::println;
//use riscv_utils::Register_State;

//static mut register_state: Register_State = Register_State::const_default();

pub fn init() {
    
    //Configuring PMP to protect the monitor's memory. 
    //Writing only pmpaddr for now, pmpcfg is already configured with the correct permissions and
    //addressing mode. TODO: Update this to pmp_set once it is implemented. 
    println!("Protecting Tyche Region in PMP with pmpaddr value: {:x}",pmpaddr_write(TYCHE_START_ADDRESS,TYCHE_SIZE_NAPOT));

    //Making sure that ecalls from user mode trap into Tyche.
    println!("Updating medeleg");
    write_medeleg(ECALL_FROM_UMODE, 0);

    unsafe { asm!("csrw mscratch, {}", in(reg) TYCHE_STACK_POINTER); }

    //Configuring mtvec direct base address to point to Tyche's trap handler.
    let mtvec_ptr = machine_trap_handler as * const ();
    println!("mtvec_ptr to be set by Tyche {:p}",mtvec_ptr);
    set_mtvec(mtvec_ptr);
}

pub fn pmpaddr_write(addr: u64, log2len: u64) -> u64 {
    println!("Writing PMPAddr");
    let addrmask: u64;
    let mut pmpaddr: u64;

    if log2len == PMP_SHIFT {
        pmpaddr = addr >> PMP_SHIFT;
    } else {
        // TODO: Define __riscv_xlen
       // if log2len == __riscv_xlen {
       //       pmpaddr = -1;
       // } else {
       addrmask = (1u64 << (log2len - PMP_SHIFT)) - 1;
       pmpaddr = (addr >> PMP_SHIFT) & !addrmask;
       pmpaddr |= addrmask >> 1;
        // }
    }

    println!("About to write PMPAddr");
 
    //TODO: Write pmpaddr"index" instead of 1 in the following code.
    unsafe { asm!("csrw pmpaddr1, {}", in(reg) pmpaddr); }

    return pmpaddr;
    println!("Done writing PMPAddr");
}

pub fn set_mtvec(addr: *const ()) { 
    unsafe { asm!("csrw mtvec, {}", in(reg) addr); }

    let mut mtvec: usize;
    unsafe { asm!("csrr {}, mtvec", out(reg) mtvec); }

    println!("Updated mtvec {:x}",mtvec);
}

pub fn write_medeleg(pos: usize, value: usize) { 
    let mut medeleg: usize;
    unsafe { asm!("csrr {}, medeleg", out(reg) medeleg); }

    println!("Medeleg set by OpenSBI {:x}",medeleg);

    //update the value at position pos.
    medeleg &= (!(1 << pos) | (value << pos));

    println!("Medeleg to be set by Tyche {:x}",medeleg);

    unsafe { asm!("csrw medeleg, {}", in(reg) medeleg); }

    unsafe { asm!("csrr {}, medeleg", out(reg) medeleg); }

    println!("Medeleg set by Tyche {:x}",medeleg);
}

#[repr(align(4))]
#[naked]
pub fn machine_trap_handler() {
 
    unsafe { 
    
    asm!(
        "csrrw sp, mscratch, sp
        addi sp, sp, -17*4
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
        addi sp, sp, 17*4
        csrrw sp, mscratch, sp
        mret",
        trap_handler = sym trap_handler_dummy,
        options(noreturn)
    )

    }


    /* unsafe {  
     asm!( 
        "csrrw  sp, mscratch, sp", 
        "addi sp, sp, 50*8",
        "sd     ra, 0*8(sp)
        sd      gp, 2*8(sp)
        sd      tp, 3*8(sp)
        sd      t0, 4*8(sp)
        sd      t1, 5*8(sp)
        sd      t2, 6*8(sp)
        sd      s0, 7*8(sp)
        sd      s1, 8*8(sp)
        sd      a0, 9*8(sp)
        sd      a1, 10*8(sp)
        sd      a2, 11*8(sp)
        sd      a3, 12*8(sp)
        sd      a4, 13*8(sp)
        sd      a5, 14*8(sp)
        sd      a6, 15*8(sp)
        sd      a7, 16*8(sp)
        sd      s2, 17*8(sp)
        sd      s3, 18*8(sp)
        sd      s4, 19*8(sp)
        sd      s5, 20*8(sp)
        sd      s6, 21*8(sp)
        sd      s7, 22*8(sp)
        sd      s8, 23*8(sp)
        sd      s9, 24*8(sp)
        sd     s10, 25*8(sp)
        sd     s11, 26*8(sp)
        sd      t3, 27*8(sp)
        sd      t4, 28*8(sp)
        sd      t5, 29*8(sp)
        sd      t6, 30*8(sp)",
        "csrr   t0, mstatus
        sd      t0, 31*8(sp)",
        "csrr   t1, mepc
        sd      t1, 32*8(sp)",
        //csrrw t2, mscratch, sp
        "csrr  t2, mscratch", 
        "sd     t2, 1*8(sp)",
         "addi   sp, sp, -50*8",
        "j      {trap_handler}",
        trap_handler = sym trap_handler,
        options(noreturn)
    )
   } */ 
    /* 
    unsafe {
        //save register state
        asm!(
        "sw sp, {sp}",
        "sw ra, {ra}", 
        "sw a0, {a0}", 
        "sw a1, {a1}", 
        "sw a2, {a2}", 
        "sw a3, {a3}", 
        "sw a4, {a4}", 
        "sw a5, {a5}",
        "sw a6, {a6}", 
        "sw a7, {a7}", 
        "sw t0, {t0}",
        "sw t1, {t1}", 
        "sw t2, {t2}", 
        "sw t3, {t3}",
        "sw t4, {t4}", 
        "sw t5, {t5}", 
        "sw t6, {t6}", 
        //setting stack pointer 
        "lw sp, {tyche_sp}",
        " j {trap_handler}",
        sp = out(reg) register_state.sp,
        ra = out(reg) register_state.ra,
        a0 = out(reg) register_state.a0,
        a1 = out(reg) register_state.a1,
        a2 = out(reg) register_state.a2,
        a3 = out(reg) register_state.a3,
        a4 = out(reg) register_state.a4,
        a5 = out(reg) register_state.a5,
        a6 = out(reg) register_state.a6,
        a7 = out(reg) register_state.a7,
        t0 = out(reg) register_state.t0,
        t1 = out(reg) register_state.t1,
        t2 = out(reg) register_state.t2,
        t3 = out(reg) register_state.t3,
        t4 = out(reg) register_state.t4,
        t5 = out(reg) register_state.t5,
        t6 = out(reg) register_state.t6,
        tyche_sp = in(reg) TYCHE_STACK_POINTER, 
        trap_handler = sym trap_handler,
        options(noreturn));
    }
    */
}

pub extern "C" fn trap_handler_dummy() { 
}

pub extern "C" fn trap_handler() { 
    //Read mcause
    let mut mcause: usize;
    unsafe { asm!("csrr {}, mcause", out(reg) mcause); }

    //Read mepc
    let mut mepc: usize;
    unsafe { asm!("csrr {}, mepc", out(reg) mepc); }

    let mut sp: u64;
    let mut mscratch: u64;
    unsafe { asm!("mv {}, sp", out(reg) sp); }
    unsafe { asm!("csrr {}, mscratch", out(reg) mscratch); }

    println!("Handling machine trap! mcause {:x} mepc {:x} sp {:x} mscratch {:x}",mcause, mepc, sp, mscratch);

    /*unsafe {
        asm!("csrr t0, mepc");
        asm!("addi t0, t0, 0x4");
        asm!("csrw mepc, t0");
    }*/ 

    //unsafe { asm!("csrw mscratch, {}", in(reg) TYCHE_STACK_POINTER); }


    //println!("Restoring Register State");

    //restore register state
    //restore_register_state();

    println!("Returning from trap handler");

    //return
    //unsafe { asm!("mret", options(noreturn)); }
}

pub fn restore_register_state() { 
    let mut sp: u64;
    let mut mscratch: u64;
    unsafe { asm!("mv {}, sp", out(reg) sp); }
    unsafe { asm!("csrr {}, mscratch", out(reg) mscratch); }
    println!("Restoring register state! sp {:x} mscratch {:x}", sp, mscratch);
    /* unsafe { 
    asm!(
        "csrr   sp, mscratch", 
        //"mv     sp, a0"
        "addi   sp, sp, 50*8",
        )
    } */ 



    unsafe { asm!("mv {}, sp", out(reg) sp); }
    unsafe { asm!("csrr {}, mscratch", out(reg) mscratch); }
    println!("Restoring register state updated sp! sp {:x} mscratch {:x}", sp, mscratch);

    /* unsafe { 
    asm!(
        "ld     t0, 31*8(sp)
        ld      t1, 32*8(sp)
        csrw    mstatus, t0
        csrw    mepc, t1",
        "ld     ra, 0*8(sp)
        ld      gp, 2*8(sp)
        ld      tp, 3*8(sp)
        ld      t0, 4*8(sp)
        ld      t1, 5*8(sp)
        ld      t2, 6*8(sp)
        ld      s0, 7*8(sp)
        ld      s1, 8*8(sp)
        ld      a0, 9*8(sp)
        ld      a1, 10*8(sp)
        ld      a2, 11*8(sp)
        ld      a3, 12*8(sp)
        ld      a4, 13*8(sp)
        ld      a5, 14*8(sp)
        ld      a6, 15*8(sp)
        ld      a7, 16*8(sp)
        ld      s2, 17*8(sp)
        ld      s3, 18*8(sp)
        ld      s4, 19*8(sp)
        ld      s5, 20*8(sp)
        ld      s6, 21*8(sp)
        ld      s7, 22*8(sp)
        ld      s8, 23*8(sp)
        ld      s9, 24*8(sp)
        ld     s10, 25*8(sp)
        ld     s11, 26*8(sp)
        ld      t3, 27*8(sp)
        ld      t4, 28*8(sp)
        ld      t5, 29*8(sp)
        ld      t6, 30*8(sp)",
        "ld     sp, 1*8(sp)", 
        "mret",
        options(noreturn)
    )
    } */ 
    //reference: https://mullerlee.cyou/2020/07/09/riscv-exception-interrupt/
    /* unsafe { 
        asm!("lw sp, {}", in(reg) register_state.sp);
        asm!("lw ra, {}", in(reg) register_state.ra);
        asm!("lw a0, {}", in(reg) register_state.a0);
        asm!("lw a1, {}", in(reg) register_state.a1);
        asm!("lw a2, {}", in(reg) register_state.a2);
        asm!("lw a3, {}", in(reg) register_state.a3);
        asm!("lw a4, {}", in(reg) register_state.a4);
        asm!("lw a5, {}", in(reg) register_state.a5);
        asm!("lw a6, {}", in(reg) register_state.a6);
        asm!("lw a7, {}", in(reg) register_state.a7);
        asm!("lw t0, {}", in(reg) register_state.t0);
        asm!("lw t1, {}", in(reg) register_state.t1);
        asm!("lw t2, {}", in(reg) register_state.t2);
        asm!("lw t3, {}", in(reg) register_state.t3);
        asm!("lw t4, {}", in(reg) register_state.t4);
        asm!("lw t5, {}", in(reg) register_state.t5);
        asm!("lw t6, {}", in(reg) register_state.t6);
    } */
}

