use core::arch::asm;
use core::sync::atomic::AtomicUsize;

use capa_engine::{Bitmaps, Domain, Handle, LocalCapa, NextCapaToken};
use riscv_csrs::*;
use riscv_pmp::clear_pmp;
use riscv_sbi::ecall::ecall_handler;
use riscv_sbi::ipi::process_ipi;
use riscv_sbi::sbi::{EXT_IPI, self};
use riscv_utils::{
    aclint_mtimer_set_mtimecmp, clear_mie_mtie, clear_mip_seip, RegisterState,
    ACLINT_MTIMECMP_BASE_ADDR, ACLINT_MTIMECMP_SIZE, NUM_HARTS, TIMER_EVENT_TICK, system_opcode_instr, TrapState, set_rd, get_rs2, set_mip_stip, LAST_TIMER_TICK, read_mip_seip, ZERO,
};
use spin::Mutex;

use super::monitor;
use crate::arch::cpuid;
use crate::calls;
use crate::riscv::monitor::apply_core_updates;
use crate::println;

const EMPTY_ACTIVE_DOMAIN: Mutex<Option<Handle<Domain>>> = Mutex::new(None);
static ACTIVE_DOMAIN: [Mutex<Option<Handle<Domain>>>; NUM_HARTS] = [EMPTY_ACTIVE_DOMAIN; NUM_HARTS];

static mut ecalls_count: usize = 0;
static mut timer_count: [AtomicUsize; 5] = [ZERO; 5];
static mut cleared_seip: [AtomicUsize; 5] = [ZERO; 5];
static mut set_timer_count: usize = 0;
// M-mode trap handler
// Saves register state - calls trap_handler - restores register state - mret to intended mode.

#[repr(align(4))]
#[naked]
pub extern "C" fn machine_trap_handler() {
    unsafe {
        asm!(
        "csrrw sp, mscratch, sp
        addi sp, sp, -34*8
        sd zero, 0*8(sp)
        sd ra, 1*8(sp)
        sd zero, 2*8(sp)    //uninitialised sp 
        sd gp, 3*8(sp)
        sd tp, 4*8(sp)
        sd t0, 5*8(sp)
        sd t1, 6*8(sp)
        sd t2, 7*8(sp)
        sd s0, 8*8(sp)
        sd s1, 9*8(sp)
        sd a0, 10*8(sp)
        sd a1, 11*8(sp)
        sd a2, 12*8(sp)
        sd a3, 13*8(sp)
        sd a4, 14*8(sp)
        sd a5, 15*8(sp)
        sd a6, 16*8(sp)
        sd a7, 17*8(sp)
        sd s2, 18*8(sp)
        sd s3, 19*8(sp)
        sd s4, 20*8(sp)
        sd s5, 21*8(sp)
        sd s6, 22*8(sp)
        sd s7, 23*8(sp)
        sd s8, 24*8(sp)
        sd s9, 25*8(sp)
        sd s10, 26*8(sp)
        sd s11, 27*8(sp)
        sd t3, 28*8(sp)
        sd t4, 29*8(sp)
        sd t5, 30*8(sp)
        sd t6, 31*8(sp)
        mv a0, sp      //arg to trap_handler
        auipc x1, 0x0
        addi x1, x1, 10
        j {trap_handler}
        ld zero, 0*8(sp)
        ld ra, 1*8(sp)
        ld gp, 3*8(sp)
        ld tp, 4*8(sp)
        ld t0, 5*8(sp)
        ld t1, 6*8(sp)
        ld t2, 7*8(sp)
        ld s0, 8*8(sp)
        ld s1, 9*8(sp)
        ld a0, 10*8(sp)
        ld a1, 11*8(sp)
        ld a2, 12*8(sp)
        ld a3, 13*8(sp)
        ld a4, 14*8(sp)
        ld a5, 15*8(sp)
        ld a6, 16*8(sp)
        ld a7, 17*8(sp)
        ld s2, 18*8(sp)
        ld s3, 19*8(sp)
        ld s4, 20*8(sp)
        ld s5, 21*8(sp)
        ld s6, 22*8(sp)
        ld s7, 23*8(sp)
        ld s8, 24*8(sp)
        ld s9, 25*8(sp)
        ld s10, 26*8(sp)
        ld s11, 27*8(sp)
        ld t3, 28*8(sp)
        ld t4, 29*8(sp)
        ld t5, 30*8(sp)
        ld t6, 31*8(sp)
        addi sp, sp, 34*8
        csrrw sp, mscratch, sp
        mret",
            trap_handler = sym handle_exit,
            options(noreturn)
        )
    }
}

pub extern "C" fn exit_handler_failed(mcause: usize, mepc: usize) {
    // TODO: Currently, interrupts must be getting redirected here too. Confirm this and then fix
    // it.
    panic!(
        "*******WARNING: Cannot handle this trap with mcause: {:x} mepc: {:x} !*******",
        mcause, mepc
    );
}

// Exit handler - equivalent to x86 handle_exit for its guest.
// In RISC-V, any trap to machine mode will lead to this function being called (via the machine_trap_handler)

pub fn handle_exit(reg_state: &mut RegisterState) {
    let mut ret: isize = 0;
    let mut err: usize = 0;
    let mut out_val: usize = 0;
    let mut mcause: usize;
    let mut mepc: usize;
    let mut mstatus: usize;
    let mut mtval: usize;
    let mut sp: usize = 0;
    let mut mie: usize = 0;
    let mut mip: usize = 0;
    let mut mideleg: usize = 0;
    let mut satp: usize = 0;
    let hartid: usize = cpuid();
    let mut tyche_call_flag: bool = false;
    let mut tyche_call_id: usize = 0;

    unsafe {
        asm!("csrr {}, mcause", out(reg) mcause);
        asm!("csrr {}, mepc", out(reg) mepc);
        asm!("csrr {}, mstatus", out(reg) mstatus);
        asm!("csrr {}, mtval", out(reg) mtval);
        asm!("csrr {}, mie", out(reg) mie);
        asm!("csrr {}, mideleg", out(reg) mideleg);
        asm!("csrr {}, mip", out(reg) mip);
        asm!("csrr {}, satp", out(reg)satp);
    }

    log::trace!("###### TRAP FROM HART {} ######", hartid);

    //if mepc == 0xffffffff80388bb6 {
    //println!("mepc: {:x} mtval: {:x} mcause: {:x}", mepc, mtval, mcause);
    //} 
    /* if(mepc == 0x4022e050) {
        println!(
            "Handling trap: a0 {:x} a1 {:x} a2 {:x} a3 {:x} a4 {:x} a5 {:x} a6 {:x} a7 {:x}  mepc {:x} mstatus {:x}",
            reg_state.a0,
            reg_state.a1,
            reg_state.a2,
            reg_state.a3,
            reg_state.a4,
            reg_state.a5,
            reg_state.a6,
            reg_state.a7,
            mepc,
            mstatus,
        ); 
    } */


    /*println!(
        "Trap arguments: mcause {:x}, mepc {:x} mstatus {:x} mtval {:x} mie {:x} mip {:x} mideleg {:x} ra {:x} a0 {:x} a1 {:x} a2 {:x} a3 {:x} a4 {:x} a5 {:x} a6 {:x} a7 {:x} satp: {:x}",
>>>>>>> 679fd01d (WIP: Added CSR read emulation - required for u-boot. The emulation works, but something is going wrong since u-boot never stops causing the trap (it causes the same trap quite a few times in opensbi too but moves on at some point).)
        mcause,
        mepc,
        mstatus,
        mtval,
        mie,
        mip,
        mideleg,
        reg_state.ra,
        reg_state.a0,
        reg_state.a1,
        reg_state.a2,
        reg_state.a3,
        reg_state.a4,
        reg_state.a5,
        reg_state.a6,
        reg_state.a7,
        satp
    ); */

    // Check which trap it is
    // mcause register holds the cause of the machine mode trap
    match mcause {
        mcause::MSWI => {
            //println!("Servicing mcause: {:x}",mcause);   //URGENT TODO: Remove this
            process_ipi(hartid);
            let active_dom = get_active_dom(hartid);
            match active_dom {
                Some(mut domain) => apply_core_updates(&mut domain, hartid, reg_state),
                None => {}
            }
        }
        mcause::MTI => {
            /* let val;
            unsafe {
                timer_count[hartid].fetch_add(1, core::sync::atomic::Ordering::SeqCst);
                val = LAST_TIMER_TICK[hartid].load(core::sync::atomic::Ordering::SeqCst);
                if timer_count[hartid].load(core::sync::atomic::Ordering::SeqCst) % 5000 == 0 {
                    println!(" [Hart {}] Received timer interrupt! mepc: {:x} ra {:x} setting mtimecmp to: {:x}", hartid, mepc, reg_state.ra, TIMER_EVENT_TICK+val);
                }
            } */
            //panic!("Servicing mcause: {:x}",mcause);   //URGENT TODO: Remove this
            //println!("[TYCHE Timer Interrupt] mepc: {:x} mtval: {:x} mcause: {:x}", mepc, mtval, mcause);
            clear_mie_mtie();
            //log::info!(
            //    "\nHART {} MTIMER: MEPC: {:x} RA: {:x}\n",
            //    hartid,
            //    mepc,
            //    reg_state.ra
            //);
            set_mip_stip();
            //aclint_mtimer_set_mtimecmp(hartid, TIMER_EVENT_TICK + val);
        }
        mcause::MEI => {
            //panic!("MEI"); - don't do anything for now!
        }
        mcause::ILLEGAL_INSTRUCTION => {
            //println!("[TYCHE Illegal Instruction Handler]");
            illegal_instruction_handler(mepc, mstatus, mtval, reg_state);
        }
        mcause::ECALL_FROM_SMODE => {
            //println!("TYCHE ECall");
            unsafe { 
            /* ecalls_count = ecalls_count + 1;
            if reg_state.a7 == sbi::EXT_TIME {
                set_timer_count = set_timer_count + 1; 
                if set_timer_count % 20 == 0 {
                    //println!("Setting TIMER: {:x} mepc: {:x} set_timer_count: {}", reg_state.a0, mepc, set_timer_count);
                }
            } */
            //if ecalls_count > 39000 && ecalls_count < 40000 {
            //    println!("Ecall: a7: {:x} a6: {:x}", reg_state.a7, reg_state.a6);
            //}
            }
            if reg_state.a7 == 0x5479636865 {
                //Tyche call
                if reg_state.a0 == 0x5479636865 {
                    //println!("Tyche is clearing SIP.SEIE");
                    //let val_b = read_mip_seip();
                    //if val_b == 0 {
                    //    panic!("MIP.SEIP is already clear! Tyche call is redundant! Need to be patient for PLIC to do its job.");
                    //}
                    clear_mip_seip();
                    //let mut val_a = read_mip_seip();
                    //if val_a != 0 {
                    //    panic!("Tyche cleared MIP.SEIP but it's still set.");
                    //}
                    //while val_a != 0 {
                    //    println!("[RETRYING] Tyche couldn't clear SIP.SEIE before: {:x} after: {:x}",val_b, val_a); 
                    //    val_a = read_mip_seip(); 
                    //}
                    /* unsafe {
                        cleared_seip[hartid].fetch_add(1, core::sync::atomic::Ordering::SeqCst);
                        if cleared_seip[hartid].load(core::sync::atomic::Ordering::SeqCst) % 200 == 0 { 
                            println!("[Hart {}] Tyche cleared SIP.SEIE before: {:x} after: {:x}", hartid, val_b, val_a); 
                        }
                    } */

                } else {
                    tyche_call_flag = true;
                    tyche_call_id = reg_state.a0.try_into().unwrap();
                    tyche_call_handler(reg_state);
                }
            } else {
                ecall_handler(&mut ret, &mut err, &mut out_val, *reg_state);
                reg_state.a0 = ret;
                reg_state.a1 = out_val as isize;
                //log::info!("Done handling Ecall");
            }
        }
        mcause::LOAD_ADDRESS_MISALIGNED => {
            //Note: Hypervisor extension is not supported
            //log::info!("Misaligned load");
            //println!("MIS ALIGNED LOADDDDD");
            misaligned_load_handler(mtval, mepc, reg_state);
            //panic!("Load address misaligned mepc: {:x} mtval: {:x} mstatus: {:x}.", mepc, mtval, mstatus);
        }
        mcause::STORE_ADDRESS_MISALIGNED => {
            misaligned_store_handler(mtval, mepc, reg_state); 
        }
        mcause::STORE_ACCESS_FAULT
        | mcause::LOAD_ACCESS_FAULT
        | mcause::INSTRUCTION_ACCESS_FAULT => {
            panic!(
                "PMP Access Fault! mcause: {:x} mepc: {:x} mtval: {:x} satp: {:x} mstatus: {:x}",
                mcause, mepc, mtval, satp, mstatus
            );
        }
        mcause::INSTRUCTION_PAGE_FAULT | mcause::LOAD_PAGE_FAULT | mcause::STORE_PAGE_FAULT => {
            panic!(
                "Page Fault! mcause: {:x} mepc: {:x} mtval: {:x}",
                mcause, mepc, mtval
            );
        }
        _ => exit_handler_failed(mcause, mepc),
        //Default - just print whatever information you can about the trap.
    }

    log::trace!("Returning from Trap on Hart {}", hartid);
    // Return to the next instruction after the trap.
    // i.e. mepc += 4
    // TODO: This shouldn't happen in case of switch.
    if ((mcause & (1 << 63)) != (1 << 63)) && mcause != mcause::LOAD_ADDRESS_MISALIGNED && mcause != mcause::STORE_ADDRESS_MISALIGNED {
        unsafe {
            asm!("csrr t0, mepc");
            asm!("addi t0, t0, 0x4");
            asm!("csrw mepc, t0");
        }
    /* if(mepc == 0x4022e050) {
        println!(
            "Returning from trap: a0 {:x} a1 {:x} a2 {:x} a3 {:x} a4 {:x} a5 {:x} a6 {:x} a7 {:x}  mepc {:x} mstatus {:x}",
            reg_state.a0,
            reg_state.a1,
            reg_state.a2,
            reg_state.a3,
            reg_state.a4,
            reg_state.a5,
            reg_state.a6,
            reg_state.a7,
            mepc,
            mstatus,
        ); 
    } */

    }
    if tyche_call_flag {
        unsafe {
            asm!("csrr {}, mepc", out(reg) mepc);
        }
        println!("[Hart {}] Returning from Tyche Call {} to MEPC: {:x} and RA: {:x}", hartid, tyche_call_id, mepc, reg_state.ra);
    }
    if mtval == 0x10500073 {  
        println!("[Hart {}] Returning from WFI", hartid);
    }
}

pub fn illegal_instruction_handler(mepc: usize, mstatus: usize, mtval: usize, reg_state: &mut RegisterState) {
    /* let mut mepc_instr_opcode: usize = 0;

    // Read the instruction which caused the trap. (mepc points to the VA of this instruction).
    // Need to set mprv before reading the instruction pointed to by mepc (to enable VA to PA
    // translation in M-mode. Reset mprv once done.

    let mut mprv_index: usize = 1 << mstatus::MPRV;

    //clear_pmp();

    unsafe {
        asm!("csrs mstatus, {}", in(reg) mprv_index);
        asm!("csrr a0, mepc");
        asm!("lw a1, (a0)");
        asm!("csrc mstatus, {}", in(reg) mprv_index);
        asm!("mv {}, a1", out(reg) mepc_instr_opcode);
    }

    println!(
        "Illegal instruction trap from {} mode, caused by instruction with opcode {:x}",
        ((mstatus >> mstatus::MPP_LOW) & mstatus::MPP_MASK),
        mepc_instr_opcode
    ); */

    if (mtval & 3) == 3 {
        if ((mtval & 0x7c) >> 2) == 0x1c {
            if mtval == 0x10500073 {    //WFI
                println!("Trapped on WFI: MEPC: {:x} RA: {:x} ", mepc, reg_state.ra);
                //I'm also gonna raise timer interrupts to S-mode, how does that sound? 
                //set_mip_stip();
            } else {
                system_opcode_instr(mtval, mstatus, reg_state); 
            }
        } 
        else {
            panic!("Non-Truly Illegal Instruction Trap!");
        }
    } else {
        panic!("Truly Illegal Instruction Trap!");
    }
}

//Todo: Move this to riscv-utils crate -- this is a quite low-level impl. so it's better to
//modularise it appropriately. 
pub fn misaligned_load_handler(mtval: usize, mepc: usize, reg_state: &mut RegisterState) {
    //Assumption: No H-mode extension. MTVAL2 and MTINST are zero. 
    //Implies: trapped instr value is zero or special value. 

    //println!("Misaligned load handler: mtval {:x} mepc: {:x}", mtval, mepc);

    //get insn....
    let mut trap_state: TrapState = TrapState { epc: 0, cause: 0, tval: 0 };
    let mut mtvec = sbi_expected_trap as *const ();
    let mut mstatus: usize = 0;
    let mut instr: usize = 0;
    let mprv_bits: usize = (1 << mstatus::MPRV) | (1 << mstatus::MXR);
    let instr_len: usize;

    unsafe {
        asm!(
        "mv a3, {trap_st}
        csrrw {tvec}, mtvec, {tvec} 
        csrrs {status}, mstatus, {mprv}
        lhu {inst}, ({epc})
        andi a4, {inst}, 3
        addi a4, a4, -3
        bne a4, zero, 2f
        lhu a4, 2({epc})
        sll a4, a4, 16
        add {inst}, {inst}, a4
        2: csrw mstatus, {status}
        csrw mtvec, {tvec}",
        trap_st = in(reg) &trap_state,
        tvec = inout(reg) mtvec,
        status = inout(reg) mstatus,
        mprv = in(reg) mprv_bits,
        inst = inout(reg) instr,
        epc = in(reg) mepc,
        out("a3") _,
        out("a4") _,
        );
    }
    
    //println!("Done reading instr: {:x}", instr); 

    if trap_state.cause != 0 {
        panic!("Misaligned load handler: Fetch fault {:x}", trap_state.cause);
    }

    if (instr & 0x3) != 0x3 {
        instr_len = 2;
    } else {
        instr_len = 4;
    }

    let mut len: usize = 0;
    let mut shift: usize = 0;
    if (instr & 0x707f) == 0x2003 {  //Matching insn_match_lw
        len = 4;
        shift = 8*4;    
    } else if (instr & 0xe003) == 0x4000 { //Matching insn_match_c_lw
        len = 4;
        shift = 8*4;
        instr = (8 + ((instr >> 2) & ((1 << 3) - 1))) << 7; //Todo: Needs to be cleaned - check
                                                            //insn_match_c_lw (rvc_rs2s << sh_rd)
    } else {
        panic!("Cannot handle this misaligned load! mtval: {:x} mepc: {:x} instr: {:x}", mtval, mepc, instr);
    }
   
    //TODO: Is shifting needed? 

    //get value....
    let mut value: usize = 0;
    let mut tmp_value: u8 = 0;
    mstatus = 0;
    mtvec = sbi_expected_trap as *const ();
    for i in 0..len {
        let load_address = mtval + i;
        let mut load_trap_state: TrapState = TrapState { epc: 0, cause: 0, tval: 0 }; 
        unsafe {
           asm!(
            "mv a3, {trap_st}
            csrrw {tvec}, mtvec, {tvec} 
            csrrs {status}, mstatus, {mprv} 
            .option push
            .option norvc
            lbu {val}, 0({addr})
            .option pop
            csrw mstatus, {status}
            csrw mtvec, {tvec}
            ",
            trap_st = in(reg) &load_trap_state,
            tvec = inout(reg) mtvec,
            status = inout(reg) mstatus,
            mprv = in(reg) mprv_bits,
            val = out(reg) tmp_value,
            addr = in(reg) load_address,
            out("a3") _,
            out("a4") _,
            );
        }

        value = (value) | ((tmp_value as usize) << (i*8));
        if load_trap_state.cause != 0 {
            panic!("Misaligned load handler: Load fault {:x}", load_trap_state.cause);  
        }
    } 

    //println!("Misaligned load value{:x}", value);
    
    set_rd(instr, reg_state, (value << shift) as usize >> shift);
    
    unsafe {
        asm!("csrr t0, mepc");
        asm!("add t0, t0, {}", in(reg) instr_len);
        asm!("csrw mepc, t0");
    } 
}

//Todo: There is a lot of repeated code between misaligned load/store handlers. Make it common.
pub fn misaligned_store_handler(mtval: usize, mepc: usize, reg_state: &mut RegisterState) {
    //println!("Misaligned store handler: mtval {:x} mepc: {:x}", mtval, mepc);

    //get insn....
    let mut trap_state: TrapState = TrapState { epc: 0, cause: 0, tval: 0 };
    let mut mtvec = sbi_expected_trap as *const ();
    let mut mstatus: usize = 0;
    let mut instr: usize = 0;
    let mprv_bits: usize = (1 << mstatus::MPRV) | (1 << mstatus::MXR);
    let instr_len: usize;

    unsafe {
        asm!(
        "mv a3, {trap_st}
        csrrw {tvec}, mtvec, {tvec} 
        csrrs {status}, mstatus, {mprv}
        lhu {inst}, ({epc})
        andi a4, {inst}, 3
        addi a4, a4, -3
        bne a4, zero, 2f
        lhu a4, 2({epc})
        sll a4, a4, 16
        add {inst}, {inst}, a4
        2: csrw mstatus, {status}
        csrw mtvec, {tvec}",
        trap_st = in(reg) &trap_state,
        tvec = inout(reg) mtvec,
        status = inout(reg) mstatus,
        mprv = in(reg) mprv_bits,
        inst = inout(reg) instr,
        epc = in(reg) mepc,
        out("a3") _,
        out("a4") _,
        );
    }
    
    //println!("Done reading instr: {:x}", instr);  

    if trap_state.cause != 0 {
        panic!("Misaligned store handler: Fetch fault {:x}", trap_state.cause);
    }

    if (instr & 0x3) != 0x3 {
        instr_len = 2;
    } else {
        instr_len = 4;
    }

    let mut value: usize = get_rs2(instr, reg_state);
    //println!("Misaligned store val: {:x}", value);

    let mut len: usize = 0;
    if (instr & 0x707f) == 0x2023 { //Matching insn_match_sw
        len = 4;
    } else if (instr & 0xe003) == 0xc000 {  //Matching insn_match_c_sd
        len = 4;
        value = 8 + ((instr >> 2) & ((1 << 3) - 1)); //get rs2s 
        //Again a bit of repetition - need to modularise get rs1/rs2/rs2s. 
        let reg_offset = value & 0x1f;
        let reg_state_ptr = reg_state as *mut RegisterState as *const u64;
        unsafe {
            let reg_ptr = reg_state_ptr.offset(reg_offset as isize);
            value = *reg_ptr as usize;
        }
    } else {
        panic!("Cannot handle this misaligned store! mtval: {:x} mepc: {:x} instr: {:x}", mtval, mepc, instr);
    }

    //set value ...... 
    mstatus = 0;
    mtvec = sbi_expected_trap as *const ();
    for i in 0..len {
        let store_address = mtval + i;
        let tmp_value: u8 = (value & 0xff) as u8;
        value = value >> 8;
        let mut store_trap_state: TrapState = TrapState { epc: 0, cause: 0, tval: 0 }; 
        unsafe {
           asm!(
            "mv a3, {trap_st}
            csrrw {tvec}, mtvec, {tvec} 
            csrrs {status}, mstatus, {mprv} 
            .option push
            .option norvc
            sb {val}, 0({addr})
            .option pop
            csrw mstatus, {status}
            csrw mtvec, {tvec}
            ",
            trap_st = in(reg) &store_trap_state,
            tvec = inout(reg) mtvec,
            status = inout(reg) mstatus,
            mprv = in(reg) mprv_bits,
            val = in(reg) tmp_value,
            addr = in(reg) store_address,
            out("a3") _,
            out("a4") _,
            );
        }

        if store_trap_state.cause != 0 {
            panic!("Misaligned store handler: Store fault {:x}", store_trap_state.cause);  
        }
    } 

    //println!("Done storing value: {:x} and instr_len : {}", value, instr_len);

    unsafe {
        asm!("csrr t0, mepc");
        asm!("add t0, t0, {}", in(reg) instr_len);
        asm!("csrw mepc, t0");
    }
}

#[repr(align(4))]
#[naked]
pub extern "C" fn sbi_expected_trap() {
    unsafe { 
        asm!(
        "csrr a4, mepc
        sd a4, 0*8(a3)
        csrr a4, mcause 
        sd a4, 1*8(a3)
        csrr a4, mtval
        sd a4, 2*8(a3)
        csrr a4, mepc
        addi a4, a4, 4
        csrw mepc, a4
        mret",
        options(noreturn));
    }
}

pub fn tyche_call_handler(reg_state: &mut RegisterState) {
    if reg_state.a7 == 0x5479636865 {
        //It's a Tyche Call
        let tyche_call: usize = reg_state.a0.try_into().unwrap();
        let arg_1: usize = reg_state.a1.try_into().unwrap();
        let arg_2: usize = reg_state.a2;
        let arg_3: usize = reg_state.a3;
        let arg_4: usize = reg_state.a4;
        let arg_5: usize = reg_state.a5;
        let arg_6: usize = reg_state.a6;

        let mut active_dom: Handle<Domain>;
        let hartid = cpuid();
        active_dom = get_active_dom(hartid).unwrap();

        match tyche_call {
            calls::CREATE_DOMAIN => {
                log::info!("Create Domain");
                let capa = monitor::do_create_domain(active_dom).expect("TODO");
                reg_state.a0 = 0x0;
                reg_state.a1 = capa.as_usize() as isize;
                //TODO: Ok(HandlerResult::Resume) There is no main loop to check what happened
                //here, do we need a wrapper to determine when we crash? For all cases except Exit,
                //not yet. Must be handled after addition of more exception handling in Tyche.
            }
            calls::SEAL_DOMAIN => {
                log::info!("Seal Domain");
                let capa = monitor::do_seal(active_dom, LocalCapa::new(arg_1)).expect("TODO");
                reg_state.a0 = 0x0;
                reg_state.a1 = capa.as_usize() as isize;
            }
            calls::SEND => {
                log::info!("Send");
                monitor::do_send(active_dom, LocalCapa::new(arg_1), LocalCapa::new(arg_2))
                    .expect("TODO");
                reg_state.a0 = 0x0;
            }
            calls::SEGMENT_REGION => {
                log::info!("Segment Region");
                let (to_send, to_revoke) = monitor::do_segment_region(
                    active_dom,
                    LocalCapa::new(arg_1),
                    arg_2 != 0, // is_shared
                    arg_3,      // start
                    arg_4,      // end
                    arg_5,      // prot
                )
                .expect("TODO");
                reg_state.a0 = 0x0;
                reg_state.a1 = to_send.as_usize() as isize;
                reg_state.a2 = to_revoke.as_usize();
            }
            // There are no aliases on riscv so we just ignore the alias info.
            calls::REVOKE | calls::REVOKE_ALIASED_REGION => {
                log::info!("Revoke");
                monitor::do_revoke(active_dom, LocalCapa::new(arg_1)).expect("TODO");
                reg_state.a0 = 0x0;
            }
            calls::DUPLICATE => {
                log::info!("Duplicate");
                let capa = monitor::do_duplicate(active_dom, LocalCapa::new(arg_1)).expect("TODO");
                reg_state.a0 = 0x0;
                reg_state.a1 = capa.as_usize() as isize;
            }
            calls::ENUMERATE => {
                log::info!("Enumerate");
                if let Some((info, next)) =
                    monitor::do_enumerate(active_dom, NextCapaToken::from_usize(arg_1))
                {
                    let (v1, v2, v3) = info.serialize();
                    reg_state.a1 = v1 as isize;
                    reg_state.a2 = v2 as usize;
                    reg_state.a3 = v3 as usize;
                    reg_state.a4 = next.as_usize();
                } else {
                    // For now, this marks the end
                    reg_state.a4 = 0;
                }
                reg_state.a0 = 0x0;
            }
            calls::SWITCH => {
                log::info!("Switch");
                monitor::do_switch(active_dom, LocalCapa::new(arg_1), hartid, reg_state)
                    .expect("TODO");
            }
            calls::EXIT => {
                log::info!("Tyche Call: Exit");
                //TODO
                //let capa = monitor::.do_().expect("TODO");
                reg_state.a0 = 0x0;
            }
            calls::DEBUG => {
                log::info!("Debug");
                //monitor::do_debug();
                reg_state.a0 = 0x0;
            }
            calls::CONFIGURE => {
                log::info!("Configure");
                if let Ok(bitmap) = Bitmaps::from_usize(arg_1) {
                    match monitor::do_set_config(
                        active_dom,
                        LocalCapa::new(arg_2),
                        bitmap,
                        arg_3 as u64,
                    ) {
                        Ok(_) => {
                            //TODO: do_init_child_contexts is not yet implemented on RISC-V.
                            reg_state.a0 = 0x0;
                        }
                        Err(e) => {
                            log::error!("Configuration error: {:?}", e);
                            reg_state.a0 = 0x1;
                        }
                    }
                } else {
                    log::error!("Invalid configuration target");
                    reg_state.a0 = 0x1;
                }
            }
            calls::SEND_REGION => {
                log::info!("Send");
                monitor::do_send_region(active_dom, LocalCapa::new(arg_1), LocalCapa::new(arg_2))
                    .expect("TODO");
                reg_state.a0 = 0x0;
            }
            calls::CONFIGURE_CORE => {
                log::info!("Configure Core");
                let res = match monitor::do_configure_core(
                    active_dom,
                    LocalCapa::new(arg_1),
                    arg_2,
                    arg_3,
                    arg_4,
                ) {
                    Ok(()) => 0,
                    Err(e) => {
                        log::error!("Configure core error: {:?}", e);
                        1
                    }
                };
                reg_state.a0 = res;
            }
            calls::GET_CONFIG_CORE => {
                let (value, success) = match monitor::do_get_config_core(
                    active_dom,
                    LocalCapa::new(arg_1),
                    arg_2,
                    arg_3,
                ) {
                    Ok(v) => (v, 0),
                    Err(e) => {
                        log::error!("Get config core error: {:?}", e);
                        (0, 1)
                    }
                };
                reg_state.a0 = success;
                reg_state.a1 = value as isize;
            }
            calls::ALLOC_CORE_CONTEXT => {
                log::info!("Alloc core context");
                let res = match monitor::do_init_child_context(
                    active_dom,
                    LocalCapa::new(arg_1),
                    arg_2,
                ) {
                    Ok(_) => 0,
                    Err(e) => {
                        log::error!("Allocating core context error: {:?}", e);
                        1
                    }
                };
                reg_state.a0 = res;
            }
            calls::READ_ALL_GP => {
                todo!("Implement read all gp");
            }
            calls::WRITE_ALL_GP => {
                todo!("Implement write all gp");
            }
            calls::WRITE_FIELDS => {
                log::info!("Write fields");
                let res = match monitor::do_set_field(
                    active_dom,
                    LocalCapa::new(arg_1),
                    arg_2,
                    arg_3,
                    arg_4,
                ) {
                    Ok(_) => 0,
                    Err(e) => {
                        log::error!("Error writing field {:?}: {:x}", e, arg_3);
                        1
                    }
                };
                reg_state.a0 = res;
            }
            calls::SELF_CONFIG => {
                todo!("Implement that one only if needed.");
            }
            calls::ENCLAVE_ATTESTATION => {
                log::trace!("Get attestation!");
                if let Some(report) = monitor::do_domain_attestation(active_dom, arg_1, arg_2) {
                    reg_state.a0 = 0;
                    if arg_2 == 0 {
                        reg_state.a1 = usize::from_le_bytes(
                            report.public_key.as_slice()[0..8].try_into().unwrap(),
                        ) as isize;
                        reg_state.a2 = usize::from_le_bytes(
                            report.public_key.as_slice()[8..16].try_into().unwrap(),
                        );
                        reg_state.a3 = usize::from_le_bytes(
                            report.public_key.as_slice()[16..24].try_into().unwrap(),
                        ) as usize;
                        reg_state.a4 = usize::from_le_bytes(
                            report.public_key.as_slice()[24..32].try_into().unwrap(),
                        ) as usize;
                        reg_state.a5 = usize::from_le_bytes(
                            report.signed_enclave_data.as_slice()[0..8]
                                .try_into()
                                .unwrap(),
                        ) as usize;
                        reg_state.a6 = usize::from_le_bytes(
                            report.signed_enclave_data.as_slice()[8..16]
                                .try_into()
                                .unwrap(),
                        ) as usize;
                    } else if arg_2 == 1 {
                        reg_state.a1 = usize::from_le_bytes(
                            report.signed_enclave_data.as_slice()[16..24]
                                .try_into()
                                .unwrap(),
                        ) as isize;
                        reg_state.a2 = usize::from_le_bytes(
                            report.signed_enclave_data.as_slice()[24..32]
                                .try_into()
                                .unwrap(),
                        );
                        reg_state.a3 = usize::from_le_bytes(
                            report.signed_enclave_data.as_slice()[32..40]
                                .try_into()
                                .unwrap(),
                        );
                        reg_state.a4 = usize::from_le_bytes(
                            report.signed_enclave_data.as_slice()[40..48]
                                .try_into()
                                .unwrap(),
                        );
                        reg_state.a5 = usize::from_le_bytes(
                            report.signed_enclave_data.as_slice()[48..56]
                                .try_into()
                                .unwrap(),
                        );
                        reg_state.a6 = usize::from_le_bytes(
                            report.signed_enclave_data.as_slice()[56..64]
                                .try_into()
                                .unwrap(),
                        );
                    }
                } else {
                    log::trace!("Attestation error");
                    reg_state.a0 = 1;
                }
            }
            _ => {
                /*TODO: Invalid Tyche Call*/
                log::info!("Invalid Tyche Call: {:x}", reg_state.a0);
                todo!("Unknown Tyche Call.");
            }
        }
        monitor::apply_core_updates(&mut active_dom, hartid, reg_state);
        //Updating the state
        set_active_dom(hartid, active_dom);
    }
    //TODO: ELSE NOT TYCHE CALL
    //Handle Illegal Instruction Trap
}

pub fn get_active_dom(hartid: usize) -> (Option<Handle<Domain>>) {
    return *ACTIVE_DOMAIN[hartid].lock();
}

pub fn set_active_dom(hartid: usize, domain: Handle<Domain>) {
    let mut active_domain = ACTIVE_DOMAIN[hartid].lock();
    *active_domain = Some(domain);
}
