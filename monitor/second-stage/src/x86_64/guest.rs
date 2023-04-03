//! VMX guest backend

use core::arch::asm;
use core::cell::RefMut;

use capabilities::cpu::CPU;
//use mmu::eptmapper::EPT_ROOT_FLAGS;
//use mmu::{EptMapper, FrameAllocator};
use monitor::tyche::Tyche;
use monitor::{Monitor, MonitorState, Parameters};
//use qemu::_print;
//use utils::HostPhysAddr;
use vmx::bitmaps::exit_qualification;
use vmx::{ActiveVmcs, ControlRegister, Register, VmxExitReason};

use super::backend::BackendX86;
use crate::error::TycheError;
use crate::println;
use crate::x86_64::get_state;

pub struct GuestX86<'a> {
    pub state: MonitorState<'a, BackendX86>,
    pub monitor: Tyche,
}

static MONITOR: Tyche = Tyche {};

#[derive(PartialEq, Debug)]
pub enum HandlerResult {
    Resume,
    Exit,
    Crash,
}

pub fn main_loop() {
    let mut result = launch();
    loop {
        let exit_reason = match result {
            Ok(exit_reason) => handle_exit(exit_reason).expect("Failed to handle VM exit"),
            Err(err) => {
                println!("Guest crash: {:?}", err);
                HandlerResult::Crash
            }
        };

        if exit_reason != HandlerResult::Resume {
            println!("Exiting guest: {:?}", exit_reason);
            break;
        }
        // Resume VM
        result = resume();
    }
}

pub fn new<'active>(s: MonitorState<'active, BackendX86>) -> GuestX86<'active> {
    GuestX86 {
        state: s,
        monitor: Tyche {},
    }
}

pub fn get_local_cpu<'a>(state: &'a MonitorState<'a, BackendX86>) -> RefMut<CPU<BackendX86>> {
    let current = state.get_current_cpu();
    state.resources.pools.cpus.get_mut(current.handle)
}

fn launch() -> Result<vmx::VmxExitReason, TycheError> {
    let state = get_state();
    let mut cpu = get_local_cpu(&state);
    let vcpu = cpu.core.get_active_mut()?;
    unsafe {
        let exit_reason = vcpu.launch()?;
        Ok(exit_reason)
    }
}

fn resume() -> Result<vmx::VmxExitReason, TycheError> {
    let state = get_state();
    let mut cpu = get_local_cpu(&state);
    let vcpu = cpu.core.get_active_mut()?;
    unsafe {
        let exit_reason = vcpu.resume()?;
        Ok(exit_reason)
    }
}

fn handle_exit(reason: vmx::VmxExitReason) -> Result<HandlerResult, TycheError> {
    let dump = |vcpu: &mut ActiveVmcs| {
        let rip = vcpu.get(Register::Rip);
        let rax = vcpu.get(Register::Rax);
        let rcx = vcpu.get(Register::Rcx);
        let rbp = vcpu.get(Register::Rbp);
        println!(
            "VM Exit: {:?} - rip: 0x{:x} - rbp: 0x{:x} - rax: 0x{:x} - rcx: 0x{:x}",
            reason, rip, rbp, rax, rcx
        );
    };

    let mut state = get_state();

    match reason {
        VmxExitReason::Vmcall => {
            let mut cpu = get_local_cpu(&state);
            let vcpu = cpu.core.get_active_mut()?;
            let params = Parameters {
                vmcall: vcpu.get(Register::Rax) as usize,
                arg_1: vcpu.get(Register::Rdi) as usize,
                arg_2: vcpu.get(Register::Rsi) as usize,
                arg_3: vcpu.get(Register::Rdx) as usize,
                arg_4: vcpu.get(Register::Rcx) as usize,
                arg_5: vcpu.get(Register::R8) as usize,
                arg_6: vcpu.get(Register::R9) as usize,
                arg_7: vcpu.get(Register::R10) as usize,
            };
            drop(vcpu);
            drop(cpu);
            if MONITOR.is_exit(&state, &params) {
                let mut cpu = get_local_cpu(&state);
                let mut vcpu = cpu.core.get_active_mut()?;
                dump(&mut vcpu);
                Ok(HandlerResult::Exit)
            } else {
                let advance = match MONITOR.dispatch(&mut state, &params) {
                    Ok(values) => {
                        let mut cpu = get_local_cpu(&state);
                        let vcpu = cpu.core.get_active_mut()?;
                        vcpu.set(Register::Rax, 0);
                        vcpu.set(Register::Rdi, values.value_1 as u64);
                        vcpu.set(Register::Rsi, values.value_2 as u64);
                        vcpu.set(Register::Rdx, values.value_3 as u64);
                        vcpu.set(Register::Rcx, values.value_4 as u64);
                        vcpu.set(Register::R8, values.value_5 as u64);
                        vcpu.set(Register::R9, values.value_6 as u64);
                        values.next_instr
                    }
                    Err(err) => {
                        let mut cpu = get_local_cpu(&state);
                        let mut vcpu = cpu.core.get_active_mut()?;
                        dump(&mut vcpu);
                        println!("The error: {:?}", err);
                        match err {
                            capabilities::error::Error::Capability(code) => {
                                vcpu.set(Register::Rax, code as u64);
                            }
                            capabilities::error::Error::Backend(_) => panic!("Backend error"),
                        };
                        true
                    }
                };
                if advance {
                    let mut cpu = get_local_cpu(&state);
                    let vcpu = cpu.core.get_active_mut()?;
                    vcpu.next_instruction()?;
                }
                Ok(HandlerResult::Resume)
            }
        }
        VmxExitReason::Cpuid => {
            let mut cpu = get_local_cpu(&state);
            let vcpu = cpu.core.get_active_mut()?;
            let input_eax = vcpu.get(Register::Rax);
            let input_ecx = vcpu.get(Register::Rcx);
            let eax: u64;
            let ebx: u64;
            let ecx: u64;
            let edx: u64;

            unsafe {
                // Note: LLVM reserves %rbx for its internal use, so we need to use a scratch
                // register for %rbx here.
                asm!(
                    "mov {tmp}, rbx",
                    "cpuid",
                    "mov rbx, {tmp}",
                    tmp = out(reg) ebx ,
                    inout("rax") input_eax => eax,
                    inout("rcx") input_ecx => ecx,
                    out("rdx") edx,
                )
            }
            vcpu.set(Register::Rax, eax);
            vcpu.set(Register::Rbx, ebx);
            vcpu.set(Register::Rcx, ecx);
            vcpu.set(Register::Rdx, edx);
            vcpu.next_instruction()?;
            Ok(HandlerResult::Resume)
        }
        VmxExitReason::ControlRegisterAccesses => {
            let mut cpu = get_local_cpu(&state);
            let vcpu = cpu.core.get_active_mut()?;
            let qualification = vcpu.exit_qualification()?.control_register_accesses();
            match qualification {
                exit_qualification::ControlRegisterAccesses::MovToCr(cr, reg) => {
                    if cr != ControlRegister::Cr4 {
                        todo!("Handle {:?}", cr);
                    }
                    let value = vcpu.get(reg) as usize;
                    vcpu.set_cr4_shadow(value)?;
                    let real_value = value | (1 << 13); // VMXE
                    vcpu.set_cr(cr, real_value);

                    vcpu.next_instruction()?;
                }
                _ => todo!("Emulation not yet implemented for {:?}", qualification),
            };
            Ok(HandlerResult::Resume)
        }
        VmxExitReason::EptViolation => {
            let mut cpu = get_local_cpu(&state);
            let vcpu = cpu.core.get_active_mut()?;
            let addr = vcpu.guest_phys_addr()?;
            println!(
                "EPT Violation! virt: 0x{:x}, phys: 0x{:x}",
                vcpu.guest_linear_addr()
                    .expect("unable to get the virt addr")
                    .as_u64(),
                addr.as_u64(),
            );
            println!("The vcpu {:x?}", vcpu);
            Ok(HandlerResult::Crash)
        }
        VmxExitReason::Xsetbv => {
            let mut cpu = get_local_cpu(&state);
            let vcpu = cpu.core.get_active_mut()?;
            let ecx = vcpu.get(Register::Rcx);
            let eax = vcpu.get(Register::Rax);
            let edx = vcpu.get(Register::Rdx);

            let xrc_id = ecx & 0xFFFFFFFF; // Ignore 32 high-order bits
            if xrc_id != 0 {
                println!("Xsetbv: invalid rcx 0x{:x}", ecx);
                return Ok(HandlerResult::Crash);
            }

            unsafe {
                asm!(
                    "xsetbv",
                    in("ecx") ecx,
                    in("eax") eax,
                    in("edx") edx,
                );
            }

            vcpu.next_instruction()?;
            Ok(HandlerResult::Resume)
        }
        VmxExitReason::Wrmsr => {
            let mut cpu = get_local_cpu(&state);
            let vcpu = cpu.core.get_active_mut()?;
            let ecx = vcpu.get(Register::Rcx);
            if ecx >= 0x4B564D00 && ecx <= 0x4B564DFF {
                // Custom MSR range, used by KVM
                // See https://docs.kernel.org/virt/kvm/x86/msr.html
                // TODO: just ignore them for now, should add support in the future
                vcpu.next_instruction()?;
                Ok(HandlerResult::Resume)
            } else {
                println!("Unknown MSR: 0x{:x}", ecx);
                Ok(HandlerResult::Crash)
            }
        }
        VmxExitReason::Rdmsr => {
            let mut cpu = get_local_cpu(&state);
            let vcpu = cpu.core.get_active_mut()?;
            let ecx = vcpu.get(Register::Rcx);
            if ecx == 0xc0011029 {
                // Reading an AMD specifig register, just ignore it
                vcpu.next_instruction()?;
                Ok(HandlerResult::Resume)
            } else {
                println!("Unexpected rdmsr number: {:#x}", ecx);
                Ok(HandlerResult::Crash)
            }
        }
        VmxExitReason::Exception => {
            let mut cpu = get_local_cpu(&state);
            let vcpu = cpu.core.get_active_mut()?;
            match vcpu.interrupt_info() {
                Ok(Some(exit)) => {
                    println!("Exception: {:?}", vcpu.interrupt_info());
                    dump(vcpu);
                    // Inject the fault back into the guest.
                    let injection = exit.as_injectable_u32();
                    vcpu.set_vm_entry_interruption_information(injection)?;
                    Ok(HandlerResult::Resume)
                }
                _ => {
                    println!("VM received an exception");
                    println!("{:?}", vcpu);
                    Ok(HandlerResult::Crash)
                }
            }
        }
        _ => {
            println!(
                "Emulation is not yet implemented for exit reason: {:?}",
                reason
            );
            let cpu = get_local_cpu(&state);
            let vcpu = cpu.core.get_active()?;
            println!("{:?}", vcpu);
            Ok(HandlerResult::Crash)
        }
    }
}
