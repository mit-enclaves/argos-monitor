//! VMX guest backend

use core::arch::asm;
use core::cell::RefMut;

use capabilities::cpu::CPU;
use monitor::{MonitorState, Parameters};
use vmx::bitmaps::exit_qualification;
use vmx::{ActiveVmcs, ControlRegister, Register, VmxExitReason};

use super::backend::BackendX86;
use crate::error::TycheError;
use crate::{calls, println};

#[derive(PartialEq, Debug)]
pub enum HandlerResult {
    Resume,
    Exit,
    Crash,
}

pub fn main_loop(mut vcpu: ActiveVmcs<'static>) {
    let mut result = unsafe { vcpu.launch() };
    loop {
        let exit_reason = match result {
            Ok(exit_reason) => {
                handle_exit(&mut vcpu, exit_reason).expect("Failed to handle VM exit")
            }
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
        result = unsafe { vcpu.resume() };
    }
}

pub fn get_local_cpu<'a>(state: &'a MonitorState<'a, BackendX86>) -> RefMut<CPU<BackendX86>> {
    let current = state.get_current_cpu();
    state.resources.pools.cpus.get_mut(current.handle)
}

fn handle_exit(
    vcpu: &mut ActiveVmcs<'static>,
    reason: vmx::VmxExitReason,
) -> Result<HandlerResult, TycheError> {
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

    match reason {
        VmxExitReason::Vmcall => {
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
            match params.vmcall {
                calls::CREATE_DOMAIN => {
                    println!("Create Domain");
                    vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::SEAL_DOMAIN => {
                    println!("Seal Domain");
                    vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::SHARE => {
                    println!("Share");
                    vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::GRANT => {
                    println!("Grant");
                    vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::GIVE => {
                    println!("Give");
                    vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::REVOKE => {
                    println!("Revoke");
                    vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::DUPLICATE => {
                    println!("Duplicate");
                    vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::ENUMERATE => {
                    println!("Enumerate");
                    vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::SWITCH => {
                    println!("Switch");
                    vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::EXIT => {
                    dump(vcpu);
                    Ok(HandlerResult::Exit)
                }
                _ => {
                    println!("VMCall: 0x{:x}", params.vmcall);
                    todo!("Unknown VMCall");
                }
            }
        }
        VmxExitReason::Cpuid => {
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
                    "mov {rbx_out}, rbx",
                    "mov rbx, {tmp}",
                    tmp = out(reg) _,
                    rbx_out = out(reg) ebx,
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
            println!("{:?}", vcpu);
            Ok(HandlerResult::Crash)
        }
    }
}
