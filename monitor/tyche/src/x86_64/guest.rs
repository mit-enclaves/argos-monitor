//! VMX guest backend

use core::arch::asm;

use capa_engine::{Bitmaps, Domain, Handle, LocalCapa, NextCapaToken};
use vmx::bitmaps::exit_qualification;
use vmx::errors::Trapnr;
use vmx::fields::VmcsField;
use vmx::{ActiveVmcs, VmxExitReason, Vmxon};

use super::cpuid_filter::{filter_mpk, filter_tpause};
use super::{cpuid, monitor};
use crate::calls;
use crate::error::TycheError;

#[derive(PartialEq, Debug)]
pub enum HandlerResult {
    Resume,
    Exit,
    Crash,
}

/// VMXState encapsulates the vmxon and current vcpu.
/// The vcpu is subject to changes, but the vmxon remains the same
/// for the entire execution.
pub struct VmxState {
    pub vcpu: ActiveVmcs<'static>,
    pub vmxon: Vmxon,
}

pub fn main_loop(mut vmx_state: VmxState, mut domain: Handle<Domain>) {
    let core_id = cpuid();
    let mut result = unsafe { vmx_state.vcpu.run() };
    loop {
        let exit_reason = match result {
            Ok(exit_reason) => {
                let res = handle_exit(&mut vmx_state, exit_reason, &mut domain)
                    .expect("Failed to handle VM exit");

                // Apply core-local updates before returning
                monitor::apply_core_updates(&mut vmx_state, &mut domain, core_id);

                res
            }
            Err(err) => {
                log::error!("Guest crash: {:?}", err);
                log::error!("Vcpu: {:x?}", vmx_state.vcpu);
                HandlerResult::Crash
            }
        };

        match exit_reason {
            HandlerResult::Resume => {
                result = unsafe { vmx_state.vcpu.run() };
            }
            _ => {
                log::info!("Exiting guest: {:?}", exit_reason);
                break;
            }
        }
    }
}

fn handle_exit(
    vs: &mut VmxState,
    reason: vmx::VmxExitReason,
    domain: &mut Handle<Domain>,
) -> Result<HandlerResult, TycheError> {
    //let vcpu = &mut vmx_state.vcpu;
    let dump = |vcpu: &mut ActiveVmcs| {
        let rip = vcpu.get(VmcsField::GuestRip).unwrap();
        let rax = vcpu.get(VmcsField::GuestRax).unwrap();
        let rcx = vcpu.get(VmcsField::GuestRcx).unwrap();
        let rbp = vcpu.get(VmcsField::GuestRbp).unwrap();
        log::info!(
            "VM Exit: {:?} - rip: 0x{:x} - rbp: 0x{:x} - rax: 0x{:x} - rcx: 0x{:x}",
            reason,
            rip,
            rbp,
            rax,
            rcx
        );
    };

    match reason {
        VmxExitReason::Vmcall => {
            let vmcall = vs.vcpu.get(VmcsField::GuestRax)?;
            let arg_1 = vs.vcpu.get(VmcsField::GuestRdi)?;
            let arg_2 = vs.vcpu.get(VmcsField::GuestRsi)?;
            let arg_3 = vs.vcpu.get(VmcsField::GuestRdx)?;
            let arg_4 = vs.vcpu.get(VmcsField::GuestRcx)?;
            let arg_5 = vs.vcpu.get(VmcsField::GuestR8)?;
            let arg_6 = vs.vcpu.get(VmcsField::GuestR9)?;
            match vmcall {
                calls::CREATE_DOMAIN => {
                    log::trace!("Create Domain");
                    let capa = monitor::do_create_domain(*domain, arg_1 != 0).expect("TODO");
                    vs.vcpu.set(VmcsField::GuestRdi, capa.as_usize())?;
                    vs.vcpu.set(VmcsField::GuestRax, 0)?;
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::CONFIGURE => {
                    log::trace!("Configure");
                    if let Ok(bitmap) = Bitmaps::from_usize(arg_1) {
                        match monitor::do_set_config(
                            *domain,
                            LocalCapa::new(arg_2),
                            bitmap,
                            arg_3 as u64,
                        ) {
                            Ok(_) => {
                                vs.vcpu.set(VmcsField::GuestRax, 0)?;
                            }
                            Err(e) => {
                                log::error!("Configuration error: {:?}", e);
                                vs.vcpu.set(VmcsField::GuestRax, 1)?;
                            }
                        }
                    } else {
                        log::error!("Invalid configuration target");
                        vs.vcpu.set(VmcsField::GuestRax, 1)?;
                    }
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::ALLOC_CORE_CONTEXT => {
                    log::trace!("Alloc core context");
                    match monitor::do_init_child_context(
                        *domain,
                        LocalCapa::new(arg_1),
                        arg_2,
                        &mut vs.vcpu,
                        &vs.vmxon,
                    ) {
                        Ok(_) => {
                            vs.vcpu.set(VmcsField::GuestRax, 0)?;
                        }
                        Err(e) => {
                            log::error!("Allocating core context error: {:?}", e);
                            vs.vcpu.set(VmcsField::GuestRax, 1)?;
                        }
                    };
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::CONFIGURE_CORE => {
                    log::trace!("Configure Core");
                    match monitor::do_configure_core(
                        *domain,
                        LocalCapa::new(arg_1),
                        arg_2,
                        arg_3,
                        arg_4,
                        &mut vs.vcpu,
                    ) {
                        Ok(()) => vs.vcpu.set(VmcsField::GuestRax, 0)?,
                        Err(e) => {
                            log::error!("Configure core error: {:?}", e);
                            vs.vcpu.set(VmcsField::GuestRax, 1)?;
                        }
                    }
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::GET_CONFIG_CORE => {
                    match monitor::do_get_config_core(
                        *domain,
                        LocalCapa::new(arg_1),
                        arg_2,
                        arg_3,
                        &mut vs.vcpu,
                    ) {
                        Ok(v) => {
                            vs.vcpu.set(VmcsField::GuestRdi, v)?;
                            vs.vcpu.set(VmcsField::GuestRax, 0)?;
                        }
                        Err(e) => {
                            log::error!("Get config core error: {:?}", e);
                            vs.vcpu.set(VmcsField::GuestRax, 1)?;
                        }
                    }
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::SEAL_DOMAIN => {
                    log::trace!("Seal Domain");
                    let capa = monitor::do_seal(*domain, LocalCapa::new(arg_1)).expect("TODO");
                    vs.vcpu.set(VmcsField::GuestRdi, capa.as_usize())?;
                    vs.vcpu.set(VmcsField::GuestRax, 0)?;
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::SHARE => {
                    log::trace!("Share");
                    log::warn!("Share is NOT IMPLEMENTED in v3");
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::SEND => {
                    log::trace!("Send");
                    monitor::do_send(*domain, LocalCapa::new(arg_1), LocalCapa::new(arg_2))
                        .expect("TODO");
                    vs.vcpu.set(VmcsField::GuestRax, 0)?;
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::SEND_ALIASED => {
                    log::trace!("Send aliased");
                    // Send a region capa and adds an alias to it.
                    // TODO: check it works.
                    monitor::do_send_aliased(
                        *domain,
                        LocalCapa::new(arg_1),
                        LocalCapa::new(arg_2),
                        arg_3,
                    )
                    .expect("TODO");
                    vs.vcpu.set(VmcsField::GuestRax, 0)?;
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::SEGMENT_REGION => {
                    log::trace!("Segment region");
                    let (left, right) = monitor::do_segment_region(
                        *domain,
                        LocalCapa::new(arg_1),
                        arg_2,               // start
                        arg_3,               // end
                        arg_6 >> 32,         // prot1
                        arg_4,               // start
                        arg_5,               // end
                        (arg_6 << 32) >> 32, // prot2
                    )
                    .expect("TODO");
                    vs.vcpu.set(VmcsField::GuestRdi, left.as_usize())?;
                    vs.vcpu.set(VmcsField::GuestRsi, right.as_usize())?;
                    vs.vcpu.set(VmcsField::GuestRax, 0)?;
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::REVOKE => {
                    log::trace!("Revoke");
                    monitor::do_revoke(*domain, LocalCapa::new(arg_1)).expect("TODO");
                    vs.vcpu.set(VmcsField::GuestRax, 0)?;
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::DUPLICATE => {
                    log::trace!("Duplicate");
                    let capa = monitor::do_duplicate(*domain, LocalCapa::new(arg_1)).expect("TODO");
                    vs.vcpu.set(VmcsField::GuestRdi, capa.as_usize())?;
                    vs.vcpu.set(VmcsField::GuestRax, 0)?;
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::ENUMERATE => {
                    log::trace!("Enumerate");
                    if let Some((info, next)) =
                        monitor::do_enumerate(*domain, NextCapaToken::from_usize(arg_1))
                    {
                        let (v1, v2, v3) = info.serialize();
                        vs.vcpu.set(VmcsField::GuestRdi, v1)?;
                        vs.vcpu.set(VmcsField::GuestRsi, v2)?;
                        vs.vcpu.set(VmcsField::GuestRdx, v3 as usize)?;
                        vs.vcpu.set(VmcsField::GuestRcx, next.as_usize())?;
                    } else {
                        // For now, this marks the end
                        vs.vcpu.set(VmcsField::GuestRcx, 0)?;
                    }
                    vs.vcpu.set(VmcsField::GuestRax, 0)?;
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::SWITCH => {
                    log::trace!("Switch");
                    vs.vcpu.next_instruction()?;
                    monitor::do_switch(*domain, LocalCapa::new(arg_1), cpuid()).expect("TODO");
                    Ok(HandlerResult::Resume)
                }
                calls::DEBUG => {
                    log::trace!("Debug");
                    monitor::do_debug();
                    vs.vcpu.set(VmcsField::GuestRax, 0)?;
                    vs.vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                }
                calls::EXIT => {
                    log::info!("MonCall: exit");
                    dump(&mut vs.vcpu);
                    Ok(HandlerResult::Exit)
                }
                _ => {
                    log::info!("Unknown MonCall: 0x{:x}", vmcall);
                    todo!("Unknown VMCall");
                }
            }
        }
        VmxExitReason::Cpuid => {
            // TODO implement a filter for the cpuid.
            let input_eax = vs.vcpu.get(VmcsField::GuestRax)?;
            let input_ecx = vs.vcpu.get(VmcsField::GuestRcx)?;
            let mut eax: usize;
            let mut ebx: usize;
            let mut ecx: usize;
            let mut edx: usize;

            unsafe {
                // Note: LLVM reserves %rbx for its internal use, so we need to use a scratch
                // register for %rbx here.
                asm!(
                    "mov {tmp}, rbx",
                    "cpuid",
                    "mov rsi, rbx",
                    "mov rbx, {tmp}",
                    tmp = out(reg) _,
                    inout("rax") input_eax => eax,
                    inout("rcx") input_ecx => ecx,
                    out("rdx") edx,
                    out("rsi") ebx
                )
            }
            //Apply cpuid filters.
            filter_tpause(input_eax, input_ecx, &mut eax, &mut ebx, &mut ecx, &mut edx);
            filter_mpk(input_eax, input_ecx, &mut eax, &mut ebx, &mut ecx, &mut edx);

            vs.vcpu.set(VmcsField::GuestRax, eax as usize)?;
            vs.vcpu.set(VmcsField::GuestRbx, ebx as usize)?;
            vs.vcpu.set(VmcsField::GuestRcx, ecx as usize)?;
            vs.vcpu.set(VmcsField::GuestRdx, edx as usize)?;
            vs.vcpu.next_instruction()?;
            Ok(HandlerResult::Resume)
        }
        VmxExitReason::ControlRegisterAccesses if domain.idx() == 0 => {
            // Handle some of these only for dom0, the other domain's problems
            // are for now forwarded to the manager domain.
            let qualification = vs.vcpu.exit_qualification()?.control_register_accesses();
            match qualification {
                exit_qualification::ControlRegisterAccesses::MovToCr(cr, reg) => {
                    log::info!("MovToCr {:?} into {:?} on domain {:?}", reg, cr, *domain);
                    if !cr.is_guest_cr() {
                        log::error!("Invalid register: {:x?}", cr);
                        panic!("VmExit reason for access to control register is not a control register.");
                    }
                    if cr == VmcsField::GuestCr4 {
                        let value = vs.vcpu.get(reg)? as usize;
                        vs.vcpu.set(VmcsField::Cr4ReadShadow, value)?;
                        let real_value = value | (1 << 13); // VMXE
                        vs.vcpu.set(cr, real_value)?;
                    } else {
                        todo!("Handle cr: {:?}", cr);
                    }

                    vs.vcpu.next_instruction()?;
                }
                _ => todo!("Emulation not yet implemented for {:?}", qualification),
            };
            Ok(HandlerResult::Resume)
        }
        VmxExitReason::Xsetbv => {
            let ecx = vs.vcpu.get(VmcsField::GuestRcx)?;
            let eax = vs.vcpu.get(VmcsField::GuestRax)?;
            let edx = vs.vcpu.get(VmcsField::GuestRdx)?;

            let xrc_id = ecx & 0xFFFFFFFF; // Ignore 32 high-order bits
            if xrc_id != 0 {
                log::error!("Xsetbv: invalid rcx 0x{:x}", ecx);
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

            vs.vcpu.next_instruction()?;
            Ok(HandlerResult::Resume)
        }
        VmxExitReason::Wrmsr => {
            let ecx = vs.vcpu.get(VmcsField::GuestRcx)?;
            if ecx >= 0x4B564D00 && ecx <= 0x4B564DFF {
                // Custom MSR range, used by KVM
                // See https://docs.kernel.org/virt/kvm/x86/msr.html
                // TODO: just ignore them for now, should add support in the future
                vs.vcpu.next_instruction()?;
                Ok(HandlerResult::Resume)
            } else {
                log::error!("Unknown MSR: 0x{:x}", ecx);
                Ok(HandlerResult::Crash)
            }
        }
        VmxExitReason::Rdmsr => {
            let ecx = vs.vcpu.get(VmcsField::GuestRcx)?;
            log::trace!("rdmsr");
            if ecx == 0xc0011029 || (ecx >= 0xc0010200 && ecx <= 0xc001020b) {
                // Reading an AMD specific register, just ignore it
                // The other interval seems to be related to pmu...
                // TODO: figure this out and why it only works on certain hardware.
                vs.vcpu.next_instruction()?;
                Ok(HandlerResult::Resume)
            } else {
                let msr_reg = vmx::msr::Msr::new(ecx as u32);
                let (low, high) = unsafe { msr_reg.read_raw() };
                log::trace!("Emulated read of msr {:x} = h:{:x};l:{:x}", ecx, high, low);
                vs.vcpu.set(VmcsField::GuestRax, low as usize)?;
                vs.vcpu.set(VmcsField::GuestRdx, high as usize)?;
                vs.vcpu.next_instruction()?;
                Ok(HandlerResult::Resume)
            }
        }
        VmxExitReason::Exception => {
            match vs.vcpu.interrupt_info() {
                Ok(Some(exit)) => {
                    // The domain exited, so it shouldn't be able to handle it.
                    log::trace!(
                        "EXCEPTION RECEIVED {:b}, vector: {:?}, type: {:?}",
                        exit.as_u32(),
                        Trapnr::from_u8(exit.vector()),
                        exit.interrupt_type()
                    );
                    match monitor::handle_trap(*domain, cpuid(), exit) {
                        Ok(()) => {
                            log::debug!("Received exception {}, re-routing it", exit.vector());
                            Ok(HandlerResult::Resume)
                        }
                        Err(e) => {
                            log::error!(
                                "Unable to handle the exception {}, capa error:{:?}",
                                exit.vector(),
                                e
                            );
                            log::error!("{:?}", vs.vcpu);
                            Ok(HandlerResult::Crash)
                        }
                    }
                }
                _ => {
                    log::error!("VM received an exception");
                    log::info!("{:?}", vs.vcpu);
                    Ok(HandlerResult::Crash)
                }
            }
        }
        VmxExitReason::EptViolation
        | VmxExitReason::ExternalInterrupt
        | VmxExitReason::IoInstruction
        | VmxExitReason::ControlRegisterAccesses
        | VmxExitReason::TripleFault => {
            log::trace!("Handling {:?} for dom {}", reason, domain.idx());
            let addr = vs.vcpu.guest_phys_addr()?;
            // TODO(aghosn): for the moment, crash on EPT violations
            // on dom0. Later on, we should route them to the domain in a different
            // way.
            match monitor::do_handle_violation(*domain) {
                Ok(_) => {
                    return Ok(HandlerResult::Resume);
                }
                Err(e) => {
                    log::error!("Unable to handle {:?}: {:?}", reason, e);
                    if reason == VmxExitReason::EptViolation {
                        log::error!(
                            "Ept Violation! virt: 0x{:x}, phys: 0x{:x} on dom{}",
                            vs.vcpu
                                .guest_linear_addr()
                                .expect("Unable to get virt addr")
                                .as_u64(),
                            addr.as_u64(),
                            *domain
                        );
                    }
                    log::info!("The vcpu: {:x?}", vs.vcpu);
                    return Ok(HandlerResult::Crash);
                }
            }
        }
        _ => {
            log::error!(
                "Emulation is not yet implemented for exit reason: {:?}",
                reason
            );
            log::error!("This happened on domain {}", domain.idx());
            log::info!("{:?}", vs.vcpu);
            Ok(HandlerResult::Crash)
        }
    }
}
