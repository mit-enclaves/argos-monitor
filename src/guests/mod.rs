use crate::mmu::FrameAllocator;
use crate::println;
use crate::vmx;
use crate::vmx::bitmaps::exit_qualification;
use crate::vmx::bitmaps::{
    EntryControls, ExceptionBitmap, ExitControls, PinbasedControls, PrimaryControls,
    SecondaryControls,
};
use crate::vmx::errors::Trapnr;
use crate::vmx::fields;
use crate::vmx::fields::traits::*;
use crate::vmx::VmExitInterrupt;
use crate::vmx::{ActiveVmcs, ControlRegister, Register, VmcsRegion};
use x86_64::registers::model_specific::Efer;

use core::{arch, arch::asm};

pub mod boot_params;
pub mod elf;
pub mod elf_program;
pub mod identity;
pub mod linux;
pub mod rawc;

const ONEGB: usize = 1 << 30;
const ONEPAGE: usize = 1 << 12;

#[derive(PartialEq, Debug)]
pub enum HandlerResult {
    Resume,
    Exit,
    Crash,
}

pub trait Guest {
    unsafe fn instantiate<'vmx>(
        &self,
        vmxon: &'vmx vmx::Vmxon,
        allocator: &impl FrameAllocator,
    ) -> VmcsRegion<'vmx>;

    unsafe fn vmcall_handler(
        &self,
        vcpu: &mut vmx::ActiveVmcs,
    ) -> Result<HandlerResult, vmx::VmxError>;

    fn handle_exit(
        &self,
        vcpu: &mut vmx::ActiveVmcs,
        reason: vmx::VmxExitReason,
    ) -> Result<HandlerResult, vmx::VmxError> {
        match reason {
            vmx::VmxExitReason::Vmcall => unsafe { self.vmcall_handler(vcpu) },
            vmx::VmxExitReason::Cpuid => {
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
                        "mov rbx, {tmp}",
                        "cpuid",
                        "mov {tmp}, rbx",
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
            vmx::VmxExitReason::ControlRegisterAccesses => {
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
            vmx::VmxExitReason::EptViolation => {
                let addr = vcpu.guest_linear_addr()?;
                println!("EPT Violation: 0x{:x}", addr.as_u64());
                Ok(HandlerResult::Crash)
            }
            vmx::VmxExitReason::Xsetbv => {
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
            vmx::VmxExitReason::Wrmsr => {
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
            vmx::VmxExitReason::Exception => {
                let _value: u8 = Trapnr::InvalidOpcode.as_u8();
                match vcpu.interrupt_info() {
                    Ok(Some(VmExitInterrupt { vector: _value, .. })) => {
                        println!("Exception: {:?}", vcpu.interrupt_info());
                        // Clear the exception bitmap and let the guest handle it.
                        vcpu.set_exception_bitmap(ExceptionBitmap::empty())?;
                        return Ok(HandlerResult::Resume);
                    }
                    _ => {}
                }
                println!("VM received an exception");
                println!("{:?}", vcpu);
                Ok(HandlerResult::Crash)
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
}

fn configure_msr() -> Result<(), vmx::VmxError> {
    unsafe {
        fields::Ctrl32::VmExitMsrLoadCount.vmwrite(0)?;
        fields::Ctrl32::VmExitMsrStoreCount.vmwrite(0)?;
        fields::Ctrl32::VmEntryMsrLoadCount.vmwrite(0)?;
    }

    Ok(())
}

fn setup_guest(vcpu: &mut vmx::ActiveVmcs) -> Result<(), vmx::VmxError> {
    // Mostly copied from https://nixhacker.com/developing-hypervisor-from-scratch-part-4/

    // Control registers
    let cr0: usize;
    let cr3: usize;
    let cr4: usize;
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        vcpu.set_nat(fields::GuestStateNat::Cr0, cr0)?;
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        vcpu.set_nat(fields::GuestStateNat::Cr3, cr3)?;
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        vcpu.set_nat(fields::GuestStateNat::Cr4, cr4)?;
    }

    // Segments selectors
    let es: u16;
    let cs: u16;
    let ss: u16;
    let ds: u16;
    let fs: u16;
    let gs: u16;
    let tr: u16;
    unsafe {
        asm!("mov {:x}, es", out(reg) es, options(nomem, nostack, preserves_flags));
        vcpu.set16(fields::GuestState16::EsSelector, es)?;
        asm!("mov {:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags));
        vcpu.set16(fields::GuestState16::CsSelector, cs)?;
        asm!("mov {:x}, ss", out(reg) ss, options(nomem, nostack, preserves_flags));
        vcpu.set16(fields::GuestState16::SsSelector, ss)?;
        asm!("mov {:x}, ds", out(reg) ds, options(nomem, nostack, preserves_flags));
        vcpu.set16(fields::GuestState16::DsSelector, ds)?;
        asm!("mov {:x}, fs", out(reg) fs, options(nomem, nostack, preserves_flags));
        vcpu.set16(fields::GuestState16::FsSelector, fs)?;
        asm!("mov {:x}, gs", out(reg) gs, options(nomem, nostack, preserves_flags));
        vcpu.set16(fields::GuestState16::GsSelector, gs)?;
        asm!("str {:x}", out(reg) tr, options(nostack, preserves_flags));
        vcpu.set16(fields::GuestState16::TrSelector, tr)?;
        vcpu.set16(fields::GuestState16::LdtrSelector, 0)?;
    }
    vcpu.set32(fields::GuestState32::EsAccessRights, 0xC093)?;
    vcpu.set32(fields::GuestState32::CsAccessRights, 0xA09B)?;
    vcpu.set32(fields::GuestState32::SsAccessRights, 0x10000)?;
    vcpu.set32(fields::GuestState32::DsAccessRights, 0xC093)?;
    vcpu.set32(fields::GuestState32::FsAccessRights, 0x10000)?;
    vcpu.set32(fields::GuestState32::GsAccessRights, 0x10000)?;
    vcpu.set32(fields::GuestState32::LdtrAccessRights, 0x10000)?;
    vcpu.set32(fields::GuestState32::TrAccessRights, 0x8B)?;

    let limit = 0xFFFF;
    vcpu.set32(fields::GuestState32::EsLimit, limit)?;
    vcpu.set32(fields::GuestState32::CsLimit, limit)?;
    vcpu.set32(fields::GuestState32::SsLimit, limit)?;
    vcpu.set32(fields::GuestState32::DsLimit, limit)?;
    vcpu.set32(fields::GuestState32::FsLimit, limit)?;
    vcpu.set32(fields::GuestState32::GsLimit, limit)?;
    vcpu.set32(fields::GuestState32::LdtrLimit, limit)?;
    vcpu.set32(fields::GuestState32::TrLimit, 0xff)?; // At least 0x67
    vcpu.set32(fields::GuestState32::GdtrLimit, 0xffff)?;
    vcpu.set32(fields::GuestState32::IdtrLimit, 0xffff)?;

    unsafe {
        vcpu.set_nat(fields::GuestStateNat::EsBase, 0)?;
        vcpu.set_nat(fields::GuestStateNat::CsBase, 0)?;
        vcpu.set_nat(fields::GuestStateNat::SsBase, 0)?;
        vcpu.set_nat(fields::GuestStateNat::DsBase, 0)?;
        vcpu.set_nat(fields::GuestStateNat::FsBase, 0)?;
        vcpu.set_nat(fields::GuestStateNat::GsBase, 0)?;
        vcpu.set_nat(fields::GuestStateNat::LdtrBase, 0)?;
        vcpu.set_nat(
            fields::GuestStateNat::TrBase,
            fields::HostStateNat::TrBase.vmread()?,
        )?;
        vcpu.set_nat(
            fields::GuestStateNat::GdtrBase,
            fields::HostStateNat::GdtrBase.vmread()?,
        )?;
        vcpu.set_nat(
            fields::GuestStateNat::IdtrBase,
            fields::HostStateNat::IdtrBase.vmread()?,
        )?;

        // MSRs
        vcpu.set_nat(
            fields::GuestStateNat::Ia32SysenterEsp,
            fields::HostStateNat::Ia32SysenterEsp.vmread()?,
        )?;
        vcpu.set_nat(
            fields::GuestStateNat::Ia32SysenterEip,
            fields::HostStateNat::Ia32SysenterEip.vmread()?,
        )?;
        vcpu.set32(
            fields::GuestState32::Ia32SysenterCs,
            fields::HostState32::Ia32SysenterCs.vmread()?,
        )?;

        if fields::GuestState64::Ia32Efer.is_unsupported() {
            println!("Ia32Efer field is not supported");
        }
        // vcpu.set64(fields::GuestState64::Ia32Pat, fields::HostState64)
        // vcpu.set64(fields::GuestState64::Ia32Debugctl, 0)?;
        vcpu.set64(fields::GuestState64::Ia32Efer, Efer::read().bits())?;
        vcpu.set_nat(fields::GuestStateNat::Rflags, 0x2)?;
    }

    vcpu.set32(fields::GuestState32::ActivityState, 0)?;
    vcpu.set64(fields::GuestState64::VmcsLinkPtr, u64::max_value())?;
    vcpu.set16(fields::GuestState16::InterruptStatus, 0)?;
    // vcpu.set16(fields::GuestState16::PmlIndex, 0)?; // <- Not supported on dev server
    vcpu.set32(fields::GuestState32::VmxPreemptionTimerValue, 0)?;

    Ok(())
}

/// Returns optional secondary controls depending on the host cpuid.
fn cpuid_secondary_controls() -> SecondaryControls {
    let mut controls = SecondaryControls::empty();
    let cpuid = unsafe { arch::x86_64::__cpuid(7) };
    if cpuid.ebx & vmx::CPUID_EBX_X64_FEATURE_INVPCID != 0 {
        controls |= SecondaryControls::ENABLE_INVPCID;
    }
    return controls;
}

fn default_vmcs_config(vmcs: &mut ActiveVmcs, switching: bool) {
    // Look for XSAVES capabilities
    let capabilities =
        vmx::secondary_controls_capabilities().expect("Secondary controls are not supported");
    let xsaves = capabilities.contains(SecondaryControls::ENABLE_XSAVES_XRSTORS);

    let err = vmcs
        .set_pin_based_ctrls(PinbasedControls::empty())
        .and_then(|_| {
            vmcs.set_vm_exit_ctrls(
                ExitControls::HOST_ADDRESS_SPACE_SIZE
                    | ExitControls::LOAD_IA32_EFER
                    | ExitControls::SAVE_IA32_EFER,
            )
        })
        .and_then(|_| {
            vmcs.set_vm_entry_ctrls(EntryControls::IA32E_MODE_GUEST | EntryControls::LOAD_IA32_EFER)
        })
        .and_then(|_| vmcs.set_exception_bitmap(ExceptionBitmap::INVALID_OPCODE))
        .and_then(|_| vmcs.save_host_state())
        .and_then(|_| setup_guest(vmcs));
    println!("Config: {:?}", err);
    println!("MSRs:   {:?}", configure_msr());
    println!(
        "1'Ctrl: {:?}",
        vmcs.set_primary_ctrls(
            PrimaryControls::SECONDARY_CONTROLS | PrimaryControls::USE_MSR_BITMAPS
        )
    );

    let mut secondary_ctrls = SecondaryControls::ENABLE_RDTSCP | SecondaryControls::ENABLE_EPT;
    if switching {
        secondary_ctrls |= SecondaryControls::ENABLE_VM_FUNCTIONS
    }
    if xsaves {
        secondary_ctrls |= SecondaryControls::ENABLE_XSAVES_XRSTORS;
    }
    secondary_ctrls |= cpuid_secondary_controls();
    println!("2'Ctrl: {:?}", vmcs.set_secondary_ctrls(secondary_ctrls));
}
