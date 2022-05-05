//! Raw VMX operations
//!
//! This modules exposes low-level VMX functionalities. The functions here are marked as unsafe
//! because they do not verify the validity of input arguments or processor state. This module is
//! intended to be used through higher-level wrappers that provide more safety through typing.

use core::arch::asm;

use x86_64::registers::rflags::RFlags;

use super::errors::{VmxError, VmxInstructionError};
use super::fields;

/// Executes VMXON.
///
/// `addr` must be the physical address of a page-aligned region large enough to contain a VMXON
/// region.
pub unsafe fn vmxon(addr: u64) -> Result<(), VmxError> {
    asm!("vmxon ({0})", in(reg) &addr, options(att_syntax));
    vmx_capture_status()
}

/// Executes VMXOFF.
///
/// The processor must be in VMX operation mode, and will have exited that mode if the operation
/// succeeds.
pub unsafe fn vmxoff() -> Result<(), VmxError> {
    asm!("vmxoff");
    vmx_capture_status()
}

/// Executes VMCLEAR.
///
/// This will clear the VMCS at the provided physical address.
pub unsafe fn vmclear(addr: u64) -> Result<(), VmxError> {
    asm! {"vmclear ({0})", in(reg) &addr, options(att_syntax)};
    vmx_capture_status()
}

/// Executes VMWRITE.
///
/// This will write the value to the current VMCS in the provided field.
pub unsafe fn vmwrite(field: u64, value: u64) -> Result<(), VmxError> {
    asm!("vmwrite {1}, {0}", in(reg) field, in(reg) value, options(att_syntax));
    vmx_capture_status()
}

/// Executes VMREAD.
///
/// This will read a field from the current VMCS and return its value.
pub unsafe fn vmread(field: u64) -> Result<u64, VmxError> {
    let value: u64;
    asm!("vmread {0}, {1}", in(reg) field, out(reg) value, options(att_syntax));
    vmx_capture_status().and(Ok(value))
}

/// Executes VMPTRLD.
///
/// This loads a VMCS and mark it as active. All further VMWRITE and VMREAD operations will operate
/// on this VMCS until it is replaced.
pub unsafe fn vmptrld(addr: u64) -> Result<(), VmxError> {
    asm!("vmptrld ({0})", in(reg) &addr, options(att_syntax));
    vmx_capture_status()
}

/// Save host state and executes VMLAUNCH.
///
/// On success, this will switch to non-root mode and load guest state from current VMCS and return
/// the exit reason.
/// In addition to VMLAUNCH, this function save the minimal required state to resume execution
/// after VMLAUNCH: it saves ¨%rbp on the stack, compute an save suitable %rip and %rsp in the VMCS
/// to contiunue execution of the function afer VM Exit. On Vmexit,
pub unsafe fn vmlaunch() -> Result<(), VmxError> {
    let rip_field = fields::HostStateNat::Rip as u64;
    let rsp_field = fields::HostStateNat::Rsp as u64;
    asm!(
        "push rbp",                   // Save %rbp
        "vmwrite {rsp_field}, rsp",   // Write %rsp to VMCS
        "lea {tmp}, [rip + 6]",       // Compute the address of the next instruction after vmlaunch
        "vmwrite {rip_field}, {tmp}", // Write tha value to VMCS
        "vmlaunch",                   // Launch the VM
        "nop",                        // After VM Exit we land here
        "pop rbp",                    // Restore %rbp
        tmp = out(reg) _,
        rip_field = in(reg) rip_field,
        rsp_field = in(reg) rsp_field,
        // TODO: mark clobbered registers (all of general purpose ones)
    );
    // NOTE: it is correct to check the flag even after a nop and pop instructions since none of
    // them modifies any flags.
    vmx_capture_status()
}

/// Helper used to extract VMX-specific Result in accordance with
/// conventions described in Intel SDM, Volume 3C, Section 30.2.
//  We inline this to provide an obstruction-free path from this function's
//  call site to the moment where `rflags::read()` reads RFLAGS. Otherwise it's
//  possible for RFLAGS register to be clobbered by a function prologue,
//  see https://github.com/gz/rust-x86/pull/50.
#[inline(always)]
pub(crate) unsafe fn vmx_capture_status() -> Result<(), VmxError> {
    let flags = rflags_read();

    if flags.contains(RFlags::ZERO_FLAG) {
        // A valid VMCS is installed, we can read the error field
        let instr_err_field = fields::GuestState32Ro::VmInstructionError as u64;
        let err: u64;
        asm!("vmread {0}, {1}", in(reg) instr_err_field, out(reg) err, options(att_syntax));
        let flags = rflags_read();
        let error = if flags.intersects(RFlags::ZERO_FLAG | RFlags::CARRY_FLAG) {
            // An error occured during VMREAD
            VmxInstructionError::Unknown
        } else {
            VmxInstructionError::from_u64(err)
        };

        Err(VmxError::VmFailValid(error))
    } else if flags.contains(RFlags::CARRY_FLAG) {
        Err(VmxError::VmFailInvalid)
    } else {
        Ok(())
    }
}

/// Returns the current value of the RFLAGS register.
///
/// NOTE: We redefine this function here with an inline(always) hint so that it is always inlined
/// which prevent the flags from being clobbered by function calls.
#[inline(always)]
fn rflags_read() -> RFlags {
    let r: u64;

    unsafe {
        asm!("pushfq; pop {}", out(reg) r, options(nomem, preserves_flags));
    }
    RFlags::from_bits_truncate(r)
}
