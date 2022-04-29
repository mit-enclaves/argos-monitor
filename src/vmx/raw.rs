//! Raw VMX operations
//!
//! This modules exposes low-level VMX functionalities. The functions here are marked as unsafe
//! because they do not verify the validity of input arguments or processor state. This module is
//! intended to be used through higher-level wrappers that provide more safety through typing.

use core::arch::asm;

use x86_64::registers::rflags::RFlags;

use super::VmxError;

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

/// Executes VMPTRLD.
///
/// This loads a VMCS and mark it as active. All further VMWRITE and VMREAD operations will operate
/// on this VMCS until it is replaced.
pub unsafe fn vmptrld(addr: u64) -> Result<(), VmxError> {
    asm!("vmptrld ({0})", in(reg) &addr, options(att_syntax));
    vmx_capture_status()
}

/// Helper used to extract VMX-specific Result in accordance with
/// conventions described in Intel SDM, Volume 3C, Section 30.2.
//  We inline this to provide an obstruction-free path from this function's
//  call site to the moment where `rflags::read()` reads RFLAGS. Otherwise it's
//  possible for RFLAGS register to be clobbered by a function prologue,
//  see https://github.com/gz/rust-x86/pull/50.
#[inline(always)]
pub(crate) fn vmx_capture_status() -> Result<(), VmxError> {
    let flags = rflags_read();

    if flags.contains(RFlags::ZERO_FLAG) {
        Err(VmxError::VmFailValid)
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
