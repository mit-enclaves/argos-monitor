//! VMX support

use core::arch;
use core::arch::asm;

use x86_64::registers::control::{Cr4, Cr4Flags};
use x86_64::registers::model_specific::Msr;
use x86_64::PhysAddr;

/// CPUID mask for VMX support
const CPUID_ECX_VMX_MASK: u32 = 1 << 5;

/// Model Specific Registers
const MSR_IA32_FEATURE_CONTROL: Msr = Msr::new(0x3A);

/// Returns Ok is VMX is available, otherwise returns the reason it's not.
pub fn vmx_available() -> Result<(), &'static str> {
    // SAFETY: the CPUID instruction is not supported under SGX, we assume that this function is
    // never executed under SGX.
    let cpuid = unsafe { arch::x86_64::__cpuid(0x01) };
    if (cpuid.ecx & CPUID_ECX_VMX_MASK) == 0 {
        crate::println!("CPUID.ECX: {:b}", cpuid.ecx);
        return Err("CPU does not support VMX");
    }

    let cr4 = Cr4::read();
    if !cr4.contains(Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS) {
        return Err("VMX is supported but not enabled (CR4.VMXE = 0)");
    }

    // See manual 3C Section 23.7
    let mut msr = MSR_IA32_FEATURE_CONTROL;
    unsafe { msr.write(0b101) };
    let feature_control = unsafe { msr.read() };
    crate::println!("MSR: {:b}", feature_control);
    if feature_control & 0b001 == 0 {
        return Err("VMXON is disabled in the IA32_FEATURE_CONTROL MSR");
    }

    Ok(())
}

/// Enter VMX operations.
///
/// This allocates a VMXON region, which must be page-align and can take up to 4kb.
/// The region **must** be available for the whole duration of VMX operations.
pub unsafe fn vmxon(addr: PhysAddr) {
    let addr = addr.as_u64();
    asm!("vmxon ({0})", in(reg) &addr, options(att_syntax));
}
