//! VMX support
//!
//! Inspired and in part copied from the [x86] crate.
//!
//! [x86]: https://hermitcore.github.io/libhermit-rs/x86/bits64/vmx/index.html

use core::arch;
use core::arch::asm;

use bitflags::bitflags;
use x86_64::registers::control::{Cr4, Cr4Flags};
use x86_64::registers::model_specific::Msr;
use x86_64::registers::rflags::RFlags;
use x86_64::PhysAddr;

use crate::memory::{VirtualMemoryArea, VirtualMemoryAreaAllocator};

const LOW_32_BITS_MASK: u64 = (1 << 32) - 1;

/// CPUID mask for VMX support
const CPUID_ECX_VMX_MASK: u32 = 1 << 5;

/// Model Specific Registers
const MSR_IA32_FEATURE_CONTROL: Msr = Msr::new(0x3A);
const MSR_IA32_VMX_BASIC: Msr = Msr::new(0x480);
const MSR_IA32_VMX_PINBASED_CTLS: Msr = Msr::new(0x481);
const MSR_IA32_VMX_TRUE_PINBASED_CTLS: Msr = Msr::new(0x48D);

/// Basic VMX Information.
///
/// See Intel SDM Vol. 3D Appendix A-1.
#[derive(Clone, Debug)]
pub struct VmxBasicInfo {
    /// The 31-bits VMCS revision identifier used by the CPU.
    pub revision: u32,

    /// Minimum required size in bytes for VMCS and VMXON regions.
    pub vmcs_width: u32,

    /// Support the VMX_TRUE_CTLS registers.
    pub support_true_ctls: bool,
    // TODO: list supported memory types.
}

#[derive(Debug)]
pub enum VmxError {
    /// VMCS pointer is valid, but some other error was encountered. Read VM-instruction error
    /// field of VMCS for more details.
    VmFailValid,

    /// VMCS pointer is invalid.
    VmFailInvalid,

    /// VMX is not supported by the current CPU.
    VmxNotSupported,

    /// VMX is supported by the CPU but not enabled. See IA_32_FEATURE_CONTROL MSR.
    VmxNotEnabled,

    /// Value 1 is not supported for one of the configuration bits for which it was requested.
    Disallowed1,

    /// Value 0 is not supported for one of the configuration bits for which it was requested.
    Disallowed0,
}

/// Returns Ok is VMX is available, otherwise returns the reason it's not.
///
/// If VMX is available but not enabled, the configuration registers are updated properly to enable
/// it.
pub fn vmx_available() -> Result<(), VmxError> {
    // SAFETY: the CPUID instruction is not supported under SGX, we assume that this function is
    // never executed under SGX.
    let cpuid = unsafe { arch::x86_64::__cpuid(0x01) };
    if (cpuid.ecx & CPUID_ECX_VMX_MASK) == 0 {
        return Err(VmxError::VmxNotSupported);
    }

    // Enable VMX if available but not configured.
    let cr4 = Cr4::read();
    if !Cr4::read().contains(Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS) {
        // SAFETY: it is always (really?) possible to set the VMX bit, but removing it during VMX
        // operation causes #UD.
        unsafe {
            Cr4::write(cr4 | Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS);
        }
    }

    // See manual 3C Section 23.7
    let feature_control = unsafe { MSR_IA32_FEATURE_CONTROL.read() };
    if feature_control & 0b110 == 0 || feature_control & &0b001 == 0 {
        return Err(VmxError::VmxNotSupported);
    }

    Ok(())
}

/// Enter VMX operations.
///
/// SAFETY: This function assumes that VMX is available, otherwise its behavior is unefined.
//  NOTE: see Intel SDM Vol 3C Section 24.11.5
pub unsafe fn vmxon(allocator: &VirtualMemoryAreaAllocator) -> Result<(), VmxError> {
    let vmcs_info = get_vmx_info();

    // Allocate a VMXON region with the required capacity
    let mut vmxon_vma = allocator
        .with_capacity(vmcs_info.vmcs_width as usize)
        .expect("Failed to allocate VMXON region");

    // Initialize the VMXON region by copying the revision ID into the 4 first bytes of VMXON
    // region
    vmxon_vma.as_bytes_mut()[0..4].copy_from_slice(&vmcs_info.revision.to_le_bytes());

    // SAFETY: VMAs are always allocated as page-aligned regions.
    let phys_addr = vmxon_vma.as_phys_addr().as_u64();
    asm!("vmxon ({0})", in(reg) &phys_addr, options(att_syntax));
    vmx_capture_status()
}

/// Exit VMX operations
pub unsafe fn vmxoff() -> Result<(), VmxError> {
    asm!("vmxoff");
    vmx_capture_status()
}

/// Clear the VMCS at the provided physical address.
unsafe fn vmclear(addr: PhysAddr) -> Result<(), VmxError> {
    let addr = addr.as_u64();
    asm! {"vmclear ({0})", in(reg) &addr, options(att_syntax)};
    vmx_capture_status()
}

/// Return basic info about VMX CPU-defined structures.
///
/// SAFETY: This function assumes that VMX is available, otherwise its behavior is undefined.
pub unsafe fn get_vmx_info() -> VmxBasicInfo {
    // SAFETY: this register can be read if VMX is available.
    let raw_info = MSR_IA32_VMX_BASIC.read();
    let revision = raw_info & ((1 << 32) - 1); // bits 31:0
    let revision = revision as u32;
    let vmcs_width = (raw_info & ((1 << 45) - 1)) >> 32; // bits 44:32
    let vmcs_width = vmcs_width as u32;
    let support_true_ctls = raw_info & (1 << 55) != 0;
    VmxBasicInfo {
        revision,
        vmcs_width,
        support_true_ctls,
    }
}

/// Helper used to extract VMX-specific Result in accordance with
/// conventions described in Intel SDM, Volume 3C, Section 30.2.
//  We inline this to provide an obstruction-free path from this function's
//  call site to the moment where `rflags::read()` reads RFLAGS. Otherwise it's
//  possible for RFLAGS register to be clobbered by a function prologue,
//  see https://github.com/gz/rust-x86/pull/50.
#[inline(always)]
fn vmx_capture_status() -> Result<(), VmxError> {
    let flags = rflags_read();

    if flags.contains(RFlags::ZERO_FLAG) {
        Err(VmxError::VmFailValid)
    } else if flags.contains(RFlags::CARRY_FLAG) {
        Err(VmxError::VmFailInvalid)
    } else {
        Ok(())
    }
}

/// Return the current value of the RFLAGS register.
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

// —————————————————————————————————— VMCS —————————————————————————————————— //

pub struct VmcsRegion {
    /// The physical address of the region, corresponds to the VMCS pointer.
    phys_addr: PhysAddr,
    /// The VMA used by the region.
    vma: VirtualMemoryArea,
}

impl VmcsRegion {
    pub unsafe fn new(allocator: &VirtualMemoryAreaAllocator) -> Result<Self, VmxError> {
        let vmcs_info = get_vmx_info();

        // Allocate a VMCS region with the required capacity
        let mut vmcs_vma = allocator
            .with_capacity(vmcs_info.vmcs_width as usize)
            .expect("Failed to allocate VMXON region");

        // Initialize the VMCS region by copying the revision ID into the 4 first bytes of VMCS
        // region
        vmcs_vma.as_bytes_mut()[0..4].copy_from_slice(&vmcs_info.revision.to_le_bytes());

        // Use VMCLEAR to put the VMCS in a clear (valid) state.
        let phys_addr = vmcs_vma.as_phys_addr();
        vmclear(phys_addr)?;

        Ok(VmcsRegion {
            phys_addr,
            vma: vmcs_vma,
        })
    }

    pub unsafe fn set_as_active() {
        // Use VMPTRLD
        todo!()
    }

    pub unsafe fn deactivate() {
        // Use VMCLEAR
        todo!()
    }

    /// Set the pin-based controls.
    pub fn set_pin_based_ctls(&mut self, flags: PinbasedControls) -> Result<(), VmxError> {
        // NOTE: see Intel SDM Vol 3D Appending A.3.1 for allowed settings explanation.
        let raw_flags = flags.bits();
        let vmx_info = unsafe { get_vmx_info() };
        let spec = unsafe { MSR_IA32_VMX_PINBASED_CTLS.read() };
        let known = PinbasedControls::all().bits();
        let new_flags = if vmx_info.support_true_ctls {
            let true_spec = unsafe { MSR_IA32_VMX_TRUE_PINBASED_CTLS.read() };
            Self::get_true_ctls(raw_flags, spec, true_spec, known)?
        } else {
            Self::get_ctls(raw_flags, spec, known)?
        };

        todo!();
    }

    /// Computes the controls bits when there is no support for true controls.
    fn get_ctls(user: u32, spec: u64, known: u32) -> Result<u32, VmxError> {
        // NOTE: see Intel SDM Vol 3C Section 31.5.1, algorithm 3
        let allowed_zeros = (spec & LOW_32_BITS_MASK) as u32;
        let allowed_ones = (spec >> 32) as u32;

        if !user & allowed_zeros & known != 0 {
            return Err(VmxError::Disallowed0);
        }
        if user & !allowed_ones & known != 0 {
            return Err(VmxError::Disallowed1);
        }

        let default_value = allowed_zeros & allowed_ones;
        Ok(user | default_value)
    }

    fn get_true_ctls(user: u32, spec: u64, true_spec: u64, known: u32) -> Result<u32, VmxError> {
        // NOTE: see Intel SDM Vol 3C Section 31.5.1, algorithm 3
        let allowed_zeros = (spec & LOW_32_BITS_MASK) as u32;
        let true_allowed_zeros = (true_spec & LOW_32_BITS_MASK) as u32;
        let true_allowed_ones = (true_spec >> 32) as u32;

        if !user & true_allowed_zeros & known != 0 {
            return Err(VmxError::Disallowed0);
        }
        if user & !true_allowed_ones & known != 0 {
            return Err(VmxError::Disallowed1);
        }

        let default_value = true_allowed_zeros & true_allowed_ones;
        let can_be_both = true_allowed_ones & !true_allowed_zeros;
        let must_be_ones = can_be_both & !known & !allowed_zeros;
        Ok(default_value | must_be_ones)
    }
}

// —————————————————————— VM Execution Control Fields ——————————————————————— //

bitflags! {
    /// Pin-based VM-execution controls.
    ///
    /// A set of bitmask flags useful when setting up [`PINBASED_EXEC_CONTROLS`] VMCS field.
    ///
    /// See Intel SDM, Volume 3C, Section 24.6.1.
    pub struct PinbasedControls: u32 {
        /// External-interrupt exiting.
        const EXTERNAL_INTERRUPT_EXITING = 1 << 0;
        /// NMI exiting.
        const NMI_EXITING = 1 << 3;
        /// Virtual NMIs.
        const VIRTUAL_NMIS = 1 << 5;
        /// Activate VMX-preemption timer.
        const VMX_PREEMPTION_TIMER = 1 << 6;
        /// Process posted interrupts.
        const POSTED_INTERRUPTS = 1 << 7;
    }
}
