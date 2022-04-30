//! VMX support
//!
//! Inspired and in part copied from the [x86] crate.
//!
//! [x86]: https://hermitcore.github.io/libhermit-rs/x86/bits64/vmx/index.html

pub mod bitmaps;
pub mod fields;
pub mod msr;
pub mod raw;
pub mod errors;

use core::arch;
use core::arch::asm;

use x86_64::instructions::tables::{sgdt, sidt};
use x86_64::registers::control::{Cr0, Cr3, Cr4, Cr4Flags};
use x86_64::registers::segmentation;
use x86_64::registers::segmentation::Segment;
use x86_64::PhysAddr;

use crate::memory::{VirtualMemoryArea, VirtualMemoryAreaAllocator};
use bitmaps::{EntryControls, ExceptionBitmap, ExitControls, PinbasedControls, PrimaryControls};
use fields::traits::*;
pub use errors::VmxError;

/// Mask for keeping only the 32 lower bits.
const LOW_32_BITS_MASK: u64 = (1 << 32) - 1;

/// CPUID mask for VMX support
const CPUID_ECX_VMX_MASK: u32 = 1 << 5;

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
    let feature_control = unsafe { msr::FEATURE_CONTROL.read() };
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
    raw::vmxon(phys_addr)
}

/// Return basic info about VMX CPU-defined structures.
///
/// SAFETY: This function assumes that VMX is available, otherwise its behavior is undefined.
pub unsafe fn get_vmx_info() -> VmxBasicInfo {
    // SAFETY: this register can be read if VMX is available.
    let raw_info = msr::VMX_BASIC.read();
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

// —————————————————————————————————— VMCS —————————————————————————————————— //

/// A region containing information about a VM.
pub struct VmcsRegion {
    /// The physical address of the region, corresponds to the VMCS pointer.
    phys_addr: PhysAddr,
    /// Virtual CPU, contains guest state.
    pub vcpu: VCpu,
    /// The VMA used by the region.
    _vma: VirtualMemoryArea,
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
        raw::vmclear(phys_addr.as_u64())?;

        Ok(VmcsRegion {
            phys_addr,
            vcpu: VCpu { _private: () },
            _vma: vmcs_vma,
        })
    }

    /// Makes this region the current active region.
    pub unsafe fn set_as_active(&self) -> Result<(), VmxError> {
        raw::vmptrld(self.phys_addr.as_u64())
    }

    pub unsafe fn deactivate() {
        // Use VMCLEAR
        todo!()
    }

    /// Sets the pin-based controls.
    ///
    /// WARNING: the region must be active, otherwise this function might modify another VMCS.
    pub fn set_pin_based_ctrls(&mut self, flags: PinbasedControls) -> Result<(), VmxError> {
        unsafe {
            Self::set_ctrls(
                flags.bits(),
                PinbasedControls::all().bits(),
                msr::VMX_PINBASED_CTLS,
                msr::VMX_TRUE_PINBASED_CTLS,
                fields::Ctrl32::PinBasedExecCtrls,
            )
        }
    }

    /// Sets the primary processor-based controls.
    ///
    /// WARNING: the region must be active, otherwise this function might modify another VMCS.
    pub fn set_primary_ctrls(&mut self, flags: PrimaryControls) -> Result<(), VmxError> {
        unsafe {
            Self::set_ctrls(
                flags.bits(),
                PrimaryControls::all().bits(),
                msr::VMX_PROCBASED_CTL,
                msr::VMX_TRUE_PROCBASED_CTLS,
                fields::Ctrl32::PrimaryProcBasedExecCtrls,
            )
        }
    }

    /// Sets the VM exit controls.
    ///
    /// WARNING: the region must be active, otherwise this function might modify another VMCS.
    pub fn set_vm_exit_ctrls(&mut self, flags: ExitControls) -> Result<(), VmxError> {
        unsafe {
            Self::set_ctrls(
                flags.bits(),
                ExitControls::all().bits(),
                msr::VMX_EXIT_CTLS,
                msr::VMX_TRUE_EXIT_CTLS,
                fields::Ctrl32::VmExitCtrls,
            )
        }
    }

    /// Sets the VM entry controls.
    ///
    /// WARNING: the region must be active, otherwise this function might modify another VMCS.
    pub fn set_vm_entry_ctrls(&mut self, flags: EntryControls) -> Result<(), VmxError> {
        unsafe {
            Self::set_ctrls(
                flags.bits(),
                EntryControls::all().bits(),
                msr::VMX_ENTRY_CTLS,
                msr::VMX_TRUE_ENTRY_CTLS,
                fields::Ctrl32::VmEntryCtrls,
            )
        }
    }

    /// Sets the exception bitmap.
    ///
    /// WARNING: the region must be active, otherwise this function might modify another VMCS.
    pub fn set_exception_bitmap(&mut self, bitmap: ExceptionBitmap) -> Result<(), VmxError> {
        // TODO: is there a list of allowed settings?
        unsafe { fields::Ctrl32::ExceptionBitmap.vmwrite(bitmap.bits()) }
    }

    /// Saves the host state (control registers, segments...), so that they are restored on VM Exit.
    ///
    /// WARNING: the region must be active, otherwise this function might modify another VMCS.
    pub fn save_host_state(&mut self) -> Result<(), VmxError> {
        // NOTE: See section 24.5 of volume 3C.

        // Segments
        let cs = segmentation::CS::get_reg();
        let ds = segmentation::DS::get_reg();
        let es = segmentation::ES::get_reg();
        let fs = segmentation::FS::get_reg();
        let gs = segmentation::GS::get_reg();
        let ss = segmentation::SS::get_reg();
        let tr: u16;
        let gdt = sgdt().base.as_u64() as usize;
        let idt = sidt().base.as_u64() as usize;

        unsafe {
            // There is no nice wrapper to read `tr` in the x86_64 crate.
            asm!("str {0:x}",
                out(reg) tr,
                options(att_syntax, nostack, nomem, preserves_flags));
        }

        unsafe {
            fields::HostState16::CsSelector.vmwrite(cs.0)?;
            fields::HostState16::DsSelector.vmwrite(ds.0)?;
            fields::HostState16::EsSelector.vmwrite(es.0)?;
            fields::HostState16::FsSelector.vmwrite(fs.0)?;
            fields::HostState16::GsSelector.vmwrite(gs.0)?;
            fields::HostState16::SsSelector.vmwrite(ss.0)?;
            fields::HostState16::TrSelector.vmwrite(tr)?;

            // NOTE: those might throw an exception depending on the CPU features, let's just
            // ignore them for now.
            // VmcsHostStateNat::FsBase.vmwrite(FS::read_base().as_u64() as usize)?;
            // VmcsHostStateNat::GsBase.vmwrite(GS::read_base().as_u64() as usize)?;

            fields::HostStateNat::IdtrBase.vmwrite(idt)?;
            fields::HostStateNat::GdtrBase.vmwrite(gdt)?;
            // TODO: save TR base
        }

        // MSRs
        unsafe {
            fields::HostStateNat::Ia32SysenterEsp.vmwrite(msr::SYSENTER_ESP.read() as usize)?;
            fields::HostStateNat::Ia32SysenterEip.vmwrite(msr::SYSENTER_EIP.read() as usize)?;
            fields::HostState32::Ia32SysenterCs.vmwrite(msr::SYSENTER_CS.read() as u32)?;
        }

        // Control registers
        let cr0 = Cr0::read();
        let (_, cr3) = Cr3::read();
        let cr4 = Cr4::read();

        unsafe {
            fields::HostStateNat::Cr0.vmwrite(cr0.bits() as usize)?;
            fields::HostStateNat::Cr3.vmwrite(cr3.bits() as usize)?;
            fields::HostStateNat::Cr4.vmwrite(cr4.bits() as usize)
        }
    }

    /// Sets a control setting for the current VMCS.
    ///
    /// Raw flags is a raw 32 bits bitflag vector, known is the birflags of bits known by the VMM,
    /// spec and true_spec MSRs are the MSRs containing the supported features of the current CPU.
    ///
    /// See Intel SDM Vol 3D Appending A.3.1 for allowed settings explanation.
    unsafe fn set_ctrls(
        raw_flags: u32,
        known: u32,
        spec_msr: msr::Msr,
        true_spec_msr: msr::Msr,
        control: fields::Ctrl32,
    ) -> Result<(), VmxError> {
        let vmx_info = get_vmx_info();
        let spec = spec_msr.read();
        let new_flags = if vmx_info.support_true_ctls {
            let true_spec = true_spec_msr.read();
            Self::get_true_ctls(raw_flags, spec, true_spec, known)?
        } else {
            Self::get_ctls(raw_flags, spec, known)?
        };

        control.vmwrite(new_flags)
    }

    /// Computes the control bits when there is no support for true controls.
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

    /// Computes the control bits when there  is support for true controls.
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
        let must_be_ones = can_be_both & !known & allowed_zeros;
        Ok(default_value | user | must_be_ones)
    }
}

// —————————————————————————————— Virtual CPU ——————————————————————————————— //

/// A virtual CPU.
pub struct VCpu {
    // This field prevents a VCpu from being instantiated outside of this module, by not marking it
    // public.
    _private: (),
}

impl VCpu {
    pub fn set16(&mut self, field: fields::GuestState16, value: u16) -> Result<(), VmxError> {
        unsafe { field.vmwrite(value) }
    }

    pub fn set32(&mut self, field: fields::GuestState32, value: u32) -> Result<(), VmxError> {
        unsafe { field.vmwrite(value) }
    }

    pub fn set64(&mut self, field: fields::GuestState64, value: u64) -> Result<(), VmxError> {
        unsafe { field.vmwrite(value) }
    }

    pub fn set_nat(&mut self, field: fields::GuestStateNat, value: usize) -> Result<(), VmxError> {
        unsafe { field.vmwrite(value) }
    }

    pub fn exit_reason(&self) -> Result<(), VmxError> {
        let reason = unsafe { fields::GuestState32Ro::ExitReason.vmread() }?;
        crate::println!("Exit reason: 0b{:b}", reason);
        Ok(())
    }
}

// ————————————————————————————————— Tests —————————————————————————————————— //

#[cfg(test)]
mod test {
    use super::*;

    /// See manual Annex A.3.
    #[rustfmt::skip]
    #[test_case]
    fn ctls_flags_spec() {
        // testing valid combinations
        let spec_0_setting: u64 = 0b001_00_01;
        let spec_1_setting: u64 = 0b011_01_11;
        let user_request:   u32 = 0b000_00_11;
        let known:          u32 = 0b000_11_11;
        let expected:       u32 = 0b001_00_11;

        let spec = (spec_1_setting << 32) + spec_0_setting;
        assert_eq!(VmcsRegion::get_ctls(user_request, spec, known), Ok(expected));

        // testing disallowed one
        let spec_0_setting: u64 = 0b0;
        let spec_1_setting: u64 = 0b0;
        let user_request:   u32 = 0b1;
        let known:          u32 = 0b1;

        let spec = (spec_1_setting << 32) + spec_0_setting;
        assert_eq!(VmcsRegion::get_ctls(user_request, spec, known), Err(VmxError::Disallowed1));

        // testing disallowed zero
        let spec_0_setting: u64 = 0b1;
        let spec_1_setting: u64 = 0b1;
        let user_request:   u32 = 0b0;
        let known:          u32 = 0b1;

        let spec = (spec_1_setting << 32) + spec_0_setting;
        assert_eq!(VmcsRegion::get_ctls(user_request, spec, known), Err(VmxError::Disallowed0));
    }

    /// See manual Annex A.3.
    #[rustfmt::skip]
    #[test_case]
    fn ctls_flags_true_spec() {
        // testing valid combinations
        let spec_0_setting:      u64 = 0b000_1_00_011;
        let true_spec_0_setting: u64 = 0b001_0_00_010;
        let true_spec_1_setting: u64 = 0b011_1_01_111;
        let user_request:        u32 = 0b000_0_00_111;
        let known:               u32 = 0b000_0_11_111;
        let expected:            u32 = 0b001_1_00_111;

        let spec = spec_0_setting;
        let true_spec = (true_spec_1_setting << 32) + true_spec_0_setting;
        assert_eq!(VmcsRegion::get_true_ctls(user_request, spec, true_spec, known), Ok(expected));

        // testing disallowed one
        let spec_0_setting:      u64 = 0b0;
        let true_spec_0_setting: u64 = 0b0;
        let true_spec_1_setting: u64 = 0b0;
        let user_request:        u32 = 0b1;
        let known:               u32 = 0b1;

        let spec = spec_0_setting;
        let true_spec = (true_spec_1_setting << 32) + true_spec_0_setting;
        assert_eq!(
            VmcsRegion::get_true_ctls(user_request, spec, true_spec, known),
            Err(VmxError::Disallowed1),
        );

        // testing disallowed zero
        let spec_0_setting:      u64 = 0b1;
        let true_spec_0_setting: u64 = 0b1;
        let true_spec_1_setting: u64 = 0b0;
        let user_request:        u32 = 0b0;
        let known:               u32 = 0b1;

        let spec = spec_0_setting;
        let true_spec = (true_spec_1_setting << 32) + true_spec_0_setting;
        assert_eq!(
            VmcsRegion::get_true_ctls(user_request, spec, true_spec, known),
            Err(VmxError::Disallowed0),
        );
    }
}
