//! VMX support
//!
//! Inspired and in part copied from the [x86] crate.
//!
//! [x86]: https://hermitcore.github.io/libhermit-rs/x86/bits64/vmx/index.html

pub mod bitmaps;
pub mod errors;
pub mod fields;
pub mod msr;
pub mod raw;

use core::arch::asm;
use core::{arch, usize};

use x86_64::instructions::tables::{sgdt, sidt};
use x86_64::registers::control::{Cr4, Cr4Flags};
use x86_64::registers::model_specific::Efer;
use x86_64::registers::segmentation;
use x86_64::registers::segmentation::Segment;
use x86_64::PhysAddr;

use crate::gdt;
use crate::memory::{VirtualMemoryArea, VirtualMemoryAreaAllocator};
use bitmaps::{EntryControls, ExceptionBitmap, ExitControls, PinbasedControls, PrimaryControls};
pub use errors::{VmExitInterrupt, VmxError, VmxExitReason, VmxFieldError};
use fields::traits::*;

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

/// Return the EPT and VPID capabilities.
///
/// See Intel manual volume 3 annex A.10.
pub fn ept_capabilities() -> Result<bitmaps::EptCapability, VmxError> {
    // Check that VMX is available
    vmx_available()?;

    // SAFETY: MSR exists if vmx is available.
    let procbased_ctls = unsafe { msr::VMX_PROCBASED_CTLS.read() };
    if procbased_ctls & (1 << 63) == 0 {
        return Err(VmxError::FeatureNotSupported);
    }

    // SAFETY: MSR exists if bit 63 of procbased_ctls is 1.
    let second_procbased_ctrl = unsafe { msr::VMX_PROCBASED_CTLS2.read() };
    if second_procbased_ctrl & (1 << 33) == 0 {
        return Err(VmxError::FeatureNotSupported);
    }

    // SAFETY: MSR exists if bit 33 of second_procbased_ctrl is 1.
    let capabilities = unsafe { msr::VMX_EPT_VPID_CAP.read() };
    Ok(bitmaps::EptCapability::from_bits_truncate(capabilities))
}

/// Return available VM functions.
///
/// See Intel manual volume 3 section 24.6.14.
pub fn available_vmfuncs() -> Result<bitmaps::VmFuncControls, VmxError> {
    // Check that VMX is available
    vmx_available()?;

    // SAFETY: MSR exists if vmx is available.
    let procbased_ctls = unsafe { msr::VMX_PROCBASED_CTLS.read() };
    if procbased_ctls & (1 << 63) == 0 {
        return Err(VmxError::FeatureNotSupported);
    }

    // SAFETY: MSR exists if bit 63 of procbased_ctls is 1.
    let second_procbased_ctrl = unsafe { msr::VMX_PROCBASED_CTLS2.read() };
    if second_procbased_ctrl & (1 << 45) == 0 {
        return Err(VmxError::FeatureNotSupported);
    }

    // SAFETY: MSR exists if bit 45 of second_procbased_ctrl is 1.
    let capabilities = unsafe { msr::VMX_VMFUNC.read() };
    Ok(bitmaps::VmFuncControls::from_bits_truncate(capabilities))
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
unsafe fn get_vmx_info() -> VmxBasicInfo {
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

    /// Run the VM.
    ///
    /// SAFETY: the VMCS must be properly configured so that the host can resume execution in a
    /// sensible environment. A simple way of ensuring that is to save the current environment as
    /// host state.
    pub unsafe fn run(&mut self) -> Result<VmxExitReason, VmxError> {
        raw::vmlaunch()?;
        self.vcpu.exit_reason()
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
            .map_err(|err| err.set_field(VmxFieldError::PinBasedControls))
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
                msr::VMX_PROCBASED_CTLS,
                msr::VMX_TRUE_PROCBASED_CTLS,
                fields::Ctrl32::PrimaryProcBasedExecCtrls,
            )
            .map_err(|err| err.set_field(VmxFieldError::PrimaryControls))
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
            .map_err(|err| err.set_field(VmxFieldError::ExitControls))
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
            .map_err(|err| err.set_field(VmxFieldError::EntryControls))
        }
    }

    /// Returns the VM entry controls.
    pub fn get_vm_entry_cntrls(&self) -> Result<EntryControls, VmxError> {
        let ctrls = unsafe { fields::Ctrl32::VmEntryCtrls.vmread()? };
        Ok(EntryControls::from_bits_truncate(ctrls))
    }

    /// Sets the exception bitmap.
    ///
    /// WARNING: the region must be active, otherwise this function might modify another VMCS.
    pub fn set_exception_bitmap(&mut self, bitmap: ExceptionBitmap) -> Result<(), VmxError> {
        // TODO: is there a list of allowed settings?
        unsafe { fields::Ctrl32::ExceptionBitmap.vmwrite(bitmap.bits()) }
    }

    /// Check that the current VMCS is in a valid stat, such that VMLAUNCH or VMRESUME can
    /// successfully complete.
    ///
    /// WARNING: the checks are not (yet) complete!
    pub fn check(&self) -> Result<(), VmxError> {
        // Validate host state
        let host_cr0 = unsafe { fields::HostStateNat::Cr0.vmread()? } as usize;
        Self::validate_cr0(host_cr0).map_err(|err| err.set_field(VmxFieldError::HostCr0))?;
        let host_cr4 = unsafe { fields::HostStateNat::Cr4.vmread()? } as usize;
        Self::validate_cr4(host_cr4).map_err(|err| err.set_field(VmxFieldError::HostCr4))?;

        // validate guest state
        //
        // See manual section 26.3
        let guest_cr0 = unsafe { fields::GuestStateNat::Cr0.vmread()? } as usize;
        Self::validate_cr0(guest_cr0).map_err(|err| err.set_field(VmxFieldError::GuestCr0))?;
        let guest_cr4 = unsafe { fields::GuestStateNat::Cr4.vmread()? } as usize;
        Self::validate_cr4(guest_cr4).map_err(|err| err.set_field(VmxFieldError::GuestCr4))?;

        // If CR0.PG == 1, then CR0.PE must be 1
        if (guest_cr0 & (1 << 31)) != 0 {
            if (guest_cr0 & 1) != 1 {
                return Err(VmxError::Disallowed0(VmxFieldError::GuestCr0, 0));
            }
        }

        let entry_cntrls = self.get_vm_entry_cntrls()?;
        if entry_cntrls.contains(bitmaps::EntryControls::IA32E_MODE_GUEST) {
            if guest_cr0 & (1 << 31) == 0 {
                return Err(VmxError::Disallowed0(VmxFieldError::GuestCr0, 31));
            }
            if guest_cr4 & (1 << 5) == 0 {
                return Err(VmxError::Disallowed0(VmxFieldError::GuestCr4, 5));
            }
        } else {
            if guest_cr4 & (1 << 17) != 0 {
                return Err(VmxError::Disallowed1(VmxFieldError::GuestCr4, 17));
            }
        }

        let tr = unsafe { fields::GuestState16::TrSelector.vmread()? };
        let ss = unsafe { fields::GuestState16::SsSelector.vmread()? };
        let cs = unsafe { fields::GuestState16::CsSelector.vmread()? };
        if tr & (1 << 2) != 0 {
            return Err(VmxError::Disallowed1(VmxFieldError::GuestTrSelector, 2));
        }
        if (ss & 0b01) != (cs & 0b01) {
            return Err(VmxError::MisconfiguredBit(
                VmxFieldError::GuestSsSelector,
                0,
            ));
        }
        if (ss & 0b10) != (cs & 0b10) {
            return Err(VmxError::MisconfiguredBit(
                VmxFieldError::GuestSsSelector,
                1,
            ));
        }

        let cs_ar = unsafe { fields::GuestState32::CsAccessRights.vmread()? };
        let ss_ar = unsafe { fields::GuestState32::SsAccessRights.vmread()? };
        let ds_ar = unsafe { fields::GuestState32::DsAccessRights.vmread()? };
        let es_ar = unsafe { fields::GuestState32::EsAccessRights.vmread()? };
        let fs_ar = unsafe { fields::GuestState32::FsAccessRights.vmread()? };
        let gs_ar = unsafe { fields::GuestState32::GsAccessRights.vmread()? };
        let tr_ar = unsafe { fields::GuestState32::TrAccessRights.vmread()? };
        let ldtr_ar = unsafe { fields::GuestState32::LdtrAccessRights.vmread()? };
        let tr_limit = unsafe { fields::GuestState32::TrLimit.vmread()? };
        let gdtr_limit = unsafe { fields::GuestState32::GdtrLimit.vmread()? };
        let idtr_limit = unsafe { fields::GuestState32::IdtrLimit.vmread()? };
        let rflags = unsafe { fields::GuestStateNat::Rflags.vmread()? };

        let cs_type = cs_ar & 0b1111;
        let ss_type = ss_ar & 0b1111;
        const UNUSABLE_MASK: u32 = 1 << 16;
        if cs_type != 9 && cs_type != 11 && cs_type != 13 && cs_type != 15 {
            // We assume "unrestricted guest" is set to 0
            return Err(VmxError::Misconfigured(VmxFieldError::GuestCsAccessRights));
        }
        if ss_ar & UNUSABLE_MASK == 0 && ss_type != 3 && ss_type != 7 {
            return Err(VmxError::Misconfigured(VmxFieldError::GuestSsAccessRights));
        }
        let check_segment_ar = |ar: u32, field: VmxFieldError| {
            if ar & UNUSABLE_MASK == 0 {
                if ar & 0b1 != 1 {
                    return Err(VmxError::Disallowed0(field, 0));
                }
                if (ar & 0b1000 != 0) && (ar & 0b0010 == 0) {
                    return Err(VmxError::MisconfiguredBit(field, 1));
                }
            }
            Ok(())
        };
        check_segment_ar(ds_ar, VmxFieldError::GuestDsAccessRights)?;
        check_segment_ar(es_ar, VmxFieldError::GuestEsAccessRights)?;
        check_segment_ar(fs_ar, VmxFieldError::GuestFsAccessRights)?;
        check_segment_ar(gs_ar, VmxFieldError::GuestGsAccessRights)?;
        if (cs_ar & UNUSABLE_MASK == 0) && (cs_ar & (1 << 4) == 0) {
            return Err(VmxError::Disallowed0(VmxFieldError::GuestCsAccessRights, 4));
        }
        if (tr_ar & 0b1111) != 11 {
            return Err(VmxError::Misconfigured(VmxFieldError::GuestTrAccessRights));
        }
        if (tr_ar & (1 << 4)) != 0 {
            return Err(VmxError::Disallowed1(VmxFieldError::GuestTrAccessRights, 4));
        }
        if (tr_ar & (1 << 7)) == 0 {
            return Err(VmxError::Disallowed0(VmxFieldError::GuestTrAccessRights, 7));
        }
        if (tr_ar & ((1 << 8) | (1 << 9) | (1 << 10) | (1 << 11))) != 0 {
            return Err(VmxError::Misconfigured(VmxFieldError::GuestTrAccessRights));
        }
        if ((tr_limit & 0b111111111111) != 0b111111111111) && (tr_ar & (1 << 15) != 0) {
            return Err(VmxError::MisconfiguredBit(
                VmxFieldError::GuestTrAccessRights,
                15,
            ));
        }
        if ((tr_limit & 0b11111111111100000000000000000000) != 0) && (tr & (1 << 15) == 0) {
            return Err(VmxError::MisconfiguredBit(
                VmxFieldError::GuestTrAccessRights,
                15,
            ));
        }
        if (tr_ar & UNUSABLE_MASK) != 0 {
            return Err(VmxError::Disallowed1(
                VmxFieldError::GuestTrAccessRights,
                16,
            ));
        }
        if (tr_ar >> 16) != 0 {
            return Err(VmxError::Misconfigured(VmxFieldError::GuestTrAccessRights));
        }
        if (ldtr_ar & UNUSABLE_MASK) == 0 {
            todo!();
        }
        if (gdtr_limit >> 16) != 0 {
            return Err(VmxError::Misconfigured(VmxFieldError::GuestGdtrLimit));
        }
        if (idtr_limit >> 16) != 0 {
            return Err(VmxError::Misconfigured(VmxFieldError::GuestIdtrLimit));
        }
        if (rflags >> 22) != 0 {
            return Err(VmxError::Misconfigured(VmxFieldError::GuestRflags));
        }
        if (rflags & (1 << 15)) != 0 {
            return Err(VmxError::Disallowed1(VmxFieldError::GuestRflags, 15));
        }
        if (rflags & (1 << 5)) != 0 {
            return Err(VmxError::Disallowed1(VmxFieldError::GuestRflags, 5));
        }
        if (rflags & (1 << 3)) != 0 {
            return Err(VmxError::Disallowed1(VmxFieldError::GuestRflags, 3));
        }

        if (rflags & (1 << 1)) == 0 {
            return Err(VmxError::Disallowed0(VmxFieldError::GuestRflags, 1));
        }

        Ok(())
    }

    /// Validates CR0 register.
    fn validate_cr0(cr0: usize) -> Result<(), VmxError> {
        let fixed_0 = unsafe { msr::VMX_CR0_FIXED0.read() } as usize;
        let fixed_1 = unsafe { msr::VMX_CR0_FIXED1.read() } as usize;
        Self::validate_cr(cr0, fixed_0, fixed_1)
    }

    /// Validates CR4 register.
    fn validate_cr4(cr4: usize) -> Result<(), VmxError> {
        let fixed_0 = unsafe { msr::VMX_CR4_FIXED0.read() } as usize;
        let fixed_1 = unsafe { msr::VMX_CR4_FIXED1.read() } as usize;
        Self::validate_cr(cr4, fixed_0, fixed_1)
    }

    /// Validates a control register (CR0 or CR4) against its valid state.
    ///
    /// See Intel Manual volume 3 annex A.7 & A.8.
    fn validate_cr(cr: usize, fixed_0: usize, fixed_1: usize) -> Result<(), VmxError> {
        let must_be_zero = fixed_0 & !cr;
        if must_be_zero != 0 {
            let idx = must_be_zero.trailing_zeros() as u8;
            return Err(VmxError::Disallowed0(VmxFieldError::Unknown, idx));
        }

        let must_be_zero = (!fixed_1) & cr;
        if must_be_zero != 0 {
            let idx = must_be_zero.trailing_zeros() as u8;
            return Err(VmxError::Disallowed1(VmxFieldError::Unknown, idx));
        }

        Ok(())
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
        let gdt = sgdt();
        let idt = sidt();

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

            fields::HostStateNat::IdtrBase.vmwrite(idt.base.as_u64() as usize)?;
            fields::HostStateNat::GdtrBase.vmwrite(gdt.base.as_u64() as usize)?;

            // Save TR base
            let tr_offset = (tr >> 3) as usize;
            let gdt = gdt::gdt().as_raw_slice();
            let low = gdt[tr_offset];
            let high = gdt[tr_offset + 1];
            let tr_base = get_tr_base(high, low);
            fields::HostStateNat::TrBase.vmwrite(tr_base as usize)?;
        }

        // MSRs
        unsafe {
            fields::HostStateNat::Ia32SysenterEsp.vmwrite(msr::SYSENTER_ESP.read() as usize)?;
            fields::HostStateNat::Ia32SysenterEip.vmwrite(msr::SYSENTER_EIP.read() as usize)?;
            fields::HostState32::Ia32SysenterCs.vmwrite(msr::SYSENTER_CS.read() as u32)?;
            fields::HostState64::Ia32Efer.vmwrite(Efer::read().bits())?;
        }

        // Control registers
        let cr0: usize;
        let cr3: usize;
        let cr4: usize;
        unsafe {
            asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
            asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
            asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
            fields::HostStateNat::Cr0.vmwrite(cr0)?;
            fields::HostStateNat::Cr3.vmwrite(cr3)?;
            fields::HostStateNat::Cr4.vmwrite(cr4)
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
    ///
    /// In case of error, returns the index of a bit
    fn get_ctls(user: u32, spec: u64, known: u32) -> Result<u32, VmxError> {
        // NOTE: see Intel SDM Vol 3C Section 31.5.1, algorithm 3
        let allowed_zeros = (spec & LOW_32_BITS_MASK) as u32;
        let allowed_ones = (spec >> 32) as u32;

        let must_be_0 = !user & allowed_zeros & known;
        if must_be_0 != 0 {
            let idx = must_be_0.trailing_zeros() as u8;
            return Err(VmxError::Disallowed0(VmxFieldError::Unknown, idx));
        }
        let must_be_0 = user & !allowed_ones & known;
        if must_be_0 != 0 {
            let idx = must_be_0.trailing_zeros() as u8;
            return Err(VmxError::Disallowed1(VmxFieldError::Unknown, idx));
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

        let must_be_0 = !user & true_allowed_zeros & known;
        if must_be_0 != 0 {
            let idx = must_be_0.trailing_zeros() as u8;
            return Err(VmxError::Disallowed0(VmxFieldError::Unknown, idx));
        }
        let must_be_0 = user & !true_allowed_ones & known;
        if must_be_0 != 0 {
            let idx = must_be_0.trailing_zeros() as u8;
            return Err(VmxError::Disallowed1(VmxFieldError::Unknown, idx));
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

    pub fn exit_reason(&self) -> Result<VmxExitReason, VmxError> {
        let reason = unsafe { fields::GuestState32Ro::ExitReason.vmread() }?;
        Ok(VmxExitReason::from_u16((reason & 0xFFFF) as u16))
    }

    pub fn interrupt_info(&self) -> Result<Option<VmExitInterrupt>, VmxError> {
        let info = unsafe { fields::GuestState32Ro::VmExitInterruptInfo.vmread()? };
        if (info & (1 << 31)) == 0 {
            return Ok(None);
        }

        let vector = (info & 0xFF) as u8;
        let int_type = errors::InterruptionType::from_raw(info);
        let error_code = if (info & (1 << 11)) != 0 {
            Some(unsafe { fields::GuestState32Ro::VmExitInterruptErrCode.vmread()? })
        } else {
            None
        };
        Ok(Some(VmExitInterrupt {
            vector,
            int_type,
            error_code,
        }))
    }
}

// ———————————————————————————— Helper Functions ———————————————————————————— //

/// Construct the TR base from its system segment descriptor.
///
/// See Intel manual 7.2.3.
fn get_tr_base(desc_high: u64, desc_low: u64) -> u64 {
    const BASE_2_MASK: u64 = ((1 << 8) - 1) << 24;
    const BASE_1_MASK: u64 = ((1 << 24) - 1) << 16;

    let mut ptr = 0;
    ptr |= (desc_high & LOW_32_BITS_MASK) << 32;
    ptr |= (desc_low & BASE_2_MASK) >> 32;
    ptr |= (desc_low & BASE_1_MASK) >> 16;
    ptr
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
        let spec_0_setting: u64 = 0b0_1;
        let spec_1_setting: u64 = 0b0_1;
        let user_request:   u32 = 0b1_1;
        let known:          u32 = 0b1_1;

        let spec = (spec_1_setting << 32) + spec_0_setting;
        assert_eq!(VmcsRegion::get_ctls(user_request, spec, known), Err(VmxError::Disallowed1(VmxFieldError::Unknown, 1)));

        // testing disallowed zero
        let spec_0_setting: u64 = 0b1;
        let spec_1_setting: u64 = 0b1;
        let user_request:   u32 = 0b0;
        let known:          u32 = 0b1;

        let spec = (spec_1_setting << 32) + spec_0_setting;
        assert_eq!(VmcsRegion::get_ctls(user_request, spec, known), Err(VmxError::Disallowed0(VmxFieldError::Unknown, 0)));
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
        let spec_0_setting:      u64 = 0b0_1;
        let true_spec_0_setting: u64 = 0b0_0;
        let true_spec_1_setting: u64 = 0b0_1;
        let user_request:        u32 = 0b1_1;
        let known:               u32 = 0b1_1;

        let spec = spec_0_setting;
        let true_spec = (true_spec_1_setting << 32) + true_spec_0_setting;
        assert_eq!(
            VmcsRegion::get_true_ctls(user_request, spec, true_spec, known),
            Err(VmxError::Disallowed1(VmxFieldError::Unknown, 1)),
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
            Err(VmxError::Disallowed0(VmxFieldError::Unknown, 0)),
        );
    }

    /// See manual Annex A.7 & A.8
    #[rustfmt::skip]
    #[test_case]
    fn validate_cr() {
        // Testing valid combinations
        let fixed_0: usize = 0b001_000;
        let fixed_1: usize = 0b111_011;
        let cr:      usize = 0b011_010;

        assert_eq!(VmcsRegion::validate_cr(cr, fixed_0, fixed_1), Ok(()));

        // testing disallowed one
        let fixed_0: usize = 0b0_001;
        let fixed_1: usize = 0b0_111;
        let cr:      usize = 0b1_011;

        assert_eq!(
            VmcsRegion::validate_cr(cr, fixed_0, fixed_1),
            Err(VmxError::Disallowed1(VmxFieldError::Unknown, 3))
        );

        // testing disallowed one
        let fixed_0: usize = 0b1_01;
        let fixed_1: usize = 0b1_11;
        let cr:      usize = 0b0_11;

        assert_eq!(
            VmcsRegion::validate_cr(cr, fixed_0, fixed_1),
            Err(VmxError::Disallowed0(VmxFieldError::Unknown, 2))
        );
    }
}
