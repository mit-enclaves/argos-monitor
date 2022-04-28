//! VMX support
//!
//! Inspired and in part copied from the [x86] crate.
//!
//! [x86]: https://hermitcore.github.io/libhermit-rs/x86/bits64/vmx/index.html

use core::arch;
use core::arch::asm;

use bitflags::bitflags;
use x86_64::registers::control::{Cr0, Cr3, Cr4, Cr4Flags};
use x86_64::registers::rflags::RFlags;
use x86_64::PhysAddr;

use crate::memory::{VirtualMemoryArea, VirtualMemoryAreaAllocator};

const LOW_32_BITS_MASK: u64 = (1 << 32) - 1;

/// CPUID mask for VMX support
const CPUID_ECX_VMX_MASK: u32 = 1 << 5;

pub mod msr {
    //! VMX Model Specific Registers

    pub use x86_64::registers::model_specific::Msr;

    pub const FEATURE_CONTROL: Msr = Msr::new(0x3A);
    pub const VMX_BASIC: Msr = Msr::new(0x480);
    pub const VMX_PINBASED_CTLS: Msr = Msr::new(0x481);
    pub const VMX_PROCBASED_CTL: Msr = Msr::new(0x482);
    pub const VMX_EXIT_CTLS: Msr = Msr::new(0x483);
    pub const VMX_ENTRY_CTLS: Msr = Msr::new(0x484);
    pub const VMX_TRUE_PINBASED_CTLS: Msr = Msr::new(0x48D);
    pub const VMX_TRUE_PROCBASED_CTLS: Msr = Msr::new(0x48E);
    pub const VMX_TRUE_EXIT_CTLS: Msr = Msr::new(0x48F);
    pub const VMX_TRUE_ENTRY_CTLS: Msr = Msr::new(0x490);
}

/// VMCS fields encoding.of 64 bits control fields.
///
/// See appendix B.
#[rustfmt::skip]
#[repr(u32)]
pub enum VmcsCtrl64 {
    IoBitmapA         = 0x00002000,
    IoBitmapB         = 0x00002002,
    MsrBitmaps        = 0x00002004,
    VmExitStoreAddr   = 0x00002006,
    VmExitLoadAddr    = 0x00002008,
    VmEntryLoadAddr   = 0x0000200A,
    ExecVmcsPtr       = 0x0000200C,
    PmlAddr           = 0x0000200E,
    TscOffset         = 0x00002010,
    VirtApicAddr      = 0x00002012,
    ApicAccessAddr    = 0x00002014,
    PostedIntDescAddr = 0x00002016,
    VmFuncCtrls       = 0x00002018,
    EptPtr            = 0x0000201A,
    EoiExitBitmap0    = 0x0000201C,
    EoiExitBitmap1    = 0x0000201E,
    EoiExitBitmap2    = 0x00002020,
    EoiExitBitmap3    = 0x00002022,
    EptpListAddr      = 0x00002024,
    VmreadBitmapAddr  = 0x00002026,
    VmwriteBitmapAddr = 0x00002028,
    VirtExceptInfAddr = 0x0000202A,
    XssExitBitmap     = 0x0000202C,
    EnclsExitBitmap   = 0x0000202E,
    TscMultiplier     = 0x00002032,
}

/// VMCS fields encoding.of 32 bits control fields.
///
/// See appendix B.
#[rustfmt::skip]
#[repr(u32)]
pub enum VmcsCtrl32 {
    PinBasedExecCtrls             = 0x00004000,
    PrimaryProcBasedExecCtrls     = 0x00004002,
    ExceptionBitmap               = 0x00004004,
    PageFaultErrCodeMask          = 0x00004006,
    PageFaultErrCodeMatch         = 0x00004008,
    Cr3TargetCount                = 0x0000400A,
    VmExitCtrls                   = 0x0000400C,
    VmExitMsrStoreCount           = 0x0000400E,
    VmExitMsrLoadCount            = 0x00004010,
    VmEntryCtrls                  = 0x00004012,
    VmEntryMsrLoadCount           = 0x00004014,
    VmEntryIntInfoField           = 0x00004016,
    VmEntryExceptErrCode          = 0x00004018,
    VmEntryInstrLenght            = 0x0000401A,
    TprThreshold                  = 0x0000401C,
    SecondaryProcBasedVmExecCtrls = 0x0000401E,
    PleGap                        = 0x00004020,
    PleWindow                     = 0x00004022,
}

/// VMCS fields containing host state fields.
///
/// See appendix B.
#[rustfmt::skip]
#[repr(u32)]
pub enum VmcsHostState {
    Cr0             = 0x00006C00,
    Cr3             = 0x00006C02,
    Cr4             = 0x00006C04,
    FsBase          = 0x00006C06,
    GsBase          = 0x00006C08,
    TrBase          = 0x00006C0A,
    GdtrBase        = 0x00006C0C,
    IdtrBase        = 0x00006C0E,
    Ia32SysenterEsp = 0x00006C10,
    Ia32SysenterEip = 0x00006C12,
    Rsp             = 0x00006C14,
    Rip             = 0x00006C16,
}

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

#[derive(Debug, PartialEq, Eq)]
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
    asm!("vmxon ({0})", in(reg) &phys_addr, options(att_syntax));
    vmx_capture_status()
}

/// Exits VMX operations
pub unsafe fn vmxoff() -> Result<(), VmxError> {
    asm!("vmxoff");
    vmx_capture_status()
}

/// Clears the VMCS at the provided physical address.
unsafe fn vmclear(addr: PhysAddr) -> Result<(), VmxError> {
    let addr = addr.as_u64();
    asm! {"vmclear ({0})", in(reg) &addr, options(att_syntax)};
    vmx_capture_status()
}

/// Writes to the current VMCS.
unsafe fn vmwrite64(field: VmcsCtrl64, value: u64) -> Result<(), VmxError> {
    let field: u64 = field as u64;
    asm!("vmwrite {1}, {0}", in(reg) field, in(reg) value, options(att_syntax));
    vmx_capture_status()
}

/// Writes to the current VMCS.
unsafe fn vmwrite32(field: VmcsCtrl32, value: u32) -> Result<(), VmxError> {
    let field: u64 = field as u64;
    let value: u64 = value as u64;
    asm!("vmwrite {1}, {0}", in(reg) field, in(reg) value, options(att_syntax));
    vmx_capture_status()
}

/// Writes to the current VMCS.
unsafe fn vmwrite_nat_width(field: VmcsHostState, value: usize) -> Result<(), VmxError> {
    let field: u64 = field as u64;
    let value: u64 = value as u64;
    asm!("vmwrite {1}, {0}", in(reg) field, in(reg) value, options(att_syntax));
    vmx_capture_status()
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
        vmclear(phys_addr)?;

        Ok(VmcsRegion {
            phys_addr,
            _vma: vmcs_vma,
        })
    }

    /// Makes this region the current active region.
    pub unsafe fn set_as_active(&self) -> Result<(), VmxError> {
        asm!("vmptrld ({0})", in(reg) &self.phys_addr, options(att_syntax));
        vmx_capture_status()
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
                VmcsCtrl32::PinBasedExecCtrls,
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
                VmcsCtrl32::PrimaryProcBasedExecCtrls,
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
                VmcsCtrl32::VmExitCtrls,
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
                VmcsCtrl32::VmEntryCtrls,
            )
        }
    }

    /// Sets the exception bitmap.
    ///
    /// WARNING: the region must be active, otherwise this function might modify another VMCS.
    pub fn set_exception_bitmap(&mut self, bitmap: ExceptionBitmap) -> Result<(), VmxError> {
        // TODO: is there a list of allowed settings?
        unsafe { vmwrite32(VmcsCtrl32::ExceptionBitmap, bitmap.bits()) }
    }

    /// Saves the host control registers, so that they are restored on VM Exit.
    ///
    /// WARNING: the region must be active, otherwise this function might modify another VMCS.
    pub fn save_control_register(&mut self) -> Result<(), VmxError> {
        let cr0 = Cr0::read();
        let (_, cr3) = Cr3::read();
        let cr4 = Cr4::read();

        unsafe {
            vmwrite_nat_width(VmcsHostState::Cr0, cr0.bits() as usize)?;
            vmwrite_nat_width(VmcsHostState::Cr3, cr3.bits() as usize)?;
            vmwrite_nat_width(VmcsHostState::Cr4, cr4.bits() as usize)
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
        control: VmcsCtrl32,
    ) -> Result<(), VmxError> {
        let vmx_info = get_vmx_info();
        let spec = spec_msr.read();
        let new_flags = if vmx_info.support_true_ctls {
            let true_spec = true_spec_msr.read();
            Self::get_true_ctls(raw_flags, spec, true_spec, known)?
        } else {
            Self::get_ctls(raw_flags, spec, known)?
        };

        vmwrite32(control, new_flags)
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
        const NMI_EXITING                = 1 << 3;
        /// Virtual NMIs.
        const VIRTUAL_NMIS               = 1 << 5;
        /// Activate VMX-preemption timer.
        const VMX_PREEMPTION_TIMER       = 1 << 6;
        /// Process posted interrupts.
        const POSTED_INTERRUPTS          = 1 << 7;
    }

    /// Primary processor-based VM-execution controls.
    ///
    /// A set of bitmask flags useful when setting up [`PRIMARY_PROCBASED_EXEC_CONTROLS`] VMCS field.
    ///
    /// See Intel SDM, Volume 3C, Section 24.6.2, Table 24-6.
    pub struct PrimaryControls: u32 {
        /// Interrupt-window exiting.
        const INTERRUPT_WINDOW_EXITING = 1 << 2;
        /// Use TSC offsetting.
        const USE_TSC_OFFSETTING       = 1 << 3;
        /// HLT exiting.
        const HLT_EXITING              = 1 << 7;
        /// INVLPG exiting.
        const INVLPG_EXITING           = 1 << 9;
        /// MWAIT exiting.
        const MWAIT_EXITING            = 1 << 10;
        /// RDPMC exiting.
        const RDPMC_EXITING            = 1 << 11;
        /// RDTSC exiting.
        const RDTSC_EXITING            = 1 << 12;
        /// CR3-load exiting.
        const CR3_LOAD_EXITING         = 1 << 15;
        /// CR3-store exiting.
        const CR3_STORE_EXITING        = 1 << 16;
        /// CR8-load exiting.
        const CR8_LOAD_EXITING         = 1 << 19;
        /// CR8-store exiting.
        const CR8_STORE_EXITING        = 1 << 20;
        /// Use TPR shadow.
        const USE_TPR_SHADOW           = 1 << 21;
        /// NMI-window exiting.
        const NMI_WINDOW_EXITING       = 1 << 22;
        /// MOV-DR exiting
        const MOV_DR_EXITING           = 1 << 23;
        /// Unconditional I/O exiting.
        const UNCOND_IO_EXITING        = 1 << 24;
        /// Use I/O bitmaps.
        const USE_IO_BITMAPS           = 1 << 25;
        /// Monitor trap flag.
        const MONITOR_TRAP_FLAG        = 1 << 27;
        /// Use MSR bitmaps.
        const USE_MSR_BITMAPS          = 1 << 28;
        /// MONITOR exiting.
        const MONITOR_EXITING          = 1 << 29;
        /// PAUSE exiting.
        const PAUSE_EXITING            = 1 << 30;
        /// Activate secondary controls.
        const SECONDARY_CONTROLS       = 1 << 31;
    }

    /// VM-exit controls.
    ///
    /// A set of bitmask flags useful when setting up [`VMEXIT_CONTROLS`] VMCS field.
    ///
    /// See Intel SDM, Volume 3C, Section 24.7.
    pub struct ExitControls: u32 {
        /// Save debug controls.
        const SAVE_DEBUG_CONTROLS        = 1 << 2;
        /// Host address-space size.
        const HOST_ADDRESS_SPACE_SIZE    = 1 << 9;
        /// Load IA32_PERF_GLOBAL_CTRL.
        const LOAD_IA32_PERF_GLOBAL_CTRL = 1 << 12;
        /// Acknowledge interrupt on exit.
        const ACK_INTERRUPT_ON_EXIT      = 1 << 15;
        /// Save IA32_PAT.
        const SAVE_IA32_PAT              = 1 << 18;
        /// Load IA32_PAT.
        const LOAD_IA32_PAT              = 1 << 19;
        /// Save IA32_EFER.
        const SAVE_IA32_EFER             = 1 << 20;
        /// Load IA32_EFER.
        const LOAD_IA32_EFER             = 1 << 21;
        /// Save VMX-preemption timer.
        const SAVE_VMX_PREEMPTION_TIMER  = 1 << 22;
        /// Clear IA32_BNDCFGS.
        const CLEAR_IA32_BNDCFGS         = 1 << 23;
        /// Conceal VMX from PT.
        const CONCEAL_VMX_FROM_PT        = 1 << 24;
        /// Clear IA32_RTIT_CTL.
        const CLEAR_IA32_RTIT_CTL        = 1 << 25;
    }

    /// VM-entry controls.
    ///
    /// A set of bitmask flags useful when setting up [`VMENTRY_CONTROLS`] VMCS field.
    ///
    /// See Intel SDM, Volume 3C, Section 24.8.
    pub struct EntryControls: u32 {
        /// Load debug controls.
        const LOAD_DEBUG_CONTROLS        = 1 << 2;
        /// IA-32e mode guest.
        const IA32E_MODE_GUEST           = 1 << 9;
        /// Entry to SMM.
        const ENTRY_TO_SMM               = 1 << 10;
        /// Deactivate dual-monitor treatment.
        const DEACTIVATE_DUAL_MONITOR    = 1 << 11;
        /// Load IA32_PERF_GLOBAL_CTRL.
        const LOAD_IA32_PERF_GLOBAL_CTRL = 1 << 13;
        /// Load IA32_PAT.
        const LOAD_IA32_PAT              = 1 << 14;
        /// Load IA32_EFER.
        const LOAD_IA32_EFER             = 1 << 15;
        /// Load IA32_BNDCFGS.
        const LOAD_IA32_BNDCFGS          = 1 << 16;
        /// Conceal VMX from PT.
        const CONCEAL_VMX_FROM_PT        = 1 << 17;
        /// Load IA32_RTIT_CTL.
        const LOAD_IA32_RTIT_CTL         = 1 << 18;
    }

    pub struct ExceptionBitmap: u32 {
        // Dive Error #DE
        const DIVIDE_ERROR             = 1 << 0;
        // Debug #DB
        const DEBUG                    = 1 << 1;
        // Non Maskable Interrupt (NMI)
        const NMI                      = 1 << 2;
        // Breakpoint #BP
        const BREAKPOINT               = 1 << 3;
        // Overflow #OF
        const OVERFLOW                 = 1 << 4;
        // Bound range exceeded #BR
        const BOUND_RANGE_EXCEEDED     = 1 << 5;
        // Invalid Opcode #UD
        const INVALID_OPCODE           = 1 << 6;
        // Device not available #NM
        const DEVICE_NOT_AVAILABLE     = 1 << 7;
        // Double fault
        const DOUBLE_FAULT             = 1 << 8;
        // Invalid TSS exception #TS
        const INVALID_TSS              = 1 << 10;
        // Segment not present #NP
        const SEGMENT_NOT_PRESENT      = 1 << 11;
        // Stack segment #SS
        const STACK_SEGMENT_FAULT      = 1 << 12;
        // General protection fault #GP
        const GENERAL_PROTECTION_FAULT = 1 << 13;
        // Page fault #PF
        const PAGE_FAULT               = 1 << 14;
        // x87 floating point #MF
        const X87_FLOATING_POINT       = 1 << 16;
        // Alignment check #AC
        const ALIGNMENT_CHECK          = 1 << 17;
        // Machine check #MC
        const MACHINE_CHECK            = 1 << 18;
        // SIMD floating point #XF
        const SIMD_FLOATING_POINT      = 1 << 19;
        // ?
        const VIRTUALIZATION           = 1 << 20;
        // VMM communication #VC
        const VMM_COMMUNICATION        = 1 << 29;
        // Security #SX
        const SECURITY_EXCEPTION       = 1 << 30;
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
