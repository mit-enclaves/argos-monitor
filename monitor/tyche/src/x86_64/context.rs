use capa_engine::Handle;
use spin::Mutex;
use vmx::fields::{GeneralPurposeField as GPF, VmcsField, VmcsFieldWidth, REGFILE_SIZE};
use vmx::msr::IA32_LSTAR;
use vmx::ActiveVmcs;

use crate::rcframe::{RCFrame, RCFramePool};

#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(usize)]
pub enum ContextGpx86 {
    Rax = 0,
    Rbx = 1,
    Rcx = 2,
    Rdx = 3,
    Rbp = 4,
    Rsi = 5,
    Rdi = 6,
    R8 = 7,
    R9 = 8,
    R10 = 9,
    R11 = 10,
    R12 = 11,
    R13 = 12,
    R14 = 13,
    R15 = 14,
    Lstar = 15,
}

#[allow(dead_code)]
impl ContextGpx86 {
    pub fn as_vmcs_field(&self) -> VmcsField {
        match self {
            Self::Rax => VmcsField::GuestRax,
            Self::Rbx => VmcsField::GuestRbx,
            Self::Rcx => VmcsField::GuestRcx,
            Self::Rdx => VmcsField::GuestRdx,
            Self::Rbp => VmcsField::GuestRbp,
            Self::Rsi => VmcsField::GuestRsi,
            Self::Rdi => VmcsField::GuestRdi,
            Self::R8 => VmcsField::GuestR8,
            Self::R9 => VmcsField::GuestR9,
            Self::R10 => VmcsField::GuestR10,
            Self::R11 => VmcsField::GuestR11,
            Self::R12 => VmcsField::GuestR12,
            Self::R13 => VmcsField::GuestR13,
            Self::R14 => VmcsField::GuestR14,
            Self::R15 => VmcsField::GuestR15,
            Self::Lstar => VmcsField::GuestLstar,
        }
    }
    pub fn from_vmcs_field(field: VmcsField) -> Option<Self> {
        match field {
            VmcsField::GuestRax => Some(Self::Rax),
            VmcsField::GuestRbx => Some(Self::Rbx),
            VmcsField::GuestRcx => Some(Self::Rcx),
            VmcsField::GuestRdx => Some(Self::Rdx),
            VmcsField::GuestRbp => Some(Self::Rbp),
            VmcsField::GuestRsi => Some(Self::Rsi),
            VmcsField::GuestRdi => Some(Self::Rdi),
            VmcsField::GuestR8 => Some(Self::R8),
            VmcsField::GuestR9 => Some(Self::R9),
            VmcsField::GuestR10 => Some(Self::R10),
            VmcsField::GuestR11 => Some(Self::R11),
            VmcsField::GuestR12 => Some(Self::R12),
            VmcsField::GuestR13 => Some(Self::R13),
            VmcsField::GuestR14 => Some(Self::R14),
            VmcsField::GuestR15 => Some(Self::R15),
            VmcsField::GuestLstar => Some(Self::Lstar),
            _ => None,
        }
    }

    pub fn from_usize(v: usize) -> Self {
        match v {
            0 => Self::Rax,
            1 => Self::Rbx,
            2 => Self::Rcx,
            3 => Self::Rdx,
            4 => Self::Rbp,
            5 => Self::Rsi,
            6 => Self::Rdi,
            7 => Self::R8,
            8 => Self::R9,
            9 => Self::R10,
            10 => Self::R11,
            11 => Self::R12,
            12 => Self::R13,
            13 => Self::R14,
            14 => Self::R15,
            15 => Self::Lstar,
            _ => panic!("Invalid value"),
        }
    }
    pub const fn size() -> usize {
        return Self::Lstar as usize + 1;
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(usize)]
pub enum Context64x86 {
    PinBasedVmExecControl = 0,
    CpuBasedVmExecControl,
    ExceptionBitmap,
    PageFaultErrorCodeMask,
    PageFaultErrorCodeMatch,
    Cr3TargetCount,
    VmExitControls,
    VmExitMsrStoreCount,
    VmExitMsrLoadCount,
    VmEntryControls,
    VmEntryMsrLoadCount,
    VmEntryIntrInfoField,
    VmEntryExceptionErrorCode,
    VmEntryInstructionLen,
    TprThreshold,
    SecondaryVmExecControl,
    PleGap,
    PleWindow,
    NotifyWindow,
    VmInstructionError,
    VmExitReason,
    VmExitIntrInfo,
    VmExitIntrErrorCode,
    IdtVectoringInfoField,
    IdtVectoringErrorCode,
    VmExitInstructionLen,
    VmxInstructionInfo,
    GuestEsLimit,
    GuestCsLimit,
    GuestSsLimit,
    GuestDsLimit,
    GuestFsLimit,
    GuestGsLimit,
    GuestLdtrLimit,
    GuestTrLimit,
    GuestGdtrLimit,
    GuestIdtrLimit,
    GuestEsArBytes,
    GuestCsArBytes,
    GuestSsArBytes,
    GuestDsArBytes,
    GuestFsArBytes,
    GuestGsArBytes,
    GuestLdtrArBytes,
    GuestTrArBytes,
    GuestInterruptibilityInfo,
    GuestActivityState,
    GuestSysenterCs,
    VmxPreemptionTimerValue,
}

#[allow(dead_code)]
impl Context64x86 {
    pub fn as_vmcs_field(&self) -> VmcsField {
        match self {
            Self::PinBasedVmExecControl => VmcsField::PinBasedVmExecControl,
            Self::CpuBasedVmExecControl => VmcsField::CpuBasedVmExecControl,
            Self::ExceptionBitmap => VmcsField::ExceptionBitmap,
            Self::PageFaultErrorCodeMask => VmcsField::PageFaultErrorCodeMask,
            Self::PageFaultErrorCodeMatch => VmcsField::PageFaultErrorCodeMatch,
            Self::Cr3TargetCount => VmcsField::Cr3TargetCount,
            Self::VmExitControls => VmcsField::VmExitControls,
            Self::VmExitMsrStoreCount => VmcsField::VmExitMsrStoreCount,
            Self::VmExitMsrLoadCount => VmcsField::VmExitMsrLoadCount,
            Self::VmEntryControls => VmcsField::VmEntryControls,
            Self::VmEntryMsrLoadCount => VmcsField::VmEntryMsrLoadCount,
            Self::VmEntryIntrInfoField => VmcsField::VmEntryIntrInfoField,
            Self::VmEntryExceptionErrorCode => VmcsField::VmEntryExceptionErrorCode,
            Self::VmEntryInstructionLen => VmcsField::VmEntryInstructionLen,
            Self::TprThreshold => VmcsField::TprThreshold,
            Self::SecondaryVmExecControl => VmcsField::SecondaryVmExecControl,
            Self::PleGap => VmcsField::PleGap,
            Self::PleWindow => VmcsField::PleWindow,
            Self::NotifyWindow => VmcsField::NotifyWindow,
            Self::VmInstructionError => VmcsField::VmInstructionError,
            Self::VmExitReason => VmcsField::VmExitReason,
            Self::VmExitIntrInfo => VmcsField::VmExitIntrInfo,
            Self::VmExitIntrErrorCode => VmcsField::VmExitIntrErrorCode,
            Self::IdtVectoringInfoField => VmcsField::IdtVectoringInfoField,
            Self::IdtVectoringErrorCode => VmcsField::IdtVectoringErrorCode,
            Self::VmExitInstructionLen => VmcsField::VmExitInstructionLen,
            Self::VmxInstructionInfo => VmcsField::VmxInstructionInfo,
            Self::GuestEsLimit => VmcsField::GuestEsLimit,
            Self::GuestCsLimit => VmcsField::GuestCsLimit,
            Self::GuestSsLimit => VmcsField::GuestSsLimit,
            Self::GuestDsLimit => VmcsField::GuestDsLimit,
            Self::GuestFsLimit => VmcsField::GuestFsLimit,
            Self::GuestGsLimit => VmcsField::GuestGsLimit,
            Self::GuestLdtrLimit => VmcsField::GuestLdtrLimit,
            Self::GuestTrLimit => VmcsField::GuestTrLimit,
            Self::GuestGdtrLimit => VmcsField::GuestGdtrLimit,
            Self::GuestIdtrLimit => VmcsField::GuestIdtrLimit,
            Self::GuestEsArBytes => VmcsField::GuestEsArBytes,
            Self::GuestCsArBytes => VmcsField::GuestCsArBytes,
            Self::GuestSsArBytes => VmcsField::GuestSsArBytes,
            Self::GuestDsArBytes => VmcsField::GuestDsLimit,
            Self::GuestFsArBytes => VmcsField::GuestFsArBytes,
            Self::GuestGsArBytes => VmcsField::GuestGsArBytes,
            Self::GuestLdtrArBytes => VmcsField::GuestLdtrArBytes,
            Self::GuestTrArBytes => VmcsField::GuestTrArBytes,
            Self::GuestInterruptibilityInfo => VmcsField::GuestInterruptibilityInfo,
            Self::GuestActivityState => VmcsField::GuestActivityState,
            Self::GuestSysenterCs => VmcsField::GuestSysenterCs,
            Self::VmxPreemptionTimerValue => VmcsField::VmxPreemptionTimerValue,
        }
    }

    pub fn from_vmcs_field(field: VmcsField) -> Option<Self> {
        match field {
            VmcsField::PinBasedVmExecControl => Some(Self::PinBasedVmExecControl),
            VmcsField::CpuBasedVmExecControl => Some(Self::CpuBasedVmExecControl),
            VmcsField::ExceptionBitmap => Some(Self::ExceptionBitmap),
            VmcsField::PageFaultErrorCodeMask => Some(Self::PageFaultErrorCodeMask),
            VmcsField::PageFaultErrorCodeMatch => Some(Self::PageFaultErrorCodeMatch),
            VmcsField::Cr3TargetCount => Some(Self::Cr3TargetCount),
            VmcsField::VmExitControls => Some(Self::VmExitControls),
            VmcsField::VmExitMsrStoreCount => Some(Self::VmExitMsrStoreCount),
            VmcsField::VmExitMsrLoadCount => Some(Self::VmExitMsrLoadCount),
            VmcsField::VmEntryControls => Some(Self::VmEntryControls),
            VmcsField::VmEntryMsrLoadCount => Some(Self::VmEntryMsrLoadCount),
            VmcsField::VmEntryIntrInfoField => Some(Self::VmEntryIntrInfoField),
            VmcsField::VmEntryExceptionErrorCode => Some(Self::VmEntryExceptionErrorCode),
            VmcsField::VmEntryInstructionLen => Some(Self::VmEntryInstructionLen),
            VmcsField::TprThreshold => Some(Self::TprThreshold),
            VmcsField::SecondaryVmExecControl => Some(Self::SecondaryVmExecControl),
            VmcsField::PleGap => Some(Self::PleGap),
            VmcsField::PleWindow => Some(Self::PleWindow),
            VmcsField::NotifyWindow => Some(Self::NotifyWindow),
            VmcsField::VmInstructionError => Some(Self::VmInstructionError),
            VmcsField::VmExitReason => Some(Self::VmExitReason),
            VmcsField::VmExitIntrInfo => Some(Self::VmExitIntrInfo),
            VmcsField::VmExitIntrErrorCode => Some(Self::VmExitIntrErrorCode),
            VmcsField::IdtVectoringInfoField => Some(Self::IdtVectoringInfoField),
            VmcsField::IdtVectoringErrorCode => Some(Self::IdtVectoringErrorCode),
            VmcsField::VmExitInstructionLen => Some(Self::VmExitInstructionLen),
            VmcsField::VmxInstructionInfo => Some(Self::VmxInstructionInfo),
            VmcsField::GuestEsLimit => Some(Self::GuestEsLimit),
            VmcsField::GuestCsLimit => Some(Self::GuestCsLimit),
            VmcsField::GuestSsLimit => Some(Self::GuestSsLimit),
            VmcsField::GuestDsLimit => Some(Self::GuestDsLimit),
            VmcsField::GuestFsLimit => Some(Self::GuestFsLimit),
            VmcsField::GuestGsLimit => Some(Self::GuestGsLimit),
            VmcsField::GuestLdtrLimit => Some(Self::GuestLdtrLimit),
            VmcsField::GuestTrLimit => Some(Self::GuestTrLimit),
            VmcsField::GuestGdtrLimit => Some(Self::GuestGdtrLimit),
            VmcsField::GuestIdtrLimit => Some(Self::GuestIdtrLimit),
            VmcsField::GuestEsArBytes => Some(Self::GuestEsArBytes),
            VmcsField::GuestCsArBytes => Some(Self::GuestCsArBytes),
            VmcsField::GuestSsArBytes => Some(Self::GuestSsArBytes),
            VmcsField::GuestDsArBytes => Some(Self::GuestDsLimit),
            VmcsField::GuestFsArBytes => Some(Self::GuestFsArBytes),
            VmcsField::GuestGsArBytes => Some(Self::GuestGsArBytes),
            VmcsField::GuestLdtrArBytes => Some(Self::GuestLdtrArBytes),
            VmcsField::GuestTrArBytes => Some(Self::GuestTrArBytes),
            VmcsField::GuestInterruptibilityInfo => Some(Self::GuestInterruptibilityInfo),
            VmcsField::GuestActivityState => Some(Self::GuestActivityState),
            VmcsField::GuestSysenterCs => Some(Self::GuestSysenterCs),
            VmcsField::VmxPreemptionTimerValue => Some(Self::VmxPreemptionTimerValue),
            _ => None,
        }
    }

    pub fn from_usize(v: usize) -> Self {
        match v {
            0 => Self::PinBasedVmExecControl,
            1 => Self::CpuBasedVmExecControl,
            2 => Self::ExceptionBitmap,
            3 => Self::PageFaultErrorCodeMask,
            4 => Self::PageFaultErrorCodeMatch,
            5 => Self::Cr3TargetCount,
            6 => Self::VmExitControls,
            7 => Self::VmExitMsrStoreCount,
            8 => Self::VmExitMsrLoadCount,
            9 => Self::VmEntryControls,
            10 => Self::VmEntryMsrLoadCount,
            11 => Self::VmEntryIntrInfoField,
            12 => Self::VmEntryExceptionErrorCode,
            13 => Self::VmEntryInstructionLen,
            14 => Self::TprThreshold,
            15 => Self::SecondaryVmExecControl,
            16 => Self::PleGap,
            17 => Self::PleWindow,
            18 => Self::NotifyWindow,
            19 => Self::VmInstructionError,
            20 => Self::VmExitReason,
            21 => Self::VmExitIntrInfo,
            22 => Self::VmExitIntrErrorCode,
            23 => Self::IdtVectoringInfoField,
            24 => Self::IdtVectoringErrorCode,
            25 => Self::VmExitInstructionLen,
            26 => Self::VmxInstructionInfo,
            27 => Self::GuestEsLimit,
            28 => Self::GuestCsLimit,
            29 => Self::GuestSsLimit,
            30 => Self::GuestDsLimit,
            31 => Self::GuestFsLimit,
            32 => Self::GuestGsLimit,
            33 => Self::GuestLdtrLimit,
            34 => Self::GuestTrLimit,
            35 => Self::GuestGdtrLimit,
            36 => Self::GuestIdtrLimit,
            37 => Self::GuestEsArBytes,
            38 => Self::GuestCsArBytes,
            39 => Self::GuestSsArBytes,
            40 => Self::GuestDsArBytes,
            41 => Self::GuestFsArBytes,
            42 => Self::GuestGsArBytes,
            43 => Self::GuestLdtrArBytes,
            44 => Self::GuestTrArBytes,
            45 => Self::GuestInterruptibilityInfo,
            46 => Self::GuestActivityState,
            47 => Self::GuestSysenterCs,
            48 => Self::VmxPreemptionTimerValue,
            _ => panic!("Invalid value"),
        }
    }

    pub const fn size() -> usize {
        return Self::VmxPreemptionTimerValue as usize + 1;
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(usize)]
pub enum Context32x86 {
    IoBitmapA = 0,
    IoBitmapAHigh,
    IoBitmapB,
    IoBitmapBHigh,
    MsrBitmap,
    MsrBitmapHigh,
    VmExitMsrStoreAddr,
    VmExitMsrStoreAddrHigh,
    VmExitMsrLoadAddr,
    VMExitMsrLoadAddrHigh,
    VmEntryMsrLoadAddr,
    VmEntryMsrLoadAddrHigh,
    PmlAddress,
    PmlAddressHigh,
    TscOffset,
    TscOffsetHigh,
    VirtualApicPageAddr,
    VirtualApicPageAddrHigh,
    ApicAccessAddr,
    ApicAccessAddrHigh,
    PostedIntrDescAddr,
    PostedIntrDescAddrHigh,
    VmFunctionControl,
    VmFunctionControlHigh,
    EptPointer,
    EptPointerHigh,
    EoiExitBitmap0,
    EoiExitBitmap0High,
    EoiExitBitmap1,
    EoiExitBitmap1High,
    EoiExitBitmap2,
    EoiExitBitmap2High,
    EoiExitBitmap3,
    EoiExitBitmap3High,
    EptpListAddress,
    EptpListAddressHigh,
    VmreadBitmap,
    VmreadBitmapHigh,
    VmwriteBitmap,
    VmwriteBitmapHigh,
    XssExitBitmap,
    XssExitBitmapHigh,
    EnclsExitingBitmap,
    EnclsExitingBitmapHigh,
    TscMultiplier,
    TscMultiplierHigh,
    TertiaryVmExecControl,
    TertiaryVmExecControlHigh,
    PidPointerTable,
    PidPointerTableHigh,
    GuestPhysicalAddress,
    GuestPhysicalAddressHigh,
    VmcsLinkPointer,
    VmcsLinkPointerHigh,
    GuestIa32Debugctl,
    GuestIa32DebugctlHigh,
    GuestIa32Pat,
    GuestIa32PatHigh,
    GuestIa32Efer,
    GuestIa32EferHigh,
    GuestIa32PerfGlobalCtrl,
    GuestIa32PerfGlobalCtrlHigh,
    GuestPdptr0,
    GuestPdprt0High,
    GuestPdptr1,
    GuestPdptr1High,
    GuestPdptr2,
    GuestPdptr2High,
    GuestPdptr3,
    GuestPdptr3High,
    GuestBndcfgs,
    GuestBndcfgsHigh,
    GuestIa32RtitCtl,
    GuestIa32RtitCtlHigh,
    HostIa32Pat,
    HostIa32PatHigh,
    HostIa32Efer,
    HostIa32EferHigh,
    HostIa32PerfGlobalCtrl,
    HostIa32PerfGlobalCtrlHigh,
}

#[allow(dead_code)]
impl Context32x86 {
    pub fn as_vmcs_field(&self) -> VmcsField {
        match self {
            Self::IoBitmapA => VmcsField::IoBitmapA,
            Self::IoBitmapAHigh => VmcsField::IoBitmapAHigh,
            Self::IoBitmapB => VmcsField::IoBitmapB,
            Self::IoBitmapBHigh => VmcsField::IoBitmapBHigh,
            Self::MsrBitmap => VmcsField::MsrBitmap,
            Self::MsrBitmapHigh => VmcsField::MsrBitmapHigh,
            Self::VmExitMsrStoreAddr => VmcsField::VmExitMsrStoreAddr,
            Self::VmExitMsrStoreAddrHigh => VmcsField::VmExitMsrStoreAddrHigh,
            Self::VmExitMsrLoadAddr => VmcsField::VmExitMsrLoadAddr,
            Self::VMExitMsrLoadAddrHigh => VmcsField::VMExitMsrLoadAddrHigh,
            Self::VmEntryMsrLoadAddr => VmcsField::VmEntryMsrLoadAddr,
            Self::VmEntryMsrLoadAddrHigh => VmcsField::VmEntryMsrLoadAddrHigh,
            Self::PmlAddress => VmcsField::PmlAddress,
            Self::PmlAddressHigh => VmcsField::PmlAddressHigh,
            Self::TscOffset => VmcsField::TscOffset,
            Self::TscOffsetHigh => VmcsField::TscOffsetHigh,
            Self::VirtualApicPageAddr => VmcsField::VirtualApicPageAddr,
            Self::VirtualApicPageAddrHigh => VmcsField::VirtualApicPageAddrHigh,
            Self::ApicAccessAddr => VmcsField::ApicAccessAddr,
            Self::ApicAccessAddrHigh => VmcsField::ApicAccessAddrHigh,
            Self::PostedIntrDescAddr => VmcsField::PostedIntrDescAddr,
            Self::PostedIntrDescAddrHigh => VmcsField::PostedIntrDescAddrHigh,
            Self::VmFunctionControl => VmcsField::VmFunctionControl,
            Self::VmFunctionControlHigh => VmcsField::VmFunctionControlHigh,
            Self::EptPointer => VmcsField::EptPointer,
            Self::EptPointerHigh => VmcsField::EptPointerHigh,
            Self::EoiExitBitmap0 => VmcsField::EoiExitBitmap0,
            Self::EoiExitBitmap0High => VmcsField::EoiExitBitmap0High,
            Self::EoiExitBitmap1 => VmcsField::EoiExitBitmap1,
            Self::EoiExitBitmap1High => VmcsField::EoiExitBitmap1High,
            Self::EoiExitBitmap2 => VmcsField::EoiExitBitmap2,
            Self::EoiExitBitmap2High => VmcsField::EoiExitBitmap2High,
            Self::EoiExitBitmap3 => VmcsField::EoiExitBitmap3,
            Self::EoiExitBitmap3High => VmcsField::EoiExitBitmap3High,
            Self::EptpListAddress => VmcsField::EptpListAddress,
            Self::EptpListAddressHigh => VmcsField::EptpListAddressHigh,
            Self::VmreadBitmap => VmcsField::VmreadBitmap,
            Self::VmreadBitmapHigh => VmcsField::VmreadBitmapHigh,
            Self::VmwriteBitmap => VmcsField::VmwriteBitmap,
            Self::VmwriteBitmapHigh => VmcsField::VmwriteBitmapHigh,
            Self::XssExitBitmap => VmcsField::XssExitBitmap,
            Self::XssExitBitmapHigh => VmcsField::XssExitBitmapHigh,
            Self::EnclsExitingBitmap => VmcsField::EnclsExitingBitmap,
            Self::EnclsExitingBitmapHigh => VmcsField::EnclsExitingBitmapHigh,
            Self::TscMultiplier => VmcsField::TscMultiplier,
            Self::TscMultiplierHigh => VmcsField::TscMultiplierHigh,
            Self::TertiaryVmExecControl => VmcsField::TertiaryVmExecControl,
            Self::TertiaryVmExecControlHigh => VmcsField::TertiaryVmExecControlHigh,
            Self::PidPointerTable => VmcsField::PidPointerTable,
            Self::PidPointerTableHigh => VmcsField::PidPointerTableHigh,
            Self::GuestPhysicalAddress => VmcsField::GuestPhysicalAddress,
            Self::GuestPhysicalAddressHigh => VmcsField::GuestPhysicalAddressHigh,
            Self::VmcsLinkPointer => VmcsField::VmcsLinkPointerHigh,
            Self::VmcsLinkPointerHigh => VmcsField::VmcsLinkPointerHigh,
            Self::GuestIa32Debugctl => VmcsField::GuestIa32Debugctl,
            Self::GuestIa32DebugctlHigh => VmcsField::GuestIa32DebugctlHigh,
            Self::GuestIa32Pat => VmcsField::GuestIa32Pat,
            Self::GuestIa32PatHigh => VmcsField::GuestIa32PatHigh,
            Self::GuestIa32Efer => VmcsField::GuestIa32Efer,
            Self::GuestIa32EferHigh => VmcsField::GuestIa32EferHigh,
            Self::GuestIa32PerfGlobalCtrl => VmcsField::GuestIa32PerfGlobalCtrl,
            Self::GuestIa32PerfGlobalCtrlHigh => VmcsField::GuestIa32PerfGlobalCtrlHigh,
            Self::GuestPdptr0 => VmcsField::GuestPdptr0,
            Self::GuestPdprt0High => VmcsField::GuestPdprt0High,
            Self::GuestPdptr1 => VmcsField::GuestPdptr1,
            Self::GuestPdptr1High => VmcsField::GuestPdptr1High,
            Self::GuestPdptr2 => VmcsField::GuestPdptr2,
            Self::GuestPdptr2High => VmcsField::GuestPdptr2High,
            Self::GuestPdptr3 => VmcsField::GuestPdptr3,
            Self::GuestPdptr3High => VmcsField::GuestPdptr3High,
            Self::GuestBndcfgs => VmcsField::GuestBndcfgs,
            Self::GuestBndcfgsHigh => VmcsField::GuestBndcfgsHigh,
            Self::GuestIa32RtitCtl => VmcsField::GuestIa32RtitCtl,
            Self::GuestIa32RtitCtlHigh => VmcsField::GuestIa32RtitCtlHigh,
            Self::HostIa32Pat => VmcsField::HostIa32Pat,
            Self::HostIa32PatHigh => VmcsField::HostIa32PatHigh,
            Self::HostIa32Efer => VmcsField::HostIa32Efer,
            Self::HostIa32EferHigh => VmcsField::HostIa32EferHigh,
            Self::HostIa32PerfGlobalCtrl => VmcsField::HostIa32PerfGlobalCtrl,
            Self::HostIa32PerfGlobalCtrlHigh => VmcsField::HostIa32PerfGlobalCtrlHigh,
        }
    }

    pub fn from_vmcs_field(field: VmcsField) -> Option<Self> {
        match field {
            VmcsField::IoBitmapA => Some(Self::IoBitmapA),
            VmcsField::IoBitmapAHigh => Some(Self::IoBitmapAHigh),
            VmcsField::IoBitmapB => Some(Self::IoBitmapB),
            VmcsField::IoBitmapBHigh => Some(Self::IoBitmapBHigh),
            VmcsField::MsrBitmap => Some(Self::MsrBitmap),
            VmcsField::MsrBitmapHigh => Some(Self::MsrBitmapHigh),
            VmcsField::VmExitMsrStoreAddr => Some(Self::VmExitMsrStoreAddr),
            VmcsField::VmExitMsrStoreAddrHigh => Some(Self::VmExitMsrStoreAddrHigh),
            VmcsField::VmExitMsrLoadAddr => Some(Self::VmExitMsrLoadAddr),
            VmcsField::VMExitMsrLoadAddrHigh => Some(Self::VMExitMsrLoadAddrHigh),
            VmcsField::VmEntryMsrLoadAddr => Some(Self::VmEntryMsrLoadAddr),
            VmcsField::VmEntryMsrLoadAddrHigh => Some(Self::VmEntryMsrLoadAddrHigh),
            VmcsField::PmlAddress => Some(Self::PmlAddress),
            VmcsField::PmlAddressHigh => Some(Self::PmlAddressHigh),
            VmcsField::TscOffset => Some(Self::TscOffset),
            VmcsField::TscOffsetHigh => Some(Self::TscOffsetHigh),
            VmcsField::VirtualApicPageAddr => Some(Self::VirtualApicPageAddr),
            VmcsField::VirtualApicPageAddrHigh => Some(Self::VirtualApicPageAddrHigh),
            VmcsField::ApicAccessAddr => Some(Self::ApicAccessAddr),
            VmcsField::ApicAccessAddrHigh => Some(Self::ApicAccessAddrHigh),
            VmcsField::PostedIntrDescAddr => Some(Self::PostedIntrDescAddr),
            VmcsField::PostedIntrDescAddrHigh => Some(Self::PostedIntrDescAddrHigh),
            VmcsField::VmFunctionControl => Some(Self::VmFunctionControl),
            VmcsField::VmFunctionControlHigh => Some(Self::VmFunctionControlHigh),
            VmcsField::EptPointer => Some(Self::EptPointer),
            VmcsField::EptPointerHigh => Some(Self::EptPointerHigh),
            VmcsField::EoiExitBitmap0 => Some(Self::EoiExitBitmap0),
            VmcsField::EoiExitBitmap0High => Some(Self::EoiExitBitmap0High),
            VmcsField::EoiExitBitmap1 => Some(Self::EoiExitBitmap1),
            VmcsField::EoiExitBitmap1High => Some(Self::EoiExitBitmap1High),
            VmcsField::EoiExitBitmap2 => Some(Self::EoiExitBitmap2),
            VmcsField::EoiExitBitmap2High => Some(Self::EoiExitBitmap2High),
            VmcsField::EoiExitBitmap3 => Some(Self::EoiExitBitmap3),
            VmcsField::EoiExitBitmap3High => Some(Self::EoiExitBitmap3High),
            VmcsField::EptpListAddress => Some(Self::EptpListAddress),
            VmcsField::EptpListAddressHigh => Some(Self::EptpListAddressHigh),
            VmcsField::VmreadBitmap => Some(Self::VmreadBitmap),
            VmcsField::VmreadBitmapHigh => Some(Self::VmreadBitmapHigh),
            VmcsField::VmwriteBitmap => Some(Self::VmwriteBitmap),
            VmcsField::VmwriteBitmapHigh => Some(Self::VmwriteBitmapHigh),
            VmcsField::XssExitBitmap => Some(Self::XssExitBitmap),
            VmcsField::XssExitBitmapHigh => Some(Self::XssExitBitmapHigh),
            VmcsField::EnclsExitingBitmap => Some(Self::EnclsExitingBitmap),
            VmcsField::EnclsExitingBitmapHigh => Some(Self::EnclsExitingBitmapHigh),
            VmcsField::TscMultiplier => Some(Self::TscMultiplier),
            VmcsField::TscMultiplierHigh => Some(Self::TscMultiplierHigh),
            VmcsField::TertiaryVmExecControl => Some(Self::TertiaryVmExecControl),
            VmcsField::TertiaryVmExecControlHigh => Some(Self::TertiaryVmExecControlHigh),
            VmcsField::PidPointerTable => Some(Self::PidPointerTable),
            VmcsField::PidPointerTableHigh => Some(Self::PidPointerTableHigh),
            VmcsField::GuestPhysicalAddress => Some(Self::GuestPhysicalAddress),
            VmcsField::GuestPhysicalAddressHigh => Some(Self::GuestPhysicalAddressHigh),
            VmcsField::VmcsLinkPointer => Some(Self::VmcsLinkPointerHigh),
            VmcsField::VmcsLinkPointerHigh => Some(Self::VmcsLinkPointerHigh),
            VmcsField::GuestIa32Debugctl => Some(Self::GuestIa32Debugctl),
            VmcsField::GuestIa32DebugctlHigh => Some(Self::GuestIa32DebugctlHigh),
            VmcsField::GuestIa32Pat => Some(Self::GuestIa32Pat),
            VmcsField::GuestIa32PatHigh => Some(Self::GuestIa32PatHigh),
            VmcsField::GuestIa32Efer => Some(Self::GuestIa32Efer),
            VmcsField::GuestIa32EferHigh => Some(Self::GuestIa32EferHigh),
            VmcsField::GuestIa32PerfGlobalCtrl => Some(Self::GuestIa32PerfGlobalCtrl),
            VmcsField::GuestIa32PerfGlobalCtrlHigh => Some(Self::GuestIa32PerfGlobalCtrlHigh),
            VmcsField::GuestPdptr0 => Some(Self::GuestPdptr0),
            VmcsField::GuestPdprt0High => Some(Self::GuestPdprt0High),
            VmcsField::GuestPdptr1 => Some(Self::GuestPdptr1),
            VmcsField::GuestPdptr1High => Some(Self::GuestPdptr1High),
            VmcsField::GuestPdptr2 => Some(Self::GuestPdptr2),
            VmcsField::GuestPdptr2High => Some(Self::GuestPdptr2High),
            VmcsField::GuestPdptr3 => Some(Self::GuestPdptr3),
            VmcsField::GuestPdptr3High => Some(Self::GuestPdptr3High),
            VmcsField::GuestBndcfgs => Some(Self::GuestBndcfgs),
            VmcsField::GuestBndcfgsHigh => Some(Self::GuestBndcfgsHigh),
            VmcsField::GuestIa32RtitCtl => Some(Self::GuestIa32RtitCtl),
            VmcsField::GuestIa32RtitCtlHigh => Some(Self::GuestIa32RtitCtlHigh),
            VmcsField::HostIa32Pat => Some(Self::HostIa32Pat),
            VmcsField::HostIa32PatHigh => Some(Self::HostIa32PatHigh),
            VmcsField::HostIa32Efer => Some(Self::HostIa32Efer),
            VmcsField::HostIa32EferHigh => Some(Self::HostIa32EferHigh),
            VmcsField::HostIa32PerfGlobalCtrl => Some(Self::HostIa32PerfGlobalCtrl),
            VmcsField::HostIa32PerfGlobalCtrlHigh => Some(Self::HostIa32PerfGlobalCtrlHigh),
            _ => None,
        }
    }

    pub fn from_usize(v: usize) -> Self {
        match v {
            0 => Self::IoBitmapA,
            1 => Self::IoBitmapAHigh,
            2 => Self::IoBitmapB,
            3 => Self::IoBitmapBHigh,
            4 => Self::MsrBitmap,
            5 => Self::MsrBitmapHigh,
            6 => Self::VmExitMsrStoreAddr,
            7 => Self::VmExitMsrStoreAddrHigh,
            8 => Self::VmExitMsrLoadAddr,
            9 => Self::VMExitMsrLoadAddrHigh,
            10 => Self::VmEntryMsrLoadAddr,
            11 => Self::VmEntryMsrLoadAddrHigh,
            12 => Self::PmlAddress,
            13 => Self::PmlAddressHigh,
            14 => Self::TscOffset,
            15 => Self::TscOffsetHigh,
            16 => Self::VirtualApicPageAddr,
            17 => Self::VirtualApicPageAddrHigh,
            18 => Self::ApicAccessAddr,
            19 => Self::ApicAccessAddrHigh,
            20 => Self::PostedIntrDescAddr,
            21 => Self::PostedIntrDescAddrHigh,
            22 => Self::VmFunctionControl,
            23 => Self::VmFunctionControlHigh,
            24 => Self::EptPointer,
            25 => Self::EptPointerHigh,
            26 => Self::EoiExitBitmap0,
            27 => Self::EoiExitBitmap0High,
            28 => Self::EoiExitBitmap1,
            29 => Self::EoiExitBitmap1High,
            30 => Self::EoiExitBitmap2,
            31 => Self::EoiExitBitmap2High,
            32 => Self::EoiExitBitmap3,
            33 => Self::EoiExitBitmap3High,
            34 => Self::EptpListAddress,
            35 => Self::EptpListAddressHigh,
            36 => Self::VmreadBitmap,
            37 => Self::VmreadBitmapHigh,
            38 => Self::VmwriteBitmap,
            39 => Self::VmwriteBitmapHigh,
            40 => Self::XssExitBitmap,
            41 => Self::XssExitBitmapHigh,
            42 => Self::EnclsExitingBitmap,
            43 => Self::EnclsExitingBitmapHigh,
            44 => Self::TscMultiplier,
            45 => Self::TscMultiplierHigh,
            46 => Self::TertiaryVmExecControl,
            47 => Self::TertiaryVmExecControlHigh,
            48 => Self::PidPointerTable,
            49 => Self::PidPointerTableHigh,
            50 => Self::GuestPhysicalAddress,
            51 => Self::GuestPhysicalAddressHigh,
            52 => Self::VmcsLinkPointer,
            53 => Self::VmcsLinkPointerHigh,
            54 => Self::GuestIa32Debugctl,
            55 => Self::GuestIa32DebugctlHigh,
            56 => Self::GuestIa32Pat,
            57 => Self::GuestIa32PatHigh,
            58 => Self::GuestIa32Efer,
            59 => Self::GuestIa32EferHigh,
            60 => Self::GuestIa32PerfGlobalCtrl,
            61 => Self::GuestIa32PerfGlobalCtrlHigh,
            62 => Self::GuestPdptr0,
            63 => Self::GuestPdprt0High,
            64 => Self::GuestPdptr1,
            65 => Self::GuestPdptr1High,
            66 => Self::GuestPdptr2,
            67 => Self::GuestPdptr2High,
            68 => Self::GuestPdptr3,
            69 => Self::GuestPdptr3High,
            70 => Self::GuestBndcfgs,
            71 => Self::GuestBndcfgsHigh,
            72 => Self::GuestIa32RtitCtl,
            73 => Self::GuestIa32RtitCtlHigh,
            74 => Self::HostIa32Pat,
            75 => Self::HostIa32PatHigh,
            76 => Self::HostIa32Efer,
            77 => Self::HostIa32EferHigh,
            78 => Self::HostIa32PerfGlobalCtrl,
            79 => Self::HostIa32PerfGlobalCtrlHigh,
            _ => panic!("Invalid"),
        }
    }

    pub const fn size() -> usize {
        return Self::HostIa32PerfGlobalCtrlHigh as usize + 1;
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(usize)]
pub enum Context16x86 {
    VirtualProcessorId = 0,
    PostedIntrNv,
    LastPidPointerIndex,
    GuestEsSelector,
    GuestCsSelector,
    GuestSsSelector,
    GuestDsSelector,
    GuestFsSelector,
    GuestGsSelector,
    GuestLdtrSelector,
    GuestTrSelector,
    GuestIntrStatus,
    GuestPmlIndex,
    HostEsSelector,
    HostCsSelector,
    HostSsSelector,
    HostDsSelector,
    HostFsSelector,
    HostGsSelector,
    HostTrSelector,
}

#[allow(dead_code)]
impl Context16x86 {
    pub fn as_vmcs_field(&self) -> VmcsField {
        match self {
            Self::VirtualProcessorId => VmcsField::VirtualProcessorId,
            Self::PostedIntrNv => VmcsField::PostedIntrNv,
            Self::LastPidPointerIndex => VmcsField::LastPidPointerIndex,
            Self::GuestEsSelector => VmcsField::GuestEsSelector,
            Self::GuestCsSelector => VmcsField::GuestCsSelector,
            Self::GuestSsSelector => VmcsField::GuestSsSelector,
            Self::GuestDsSelector => VmcsField::GuestDsSelector,
            Self::GuestFsSelector => VmcsField::GuestFsSelector,
            Self::GuestGsSelector => VmcsField::GuestGsSelector,
            Self::GuestLdtrSelector => VmcsField::GuestLdtrSelector,
            Self::GuestTrSelector => VmcsField::GuestTrSelector,
            Self::GuestIntrStatus => VmcsField::GuestIntrStatus,
            Self::GuestPmlIndex => VmcsField::GuestPmlIndex,
            Self::HostEsSelector => VmcsField::HostEsSelector,
            Self::HostCsSelector => VmcsField::HostCsSelector,
            Self::HostSsSelector => VmcsField::HostSsSelector,
            Self::HostDsSelector => VmcsField::HostDsSelector,
            Self::HostFsSelector => VmcsField::HostFsSelector,
            Self::HostGsSelector => VmcsField::HostGsSelector,
            Self::HostTrSelector => VmcsField::HostTrSelector,
        }
    }

    pub fn from_vmcs_field(field: VmcsField) -> Option<Self> {
        match field {
            VmcsField::VirtualProcessorId => Some(Self::VirtualProcessorId),
            VmcsField::PostedIntrNv => Some(Self::PostedIntrNv),
            VmcsField::LastPidPointerIndex => Some(Self::LastPidPointerIndex),
            VmcsField::GuestEsSelector => Some(Self::GuestEsSelector),
            VmcsField::GuestCsSelector => Some(Self::GuestCsSelector),
            VmcsField::GuestSsSelector => Some(Self::GuestSsSelector),
            VmcsField::GuestDsSelector => Some(Self::GuestDsSelector),
            VmcsField::GuestFsSelector => Some(Self::GuestFsSelector),
            VmcsField::GuestGsSelector => Some(Self::GuestGsSelector),
            VmcsField::GuestLdtrSelector => Some(Self::GuestLdtrSelector),
            VmcsField::GuestTrSelector => Some(Self::GuestTrSelector),
            VmcsField::GuestIntrStatus => Some(Self::GuestIntrStatus),
            VmcsField::GuestPmlIndex => Some(Self::GuestPmlIndex),
            VmcsField::HostEsSelector => Some(Self::HostEsSelector),
            VmcsField::HostCsSelector => Some(Self::HostCsSelector),
            VmcsField::HostSsSelector => Some(Self::HostSsSelector),
            VmcsField::HostDsSelector => Some(Self::HostDsSelector),
            VmcsField::HostFsSelector => Some(Self::HostFsSelector),
            VmcsField::HostGsSelector => Some(Self::HostGsSelector),
            VmcsField::HostTrSelector => Some(Self::HostTrSelector),
            _ => None,
        }
    }

    pub fn from_usize(v: usize) -> Self {
        match v {
            0 => Self::VirtualProcessorId,
            1 => Self::PostedIntrNv,
            2 => Self::LastPidPointerIndex,
            3 => Self::GuestEsSelector,
            4 => Self::GuestCsSelector,
            5 => Self::GuestSsSelector,
            6 => Self::GuestDsSelector,
            7 => Self::GuestFsSelector,
            8 => Self::GuestGsSelector,
            9 => Self::GuestLdtrSelector,
            10 => Self::GuestTrSelector,
            11 => Self::GuestIntrStatus,
            12 => Self::GuestPmlIndex,
            13 => Self::HostEsSelector,
            14 => Self::HostCsSelector,
            15 => Self::HostSsSelector,
            16 => Self::HostDsSelector,
            17 => Self::HostFsSelector,
            18 => Self::HostGsSelector,
            19 => Self::HostTrSelector,
            _ => panic!("Invalid"),
        }
    }

    pub const fn size() -> usize {
        return Self::HostTrSelector as usize + 1;
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(usize)]
pub enum ContextNatx86 {
    Cr0GuestHostMask = 0,
    Cr4GuestHostMask,
    Cr0ReadShadow,
    Cr4ReadShadow,
    Cr3TargetValue0,
    Cr3TargetValue1,
    Cr3TargetValue2,
    Cr3TargetValue3,
    ExitQualification,
    GuestLinearAddress,
    GuestCr0,
    GuestCr3,
    GuestCr4,
    GuestEsBase,
    GuestCsBase,
    GuestSsBase,
    GuestDsBase,
    GuestFsBase,
    GuestGsBase,
    GuestLdtrBase,
    GuestTrBase,
    GuestGdtrBase,
    GuestIdtrBase,
    GuestDr7,
    GuestRsp,
    GuestRip,
    GuestRflags,
    GuestPendingDbgExceptions,
    GuestSysenterEsp,
    GuestSysenterEip,
    //HostCr0,
    //HostCr3,
    //HostCr4,
    //HostFsBase,
    //HostGsBase,
    //HostTrBase,
    //HostGdtrBase,
    //HostIdtrBase,
    //HostIa32SysenterEsp,
    //HostIa32SysenterEip,
    //HostRsp,
    //HostRip,
}

#[allow(dead_code)]
impl ContextNatx86 {
    pub fn as_vmcs_field(&self) -> VmcsField {
        match self {
            Self::Cr0GuestHostMask => VmcsField::Cr0GuestHostMask,
            Self::Cr4GuestHostMask => VmcsField::Cr4GuestHostMask,
            Self::Cr0ReadShadow => VmcsField::Cr0ReadShadow,
            Self::Cr4ReadShadow => VmcsField::Cr4ReadShadow,
            Self::Cr3TargetValue0 => VmcsField::Cr3TargetValue0,
            Self::Cr3TargetValue1 => VmcsField::Cr3TargetValue1,
            Self::Cr3TargetValue2 => VmcsField::Cr3TargetValue2,
            Self::Cr3TargetValue3 => VmcsField::Cr3TargetValue3,
            Self::ExitQualification => VmcsField::ExitQualification,
            Self::GuestLinearAddress => VmcsField::GuestLinearAddress,
            Self::GuestCr0 => VmcsField::GuestCr0,
            Self::GuestCr3 => VmcsField::GuestCr3,
            Self::GuestCr4 => VmcsField::GuestCr4,
            Self::GuestEsBase => VmcsField::GuestEsBase,
            Self::GuestCsBase => VmcsField::GuestCsBase,
            Self::GuestSsBase => VmcsField::GuestSsBase,
            Self::GuestDsBase => VmcsField::GuestDsBase,
            Self::GuestFsBase => VmcsField::GuestFsBase,
            Self::GuestGsBase => VmcsField::GuestGsBase,
            Self::GuestLdtrBase => VmcsField::GuestLdtrBase,
            Self::GuestTrBase => VmcsField::GuestTrBase,
            Self::GuestGdtrBase => VmcsField::GuestGdtrBase,
            Self::GuestIdtrBase => VmcsField::GuestIdtrBase,
            Self::GuestDr7 => VmcsField::GuestDr7,
            Self::GuestRsp => VmcsField::GuestRsp,
            Self::GuestRip => VmcsField::GuestRip,
            Self::GuestRflags => VmcsField::GuestRflags,
            Self::GuestPendingDbgExceptions => VmcsField::GuestPendingDbgExceptions,
            Self::GuestSysenterEsp => VmcsField::GuestSysenterEsp,
            Self::GuestSysenterEip => VmcsField::GuestSysenterEip,
        }
    }

    pub fn from_vmcs_field(field: VmcsField) -> Option<Self> {
        match field {
            VmcsField::Cr0GuestHostMask => Some(Self::Cr0GuestHostMask),
            VmcsField::Cr4GuestHostMask => Some(Self::Cr4GuestHostMask),
            VmcsField::Cr0ReadShadow => Some(Self::Cr0ReadShadow),
            VmcsField::Cr4ReadShadow => Some(Self::Cr4ReadShadow),
            VmcsField::Cr3TargetValue0 => Some(Self::Cr3TargetValue0),
            VmcsField::Cr3TargetValue1 => Some(Self::Cr3TargetValue1),
            VmcsField::Cr3TargetValue2 => Some(Self::Cr3TargetValue2),
            VmcsField::Cr3TargetValue3 => Some(Self::Cr3TargetValue3),
            VmcsField::ExitQualification => Some(Self::ExitQualification),
            VmcsField::GuestLinearAddress => Some(Self::GuestLinearAddress),
            VmcsField::GuestCr0 => Some(Self::GuestCr0),
            VmcsField::GuestCr3 => Some(Self::GuestCr3),
            VmcsField::GuestCr4 => Some(Self::GuestCr4),
            VmcsField::GuestEsBase => Some(Self::GuestEsBase),
            VmcsField::GuestCsBase => Some(Self::GuestCsBase),
            VmcsField::GuestSsBase => Some(Self::GuestSsBase),
            VmcsField::GuestDsBase => Some(Self::GuestDsBase),
            VmcsField::GuestFsBase => Some(Self::GuestFsBase),
            VmcsField::GuestGsBase => Some(Self::GuestGsBase),
            VmcsField::GuestLdtrBase => Some(Self::GuestLdtrBase),
            VmcsField::GuestTrBase => Some(Self::GuestTrBase),
            VmcsField::GuestGdtrBase => Some(Self::GuestGdtrBase),
            VmcsField::GuestIdtrBase => Some(Self::GuestIdtrBase),
            VmcsField::GuestDr7 => Some(Self::GuestDr7),
            VmcsField::GuestRsp => Some(Self::GuestRsp),
            VmcsField::GuestRip => Some(Self::GuestRip),
            VmcsField::GuestRflags => Some(Self::GuestRflags),
            VmcsField::GuestPendingDbgExceptions => Some(Self::GuestPendingDbgExceptions),
            VmcsField::GuestSysenterEsp => Some(Self::GuestSysenterEsp),
            VmcsField::GuestSysenterEip => Some(Self::GuestSysenterEip),
            _ => None,
        }
    }

    pub fn from_usize(v: usize) -> Self {
        match v {
            0 => Self::Cr0GuestHostMask,
            1 => Self::Cr4GuestHostMask,
            2 => Self::Cr0ReadShadow,
            3 => Self::Cr4ReadShadow,
            4 => Self::Cr3TargetValue0,
            5 => Self::Cr3TargetValue1,
            6 => Self::Cr3TargetValue2,
            7 => Self::Cr3TargetValue3,
            8 => Self::ExitQualification,
            9 => Self::GuestLinearAddress,
            10 => Self::GuestCr0,
            11 => Self::GuestCr3,
            12 => Self::GuestCr4,
            13 => Self::GuestEsBase,
            14 => Self::GuestCsBase,
            15 => Self::GuestSsBase,
            16 => Self::GuestDsBase,
            17 => Self::GuestFsBase,
            18 => Self::GuestGsBase,
            19 => Self::GuestLdtrBase,
            20 => Self::GuestTrBase,
            21 => Self::GuestGdtrBase,
            22 => Self::GuestIdtrBase,
            23 => Self::GuestDr7,
            24 => Self::GuestRsp,
            25 => Self::GuestRip,
            26 => Self::GuestRflags,
            27 => Self::GuestPendingDbgExceptions,
            28 => Self::GuestSysenterEsp,
            29 => Self::GuestSysenterEip,
            _ => panic!("Invalid"),
        }
    }

    pub const fn size() -> usize {
        return VmcsField::GuestSysenterEip as usize + 1;
    }
}

#[repr(usize)]
pub enum DirtyRegGroups {
    Reg16 = 0,
    Reg32,
    Reg64,
    RegNat,
    RegGp,
}

impl DirtyRegGroups {
    pub fn from_usize(v: usize) -> Self {
        match v {
            0 => Self::Reg16,
            1 => Self::Reg32,
            2 => Self::Reg64,
            3 => Self::RegNat,
            4 => Self::RegGp,
            _ => panic!("Invalid"),
        }
    }
    pub const fn size() -> usize {
        return Self::RegGp as usize + 1;
    }
}

#[allow(dead_code)]
pub struct Contextx86 {
    // Quick way to mark register groups that need to be visited.
    pub dirty: [bool; DirtyRegGroups::size()],
    // 16-bits registers.
    pub vmcs_16: [u16; Context16x86::size()],
    pub dirty_16: [bool; Context16x86::size()],
    // 32-bits registers.
    pub vmcs_32: [u32; Context32x86::size()],
    pub dirty_32: [bool; Context32x86::size()],
    // 64-bits registers.
    pub vmcs_64: [u64; Context64x86::size()],
    pub dirty_64: [bool; Context64x86::size()],
    // Nat-width registers.
    pub vmcs_nat: [usize; ContextNatx86::size()],
    pub dirty_nat: [bool; ContextNatx86::size()],
    // General purpose registers.
    pub vmcs_gp: [u64; ContextGpx86::size()],
    pub dirty_gp: [bool; ContextGpx86::size()],
    // State.
    pub interrupted: bool,
    pub vmcs: Handle<RCFrame>,
}

#[allow(dead_code)]
impl Contextx86 {
    pub fn set_register(&mut self, field: VmcsField, value: usize) {
        match (field.width(), field.is_gp_register()) {
            (_, true) => {
                let reg = ContextGpx86::from_vmcs_field(field).expect("Invalid GP");
                self.vmcs_gp[reg as usize] = value as u64;
                self.dirty_gp[reg as usize] = true;
                self.dirty[DirtyRegGroups::RegGp as usize] = true;
            }
            (VmcsFieldWidth::Width16, _) => {
                let reg = Context16x86::from_vmcs_field(field).expect("Invalid 16");
                self.vmcs_16[reg as usize] = value as u16;
                self.dirty_16[reg as usize] = true;
                self.dirty[DirtyRegGroups::Reg16 as usize] = true;
            }
            (VmcsFieldWidth::Width32, _) => {
                let reg = Context16x86::from_vmcs_field(field).expect("Invalid 32");
                self.vmcs_32[reg as usize] = value as u32;
                self.dirty_32[reg as usize] = true;
                self.dirty[DirtyRegGroups::Reg32 as usize] = true;
            }
            (VmcsFieldWidth::Width64, _) => {
                let reg = Context64x86::from_vmcs_field(field).expect("Invalid 64");
                self.vmcs_64[reg as usize] = value as u64;
                self.dirty_64[reg as usize] = true;
                self.dirty[DirtyRegGroups::Reg64 as usize] = true;
            }
            (VmcsFieldWidth::WidthNat, _) => {
                let reg = ContextNatx86::from_vmcs_field(field).expect("Invalid Nat");
                self.vmcs_nat[reg as usize] = value;
                self.dirty_nat[reg as usize] = true;
                self.dirty[DirtyRegGroups::RegNat as usize] = true;
            }
        }
    }

    pub fn get_register(&self, field: VmcsField) -> usize {
        match (field.width(), field.is_gp_register()) {
            (_, true) => {
                let reg = ContextGpx86::from_vmcs_field(field).expect("Invalid GP");
                self.vmcs_gp[reg as usize] as usize
            }
            (VmcsFieldWidth::Width16, _) => {
                let reg = Context16x86::from_vmcs_field(field).expect("Invalid 16");
                self.vmcs_16[reg as usize] as usize
            }
            (VmcsFieldWidth::Width32, _) => {
                let reg = Context32x86::from_vmcs_field(field).expect("Invalid 32");
                self.vmcs_32[reg as usize] as usize
            }
            (VmcsFieldWidth::Width64, _) => {
                let reg = Context64x86::from_vmcs_field(field).expect("Invalid 64");
                self.vmcs_64[reg as usize] as usize
            }
            (VmcsFieldWidth::WidthNat, _) => {
                let reg = ContextNatx86::from_vmcs_field(field).expect("Invalid Nat");
                self.vmcs_nat[reg as usize]
            }
        }
    }

    pub fn flush(&mut self, vcpu: &mut ActiveVmcs) {
        for i in 0..DirtyRegGroups::size() {
            if !self.dirty[i] {
                continue;
            }
            match DirtyRegGroups::from_usize(i) {
                DirtyRegGroups::Reg16 => {
                    for j in 0..Context16x86::size() {
                        if !self.dirty_16[j] {
                            continue;
                        }
                        vcpu.set(
                            Context16x86::from_usize(j).as_vmcs_field(),
                            self.vmcs_16[j] as usize,
                        )
                        .unwrap();
                        self.dirty_16[j] = false;
                    }
                }
                DirtyRegGroups::Reg32 => {
                    for j in 0..Context32x86::size() {
                        if !self.dirty_32[j] {
                            continue;
                        }
                        vcpu.set(
                            Context32x86::from_usize(j).as_vmcs_field(),
                            self.vmcs_32[j] as usize,
                        )
                        .unwrap();
                        self.dirty_32[j] = false;
                    }
                }
                DirtyRegGroups::Reg64 => {
                    for j in 0..Context64x86::size() {
                        if !self.dirty_64[j] {
                            continue;
                        }
                        vcpu.set(
                            Context64x86::from_usize(j).as_vmcs_field(),
                            self.vmcs_64[j] as usize,
                        )
                        .unwrap();
                        self.dirty_64[j] = false;
                    }
                }
                DirtyRegGroups::RegNat => {
                    for j in 0..ContextNatx86::size() {
                        if !self.dirty_nat[j] {
                            continue;
                        }
                        vcpu.set(
                            ContextNatx86::from_usize(j).as_vmcs_field(),
                            self.vmcs_nat[j],
                        )
                        .unwrap();
                        self.dirty_nat[j] = false;
                    }
                }
                DirtyRegGroups::RegGp => {
                    for j in 0..ContextGpx86::size() {
                        if !self.dirty_gp[j] {
                            continue;
                        }
                        vcpu.set(
                            ContextGpx86::from_usize(j).as_vmcs_field(),
                            self.vmcs_gp[j] as usize,
                        )
                        .unwrap();
                        self.dirty_gp[j] = false;
                    }
                }
            }
            self.dirty[i] = false;
        }
    }

    pub fn load(&mut self, vcpu: &ActiveVmcs) {
        // General purpose registers.
        for i in 0..ContextGpx86::size() {
            self.vmcs_gp[i] = vcpu
                .get(ContextGpx86::from_usize(i).as_vmcs_field())
                .unwrap() as u64;
        }

        // 16-bits.
        for i in 0..Context16x86::size() {
            self.vmcs_16[i] = vcpu
                .get(Context16x86::from_usize(i).as_vmcs_field())
                .unwrap() as u16;
        }

        // 32-bits.
        for i in 0..Context32x86::size() {
            self.vmcs_32[i] = vcpu
                .get(Context32x86::from_usize(i).as_vmcs_field())
                .unwrap() as u32;
        }

        // 64-bits.
        for i in 0..Context64x86::size() {
            self.vmcs_64[i] = vcpu
                .get(Context64x86::from_usize(i).as_vmcs_field())
                .unwrap() as u64;
        }

        // Nat-bits.
        for i in 0..ContextNatx86::size() {
            self.vmcs_nat[i] = vcpu
                .get(ContextNatx86::from_usize(i).as_vmcs_field())
                .unwrap();
        }
    }
}

pub struct ContextData {
    // VCPU for this core.
    pub vmcs: Handle<RCFrame>,
    // General purpose registers values for the context.
    pub regs: [usize; REGFILE_SIZE],
    // Extra registers stored in the context.
    // This is necessary due to shared VMCS.
    pub cr3: usize,
    pub rip: usize,
    pub rsp: usize,
    // True if the context was preempted due to an interrupt.
    pub interrupted: bool,
}

impl ContextData {
    pub fn save_partial(&mut self, vcpu: &ActiveVmcs<'static>) {
        self.cr3 = vcpu.get(VmcsField::GuestCr3).unwrap();
        self.rip = vcpu.get(VmcsField::GuestRip).unwrap();
        self.rsp = vcpu.get(VmcsField::GuestRsp).unwrap();
    }

    pub fn save(&mut self, vcpu: &mut ActiveVmcs<'static>) {
        self.save_partial(vcpu);
        vcpu.dump_regs(&mut self.regs[0..REGFILE_SIZE]);
        self.regs[GPF::Lstar as usize] = unsafe { IA32_LSTAR.read() } as usize;
        vcpu.flush();
    }

    pub fn restore_partial(&self, vcpu: &mut ActiveVmcs<'static>) {
        vcpu.set(VmcsField::GuestCr3, self.cr3).unwrap();
        vcpu.set(VmcsField::GuestRip, self.rip).unwrap();
        vcpu.set(VmcsField::GuestRsp, self.rsp).unwrap();
    }

    pub fn restore(&self, rc_vmcs: &Mutex<RCFramePool>, vcpu: &mut ActiveVmcs<'static>) {
        let locked = rc_vmcs.lock();
        let rc_frame = locked.get(self.vmcs).unwrap();
        self.restore_locked(rc_frame, vcpu);
    }

    pub fn restore_locked(&self, rc_frame: &RCFrame, vcpu: &mut ActiveVmcs<'static>) {
        vcpu.load_regs(&self.regs[0..REGFILE_SIZE]);
        unsafe {
            vmx::msr::Msr::new(IA32_LSTAR.address()).write(self.regs[GPF::Lstar as usize] as u64)
        };
        vcpu.switch_frame(rc_frame.frame).unwrap();
        // Restore partial must be called AFTER we set a valid frame.
        self.restore_partial(vcpu);
    }
}
