//! VMX Errors

/// An error that occured during VMX operations.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum VmxError {
    /// VMCS pointer is valid, but some other error was encountered. Read VM-instruction error
    /// field of VMCS for more details.
    VmFailValid(VmxInstructionError),

    /// VMCS pointer is invalid.
    VmFailInvalid,

    /// VMX is not supported by the current CPU.
    VmxNotSupported,

    /// VMX is supported by the CPU but not enabled. See IA_32_FEATURE_CONTROL MSR.
    VmxNotEnabled,

    /// Value 1 is not supported for one of the configuration bits for which it was requested.
    Disallowed1(VmxFieldError, u8),

    /// Value 0 is not supported for one of the configuration bits for which it was requested.
    Disallowed0(VmxFieldError, u8),
}

impl VmxError {
    /// If the error is either a disallowed 0 or a disallowed 1, override the faulty VMX field.
    pub(crate) fn set_field(self, field: VmxFieldError) -> Self {
        match self {
            Self::Disallowed0(_, idx) => Self::Disallowed0(field, idx),
            Self::Disallowed1(_, idx) => Self::Disallowed1(field, idx),
            _ => self,
        }
    }
}

/// An error resulting from the execution of a VMX instruction.
///
/// See Intel Manual 3C Section 30.4.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum VmxInstructionError {
    /// VMCA executed in VMX-root operation.
    VmCallRoot,
    /// VMCLEAR with invalid physical address.
    VmClearInvalid,
    /// VMCLEAR with VMXON pointer.
    VmClearVmxon,
    /// VMLAUNCH with non-clear VMCS.
    VmLaunchNonClear,
    /// VMRESUME with non-launched VMCS.
    VmResumeNonLaunched,
    /// VMRESUME after VMXOFF.
    VmResumeAfterVmxoff,
    /// VMENTRY with invalid control fields.
    VmEntryInvalidCtrlFields,
    /// VMENTRY with invalid host state.
    VmEntryInvalidHostState,
    /// VMPTRLD with invalid physical address.
    VmPtrldInvalidPhysAddr,
    /// VMPTRLD with VMXON pointer.
    VmPtrldVmxon,
    /// VMPTRLD with incorrect VMCS revision identifier.
    VmPtrldInvalidRevId,
    /// VMREAD/VMWRITE to unsupported component.
    VmAccessUnsupportedField,
    /// VMWRITE to read-only component.
    VmWriteToReadOnly,
    /// VMXON executed in VMX root operation.
    VmxonDuringVmxRoot,
    /// VM entry with invalid executive-VMCS pointer.
    VmEntryInvalidVmcs,
    /// VM entry with non-launched executive VMCS.
    VmEntryNonLaunched,
    /// VM entry with executive-VMCS pointer not VMXON pointer.
    VmEntryVmcsNotVmxon,
    /// VMCALL with non-clear VMCS.
    VmCallNonClearVmcs,
    /// VMCA with invalid VM-exit control fields,
    VmCallInvalidExitCtrlFields,
    /// VMCALL with incorrect MSEG revision identifier.
    VmCallInvalidRevId,
    /// VMXOFF under dual-monitor treatment of SMIs and SMM.
    VmxoffDualMonitor,
    /// VMCALL with invalid SMM-monitor features.
    VmCallInvalidSmmFeatures,
    /// VM entry with invalid VM-execution control fields in executive VMCS.
    VmEntryInvalidExecCtrlFields,
    /// VM entry with events blocked by MOV SS.
    VmEntryBlockedMovSS,
    /// Invalid operand to INVEPT/INVVPID.
    InvalidInvEptInvPid,
    /// Unknown error.
    Unknown,
}

impl VmxInstructionError {
    pub fn from_u64(err: u64) -> VmxInstructionError {
        match err {
            1 => Self::VmCallRoot,
            2 => Self::VmClearInvalid,
            3 => Self::VmClearVmxon,
            4 => Self::VmLaunchNonClear,
            5 => Self::VmResumeNonLaunched,
            6 => Self::VmResumeAfterVmxoff,
            7 => Self::VmEntryInvalidCtrlFields,
            8 => Self::VmEntryInvalidHostState,
            9 => Self::VmPtrldInvalidPhysAddr,
            10 => Self::VmPtrldVmxon,
            11 => Self::VmPtrldInvalidRevId,
            12 => Self::VmAccessUnsupportedField,
            13 => Self::VmWriteToReadOnly,
            15 => Self::VmxonDuringVmxRoot,
            16 => Self::VmEntryInvalidVmcs,
            17 => Self::VmEntryNonLaunched,
            18 => Self::VmEntryVmcsNotVmxon,
            19 => Self::VmCallNonClearVmcs,
            20 => Self::VmCallInvalidExitCtrlFields,
            22 => Self::VmCallInvalidRevId,
            23 => Self::VmxoffDualMonitor,
            24 => Self::VmCallInvalidSmmFeatures,
            25 => Self::VmEntryInvalidExecCtrlFields,
            26 => Self::VmEntryBlockedMovSS,
            28 => Self::InvalidInvEptInvPid,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum VmxFieldError {
    HostCr0,
    HostCr4,
    PinBasedControls,
    PrimaryControls,
    SecondaryControls,
    ExitControls,
    EntryControls,
    Unknown,
}
