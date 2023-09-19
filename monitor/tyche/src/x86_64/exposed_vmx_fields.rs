use vmx::fields::traits::VmcsField;
use vmx::fields::{GuestState16, GuestState32, GuestState64, GuestStateNat};

//TODO(@aghosn): I have some duplicated code for search.
//Can we do a macro or a generic type to simply this?

/// Array of guest state 16 we expose for setup.
/// @note: remove entries for fields we do not want to expose.
pub const GUEST_STATE_16: [GuestState16; 10] = [
    GuestState16::EsSelector,
    GuestState16::CsSelector,
    GuestState16::SsSelector,
    GuestState16::DsSelector,
    GuestState16::FsSelector,
    GuestState16::GsSelector,
    GuestState16::LdtrSelector,
    GuestState16::TrSelector,
    GuestState16::InterruptStatus,
    GuestState16::PmlIndex,
];

pub fn search_guest_16(idx: usize) -> Option<GuestState16> {
    match GUEST_STATE_16.iter().position(|item| *item as usize == idx) {
        Some(id) => Some(GUEST_STATE_16[idx]),
        _ => None,
    }
}

/// Guest state 32 bits we expose.
pub const GUEST_STATE_32: [GuestState32; 23] = [
    GuestState32::EsLimit,
    GuestState32::CsLimit,
    GuestState32::SsLimit,
    GuestState32::DsLimit,
    GuestState32::FsLimit,
    GuestState32::GsLimit,
    GuestState32::LdtrLimit,
    GuestState32::TrLimit,
    GuestState32::GdtrLimit,
    GuestState32::IdtrLimit,
    GuestState32::EsAccessRights,
    GuestState32::CsAccessRights,
    GuestState32::SsAccessRights,
    GuestState32::DsAccessRights,
    GuestState32::FsAccessRights,
    GuestState32::GsAccessRights,
    GuestState32::LdtrAccessRights,
    GuestState32::TrAccessRights,
    GuestState32::InterruptibilityState,
    GuestState32::ActivityState,
    GuestState32::Smbase,
    GuestState32::Ia32SysenterCs,
    GuestState32::VmxPreemptionTimerValue,
];

pub fn search_guest_32(idx: usize) -> Option<GuestState32> {
    match GUEST_STATE_32.iter().position(|item| *item as usize == idx) {
        Some(id) => Some(GUEST_STATE_32[idx]),
        _ => None,
    }
}

/// Guest state 64 fields we expose.
pub const GUEST_STATE_64: [GuestState64; 10] = [
    GuestState64::VmcsLinkPtr,
    GuestState64::Ia32Debugctl,
    GuestState64::Ia32Pat,
    GuestState64::Ia32Efer,
    GuestState64::Ia32PerfGlobalCtrl,
    GuestState64::Pdpte0,
    GuestState64::Pdpte1,
    GuestState64::Ptpte2,
    GuestState64::Pdpte3,
    GuestState64::Ia32Binddfgs,
];

pub fn search_guest_64(idx: usize) -> Option<GuestState64> {
    match GUEST_STATE_64.iter().position(|item| *item as usize == idx) {
        Some(id) => Some(GUEST_STATE_64[idx]),
        _ => None,
    }
}

/// Guest state native fields we expose.
pub const GUEST_STATE_NAT: [GuestStateNat; 20] = [
    GuestStateNat::Cr0,
    GuestStateNat::Cr3,
    GuestStateNat::Cr4,
    GuestStateNat::EsBase,
    GuestStateNat::CsBase,
    GuestStateNat::SsBase,
    GuestStateNat::DsBase,
    GuestStateNat::FsBase,
    GuestStateNat::GsBase,
    GuestStateNat::LdtrBase,
    GuestStateNat::TrBase,
    GuestStateNat::GdtrBase,
    GuestStateNat::IdtrBase,
    GuestStateNat::Dr7,
    GuestStateNat::Rsp,
    GuestStateNat::Rip,
    GuestStateNat::Rflags,
    GuestStateNat::PendingDebugExcept,
    GuestStateNat::Ia32SysenterEsp,
    GuestStateNat::Ia32SysenterEip,
];

pub fn search_guest_nat(idx: usize) -> Option<GuestStateNat> {
    match GUEST_STATE_NAT
        .iter()
        .position(|item| *item as usize == idx)
    {
        Some(id) => Some(GUEST_STATE_NAT[idx]),
        _ => None,
    }
}
