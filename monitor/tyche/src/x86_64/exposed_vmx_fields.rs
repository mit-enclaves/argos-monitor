use capa_engine::CapaError;
use vmx::fields::{GuestState16, GuestState32, GuestState64, GuestStateNat};
use vmx::{ActiveVmcs, ControlRegister, Register};

use super::context::ContextData;

//TODO(@aghosn): I have some duplicated code for search.
//Can we do a macro or a generic type to simply this?

/// Array of control registers we expose to the client.
pub const GUEST_STATE_CR: [ControlRegister; 3] = [
    ControlRegister::Cr0,
    ControlRegister::Cr3,
    ControlRegister::Cr4,
    //TODO should we expose cr8?
];

pub fn search_guest_cr(idx: usize) -> Option<ControlRegister> {
    match GUEST_STATE_CR.iter().position(|item| *item as usize == idx) {
        Some(id) => Some(GUEST_STATE_CR[id]),
        _ => None,
    }
}

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
        Some(id) => Some(GUEST_STATE_16[id]),
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
        Some(id) => Some(GUEST_STATE_32[id]),
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
        Some(id) => Some(GUEST_STATE_64[id]),
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
        Some(id) => Some(GUEST_STATE_NAT[id]),
        _ => None,
    }
}

/// Group configurable registers by type/size.
/// This requires one extra argument to be passed to the monitor call,
/// but facilitates the logic on the monitor side for now.
/// TODO: we should refactor crates/vmx and do the dispatch there,
/// hide everything behind a single "set" and "get".
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum GuestRegisterGroups {
    GeneralPurpose = 0,
    Controls = 1,
    Reg16 = 2,
    Reg32 = 3,
    Reg64 = 4,
    RegNat = 5,
    //TODO add more.
}

impl GuestRegisterGroups {
    pub fn from_usize(v: usize) -> Option<GuestRegisterGroups> {
        match v {
            0 => Some(Self::GeneralPurpose),
            1 => Some(Self::Controls),
            2 => Some(Self::Reg16),
            3 => Some(Self::Reg32),
            4 => Some(Self::Reg64),
            5 => Some(Self::RegNat),
            _ => None,
        }
    }
}

/// Abstract the search for the right register.
pub struct GuestRegisters {}

impl GuestRegisters {
    pub fn is_valid(reg_group: GuestRegisterGroups, idx: usize) -> bool {
        match reg_group {
            GuestRegisterGroups::GeneralPurpose => Register::from_usize(idx).is_some(),
            GuestRegisterGroups::Controls => search_guest_cr(idx).is_some(),
            GuestRegisterGroups::Reg16 => search_guest_16(idx).is_some(),
            GuestRegisterGroups::Reg32 => search_guest_32(idx).is_some(),
            GuestRegisterGroups::Reg64 => search_guest_64(idx).is_some(),
            GuestRegisterGroups::RegNat => search_guest_nat(idx).is_some(),
        }
    }

    pub fn set_register(
        vcpu: Option<&mut ActiveVmcs>,
        context: &mut ContextData,
        reg_group: GuestRegisterGroups,
        idx: usize,
        value: usize,
    ) -> Result<(), CapaError> {
        if !GuestRegisters::is_valid(reg_group, idx) {
            return Err(CapaError::InvalidOperation);
        }
        match reg_group {
            GuestRegisterGroups::GeneralPurpose => {
                let reg = Register::from_usize(idx).expect("RegGP should be valid");
                context.set_register(reg, value as u64);
            }
            GuestRegisterGroups::Controls => {
                let vcpu = vcpu.expect("Cannot be None");
                let reg = search_guest_cr(idx).expect("RegCtrl should be valid");
                vcpu.set_cr(reg, value);
            }
            GuestRegisterGroups::Reg16 => {
                let vcpu = vcpu.expect("Cannot be None");
                let reg = search_guest_16(idx).expect("Reg16 should be valid");
                vcpu.set16(reg, value as u16).expect("Unable to set reg16");
            }
            GuestRegisterGroups::Reg32 => {
                let vcpu = vcpu.expect("Cannot be None");
                let reg = search_guest_32(idx).expect("Reg32 should be valid");
                vcpu.set32(reg, value as u32).expect("Unable to set reg32");
            }
            GuestRegisterGroups::Reg64 => {
                let vcpu = vcpu.expect("Cannot be None");
                let reg = search_guest_64(idx).expect("Reg64 should be valid");
                vcpu.set64(reg, value as u64).expect("Unable to set reg64");
            }
            GuestRegisterGroups::RegNat => {
                let vcpu = vcpu.expect("Cannot be None");
                let reg = search_guest_nat(idx).expect("RegNat should be valid");
                vcpu.set_nat(reg, value).expect("Unable to set regNat");
            }
        }
        Ok(())
    }

    pub fn get_register(
        vcpu: &mut ActiveVmcs,
        reg_group: GuestRegisterGroups,
        idx: usize,
    ) -> Result<usize, CapaError> {
        if !GuestRegisters::is_valid(reg_group, idx) {
            return Err(CapaError::InvalidOperation);
        }
        let value = match reg_group {
            GuestRegisterGroups::GeneralPurpose => {
                let reg = Register::from_usize(idx).expect("RegGP should be valid");
                vcpu.get(reg) as usize
            }
            GuestRegisterGroups::Controls => {
                let reg = search_guest_cr(idx).expect("RegCtrl should be valid");
                vcpu.get_cr(reg) as usize
            }
            GuestRegisterGroups::Reg16 => {
                let reg = search_guest_16(idx).expect("Reg16 should be valid");
                vcpu.get16(reg).expect("Unable to get reg16") as usize
            }
            GuestRegisterGroups::Reg32 => {
                let reg = search_guest_32(idx).expect("Reg32 should be valid");
                vcpu.get32(reg).expect("Unable to set reg32") as usize
            }
            GuestRegisterGroups::Reg64 => {
                let reg = search_guest_64(idx).expect("Reg64 should be valid");
                vcpu.get64(reg).expect("Unable to set reg64") as usize
            }
            GuestRegisterGroups::RegNat => {
                let reg = search_guest_nat(idx).expect("RegNat should be valid");
                vcpu.get_nat(reg).expect("Unable to set regNat") as usize
            }
        };
        Ok(value)
    }
}
