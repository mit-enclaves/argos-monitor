//! Application Binary Interface
#![allow(unused)]

use crate::statics::Statics;

// ——————————————————————————————— Hypercalls ——————————————————————————————— //

#[rustfmt::skip]
pub mod vmcalls {
    pub const DOMAIN_GET_OWN_ID: usize    = 0x100;
    pub const DOMAIN_CREATE: usize        = 0x101;
    pub const DOMAIN_REGISTER_GATE: usize = 0x102;
    pub const DOMAIN_SEAL: usize          = 0x103;
    pub const EXIT: usize                 = 0x500;
}

// —————————————————————————————— Error Codes ——————————————————————————————— //

#[repr(usize)]
pub enum ErrorCode {
    Success = 0,
    Failure = 1,
    UnknownVmCall = 2,
}

// —————————————————————————————————— ABI ——————————————————————————————————— //

pub struct Parameters {
    pub vmcall: usize,
    pub arg_1: usize,
    pub arg_2: usize,
    pub arg_3: usize,
}

pub struct Registers {
    pub result: ErrorCode,
    pub value_1: usize,
    pub value_2: usize,
    pub value_3: usize,
}

impl Default for Registers {
    fn default() -> Self {
        Self {
            result: ErrorCode::Failure,
            value_1: 0,
            value_2: 0,
            value_3: 0,
        }
    }
}

pub struct Hypercalls {
    current_domain: &'static mut DomainId,
}

impl Hypercalls {
    pub fn new(statics: &mut Statics) -> Self {
        Self {
            current_domain: statics
                .current_domain
                .take()
                .expect("Missing current_domain static"),
        }
    }

    pub fn dispatch(&mut self, params: Parameters) -> Registers {
        match params.vmcall {
            vmcalls::DOMAIN_GET_OWN_ID => self.domain_get_own_id(),
            vmcalls::DOMAIN_CREATE => self.domain_create(params.arg_1.into()),
            _ => Registers {
                result: ErrorCode::UnknownVmCall,
                ..Default::default()
            },
        }
    }

    pub fn is_exit(&self, params: &Parameters) -> bool {
        params.vmcall == vmcalls::EXIT
    }
}

// ——————————————————————————————— ABI Types ———————————————————————————————— //

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Capability(usize);

impl From<Capability> for usize {
    fn from(capa: Capability) -> Self {
        capa.0
    }
}

impl From<usize> for Capability {
    fn from(capa: usize) -> Self {
        Capability(capa)
    }
}

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct DomainId(pub usize);

impl From<DomainId> for usize {
    fn from(id: DomainId) -> Self {
        id.0
    }
}

impl From<usize> for DomainId {
    fn from(id: usize) -> Self {
        DomainId(id)
    }
}

pub struct Domain {
    sealed: bool,
    receive_shared_region: Option<usize>,
    receive_exclusive_region: Option<usize>,
}

// —————————————————————————————— Capabilities —————————————————————————————— //

pub struct DomainCapability {
    terminate: bool,
    seal: bool,
}

/// Each region has a single owner and can be marked either as owned or exclusive.
pub struct RegionCapability {
    is_owned: bool,
    is_exclusive: bool,
}

// ———————————————————————————————— VM Calls ———————————————————————————————— //

impl Hypercalls {
    /// Returns the Domain ID of the current domain.
    fn domain_get_own_id(&mut self) -> Registers {
        let domain = *self.current_domain;
        Registers {
            result: ErrorCode::Success,
            value_1: domain.into(),
            ..Default::default()
        }
    }

    fn domain_create(&mut self, region: Capability) -> Registers {
        todo!();
    }

    fn domain_register_gate(
        &mut self,
        domain: Capability,
        gate_kind: usize,
        gate_addr: usize,
    ) -> Registers {
        todo!();
    }

    fn domain_seal(&mut self, domain: Capability) -> Registers {
        todo!();
    }

    /// Only owned exclusive regions can be split.
    pub fn region_split(&mut self, region: Capability, at: usize) -> Registers {
        todo!();
    }

    /// Mark an exclusive region as shared.
    pub fn region_share(&mut self, region: Capability) -> Registers {
        todo!();
    }

    /// If the region is owned, unmap it from one of the other domain with shared ownership.
    pub fn region_uneshare_one(&mut self, region: Capability) -> Registers {
        todo!();
    }
}
