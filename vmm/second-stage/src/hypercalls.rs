//! Application Binary Interface
#![allow(unused)]

use crate::arena::{Handle, TypedArena};
use crate::statics::{Statics, NB_DOMAINS, NB_REGIONS, NB_REGIONS_PER_DOMAIN};
use stage_two_abi::Manifest;

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
    OutOfMemory = 3,
}

// —————————————————————————————————— ABI ——————————————————————————————————— //

pub struct Parameters {
    pub vmcall: usize,
    pub arg_1: usize,
    pub arg_2: usize,
    pub arg_3: usize,
}

pub struct Registers {
    pub value_1: usize,
    pub value_2: usize,
    pub value_3: usize,
}

pub type HypercallResult = Result<Registers, ErrorCode>;

impl Default for Registers {
    fn default() -> Self {
        Self {
            value_1: 0,
            value_2: 0,
            value_3: 0,
        }
    }
}

// ——————————————————————————————— ABI Types ———————————————————————————————— //

type DomainArena = TypedArena<Domain, NB_DOMAINS>;
type RegionArena = TypedArena<Region, NB_REGIONS>;

pub struct Domain {
    pub sealed: bool,
    pub regions: TypedArena<RegionCapability, NB_REGIONS_PER_DOMAIN>,
}

/// Each region has a single owner and can be marked either as owned or exclusive.
pub struct RegionCapability {
    pub do_own: bool,
    pub is_shared: bool,
    pub is_valid: bool,
    pub handle: Handle<Region>,
}

pub struct Region {
    pub ref_count: usize,
    pub start: usize,
    pub end: usize,
}

// ———————————————————————————————— VM Calls ———————————————————————————————— //

pub struct Hypercalls {
    root_domain: Handle<Domain>,
    current_domain: &'static mut Handle<Domain>,
    domains_arena: &'static mut DomainArena,
}

impl Hypercalls {
    pub fn new(statics: &mut Statics, manifest: &Manifest<Statics>) -> Self {
        let current_domain = statics
            .current_domain
            .take()
            .expect("Missing current_domain_static");
        let domains_arena = statics
            .domains_arena
            .take()
            .expect("Missing domains_arena static");
        let regions_arena = statics
            .regions_arena
            .take()
            .expect("Missing regions_arena static");

        let root_region = Self::create_root_region(manifest, regions_arena);
        let root_domain = Self::create_root_domain(root_region, domains_arena);
        *current_domain = root_domain;

        Self {
            root_domain,
            current_domain,
            domains_arena,
        }
    }

    fn create_root_region(
        manifest: &Manifest<Statics>,
        regions_arena: &mut RegionArena,
    ) -> Handle<Region> {
        let handle = regions_arena
            .allocate()
            .expect("Failed to allocate root region");
        let root_region = &mut regions_arena[handle];
        root_region.start = 0;
        root_region.end = manifest.poffset as usize;
        root_region.ref_count = 1;

        handle
    }

    fn create_root_domain(
        root_region: Handle<Region>,
        domains_arena: &mut DomainArena,
    ) -> Handle<Domain> {
        let handle = domains_arena
            .allocate()
            .expect("Failed to allocate root domain");
        let root_domain = &mut domains_arena[handle];
        root_domain.sealed = true;

        let root_region_capa = root_domain
            .regions
            .allocate()
            .expect("Failed to allocate root region capability");
        root_domain.regions[root_region_capa] = RegionCapability {
            do_own: true,
            is_shared: false,
            is_valid: true,
            handle: root_region,
        };

        handle
    }

    pub fn dispatch(&mut self, params: Parameters) -> HypercallResult {
        match params.vmcall {
            vmcalls::DOMAIN_GET_OWN_ID => self.domain_get_own_id(),
            vmcalls::DOMAIN_CREATE => self.domain_create(),
            _ => Err(ErrorCode::UnknownVmCall),
        }
    }

    pub fn is_exit(&self, params: &Parameters) -> bool {
        params.vmcall == vmcalls::EXIT
    }
}

impl Hypercalls {
    /// Returns the Domain ID of the current domain.
    fn domain_get_own_id(&mut self) -> HypercallResult {
        let domain = *self.current_domain;
        Ok(Registers {
            value_1: domain.into(),
            ..Default::default()
        })
    }

    /// Creates a fresh domain.
    fn domain_create(&mut self) -> HypercallResult {
        let handle = self
            .domains_arena
            .allocate()
            .ok_or(ErrorCode::OutOfMemory)?;
        let domain = &mut self.domains_arena[handle];
        domain.sealed = false;

        Ok(Registers {
            value_1: handle.into(),
            ..Default::default()
        })
    }
}
