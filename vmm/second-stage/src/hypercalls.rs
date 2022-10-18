//! Application Binary Interface
#![allow(unused)]

use crate::arena::{ArenaItem, Handle, TypedArena};
use crate::statics::{Statics, NB_DOMAINS, NB_REGIONS, NB_REGIONS_PER_DOMAIN};
use stage_two_abi::Manifest;

// ——————————————————————————————— Hypercalls ——————————————————————————————— //

#[rustfmt::skip]
pub mod vmcalls {
    pub const DOMAIN_GET_OWN_ID: usize   = 0x100;
    pub const DOMAIN_CREATE: usize       = 0x101;
    pub const DOMAIN_SEAL: usize         = 0x102;
    pub const DOMAIN_GRANT_REGION: usize = 0x103;
    pub const REGION_SPLIT: usize        = 0x200;
    pub const REGION_GET_INFO: usize     = 0x201;
    pub const CONFIG_NB_REGIONS: usize   = 0x400;
    pub const CONFIG_READ_REGION: usize  = 0x401;
    pub const EXIT: usize                = 0x500;
}

// —————————————————————————————— Error Codes ——————————————————————————————— //

#[derive(Debug, Clone, Copy)]
#[repr(usize)]
pub enum ErrorCode {
    Success = 0,
    Failure = 1,
    UnknownVmCall = 2,
    OutOfMemory = 3,
    DomainOutOfBound = 4,
    RegionOutOfBound = 5,
    RegionCapaOutOfBound = 6,
    InvalidRegionCapa = 7,
    RegionNotOwned = 8,
    InvalidAddress = 9,
    InvalidDomain = 10,
    DomainIsSealed = 11,
    StoreAccesOutOfBound = 12,
    BadParameters = 13,
}

// ————————————————————————————————— Flags —————————————————————————————————— //

#[rustfmt::skip]
pub mod region {
    pub const OWNED: usize  = 0b001;
    pub const SHARED: usize = 0b010;
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
type DomainHandle = Handle<Domain, NB_DOMAINS>;
type RegionHandle = Handle<Region, NB_REGIONS>;
type RegionCapaHandle = Handle<RegionCapability, NB_REGIONS_PER_DOMAIN>;

pub struct Domain {
    pub is_sealed: bool,
    pub is_valid: bool,
    pub regions: TypedArena<RegionCapability, NB_REGIONS_PER_DOMAIN>,
    pub nb_initial_regions: usize,
    pub initial_regions_capa: [RegionCapaHandle; NB_REGIONS_PER_DOMAIN],
}

pub struct Region {
    pub ref_count: usize,
    pub start: usize,
    pub end: usize,
}

/// Each region has a single owner and can be marked either as owned or exclusive.
pub struct RegionCapability {
    pub is_owned: bool,
    pub is_shared: bool,
    pub is_valid: bool,
    pub handle: RegionHandle,
}

impl Domain {
    fn is_valid(&self) -> Result<(), ErrorCode> {
        match self.is_valid {
            true => Ok(()),
            false => Err(ErrorCode::InvalidDomain),
        }
    }

    fn is_unsealed(&self) -> Result<(), ErrorCode> {
        match self.is_sealed {
            true => Err(ErrorCode::DomainIsSealed),
            false => Ok(()),
        }
    }
}

impl Region {
    fn do_contain(&self, addr: usize) -> Result<(), ErrorCode> {
        if self.start <= addr && addr < self.end {
            Ok(())
        } else {
            Err(ErrorCode::InvalidAddress)
        }
    }
}

impl RegionCapability {
    fn is_valid(&self) -> Result<(), ErrorCode> {
        match self.is_valid {
            true => Ok(()),
            false => Err(ErrorCode::InvalidRegionCapa),
        }
    }

    fn is_owned(&self) -> Result<(), ErrorCode> {
        match self.is_owned {
            true => Ok(()),
            false => Err(ErrorCode::RegionNotOwned),
        }
    }

    /// Reset this capability, marking it as invalid.
    fn reset(&mut self) {
        *self = RegionCapability {
            is_owned: false,
            is_shared: false,
            is_valid: false,
            handle: Handle::new_unchecked(0),
        };
    }
}

impl ArenaItem for Domain {
    type Error = ErrorCode;
    const OUT_OF_BOUND_ERROR: ErrorCode = ErrorCode::DomainOutOfBound;
    const ALLOCATION_ERROR: Self::Error = ErrorCode::OutOfMemory;
}

impl ArenaItem for Region {
    type Error = ErrorCode;
    const OUT_OF_BOUND_ERROR: ErrorCode = ErrorCode::RegionOutOfBound;
    const ALLOCATION_ERROR: Self::Error = ErrorCode::OutOfMemory;
}

impl ArenaItem for RegionCapability {
    type Error = ErrorCode;
    const OUT_OF_BOUND_ERROR: ErrorCode = ErrorCode::RegionCapaOutOfBound;
    const ALLOCATION_ERROR: Self::Error = ErrorCode::OutOfMemory;
}

// ———————————————————————————————— VM Calls ———————————————————————————————— //

pub struct Hypercalls {
    root_domain: DomainHandle,
    current_domain: &'static mut DomainHandle,
    domains_arena: &'static mut DomainArena,
    regions_arena: &'static mut RegionArena,
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
            regions_arena,
        }
    }

    fn create_root_region(
        manifest: &Manifest<Statics>,
        regions_arena: &mut RegionArena,
    ) -> RegionHandle {
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
        root_region: RegionHandle,
        domains_arena: &mut DomainArena,
    ) -> DomainHandle {
        let handle = domains_arena
            .allocate()
            .expect("Failed to allocate root domain");
        let root_domain = &mut domains_arena[handle];
        root_domain.is_sealed = true;
        root_domain.is_valid = true;

        let root_region_capa = root_domain
            .regions
            .allocate()
            .expect("Failed to allocate root region capability");
        root_domain.regions[root_region_capa] = RegionCapability {
            is_owned: true,
            is_shared: false,
            is_valid: true,
            handle: root_region,
        };

        root_domain.nb_initial_regions = 1;
        root_domain.initial_regions_capa[0] = root_region_capa;

        handle
    }

    pub fn dispatch(&mut self, params: Parameters) -> HypercallResult {
        match params.vmcall {
            vmcalls::DOMAIN_GET_OWN_ID => self.domain_get_own_id(),
            vmcalls::DOMAIN_CREATE => self.domain_create(),
            vmcalls::DOMAIN_GRANT_REGION => self.domain_grant_region(params.arg_1, params.arg_2),
            vmcalls::REGION_SPLIT => self.region_split(params.arg_1, params.arg_2),
            vmcalls::REGION_GET_INFO => self.region_get_info(params.arg_1),
            vmcalls::CONFIG_NB_REGIONS => self.config_nb_regions(),
            vmcalls::CONFIG_READ_REGION => self.config_read_region(params.arg_1, params.arg_2),
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
        let handle = self.domains_arena.allocate()?;
        let domain = &mut self.domains_arena[handle];
        domain.is_sealed = false;
        domain.is_valid = true;

        Ok(Registers {
            value_1: handle.into(),
            ..Default::default()
        })
    }

    fn domain_grant_region(&mut self, domain: usize, region: usize) -> HypercallResult {
        let region_handle: RegionCapaHandle = region.try_into()?;
        let current_domain = &mut self.domains_arena[*self.current_domain];
        let region_capa = &mut current_domain.regions[region_handle];
        let handle = region_capa.handle;

        // Region must be valid and exclusively owned
        region_capa.is_valid()?;
        region_capa.is_owned()?;

        let domain_handle = domain.try_into()?;
        let domain = &mut self.domains_arena[domain_handle];

        // Domain must be valid and not sealed yet
        domain.is_valid()?;
        domain.is_unsealed()?;

        // Allocate new region for target domain
        let new_region_capa = domain.regions.allocate()?;
        domain.regions[new_region_capa] = RegionCapability {
            is_owned: true,
            is_shared: false,
            is_valid: false,
            handle,
        };

        // Maintain the list of initial capabilities
        domain.initial_regions_capa[domain.nb_initial_regions] = new_region_capa;
        domain.nb_initial_regions += 1;

        // Reset old capacity
        self.domains_arena[*self.current_domain].regions[region_handle].reset();

        Ok(Registers {
            value_1: new_region_capa.into(),
            ..Default::default()
        })
    }

    /// Split a region at the given address.
    fn region_split(&mut self, region: usize, addr: usize) -> HypercallResult {
        let old_region_handle = region.try_into()?;
        let domain = &mut self.domains_arena[*self.current_domain];
        let old_region_capa = &mut domain.regions[old_region_handle];
        let old_region_handle = old_region_capa.handle;

        // Region must be valid, exclusive, and contain the address.
        old_region_capa.is_valid()?;
        old_region_capa.is_owned()?;
        self.regions_arena[old_region_capa.handle].do_contain(addr)?;

        // Allocate a new capability
        let domain = &mut self.domains_arena[*self.current_domain];
        let new_region_capa = domain.regions.allocate()?;

        // All the check passed, split the region
        let new_region = self.regions_arena.allocate()?; // TODO: free domain capa if alloc fail
        let old_region = &mut self.regions_arena[old_region_handle];
        let end_addr = old_region.end;
        old_region.end = addr;
        self.regions_arena[new_region] = Region {
            ref_count: 1,
            start: addr,
            end: end_addr,
        };
        domain.regions[new_region_capa] = RegionCapability {
            is_owned: true,
            is_shared: false,
            is_valid: true,
            handle: new_region,
        };

        Ok(Registers {
            value_1: new_region.into(),
            ..Default::default()
        })
    }

    fn region_get_info(&mut self, region: usize) -> HypercallResult {
        let domain = &mut self.domains_arena[*self.current_domain];
        let region_capa = region.try_into()?;
        let region_capa = &domain.regions[region_capa];
        region_capa.is_valid()?;

        // Region is valid
        let region = &self.regions_arena[region_capa.handle];
        let mut flags = 0;
        if region_capa.is_owned {
            flags |= region::OWNED;
        }
        if region_capa.is_shared {
            flags |= region::SHARED;
        }

        Ok(Registers {
            value_1: region.start,
            value_2: region.end,
            value_3: flags,
        })
    }

    fn config_nb_regions(&self) -> HypercallResult {
        let domain = &self.domains_arena[*self.current_domain];
        Ok(Registers {
            value_1: domain.nb_initial_regions,
            ..Default::default()
        })
    }

    fn config_read_region(&self, offset: usize, nb_items: usize) -> HypercallResult {
        let domain = &self.domains_arena[*self.current_domain];
        if offset + nb_items > domain.nb_initial_regions {
            return Err(ErrorCode::StoreAccesOutOfBound);
        }

        let store = &domain.initial_regions_capa;
        let registers = match nb_items {
            1 => Registers {
                value_1: store[offset].into(),
                ..Default::default()
            },
            2 => Registers {
                value_1: store[offset].into(),
                value_2: store[offset + 1].into(),
                ..Default::default()
            },
            3 => Registers {
                value_1: store[offset].into(),
                value_2: store[offset + 1].into(),
                value_3: store[offset + 2].into(),
            },
            _ => return Err(ErrorCode::BadParameters),
        };

        Ok(registers)
    }
}
