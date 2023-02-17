//! Applicatioe Binary Interface

use crate::arena::{ArenaItem, Handle, TypedArena};
use crate::statics::{NB_DOMAINS, NB_REGIONS, NB_REGIONS_PER_DOMAIN, NB_SWITCH_PER_DOMAIN};
use mmu::FrameAllocator;
use stage_two_abi::Manifest;

// ——————————————————————————————— Hypercalls ——————————————————————————————— //

#[rustfmt::skip]
pub mod vmcalls {
    pub const DOMAIN_GET_OWN_ID: usize   = 0x100;
    pub const DOMAIN_CREATE: usize       = 0x101;
    pub const DOMAIN_SEAL: usize         = 0x102;
    pub const DOMAIN_GRANT_REGION: usize = 0x103;
    pub const DOMAIN_SHARE_REGION: usize = 0x104;
    pub const DOMAIN_REVOK_REGION: usize = 0x105;
    pub const REGION_SPLIT: usize        = 0x200;
    pub const REGION_GET_INFO: usize     = 0x201;
    pub const REGION_MERGE: usize        = 0x202;
    pub const CONFIG_NB_REGIONS: usize   = 0x400;
    pub const CONFIG_READ_REGION: usize  = 0x401;
    pub const EXIT: usize                = 0x500;
    pub const DEBUG_IOMMU: usize         = 0x600;
    pub const SEND_IPI: usize            = 0x700;
    pub const DOMAIN_SWITCH: usize       = 0x999;
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
    DomainIsNotSealed = 12,
    StoreAccesOutOfBound = 13,
    BadParameters = 14,
    RegionIsShared = 15,
    DomainIsUnsealed = 16,
    DomainSwitchFailed = 17,
    DomainSwitchOutOfBound = 18,
    InvalidSwitch = 19,
    InvalidAccessRights = 20,
    InvalidMerge = 21,
    InvalidRefCount = 22,
}

// ————————————————————————————————— Flags —————————————————————————————————— //

#[rustfmt::skip]
pub mod region {
    pub const OWNED: usize  = 0b001;
    pub const SHARED: usize = 0b010;
}

pub mod access {
    use super::ErrorCode;

    pub const NONE: usize = 0b0000;
    pub const READ: usize = 0b0001;
    pub const WRITE: usize = 0b0010;
    pub const EXEC: usize = 0b0100;
    pub const REVOK: usize = 0b1000;
    pub const DEFAULT: usize = READ | WRITE | EXEC;

    pub fn is_less(big: usize, small: usize) -> Result<(), ErrorCode> {
        // We should always have read access, revok should never be called.
        if small & READ == 0 || big & READ == 0 || big & REVOK != 0 || small & REVOK != 0 {
            return Err(ErrorCode::InvalidAccessRights);
        }
        if (small & WRITE != 0 && big & WRITE == 0) || (small & EXEC != 0 && big & EXEC == 0) {
            return Err(ErrorCode::InvalidAccessRights);
        }
        Ok(())
    }
}

// —————————————————————————————————— ABI ——————————————————————————————————— //

pub struct Parameters {
    pub vmcall: usize,
    pub arg_1: usize,
    pub arg_2: usize,
    pub arg_3: usize,
    pub arg_4: usize,
}

pub struct Registers {
    pub value_1: usize,
    pub value_2: usize,
    pub value_3: usize,
    pub value_4: usize,
    pub next_instr: bool,
}

pub type HypercallResult = Result<Registers, ErrorCode>;

impl Default for Registers {
    fn default() -> Self {
        Self {
            value_1: 0,
            value_2: 0,
            value_3: 0,
            value_4: 0,
            next_instr: true,
        }
    }
}

// ————————————————————— Architecture-Specific Backend —————————————————————— //

pub trait Backend: Sized + 'static {
    type Vcpu<'a>;

    type Store;
    type Context;

    const EMPTY_STORE: Self::Store;
    const EMPTY_CONTEXT: Self::Context;

    fn domain_seal(
        &mut self,
        target: usize,
        current: &mut Domain<Self>,
        reg_1: usize,
        reg_2: usize,
        reg_3: usize,
    ) -> HypercallResult;

    fn domain_create(
        &mut self,
        store: &mut Self::Store,
        allocator: &impl FrameAllocator,
    ) -> Result<(), ErrorCode>;

    fn domain_restore<'a>(
        &mut self,
        store: &Self::Store,
        context: &Self::Context,
        vcpu: &mut Self::Vcpu<'a>,
    ) -> Result<(), ErrorCode>;

    fn domain_save<'a>(
        &mut self,
        context: &mut Self::Context,
        vcpu: &mut Self::Vcpu<'a>,
    ) -> Result<(), ErrorCode>;

    fn add_region(
        &mut self,
        store: &mut Self::Store,
        region: &Region,
        access: usize,
        allocator: &impl FrameAllocator,
    ) -> Result<(), ErrorCode>;

    fn remove_region(
        &mut self,
        store: &mut Self::Store,
        region: &Region,
        allocator: &impl FrameAllocator,
    ) -> Result<(), ErrorCode>;

    fn debug_iommu(&mut self) -> HypercallResult;
}

// ——————————————————————————————— ABI Types ———————————————————————————————— //

pub type DomainArena<S> = TypedArena<Domain<S>, NB_DOMAINS>;
pub type RegionArena = TypedArena<Region, NB_REGIONS>;
pub type DomainHandle<S> = Handle<Domain<S>, NB_DOMAINS>;
pub type RegionHandle = Handle<Region, NB_REGIONS>;
pub type RegionCapaHandle = Handle<RegionCapability, NB_REGIONS_PER_DOMAIN>;
pub type SwitchHandle<S> = Handle<Switch<S>, NB_SWITCH_PER_DOMAIN>;

pub struct Domain<B>
where
    B: Backend,
{
    pub is_sealed: bool,
    pub is_valid: bool,
    pub regions: TypedArena<RegionCapability, NB_REGIONS_PER_DOMAIN>,
    pub nb_initial_regions: usize,
    pub initial_regions_capa: [RegionCapaHandle; NB_REGIONS_PER_DOMAIN],
    pub store: B::Store,
    pub switches: TypedArena<Switch<B>, NB_SWITCH_PER_DOMAIN>,
}

pub struct Region {
    pub ref_count: usize,
    pub start: usize,
    pub end: usize,
}

/// Revocation information for a RegionCapability.
/// This either encodes the ability to revoke a region or references the handle
/// and domain that has the capability of revoking this one.
/// The local handle is used to reference the domain's handle to access the region.
/// It is necessary to unshare a region.
pub struct RevokInfo {
    pub domain: usize,
    pub handle: usize,
    pub local_handle: usize,
}

/// Each region has a single owner and can be marked either as owned or exclusive.
pub struct RegionCapability {
    pub is_owned: bool,
    pub is_shared: bool,
    pub is_valid: bool,
    pub access: usize,
    pub revok: RevokInfo,
    pub handle: RegionHandle,
}

/// A structure that represents the ability to transition into a domain.
pub struct Switch<B>
where
    B: Backend,
{
    // The handle is correct.
    pub is_valid: bool,
    // The target domain.
    pub domain: usize,
    // The state that needs to be saved.
    pub context: B::Context,
}

impl<B> Domain<B>
where
    B: Backend,
{
    pub fn is_valid(&self) -> Result<(), ErrorCode> {
        match self.is_valid {
            true => Ok(()),
            false => Err(ErrorCode::InvalidDomain),
        }
    }

    pub fn is_unsealed(&self) -> Result<(), ErrorCode> {
        match self.is_sealed {
            true => Err(ErrorCode::DomainIsSealed),
            false => Ok(()),
        }
    }

    pub fn is_sealed(&self) -> Result<(), ErrorCode> {
        match self.is_sealed {
            true => Ok(()),
            false => Err(ErrorCode::DomainIsUnsealed),
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

    fn is_exclusive(&self) -> Result<(), ErrorCode> {
        match self.is_shared {
            true => Err(ErrorCode::RegionIsShared),
            false => Ok(()),
        }
    }

    /// Reset this capability, marking it as invalid.
    fn reset(&mut self) {
        *self = RegionCapability {
            is_owned: false,
            is_shared: false,
            is_valid: false,
            access: access::NONE,
            revok: RevokInfo {
                domain: 0,
                handle: 0,
                local_handle: 0,
            },
            handle: Handle::new_unchecked(0),
        };
    }

    fn is_not_revok(&self) -> Result<(), ErrorCode> {
        match self.access & access::REVOK == 0 {
            true => Ok(()),
            false => Err(ErrorCode::InvalidAccessRights),
        }
    }

    fn is_revok(&self) -> Result<(), ErrorCode> {
        match self.access & access::REVOK != 0 {
            true => Ok(()),
            false => Err(ErrorCode::InvalidAccessRights),
        }
    }

    fn into_revok(
        &mut self,
        domain: usize,
        handle: usize,
        local_handle: usize,
    ) -> Result<(), ErrorCode> {
        self.is_not_revok()?;
        self.access |= access::REVOK;
        self.revok.domain = domain;
        self.revok.handle = handle;
        self.revok.local_handle = local_handle;
        Ok(())
    }
    fn from_revok(&mut self) -> Result<(), ErrorCode> {
        self.is_revok()?;
        self.access ^= access::REVOK;
        self.revok.domain = 0;
        self.revok.handle = 0;
        self.is_not_revok()?;
        Ok(())
    }
}

impl<B> Switch<B>
where
    B: Backend,
{
    pub fn is_valid(&self) -> Result<(), ErrorCode> {
        match self.is_valid {
            true => Ok(()),
            false => Err(ErrorCode::InvalidSwitch),
        }
    }
    pub fn reset(&mut self) {
        self.is_valid = false;
    }
}

impl<B> ArenaItem for Domain<B>
where
    B: Backend,
{
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

impl<B> ArenaItem for Switch<B>
where
    B: Backend,
{
    type Error = ErrorCode;
    const OUT_OF_BOUND_ERROR: ErrorCode = ErrorCode::DomainSwitchOutOfBound;
    const ALLOCATION_ERROR: Self::Error = ErrorCode::OutOfMemory;
}

// ———————————————————————————————— VM Calls ———————————————————————————————— //

pub struct Hypercalls<B>
where
    B: Backend,
{
    current_domain: DomainHandle<B>,
    domains_arena: &'static mut DomainArena<B>,
    regions_arena: &'static mut RegionArena,

    /// Architecture-specifig backend
    backend: B,
}

impl<B> Hypercalls<B>
where
    B: Backend,
{
    pub fn new<'a>(
        manifest: &Manifest,
        mut backend: B,
        vcpus: &mut [Option<B::Vcpu<'a>>],
        allocator: &impl FrameAllocator,
        domains_arena: &'static mut DomainArena<B>,
        regions_arena: &'static mut RegionArena,
    ) -> Self {
        let root_region = Self::create_root_region(manifest, regions_arena);
        let root_domain = Self::create_root_domain(
            manifest,
            root_region,
            domains_arena,
            regions_arena,
            &mut backend,
            vcpus,
            allocator,
        );

        Self {
            current_domain: root_domain,
            domains_arena,
            regions_arena,
            backend,
        }
    }

    fn create_root_region(manifest: &Manifest, regions_arena: &mut RegionArena) -> RegionHandle {
        let handle = regions_arena
            .allocate()
            .expect("Failed to allocate root region");
        let root_region = &mut regions_arena[handle];
        root_region.start = 0;
        root_region.end = manifest.poffset as usize;
        root_region.ref_count = 1;

        handle
    }

    fn create_root_domain<'a>(
        _manifest: &Manifest,
        root_region: RegionHandle,
        domains_arena: &mut DomainArena<B>,
        regions_arena: &RegionArena,
        backend: &mut B,
        vcpus: &mut [Option<B::Vcpu<'a>>],
        allocator: &impl FrameAllocator,
    ) -> DomainHandle<B> {
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
            access: access::DEFAULT,
            revok: RevokInfo {
                domain: 0,
                handle: 0,
                local_handle: root_region_capa.into(),
            },
            handle: root_region,
        };
        // TODO: initialize properly
        backend
            .domain_create(&mut root_domain.store, allocator)
            .expect("Failed to create root domain");
        backend
            .add_region(
                &mut root_domain.store,
                &regions_arena[root_region],
                access::DEFAULT,
                allocator,
            )
            .expect("Failed to add root region");
        let fake_context = B::EMPTY_CONTEXT;
        backend
            .domain_restore(
                &root_domain.store,
                &fake_context,
                vcpus[0].as_mut().unwrap(),
            )
            .expect("Failed to switch to root domain");
        root_domain.nb_initial_regions = 1;
        root_domain.initial_regions_capa[0] = root_region_capa;
        handle
    }

    pub fn init<'a>(&self, backend: &mut B, vcpu: &mut B::Vcpu<'a>) {
        let root_domain = &self.domains_arena[self.current_domain];
        let fake_context = B::EMPTY_CONTEXT;
        backend
            .domain_restore(&root_domain.store, &fake_context, vcpu)
            .expect("Failed to switch to root domain");
    }

    pub fn dispatch<'a>(
        &mut self,
        allocator: &impl FrameAllocator,
        vcpu: &mut B::Vcpu<'a>,
        params: Parameters,
    ) -> HypercallResult {
        match params.vmcall {
            vmcalls::DOMAIN_GET_OWN_ID => self.domain_get_own_id(),
            vmcalls::DOMAIN_CREATE => self.domain_create(allocator),
            vmcalls::DOMAIN_GRANT_REGION => {
                self.domain_grant_region(allocator, params.arg_1, params.arg_2, params.arg_3)
            }
            vmcalls::DOMAIN_SHARE_REGION => {
                self.domain_share_region(allocator, params.arg_1, params.arg_2, params.arg_3)
            }
            vmcalls::DOMAIN_REVOK_REGION => self.domain_revok_region(allocator, params.arg_1),
            vmcalls::DOMAIN_SWITCH => self.domain_switch(params.arg_1, vcpu),
            vmcalls::REGION_SPLIT => self.region_split(params.arg_1, params.arg_2),
            vmcalls::REGION_GET_INFO => self.region_get_info(params.arg_1),
            vmcalls::REGION_MERGE => self.region_merge(params.arg_1, params.arg_2),
            vmcalls::CONFIG_NB_REGIONS => self.config_nb_regions(),
            vmcalls::CONFIG_READ_REGION => self.config_read_region(params.arg_1, params.arg_2),
            vmcalls::DEBUG_IOMMU => self.backend.debug_iommu(),
            vmcalls::DOMAIN_SEAL => {
                self.domain_seal(params.arg_1, params.arg_2, params.arg_3, params.arg_4)
            }
            vmcalls::SEND_IPI => self.send_ipi(params.arg_1 as u8),
            _ => Err(ErrorCode::UnknownVmCall),
        }
    }

    pub fn is_exit(&self, params: &Parameters) -> bool {
        params.vmcall == vmcalls::EXIT
    }

    pub fn is_switch(&self, params: &Parameters) -> bool {
        params.vmcall == vmcalls::DOMAIN_SWITCH
    }

    /// Returns the Domain ID of the current domain.
    fn domain_get_own_id(&mut self) -> HypercallResult {
        let domain = self.current_domain;
        Ok(Registers {
            value_1: domain.into(),
            ..Default::default()
        })
    }

    /// Creates a fresh domain.
    fn domain_create(&mut self, allocator: &impl FrameAllocator) -> HypercallResult {
        let handle = self.domains_arena.allocate()?;
        let domain = &mut self.domains_arena[handle];

        // Initialize domain
        self.backend.domain_create(&mut domain.store, allocator)?;
        domain.is_sealed = false;
        domain.is_valid = true;

        Ok(Registers {
            value_1: handle.into(),
            ..Default::default()
        })
    }

    fn domain_grant_region(
        &mut self,
        allocator: &impl FrameAllocator,
        domain: usize,
        region: usize,
        rights: usize,
    ) -> HypercallResult {
        let region_handle: RegionCapaHandle = region.try_into()?;
        let current_id: usize = (self.current_domain).into();
        let current_domain = &mut self.domains_arena[self.current_domain];
        let region_capa = &mut current_domain.regions[region_handle];
        let handle = region_capa.handle;

        // Region must be valid and exclusively owned
        region_capa.is_valid()?;
        region_capa.is_owned()?;
        region_capa.is_exclusive()?;
        region_capa.is_not_revok()?;

        // Access rights must be smaller or equal than current ones.
        access::is_less(region_capa.access, rights)?;

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
            is_valid: true,
            access: rights,
            revok: RevokInfo {
                domain: current_id,
                handle: region,
                local_handle: new_region_capa.into(),
            },
            handle,
        };

        // Maintain the list of initial capabilities
        domain.initial_regions_capa[domain.nb_initial_regions] = new_region_capa;
        domain.nb_initial_regions += 1;

        // Turn old capability into a revocation one (keep rights encoded).
        self.domains_arena[self.current_domain].regions[region_handle].into_revok(
            domain_handle.into(),
            new_region_capa.into(),
            region_handle.into(),
        )?;

        // Call the backend to effect the changes.
        let region = &self.regions_arena[handle];
        self.backend.remove_region(
            &mut self.domains_arena[self.current_domain].store,
            region,
            allocator,
        )?;
        self.backend.add_region(
            &mut self.domains_arena[domain_handle].store,
            region,
            rights,
            allocator,
        )?;

        // Return the revocation handle.
        Ok(Registers {
            value_1: region_handle.into(),
            ..Default::default()
        })
    }

    //TODO handle ref count.
    fn domain_share_region(
        &mut self,
        allocator: &impl FrameAllocator,
        domain: usize,
        region: usize,
        rights: usize,
    ) -> HypercallResult {
        let region_handle: RegionCapaHandle = region.try_into()?;
        let current_domain = &mut self.domains_arena[self.current_domain];
        let region_capa = &mut current_domain.regions[region_handle];
        let handle = region_capa.handle;

        // Region must be valid, no need to be owned
        region_capa.is_valid()?;
        region_capa.is_not_revok()?;

        // Access rights should be smaller or equal.
        access::is_less(region_capa.access, rights)?;

        // Allocate a revocation handle.
        let revok_handle: usize = {
            let revok = current_domain.regions.allocate()?;
            current_domain.regions[revok] = RegionCapability {
                is_owned: false,
                is_shared: true,
                is_valid: true,
                access: access::REVOK,
                revok: RevokInfo {
                    domain,
                    handle: 0, /*This is set after the allocation*/
                    local_handle: region,
                },
                handle,
            };
            revok.into()
        };

        let domain_handle = domain.try_into()?;
        let domain = &mut self.domains_arena[domain_handle];

        // Domain must be valid and not sealed yet
        domain.is_valid()?;
        domain.is_unsealed()?;

        // Allocate new region for target domain
        let new_region_capa = domain.regions.allocate()?;
        domain.regions[new_region_capa] = RegionCapability {
            is_owned: false,
            is_shared: true,
            is_valid: true,
            access: rights,
            revok: RevokInfo {
                domain: (self.current_domain).into(),
                handle: revok_handle,
                local_handle: new_region_capa.into(),
            },
            handle,
        };

        // Maintain the list of initial capabilities
        domain.initial_regions_capa[domain.nb_initial_regions] = new_region_capa;
        domain.nb_initial_regions += 1;

        // Mark old capacity as shared
        self.domains_arena[self.current_domain].regions[region_handle].is_shared = true;
        // Register the revocation handle
        self.domains_arena[self.current_domain].regions[revok_handle.try_into()?]
            .revok
            .handle = new_region_capa.into();
        // Increase the ref count to the region.
        self.regions_arena[handle].ref_count += 1;

        // Call the backend to effect the changes.
        let region = &self.regions_arena[handle];
        let store = &mut self.domains_arena[domain_handle].store;
        self.backend.add_region(store, region, rights, allocator)?;
        // Return the revocation handle.
        Ok(Registers {
            value_1: revok_handle,
            ..Default::default()
        })
    }

    fn domain_revok_region<'a>(
        &mut self,
        allocator: &impl FrameAllocator,
        handle: usize,
    ) -> HypercallResult {
        let (tgt_domain_handle, tgt_region_handle, local_handle) = {
            let revok_handle: RegionCapaHandle = handle.try_into()?;
            let current_domain = &mut self.domains_arena[self.current_domain];
            let region_capa = &mut current_domain.regions[revok_handle];
            region_capa.is_revok()?;
            (
                region_capa.revok.domain,
                region_capa.revok.handle,
                region_capa.revok.local_handle,
            )
        };

        let shared = {
            let tgt_domain = &mut self.domains_arena[tgt_domain_handle.try_into()?];
            let tgt_region = &mut tgt_domain.regions[tgt_region_handle.try_into()?];
            let region = &self.regions_arena[tgt_region.handle];
            self.backend
                .remove_region(&mut tgt_domain.store, region, allocator)?;
            let is_shared = tgt_region.is_shared;
            tgt_region.reset();
            tgt_domain.regions.free(tgt_region_handle.try_into()?);
            is_shared
        };

        let current_domain = &mut self.domains_arena[self.current_domain];
        let region_capa = &mut current_domain.regions[handle.try_into()?];
        if shared {
            let rhandle = region_capa.handle;
            region_capa.reset();
            current_domain.regions.free(handle.try_into()?);
            let region = &mut self.regions_arena[rhandle];
            if region.ref_count <= 1 {
                return Err(ErrorCode::InvalidRefCount);
            }
            region.ref_count -= 1;
            // The domain is now owned.
            if region.ref_count == 1 {
                let region = &mut self.domains_arena[self.current_domain].regions
                    [local_handle.try_into()?];
                region.is_owned = true;
                region.is_shared = false;
            }
        } else {
            region_capa.from_revok()?;
            let reg = &mut self.regions_arena[region_capa.handle];
            self.backend.add_region(
                &mut current_domain.store,
                reg,
                region_capa.access,
                allocator,
            )?;
        }

        Ok(Registers {
            ..Default::default()
        })
    }

    fn domain_switch<'a>(&mut self, handle: usize, vcpu: &mut B::Vcpu<'a>) -> HypercallResult {
        // Identify the current domain.
        let caller = {
            let interm = self.current_domain;
            interm.into()
        };
        // Check the transition handle is valid.
        let switch_domain = {
            let current = &self.domains_arena[self.current_domain];
            let switch_context = &current.switches[handle.try_into()?];
            switch_context.is_valid()?;
            switch_context.domain
        };
        // Save the current context and create a return handle.
        let ret_handle = {
            let target = &mut self.domains_arena[switch_domain.try_into()?];
            let ret_handle = target.switches.allocate()?;
            let ret_switch = &mut target.switches[ret_handle.into()];
            self.backend.domain_save(&mut ret_switch.context, vcpu)?;
            ret_switch.is_valid = true;
            ret_switch.domain = caller;
            ret_handle.into()
        };
        // Restore the previous context.
        {
            let target = &self.domains_arena[switch_domain.try_into()?];
            let current = &self.domains_arena[self.current_domain];
            let switch_context = &current.switches[handle.try_into()?].context;
            target.is_valid()?;
            target.is_sealed()?;
            self.backend
                .domain_restore(&target.store, &switch_context, vcpu)?;
        }
        // Reset
        {
            let current = &mut self.domains_arena[self.current_domain];
            let switch_context = &mut current.switches[handle.try_into()?];
            switch_context.reset();
            current.switches.free(handle.try_into()?);
        }
        self.current_domain = switch_domain.try_into()?;
        return Ok(Registers {
            value_1: ret_handle,
            value_2: 0,
            value_3: 0,
            value_4: 0,
            next_instr: false,
        });
    }

    /// Split a region at the given address.
    fn region_split(&mut self, region: usize, addr: usize) -> HypercallResult {
        let old_region_handle = region.try_into()?;
        let domain = &mut self.domains_arena[self.current_domain];
        let old_region_capa = &mut domain.regions[old_region_handle];
        let old_region_handle = old_region_capa.handle;
        let access_rights = old_region_capa.access;

        // Region must be valid, exclusive, and contain the address.
        old_region_capa.is_valid()?;
        old_region_capa.is_not_revok()?;
        old_region_capa.is_owned()?;
        old_region_capa.is_exclusive()?;
        self.regions_arena[old_region_capa.handle].do_contain(addr)?;

        // Allocate a new capability
        let domain = &mut self.domains_arena[self.current_domain];
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
            access: access_rights,
            revok: RevokInfo {
                domain: 0, //TODO should propagate?
                handle: 0,
                local_handle: new_region_capa.into(),
            },
            handle: new_region,
        };
        Ok(Registers {
            value_1: new_region_capa.into(),
            ..Default::default()
        })
    }

    fn region_get_info(&mut self, region: usize) -> HypercallResult {
        let domain = &mut self.domains_arena[self.current_domain];
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
            value_4: region_capa.access,
            next_instr: true,
        })
    }

    fn region_merge(&mut self, r1: usize, r2: usize) -> HypercallResult {
        let domain = &mut self.domains_arena[self.current_domain];
        let handle1 = r1.try_into()?;
        let region1_capa = &domain.regions[handle1];
        let handle2 = r2.try_into()?;
        let region2_capa = &domain.regions[handle2];
        let region1 = &self.regions_arena[region1_capa.handle];
        let region2 = &self.regions_arena[region2_capa.handle];

        // Checks for well-formness.
        region1_capa.is_valid()?;
        region1_capa.is_not_revok()?;
        region1_capa.is_owned()?;
        region1_capa.is_exclusive()?;

        region2_capa.is_valid()?;
        region2_capa.is_not_revok()?;
        region2_capa.is_owned()?;
        region2_capa.is_exclusive()?;

        if region1_capa.access != region2_capa.access {
            return Err(ErrorCode::InvalidAccessRights);
        }
        if region1.start >= region2.start {
            return Err(ErrorCode::InvalidMerge);
        }
        if region1.end != region2.start {
            return Err(ErrorCode::InvalidMerge);
        }
        if region2.ref_count != 1 {
            return Err(ErrorCode::InvalidMerge);
        }

        // Let's merge.
        let new_end = region2.end;
        {
            let region1 = &mut self.regions_arena[region1_capa.handle];
            region1.end = new_end;
        }
        {
            let region2 = &mut self.regions_arena[region2_capa.handle];
            region2.ref_count = 0;
            self.regions_arena.free(region2_capa.handle);
            let region2_capa = &mut domain.regions[handle2];
            region2_capa.reset();
            domain.regions.free(handle2);
        }

        Ok(Registers {
            ..Default::default()
        })
    }

    fn config_nb_regions(&self) -> HypercallResult {
        let domain = &self.domains_arena[self.current_domain];
        Ok(Registers {
            value_1: domain.nb_initial_regions,
            ..Default::default()
        })
    }

    fn config_read_region(&self, offset: usize, nb_items: usize) -> HypercallResult {
        let domain = &self.domains_arena[self.current_domain];
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
                value_4: 0,
                next_instr: true,
            },
            _ => return Err(ErrorCode::BadParameters),
        };

        Ok(registers)
    }

    fn domain_seal(
        &mut self,
        handle: usize,
        reg_1: usize,
        reg_2: usize,
        reg_3: usize,
    ) -> HypercallResult {
        let domain_handle = handle.try_into()?;
        let domain = &mut self.domains_arena[domain_handle];

        // Check that domain can be sealed
        domain.is_valid()?;
        domain.is_unsealed()?;
        domain.is_sealed = true;
        let domain = &mut self.domains_arena[self.current_domain];
        self.backend
            .domain_seal(handle, domain, reg_1, reg_2, reg_3)
    }

    fn send_ipi(&mut self, vector: u8) -> HypercallResult {
        // Assume Local APIC is at 0xfee00000
        crate::println!("send_ipi ...");

        unsafe fn write_icr(icr: u64) {
            // ICR1
            core::ptr::write_volatile(0xfee00310 as *mut u32, (icr >> 32) as u32);
            // ICR0
            core::ptr::write_volatile(0xfee00300 as *mut u32, (icr & 0xffff_ffff) as u32);
        }

        for i in 0..8 {
            crate::println!("Sending IPI with vector {} to CPU {}", vector, i);

            // Assert the level interrupt
            // Check Intel SDM 11.6.1 for more details
            let vector = 0;
            let delivery_mode = 5; // INIT
            let destination_mode = 0; // Physical
            let delivery_status = 0; // Idle
            let level = 1; // Assert
            let trigger_mode = 1; // Level-Triggered
            let destination_shorthand = 0; // No Shorthand
            let destination = i;

            let icr = (destination as u64) << 56
                | (destination_shorthand as u64) << 18
                | (trigger_mode as u64) << 15
                | (level as u64) << 14
                | (delivery_status as u64) << 12
                | (destination_mode as u64) << 11
                | (delivery_mode as u64) << 8
                | (vector as u64);

            unsafe { write_icr(icr) };


            // Deassert the level interrupt

            let level = 0; // Deassert

            let icr = (destination as u64) << 56
                | (destination_shorthand as u64) << 18
                | (trigger_mode as u64) << 15
                | (level as u64) << 14
                | (delivery_status as u64) << 12
                | (destination_mode as u64) << 11
                | (delivery_mode as u64) << 8
                | (vector as u64);

            unsafe { write_icr(icr) };

            crate::println!("Sent IPI with vector {} to CPU {}", vector, i);
        }

        Ok(Registers {
            ..Default::default()
        })
    }
}
