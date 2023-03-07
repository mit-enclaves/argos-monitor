//! Domain object implementation
use core::cell::Ref;

use arena::{ArenaItem, Handle, TypedArena};
use bitflags::bitflags;

use crate::access::AccessRights;
use crate::backend::Backend;
use crate::context::Context;
use crate::cpu::CPU;
use crate::error::ErrorCode;
use crate::memory::MemoryRegion;
use crate::{Capability, CapabilityType, Object, Ownership, Pool};

/// DomainAccess encodes a state machine.
/// NONE cannot be duplicated.
/// Unsealed and Sealed need to be partially preserved during a duplicate, i.e.,
/// left needs to be an Unsealed/Sealed (pick left to simplify logic).
/// Valid duplicates are:
/// Unsealed -> {Unsealed, Channel} if unsealed.comm == 1;
/// Unsealed -> {Unsealed, Transition} if unsealed.comm == 1;
/// Sealed -> {Sealed, Unsealed} if sealed.spawn == 1 (create domain);
/// Sealed -> {Sealed, Channel} if sealed.comm == 1;
/// Sealed -> {Sealed, Transition} if sealed.comm == 1;
/// Channel -> {Channel, NONE} | {Channel, Channel} | {NONE, Channel} | {NONE, NONE}
/// Transition(x) -> {Transition(x), Transition(y)} with x != y
#[derive(PartialEq, Copy, Clone, Debug)]
pub enum DomainAccess {
    NONE,
    Unsealed(bool, bool), // (spawn, comm)
    Sealed(bool, bool),   // (spawn, comm)
    Channel,              // The ability to send capas to a domain.
    Transition(usize),    // The ability to transition into the domain with context usize.
}

bitflags! {
    pub struct DomainCreateFlags: usize {
        const NONE = 0;
        const SPAWN = 1 << 0;
        const COMM = 1 << 1;
    }
}

impl DomainCreateFlags {
    pub fn as_unsealed(flags: usize) -> DomainAccess {
        let bits = Self::from_bits_truncate(flags);
        let spawn = (bits & Self::SPAWN) != Self::NONE;
        let comm = (bits & Self::COMM) != Self::NONE;
        return DomainAccess::Unsealed(spawn, comm);
    }
}

pub const DEFAULT_SEALED: DomainAccess = DomainAccess::Sealed(true, true);

pub const DEFAULT_UNSEALED: DomainAccess = DomainAccess::Unsealed(true, true);

pub const DEFAULT_TRANSITON_VAL: usize = usize::MAX;

pub const DEFAULT_TRANSITON: DomainAccess = DomainAccess::Transition(DEFAULT_TRANSITON_VAL);

impl AccessRights for DomainAccess {
    fn is_null(&self) -> bool {
        *self == DomainAccess::NONE
    }

    /// This function only implements partial checks.
    /// The is_valid_dup function enforces the other requirements defined
    /// by the state machine.
    fn is_subset(&self, other: &Self) -> bool {
        match *self {
            DomainAccess::NONE => {
                return false;
            }
            DomainAccess::Unsealed(spawn, comm) => {
                if let DomainAccess::Unsealed(s, c) = *other {
                    return (spawn || s == false) && (comm || c == false);
                }
                match *other {
                    DomainAccess::Channel => {
                        return comm;
                    }
                    DomainAccess::Transition(y) => {
                        return comm && y == DEFAULT_TRANSITON_VAL;
                    }
                    _ => {
                        return false;
                    }
                }
            }
            DomainAccess::Sealed(spawn, comm) => match *other {
                DomainAccess::Unsealed(_, c) => {
                    return spawn && (c == false || c == comm);
                }
                DomainAccess::Sealed(s, c) => {
                    return (spawn || s == false) && (comm || c == false);
                }
                DomainAccess::Channel => {
                    return comm;
                }
                DomainAccess::Transition(y) => {
                    return comm && y == DEFAULT_TRANSITON_VAL;
                }
                _ => {
                    return false;
                }
            },
            DomainAccess::Channel => match other {
                DomainAccess::NONE => true,
                DomainAccess::Channel => true,
                _ => false,
            },
            DomainAccess::Transition(x) => match other {
                // Authorized values or x for the left and size max for the right.
                DomainAccess::Transition(y) => x == *y || *y == DEFAULT_TRANSITON_VAL,
                _ => false,
            },
        }
    }

    fn is_valid_dup(&self, op1: &Self, op2: &Self) -> bool {
        match *self {
            DomainAccess::Sealed(_, _) => {
                let left_valid = if let DomainAccess::Sealed(_, _) = *op1 {
                    self.is_subset(op1)
                } else {
                    false
                };
                let right_valid = if let DomainAccess::Sealed(_, _) = *op2 {
                    false
                } else {
                    self.is_subset(op2)
                };
                left_valid && right_valid
            }
            DomainAccess::Unsealed(_, _) => {
                let left_valid = if let DomainAccess::Unsealed(_, _) = *op1 {
                    self.is_subset(op1)
                } else {
                    false
                };
                let right_valid = if let DomainAccess::Unsealed(_, _) = *op2 {
                    false
                } else {
                    self.is_subset(op2)
                };
                left_valid && right_valid
            }
            DomainAccess::Channel => self.is_subset(op1) && self.is_subset(op2),
            DomainAccess::Transition(x) => {
                let left_valid = if let DomainAccess::Transition(y) = *op1 {
                    x == y
                } else {
                    false
                };
                let right_valid = if let DomainAccess::Transition(y) = *op2 {
                    y == DEFAULT_TRANSITON_VAL
                } else {
                    false
                };
                left_valid && right_valid
            }
            DomainAccess::NONE => false,
        }
    }

    fn get_null() -> Self {
        DomainAccess::NONE
    }

    fn as_bits(&self) -> (usize, usize, usize) {
        match *self {
            DomainAccess::NONE => (0, 0, 0),
            DomainAccess::Unsealed(s, c) => {
                let spawn: usize = if s { 1 } else { 0 };
                let comm: usize = if c { 1 } else { 0 };
                (1, spawn, comm)
            }
            DomainAccess::Sealed(s, c) => (2, if s { 1 } else { 0 }, if c { 1 } else { 0 }),
            DomainAccess::Channel => (3, 0, 0),
            DomainAccess::Transition(x) => (4, x, 0),
        }
    }
}

/// How many capas a domain can own.
pub const CAPAS_PER_DOMAIN: usize = 100;
pub const CONTEXT_PER_DOMAIN: usize = 10;

/// Capabilities owned by the domain.
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum OwnedCapability<B>
where
    B: Backend + 'static,
{
    Empty,
    Domain(Handle<Capability<Domain<B>>>),
    Region(Handle<Capability<MemoryRegion>>),
    CPU(Handle<Capability<CPU<B>>>),
}

impl<B> OwnedCapability<B>
where
    B: Backend + 'static,
{
    pub fn as_domain(&self) -> Result<Handle<Capability<Domain<B>>>, ErrorCode> {
        match self {
            Self::Domain(h) => Ok(*h),
            _ => Err(ErrorCode::NotADomain),
        }
    }

    pub fn as_region(&self) -> Result<Handle<Capability<MemoryRegion>>, ErrorCode> {
        match self {
            Self::Region(r) => Ok(*r),
            _ => Err(ErrorCode::NotARegion),
        }
    }

    pub fn as_cpu(&self) -> Result<Handle<Capability<CPU<B>>>, ErrorCode> {
        match self {
            Self::CPU(cpu) => Ok(*cpu),
            _ => Err(ErrorCode::NotACpu),
        }
    }
}

pub enum SealedStatus<B: Backend + 'static> {
    Unsealed,
    Sealed(Handle<OwnedCapability<B>>),
}

pub const ALL_CORES_ALLOWED: usize = usize::MAX;
pub const NO_CORES_ALLOWED: usize = 0;

/// Domain representation
pub struct Domain<B>
where
    B: Backend + 'static,
{
    pub sealed: SealedStatus<B>,
    pub state: B::DomainState,
    pub allowed_cores: usize,
    pub ref_count: usize,
    pub owned: TypedArena<OwnedCapability<B>, CAPAS_PER_DOMAIN>,
    pub contexts: TypedArena<Context<B>, CONTEXT_PER_DOMAIN>,
}

impl<B> Domain<B>
where
    B: Backend,
{
    pub fn remove_capa(&self, fd: usize, _expected: OwnedCapability<B>) -> Result<(), ErrorCode> {
        //TODO fix this
        /* {
            let value = self.owned.get(Handle::new_unchecked(fd));
            if *value != expected {
                return Err(ErrorCode::WrongOwnership);
            }
        } */
        // Free the handle.
        self.owned.free(Handle::new_unchecked(fd));
        Ok(())
    }

    pub fn enumerate<F>(&self, mut callback: F)
    where
        F: FnMut(usize, &OwnedCapability<B>),
    {
        for i in 0..CAPAS_PER_DOMAIN {
            if self.owned.is_allocated(i) {
                let o = self.owned.get(Handle::new_unchecked(i));
                callback(i, &o);
            }
        }
    }

    pub fn enumerate_at<F, R>(&self, idx: usize, mut callback: F) -> Result<R, ErrorCode>
    where
        F: FnMut(usize, &OwnedCapability<B>) -> R,
    {
        for i in idx..CAPAS_PER_DOMAIN {
            if self.owned.is_allocated(i) {
                let o = self.owned.get(Handle::new_unchecked(i));
                return Ok(callback(i, &o));
            }
        }
        return Err(ErrorCode::OutOfBound);
    }

    pub fn get_local_capa(&self, idx: usize) -> Result<Ref<OwnedCapability<B>>, ErrorCode> {
        if idx >= CAPAS_PER_DOMAIN {
            return Err(ErrorCode::InvalidLocalCapa);
        }
        let local = self.owned.get(Handle::new_unchecked(idx));
        if let OwnedCapability::Empty = *local {
            return Err(ErrorCode::InvalidLocalCapa);
        }
        Ok(local)
    }

    pub fn is_sealed(&self) -> bool {
        if let SealedStatus::Unsealed = self.sealed {
            return false;
        }
        return true;
    }

    pub fn is_allowed_core(&self, idx: usize) -> bool {
        return (1 << idx) & self.allowed_cores != 0;
    }

    pub fn get_sealed_capa(&self) -> Result<Handle<Capability<Domain<B>>>, ErrorCode> {
        if !self.is_sealed() {
            return Err(ErrorCode::InvalidSeal);
        }
        match self.sealed {
            SealedStatus::Sealed(h) => {
                return self.owned.get(h).as_domain();
            }
            _ => {
                return Err(ErrorCode::InvalidSeal);
            }
        }
    }
}

impl<B: Backend> Object for Domain<B> {
    type Access = DomainAccess;
    fn from_bits(bits: usize, _: usize, _: usize) -> Self::Access {
        let bits = DomainCreateFlags::from_bits_truncate(bits);
        if bits == DomainCreateFlags::COMM {
            return DomainAccess::Channel;
        }
        return DomainAccess::NONE;
    }
    fn incr_ref(&mut self, _pool: &impl Pool<Self>, _capa: &Capability<Self>) {
        self.ref_count += 1;
    }

    fn decr_ref(&mut self, _pool: &impl Pool<Self>, _capa: &Capability<Self>) {
        //TODO when do we deallocate?
        self.ref_count -= 1;
    }

    fn get_ref(&self, _pool: &impl Pool<Self>, _capa: &Capability<Self>) -> usize {
        return self.ref_count;
    }

    fn create_from(
        pool: &impl Pool<Self>,
        capa: &Capability<Self>,
        op: &Self::Access,
    ) -> Result<Handle<Capability<Self>>, ErrorCode>
    where
        Self: Sized,
    {
        if capa.owner == Ownership::Empty {
            return Err(ErrorCode::NotOwnedCapability);
        }
        // Easy case, no need to do anything.
        if op.is_null() {
            return Ok(Handle::null());
        }
        // Check again access rights subset.
        if !capa.access.is_subset(op) {
            return Err(ErrorCode::IncreasingAccessRights);
        }

        // Attempting to create a new domain.
        let needs_create: bool = match (&capa.access, op) {
            (DomainAccess::Sealed(_, _), DomainAccess::Unsealed(_, _)) => true,
            _ => false,
        };

        // Allocate.
        let new_handle = pool.allocate_capa()?;
        {
            // Check if we need to allocate a new context.
            let access = if let DomainAccess::Transition(DEFAULT_TRANSITON_VAL) = *op {
                let obj = pool.get(capa.handle);
                let ctxt_h = obj.contexts.allocate().map_err(|e| {
                    // Something went wrong.
                    pool.free_capa(new_handle);
                    e
                })?;
                let mut ctxt = obj.contexts.get_mut(ctxt_h);
                ctxt.in_use = false;
                DomainAccess::Transition(ctxt_h.idx())
            } else {
                *op
            };
            let mut new_capa = pool.get_capa_mut(new_handle);
            new_capa.access = access;

            // Do we need a new domain.
            if needs_create {
                let domain_handle = match pool.allocate() {
                    Ok(dh) => dh,
                    Err(err) => {
                        pool.free_capa(new_handle);
                        return Err(err);
                    }
                };
                let mut domain = pool.get_mut(domain_handle);
                domain.sealed = SealedStatus::<B>::Unsealed;
                domain.ref_count = 1;
                new_capa.handle = domain_handle;
            } else {
                new_capa.handle = capa.handle;
                // Increment references
                let mut obj = pool.get_mut(capa.handle);
                obj.incr_ref(pool, &new_capa);
            }
        }
        // Handle ownership.
        if let Ownership::Domain(dom, _) = capa.owner {
            pool.set_owner_capa(new_handle, Handle::new_unchecked(dom))?;
        }

        // Do not call install now, duplicate might fail on the second handle.
        return Ok(new_handle);
    }

    /*    fn install(
            &mut self,
            _pool: &impl Pool<Self>,
            _capa: &Capability<Self>,
        ) -> Result<(), ErrorCode>
        where
            Self: Sized,
        {
            //pool.apply(capa)
            Ok(())
        }

        fn uninstall(
            &mut self,
            _pool: &impl Pool<Self>,
            _capa: &Capability<Self>,
        ) -> Result<(), ErrorCode>
        where
            Self: Sized,
        {
            //pool.unapply(capa)
            Ok(())
        }
    */
}

// ——————————————————— Capability<Domain> Implementation ———————————————————— //

impl<B: Backend> Capability<Domain<B>> {
    pub fn new(
        pool: &impl Pool<Domain<B>>,
        handle: Handle<Domain<B>>,
        access: DomainAccess,
    ) -> Result<Handle<Capability<Domain<B>>>, ErrorCode> {
        let capa_handle = pool.allocate_capa()?;
        let mut capa = pool.get_capa_mut(capa_handle);
        capa.capa_type = CapabilityType::Resource;
        capa.access = access;
        capa.handle = handle;
        capa.left = Handle::null();
        capa.right = Handle::null();
        Ok(capa_handle)
    }

    pub fn seal(
        &mut self,
        pool: &impl Pool<Domain<B>>,
        core_map: usize,
        arg1: usize,
        arg2: usize,
        arg3: usize,
    ) -> Result<Handle<Capability<Domain<B>>>, ErrorCode> {
        let (s, c) = match self.access {
            DomainAccess::Unsealed(s, c) => {
                let mut domain = pool.get_mut(self.handle);
                match domain.sealed {
                    SealedStatus::Unsealed => {
                        if let Ownership::Domain(dom, idx) = self.owner {
                            if dom != self.handle.idx() {
                                return Err(ErrorCode::InvalidSeal);
                            }
                            domain.sealed = SealedStatus::<B>::Sealed(Handle::new_unchecked(idx));
                            domain.allowed_cores = core_map;
                        }
                    }
                    _ => {
                        return Err(ErrorCode::InvalidSeal);
                    }
                }
                (s, c)
            }
            _ => {
                return Err(ErrorCode::InvalidSeal);
            }
        };
        // Set up the sealed capability
        self.access = DomainAccess::Sealed(s, c);

        // Now actually return a transition handle.
        let (_, transition) = self
            .duplicate(DomainAccess::Sealed(s, c), DEFAULT_TRANSITON, pool)
            .map_err(|e| e.code())?;

        // Setup the transition context.
        {
            let trans = pool.get_capa(transition);
            if let DomainAccess::Transition(idx) = trans.access {
                let dom = pool.get(trans.handle);
                let mut context = dom.contexts.get_mut(Handle::new_unchecked(idx));
                context.init(arg1, arg2, arg3);
            }
        }
        Ok(transition)
    }

    pub fn create_transition(
        &mut self,
        pool: &impl Pool<Domain<B>>,
    ) -> Result<(Handle<Capability<Domain<B>>>, Handle<Capability<Domain<B>>>), ErrorCode> {
        let same = match self.access {
            DomainAccess::Sealed(x, true) => DomainAccess::Sealed(x, true),
            _ => {
                return Err(ErrorCode::InvalidTransition);
            }
        };
        self.duplicate(same, DomainAccess::Transition(DEFAULT_TRANSITON_VAL), pool)
            .map_err(|e| e.code())
    }
}

// ——————————————————————— Arena Trait Implementation ——————————————————————— //
impl<B: Backend> ArenaItem for Domain<B> {
    type Error = ErrorCode;
    const OUT_OF_BOUND_ERROR: Self::Error = ErrorCode::OutOfBound;
    const ALLOCATION_ERROR: Self::Error = ErrorCode::AllocationError;
}

impl<B: Backend> ArenaItem for OwnedCapability<B> {
    type Error = ErrorCode;
    const OUT_OF_BOUND_ERROR: Self::Error = ErrorCode::OutOfBound;
    const ALLOCATION_ERROR: Self::Error = ErrorCode::AllocationError;
}
