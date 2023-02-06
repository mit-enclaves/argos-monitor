//! Domain object implementation
use core::cell::Ref;

use arena::{ArenaItem, Handle, TypedArena};
use bitflags::bitflags;

use crate::access::AccessRights;
use crate::backend::Backend;
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
/// Sealed -> {Sealed, Unsealed} if sealed.spawn == 1 (create domain);
/// Sealed -> {Sealed, Channel} if sealed.comm == 1;
/// Channel -> {Channel, NONE} | {Channel, Channel} | {NONE, Channel} | {NONE, NONE}
#[derive(PartialEq, Copy, Clone, Debug)]
pub enum DomainAccess {
    NONE,
    Unsealed(bool, bool), // (spawn, comm)
    Sealed(bool, bool),   // (spawn, comm)
    Channel,
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
                if let DomainAccess::Channel = *other {
                    return comm;
                }
                return false;
            }
            DomainAccess::Sealed(spawn, comm) => {
                if let DomainAccess::Unsealed(_, c) = other {
                    return spawn && (*c == false || *c == comm);
                }
                if let DomainAccess::Sealed(s, c) = other {
                    return (spawn || *s == false) && (comm || *c == false);
                }
                if let DomainAccess::Channel = other {
                    return comm;
                }
                return false;
            }
            DomainAccess::Channel => match other {
                DomainAccess::NONE => true,
                DomainAccess::Channel => true,
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
            DomainAccess::NONE => false,
        }
    }

    fn get_null() -> Self {
        DomainAccess::NONE
    }
}

/// How many capas a domain can own.
pub const CAPAS_PER_DOMAIN: usize = 100;

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

/// Domain representation
pub struct Domain<B>
where
    B: Backend + 'static,
{
    pub is_sealed: bool,
    pub state: B::DomainState,
    pub ref_count: usize,
    pub owned: TypedArena<OwnedCapability<B>, CAPAS_PER_DOMAIN>,
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
        //TODO create new domain.
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
            let mut new_capa = pool.get_capa_mut(new_handle);
            new_capa.access = *op;
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
                domain.is_sealed = false;
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
            pool.set_owner_capa(new_handle, dom)?;
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

    pub fn seal(&mut self) -> Result<(), ErrorCode> {
        let (s, c) = match self.access {
            DomainAccess::Unsealed(s, c) => (s, c),
            _ => {
                return Err(ErrorCode::InvalidSeal);
            }
        };
        self.access = DomainAccess::Sealed(s, c);
        Ok(())
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
