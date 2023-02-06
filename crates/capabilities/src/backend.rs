//! Backend trait.
//! The backend is the interface between the platform-independent capability model
//! and the platform enforcement.

use core::cell::RefCell;

use arena::{Handle, TypedArena};

use crate::cpu::{CPUAccess, CPUFlags, CPU};
use crate::domain::{Domain, DomainAccess, OwnedCapability, CAPAS_PER_DOMAIN};
use crate::error::Error;
use crate::memory::MemoryRegion;
use crate::{Capability, CapabilityType, Ownership, State};

pub trait Backend {
    type DomainState;
    type Core;
    type Error: core::fmt::Debug;

    fn install_region(
        &self,
        pool: &State<'_, Self>,
        capa: &Capability<MemoryRegion>,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized;
    fn uninstall_region(
        &self,
        pool: &State<'_, Self>,
        capa: &Capability<MemoryRegion>,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized;

    fn create_domain(
        &self,
        pool: &State<'_, Self>,
        capa: &Capability<Domain<Self>>,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized;

    fn install_domain(
        &self,
        pool: &State<'_, Self>,
        capa: &Capability<Domain<Self>>,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized;

    fn uninstall_domain(
        &self,
        pool: &State<'_, Self>,
        capa: &Capability<Domain<Self>>,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized;

    fn create_cpu(
        &self,
        pool: &State<'_, Self>,
        capa: &Capability<CPU<Self>>,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized;

    fn install_cpu(
        &self,
        pool: &State<'_, Self>,
        capa: &Capability<CPU<Self>>,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized;

    fn uninstall_cpu(
        &self,
        pool: &State<'_, Self>,
        capa: &Capability<CPU<Self>>,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized;
}

// ———————————————————— Default NoBackend Implementation ———————————————————— //

/// NoBackendState
#[derive(PartialEq)]
pub struct NoBackendState {}

pub struct NoBackendCore {}

/// Placeholder for a backend.
#[derive(PartialEq)]
pub struct NoBackend {}

/// Used for empty initializers.
pub const NO_BACKEND: NoBackend = NoBackend {};

pub const EMPTY_OWNED_CAPABILITY: RefCell<OwnedCapability<NoBackend>> =
    RefCell::new(OwnedCapability::Empty);

/// Empty domain.
pub const EMPTY_DOMAIN: RefCell<Domain<NoBackend>> = RefCell::new(Domain::<NoBackend> {
    is_sealed: true,
    state: NoBackendState {},
    ref_count: usize::MAX,
    owned: TypedArena::new([EMPTY_OWNED_CAPABILITY; CAPAS_PER_DOMAIN]),
});
pub const EMPTY_DOMAIN_CAPA: RefCell<Capability<Domain<NoBackend>>> = RefCell::new(Capability {
    owner: Ownership::Empty,
    capa_type: CapabilityType::Resource,
    access: DomainAccess::NONE,
    handle: Handle::null(),
    left: Handle::null(),
    right: Handle::null(),
});

pub const EMPTY_CPU: RefCell<CPU<NoBackend>> = RefCell::new(CPU::<NoBackend> {
    id: usize::MAX,
    ref_count: usize::MAX,
    core: NoBackendCore {},
});

pub const EMPTY_CPU_CAPA: RefCell<Capability<CPU<NoBackend>>> = RefCell::new(Capability {
    owner: Ownership::Empty,
    capa_type: CapabilityType::Resource,
    access: CPUAccess {
        flags: CPUFlags::NONE,
    },
    handle: Handle::null(),
    left: Handle::null(),
    right: Handle::null(),
});

impl Backend for NoBackend {
    type DomainState = NoBackendState;
    type Core = NoBackendCore;
    type Error = ();

    fn install_region(
        &self,
        _pool: &State<'_, Self>,
        _capa: &Capability<MemoryRegion>,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized,
    {
        Ok(())
    }
    fn uninstall_region(
        &self,
        _pool: &State<'_, Self>,
        _capa: &Capability<MemoryRegion>,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized,
    {
        Ok(())
    }

    fn create_domain(
        &self,
        _pool: &State<'_, Self>,
        _capa: &Capability<Domain<Self>>,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized,
    {
        Ok(())
    }

    fn install_domain(
        &self,
        _pool: &State<'_, Self>,
        _capa: &Capability<Domain<Self>>,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized,
    {
        Ok(())
    }
    fn uninstall_domain(
        &self,
        _pool: &State<'_, Self>,
        _capa: &Capability<Domain<Self>>,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized,
    {
        Ok(())
    }

    fn install_cpu(
        &self,
        _pool: &State<'_, Self>,
        _capa: &Capability<CPU<Self>>,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized,
    {
        Ok(())
    }

    fn uninstall_cpu(
        &self,
        _pool: &State<'_, Self>,
        _capa: &Capability<CPU<Self>>,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized,
    {
        Ok(())
    }

    fn create_cpu(
        &self,
        _pool: &State<'_, Self>,
        _capa: &Capability<CPU<Self>>,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized,
    {
        Ok(())
    }
}
