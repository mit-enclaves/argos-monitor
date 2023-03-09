//! Backend trait.
//! The backend is the interface between the platform-independent capability model
//! and the platform enforcement.

use core::cell::{RefCell, RefMut};

use arena::{Handle, TypedArena};

use crate::context::Context;
use crate::cpu::{CPUAccess, CPUFlags, CPU};
use crate::domain::{
    Domain, DomainAccess, OwnedCapability, SealedStatus, CAPAS_PER_DOMAIN, CONTEXT_PER_DOMAIN,
    NO_CORES_ALLOWED,
};
use crate::error::Error;
use crate::memory::MemoryRegion;
use crate::{Capability, CapabilityType, Ownership, Pool, State};

pub trait BackendContext {
    fn init(&mut self, arg1: usize, arg2: usize, arg3: usize);
}

pub trait Backend: 'static + Sized {
    type DomainState;
    type Core;
    type Context: BackendContext;
    type Error: core::fmt::Debug;

    fn install_region(
        &self,
        pool: &State<'_, Self>,
        capa: &Capability<MemoryRegion>,
    ) -> Result<(), Error<Self::Error>>;

    fn uninstall_region(
        &self,
        pool: &State<'_, Self>,
        capa: &Capability<MemoryRegion>,
    ) -> Result<(), Error<Self::Error>>;

    fn create_domain(
        &self,
        pool: &State<'_, Self>,
        capa: &Capability<Domain<Self>>,
    ) -> Result<(), Error<Self::Error>>;

    fn install_domain(
        &self,
        pool: &State<'_, Self>,
        capa: &Capability<Domain<Self>>,
    ) -> Result<(), Error<Self::Error>>;

    fn uninstall_domain(
        &self,
        pool: &State<'_, Self>,
        capa: &Capability<Domain<Self>>,
    ) -> Result<(), Error<Self::Error>>;

    fn create_cpu(
        &self,
        pool: &State<'_, Self>,
        capa: &Capability<CPU<Self>>,
    ) -> Result<(), Error<Self::Error>>;

    fn install_cpu(
        &self,
        pool: &State<'_, Self>,
        capa: &Capability<CPU<Self>>,
    ) -> Result<(), Error<Self::Error>>;

    fn uninstall_cpu(
        &self,
        pool: &State<'_, Self>,
        capa: &Capability<CPU<Self>>,
    ) -> Result<(), Error<Self::Error>>;

    fn get_current_domain<'p>(
        &self,
        pool: &'p State<'_, Self>,
    ) -> RefMut<'p, Capability<Domain<Self>>> {
        pool.get_capa_mut(self.get_current_domain_handle())
    }

    fn set_current_domain(&mut self, current: Handle<Capability<Domain<Self>>>);

    fn get_current_domain_handle(&self) -> Handle<Capability<Domain<Self>>>;

    fn get_current_cpu<'p>(&self, pool: &'p State<'_, Self>) -> RefMut<'p, Capability<CPU<Self>>> {
        pool.get_capa_mut(self.get_current_cpu_handle())
    }

    fn get_current_cpu_handle(&self) -> Handle<Capability<CPU<Self>>>;

    fn set_current_cpu(&mut self, current: Handle<Capability<CPU<Self>>>);
}

// ———————————————————— Default NoBackend Implementation ———————————————————— //

/// NoBackendState
#[derive(PartialEq)]
pub struct NoBackendState {}

pub struct NoBackendCore {}

pub struct NoBackendContext {}

impl BackendContext for NoBackendContext {
    fn init(&mut self, _arg1: usize, _arg2: usize, _arg3: usize) {
        // Nothing to do
    }
}

/// Placeholder for a backend.
#[derive(PartialEq)]
pub struct NoBackend {
    current_cpu: Handle<Capability<CPU<NoBackend>>>,
    current_domain: Handle<Capability<Domain<NoBackend>>>,
}

impl NoBackend {
    pub const fn new() -> Self {
        NO_BACKEND
    }
}

/// Used for empty initializers.
pub const NO_BACKEND: NoBackend = NoBackend {
    current_cpu: Handle::new_unchecked(usize::MAX),
    current_domain: Handle::new_unchecked(usize::MAX),
};

pub const EMPTY_OWNED_CAPABILITY: RefCell<OwnedCapability<NoBackend>> =
    RefCell::new(OwnedCapability::Empty);

pub const EMPTY_CONTEXT: RefCell<Context<NoBackend>> = RefCell::new(Context {
    in_use: false,
    state: NoBackendContext {},
});

/// Empty domain.
pub const EMPTY_DOMAIN: RefCell<Domain<NoBackend>> = RefCell::new(Domain::<NoBackend> {
    sealed: SealedStatus::<NoBackend>::Unsealed,
    allowed_cores: NO_CORES_ALLOWED,
    state: NoBackendState {},
    ref_count: usize::MAX,
    owned: TypedArena::new([EMPTY_OWNED_CAPABILITY; CAPAS_PER_DOMAIN]),
    contexts: TypedArena::new([EMPTY_CONTEXT; CONTEXT_PER_DOMAIN]),
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
    type Context = NoBackendContext;
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

    fn set_current_domain(&mut self, current: Handle<Capability<Domain<Self>>>) {
        self.current_domain = current;
    }

    fn get_current_domain_handle(&self) -> Handle<Capability<Domain<Self>>> {
        self.current_domain
    }

    fn get_current_cpu_handle(&self) -> Handle<Capability<CPU<Self>>> {
        self.current_cpu
    }

    fn set_current_cpu(&mut self, current: Handle<Capability<CPU<Self>>>) {
        self.current_cpu = current;
    }
}
