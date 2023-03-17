use core::cell::RefCell;

use arena::{Handle, TypedArena};
use capabilities::backend::{Backend, BackendContext};
use capabilities::context::Context;
use capabilities::cpu::{CPUAccess, CPUFlags, CPU};
use capabilities::domain::{
    Domain, DomainAccess, OwnedCapability, SealedStatus, CAPAS_PER_DOMAIN, CONTEXT_PER_DOMAIN,
};
use capabilities::{Capability, CapabilityType, Ownership};
use mmu::FrameAllocator;
use stage_two_abi::Manifest;

use super::BackendError;
use crate::debug::qemu::ExitCode;
use crate::statics::{allocator, pool};

// TODO: some empty types to be filled.
pub struct RiscvCore {}
pub struct RiscvContext {}
pub struct RiscvBackend {}
pub struct RiscvDomainState {}

impl Backend for RiscvBackend {
    type DomainState = RiscvDomainState;
    type Core = RiscvCore;
    type Context = RiscvContext;
    type Error = BackendError;

    fn install_region(
        &self,
        pool: &capabilities::State<'_, Self>,
        capa: &capabilities::Capability<capabilities::memory::MemoryRegion>,
    ) -> Result<(), capabilities::error::Error<Self::Error>> {
        todo!()
    }

    fn uninstall_region(
        &self,
        pool: &capabilities::State<'_, Self>,
        capa: &capabilities::Capability<capabilities::memory::MemoryRegion>,
    ) -> Result<(), capabilities::error::Error<Self::Error>> {
        todo!()
    }

    fn create_domain(
        &self,
        pool: &capabilities::State<'_, Self>,
        capa: &capabilities::Capability<capabilities::domain::Domain<Self>>,
    ) -> Result<(), capabilities::error::Error<Self::Error>> {
        todo!()
    }

    fn install_domain(
        &self,
        pool: &capabilities::State<'_, Self>,
        capa: &capabilities::Capability<capabilities::domain::Domain<Self>>,
    ) -> Result<(), capabilities::error::Error<Self::Error>> {
        todo!()
    }

    fn uninstall_domain(
        &self,
        pool: &capabilities::State<'_, Self>,
        capa: &capabilities::Capability<capabilities::domain::Domain<Self>>,
    ) -> Result<(), capabilities::error::Error<Self::Error>> {
        todo!()
    }

    fn create_cpu(
        &self,
        pool: &capabilities::State<'_, Self>,
        capa: &capabilities::Capability<capabilities::cpu::CPU<Self>>,
    ) -> Result<(), capabilities::error::Error<Self::Error>> {
        todo!()
    }

    fn install_cpu(
        &self,
        pool: &capabilities::State<'_, Self>,
        capa: &capabilities::Capability<capabilities::cpu::CPU<Self>>,
    ) -> Result<(), capabilities::error::Error<Self::Error>> {
        todo!()
    }

    fn uninstall_cpu(
        &self,
        pool: &capabilities::State<'_, Self>,
        capa: &capabilities::Capability<capabilities::cpu::CPU<Self>>,
    ) -> Result<(), capabilities::error::Error<Self::Error>> {
        todo!()
    }

    fn switch_context(
        &self,
        pool: &capabilities::State<'_, Self>,
        caller: arena::Handle<capabilities::domain::Domain<Self>>,
        callee: arena::Handle<capabilities::domain::Domain<Self>>,
        to_save: arena::Handle<capabilities::Capability<capabilities::domain::Domain<Self>>>,
        to_restore: arena::Handle<capabilities::Capability<capabilities::domain::Domain<Self>>>,
        target_cpu: arena::Handle<capabilities::Capability<capabilities::cpu::CPU<Self>>>,
    ) -> Result<(), capabilities::error::Error<Self::Error>> {
        todo!()
    }

    fn set_current_domain(
        &mut self,
        current: arena::Handle<capabilities::Capability<capabilities::domain::Domain<Self>>>,
    ) {
        todo!()
    }

    fn get_current_domain_handle(
        &self,
    ) -> arena::Handle<capabilities::Capability<capabilities::domain::Domain<Self>>> {
        todo!()
    }

    fn get_current_cpu_handle(
        &self,
    ) -> arena::Handle<capabilities::Capability<capabilities::cpu::CPU<Self>>> {
        todo!()
    }

    fn set_current_cpu(
        &mut self,
        current: arena::Handle<capabilities::Capability<capabilities::cpu::CPU<Self>>>,
    ) {
        todo!()
    }
}

impl BackendContext for RiscvContext {
    fn init(&mut self, arg1: usize, arg2: usize, arg3: usize) {
        todo!()
    }
}

// —————————————————— Empty Structures For Initialization ——————————————————— //

pub const EMPTY_OWNED_CAPABILITY: RefCell<OwnedCapability<RiscvBackend>> =
    RefCell::new(OwnedCapability::Empty);

pub const EMPTY_CONTEXT: RefCell<Context<RiscvBackend>> = RefCell::new(Context {
    return_context: None,
    state: RiscvContext {},
});

pub const EMPTY_DOMAIN: RefCell<Domain<RiscvBackend>> = RefCell::new(Domain::<RiscvBackend> {
    sealed: SealedStatus::Unsealed,
    state: RiscvDomainState {},
    allowed_cores: 0,
    ref_count: usize::MAX,
    owned: TypedArena::new([EMPTY_OWNED_CAPABILITY; CAPAS_PER_DOMAIN]),
    contexts: TypedArena::new([EMPTY_CONTEXT; CONTEXT_PER_DOMAIN]),
});

pub const EMPTY_DOMAIN_CAPA: RefCell<Capability<Domain<RiscvBackend>>> = RefCell::new(Capability {
    owner: Ownership::Empty,
    capa_type: CapabilityType::Resource,
    access: DomainAccess::NONE,
    handle: Handle::null(),
    left: Handle::null(),
    right: Handle::null(),
});

pub const EMPTY_CPU: RefCell<CPU<RiscvBackend>> = RefCell::new(CPU::<RiscvBackend> {
    id: usize::MAX,
    ref_count: usize::MAX,
    core: RiscvCore {},
});

pub const EMPTY_CPU_CAPA: RefCell<Capability<CPU<RiscvBackend>>> = RefCell::new(Capability {
    owner: Ownership::Empty,
    capa_type: CapabilityType::Resource,
    access: CPUAccess {
        flags: CPUFlags::NONE,
    },
    handle: Handle::null(),
    left: Handle::null(),
    right: Handle::null(),
});
