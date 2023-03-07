//! Monitor Interface
#![cfg_attr(not(test), no_std)]

pub mod old_monitor;
pub mod tyche;

#[cfg(test)]
mod tests;

use core::cell::RefMut;

use arena::Handle;
use capabilities::backend::Backend;
use capabilities::cpu::CPU;
use capabilities::domain::{Domain, SealedStatus};
use capabilities::error::{Error, ErrorCode};
use capabilities::memory::{MemoryAccess, MemoryRegion};
use capabilities::{cpu, domain, memory, Capability, Ownership, Pool, State};
use utils::HostPhysAddr;

// —————————————————————————————————— ABI ——————————————————————————————————— //

#[derive(Default)]
pub struct Parameters {
    pub vmcall: usize,
    pub arg_1: usize,
    pub arg_2: usize,
    pub arg_3: usize,
    pub arg_4: usize,
    pub arg_5: usize,
}

pub struct Registers {
    pub value_1: usize,
    pub value_2: usize,
    pub value_3: usize,
    pub value_4: usize,
    pub value_5: usize,
    pub value_6: usize,
    pub next_instr: bool,
}

impl Default for Registers {
    fn default() -> Self {
        Self {
            value_1: 0,
            value_2: 0,
            value_3: 0,
            value_4: 0,
            value_5: 0,
            value_6: 0,
            next_instr: true,
        }
    }
}

pub type MonitorCallResult<B> = Result<Registers, Error<<B as Backend>::Error>>;

// ——————————————————————————— Monitor Interface ———————————————————————————— //

pub trait Monitor<B>
where
    B: Backend,
{
    type MonitorCall;
    fn is_exit(&self, state: &MonitorState<B>, params: &Parameters) -> bool;
    fn dispatch(&self, state: &mut MonitorState<B>, params: &Parameters) -> MonitorCallResult<B>;
}

// ————————————————————————————— Monitor State —————————————————————————————— //
/// LocalState is a per-core state.
/// We use the handle idx rather than Handle types because otherwise I can't
/// initialize the array in MonitorState::new.
/// TODO: figure out how to fix this.
/// Should we keep track of the capability or the object?
/// I'd say the capability.
#[derive(Copy, Clone, Debug)]
pub struct LocalState {
    pub current_domain: usize,
    pub current_cpu: usize,
}

pub const MAX_CORE: usize = 24;

/// MonitorState contains tracks the current domains per cpu/vcpu.
pub struct MonitorState<'a, B>
where
    B: Backend + 'static,
{
    // Array of LocalState.
    pub locals: [LocalState; MAX_CORE],
    pub resources: State<'a, B>,
}

impl<'a, B> MonitorState<'a, B>
where
    B: Backend + 'static,
{
    // Initialize the state for the machine.
    pub fn new(mem_end: usize, capas: State<'a, B>) -> Result<Self, Error<<B as Backend>::Error>> {
        // Create the original domain.
        let default_domain = capas.pools.domains.allocate().map_err(|e| e.wrap())?;

        let default_domain_capa_handle =
            Capability::<Domain<B>>::new(&capas, default_domain, domain::DEFAULT_SEALED)
                .map_err(|e| e.wrap())?;
        capas
            .set_owner_capa(default_domain_capa_handle, default_domain)
            .map_err(|e| e.wrap())?;

        {
            let mut domain = capas.get_mut(default_domain);
            domain.ref_count = 1;
            let domain_capa = capas.get_capa(default_domain_capa_handle);
            if let Ownership::Domain(_, idx) = domain_capa.owner {
                domain.sealed = SealedStatus::<B>::Sealed(Handle::new_unchecked(idx));
            } else {
                return Err(ErrorCode::InvalidDomainCreate.wrap());
            }
        }

        // Create the orignal memory region and its capability.
        let mem_capa_handle = Capability::<MemoryRegion>::new_with_region(
            &capas,
            MemoryAccess {
                start: HostPhysAddr::new(0),
                end: HostPhysAddr::new(mem_end),
                flags: memory::ALL_RIGHTS,
            },
        )
        .map_err(|e| e.wrap())?;
        // Assign it to the domain.
        capas
            .set_owner_capa(mem_capa_handle, default_domain)
            .map_err(|e| e.wrap())?;

        // Apply it on the backend.
        let default_domain_capa = capas.get_capa(default_domain_capa_handle);
        capas.backend.create_domain(&capas, &default_domain_capa)?;
        drop(default_domain_capa);

        // Create the default cpu and its associated capability.
        // TODO if we want to allocate multiple ones from the manifest.{number of cores} do it here.
        let default_cpu_handle =
            Capability::<CPU<B>>::new(&capas, 0, cpu::ALL_RIGHTS).map_err(|e| e.wrap())?;
        capas
            .set_owner_capa(default_cpu_handle, default_domain)
            .map_err(|e| e.wrap())?;

        // Call the backend to allocate the physical core.
        let default_cpu = capas.get_capa(default_cpu_handle);
        capas.backend.create_cpu(&capas, &default_cpu)?;
        drop(default_cpu);

        let mut state = Self {
            locals: [LocalState {
                current_domain: usize::MAX,
                current_cpu: usize::MAX,
            }; MAX_CORE],
            resources: capas,
        };

        // Set current domain + core capas in the local state.
        state.locals[0] = LocalState {
            current_domain: default_domain_capa_handle.idx(),
            current_cpu: default_cpu_handle.idx(),
        };

        Ok(state)
    }

    pub fn get_current_domain(&self) -> RefMut<Capability<Domain<B>>> {
        // TODO figure out how to get thread local index.
        self.resources
            .get_capa_mut(Handle::new_unchecked(self.locals[0].current_domain))
    }

    pub fn set_current_domain(&mut self, current: Handle<Capability<Domain<B>>>) {
        self.locals[0].current_domain = current.idx();
    }

    pub fn get_current_cpu(&self) -> RefMut<Capability<CPU<B>>> {
        // TODO figure out how to get thread local idx
        self.resources
            .get_capa_mut(Handle::new_unchecked(self.locals[0].current_cpu))
    }

    pub fn get_current_cpu_handle(&self) -> Handle<Capability<CPU<B>>> {
        Handle::new_unchecked(self.locals[0].current_cpu)
    }

    pub fn set_current_cpu(&mut self, current: Handle<Capability<Domain<B>>>) {
        self.locals[0].current_cpu = current.idx();
    }
}
