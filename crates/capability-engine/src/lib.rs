#![cfg_attr(not(test), no_std)]

mod context;
mod domain;
mod free_list;
mod gen_arena;
mod region;
mod region_capa;
mod update;

use core::ops::Index;

pub use context::Context;
use context::ContextPool;
pub use domain::{permission, Domain, LocalCapa, NextCapaToken};
use domain::{Capa, DomainHandle, DomainPool};
use gen_arena::GenArena;
pub use gen_arena::Handle;
pub use region::{AccessRights, RegionTracker};
use region_capa::{CapaPool, RegionCapa};
pub use update::Update;
use update::UpdateBuffer;

pub const N: usize = 20;

#[derive(Clone, Copy, Debug)]
pub enum CapaError {
    CannotDuplicate,
    InvalidDuplicate,
    InvalidInstall,
    InternalRegionError,
    InvalidRegion,
    WrongCapabilityType,
    CapabilityDoesNotExist,
    AlreadySealed,
    InsufficientPermissions,
    InvalidPermissions,
    OutOfMemory,
}

pub struct CapaEngine {
    domains: DomainPool,
    regions: CapaPool,
    updates: UpdateBuffer,
    contexts: ContextPool,
    id_counter: usize,
}

impl CapaEngine {
    pub const fn new() -> Self {
        const EMPTY_DOMAIN: Domain = Domain::new(0);
        const EMPTY_CAPA: RegionCapa = RegionCapa::new_invalid();
        const EMPTY_CONTEXT: Context = Context::new();

        Self {
            domains: GenArena::new([EMPTY_DOMAIN; N]),
            regions: GenArena::new([EMPTY_CAPA; N]),
            updates: UpdateBuffer::new(),
            contexts: GenArena::new([EMPTY_CONTEXT; N]),
            id_counter: 0,
        }
    }

    pub fn create_manager_domain(&mut self, permissions: u64) -> Result<DomainHandle, CapaError> {
        log::trace!("Create new manager domain");

        let id = self.domain_id();
        match self.domains.allocate(Domain::new(id)) {
            Some(handle) => {
                domain::set_permissions(handle, &mut self.domains, permissions)?;
                self.domains[handle].seal()?;
                self.updates.push(Update::CreateDomain { domain: handle });
                Ok(handle)
            }
            None => {
                log::info!("Failed to create new domain: out of memory");
                Err(CapaError::OutOfMemory)
            }
        }
    }

    pub fn create_domain(&mut self, manager: Handle<Domain>) -> Result<LocalCapa, CapaError> {
        log::trace!("Create new domain");

        // Enforce permissions
        domain::has_permission(manager, &self.domains, permission::SPAWN)?;

        let id = self.domain_id();
        match self.domains.allocate(Domain::new(id)) {
            Some(handle) => {
                self.domains[handle].set_manager(manager);
                let capa = self.domains[manager].insert_capa(Capa::management(handle))?;
                self.updates.push(Update::CreateDomain { domain: handle });
                Ok(capa)
            }
            None => {
                log::info!("Failed to create new domain: out of memory");
                Err(CapaError::OutOfMemory)
            }
        }
    }

    pub fn revoke_domain(&mut self, domain: Handle<Domain>) -> Result<(), CapaError> {
        domain::revoke(
            domain,
            &mut self.regions,
            &mut self.domains,
            &mut self.updates,
            &mut self.contexts,
        )
    }

    pub fn create_region(
        &mut self,
        domain: DomainHandle,
        access: AccessRights,
    ) -> Result<LocalCapa, CapaError> {
        log::trace!("Create new region");

        match self
            .regions
            .allocate(RegionCapa::new(domain, access).confidential())
        {
            Some(handle) => {
                let capa = region_capa::install(
                    handle,
                    domain,
                    &mut self.regions,
                    &mut self.domains,
                    &mut self.updates,
                )?;
                Ok(capa)
            }
            None => {
                log::info!("Failed to create new domain: out of memory");
                Err(CapaError::OutOfMemory)
            }
        }
    }

    pub fn restore_region(
        &mut self,
        domain: Handle<Domain>,
        region: LocalCapa,
    ) -> Result<(), CapaError> {
        let region = self.domains[domain].get(region)?.as_region()?;
        region_capa::restore(
            region,
            &mut self.regions,
            &mut self.domains,
            &mut self.updates,
        )
    }

    pub fn duplicate_region(
        &mut self,
        domain: Handle<Domain>,
        region: LocalCapa,
        access_left: AccessRights,
        access_right: AccessRights,
    ) -> Result<(LocalCapa, LocalCapa), CapaError> {
        // Enforce permissions
        domain::has_permission(domain, &self.domains, permission::DUPLICATE)?;

        let region = self.domains[domain].get(region)?.as_region()?;
        let handles = region_capa::duplicate(
            region,
            &mut self.regions,
            &mut self.domains,
            &mut self.updates,
            access_left,
            access_right,
        )?;
        Ok(handles)
    }

    pub fn send(
        &mut self,
        domain: Handle<Domain>,
        capa: LocalCapa,
        to: LocalCapa,
    ) -> Result<(), CapaError> {
        // Enforce permissions
        domain::has_permission(domain, &self.domains, permission::SEND)?;

        let to = self.domains[domain].get(to)?.as_channel()?;
        let capa = self.domains[domain].remove(capa)?;
        match capa {
            // No side effect for those capas
            Capa::None => (),
            Capa::Channel(_) => (),
            Capa::Switch { .. } => (),

            // Sending those capa causes side effects
            Capa::Region(region) => {
                region_capa::send(
                    region,
                    &mut self.regions,
                    &mut self.domains,
                    &mut self.updates,
                    to,
                )?;
            }
            Capa::Management(domain) => {
                domain::send_management(domain, &mut self.domains, to)?;
            }
        }

        // Move the capa to the new domain
        let Ok(_) = self.domains[to].insert_capa(capa) else {
            log::info!("Send failed, receiving domain is out of memory");
            // Insert capa back, this should never fail as removed it just before
            self.domains[domain].insert_capa(capa).unwrap();
            return Err(CapaError::OutOfMemory);
        };

        Ok(())
    }

    pub fn set_permissions(
        &mut self,
        manager: Handle<Domain>,
        capa: LocalCapa,
        permissions: u64,
    ) -> Result<(), CapaError> {
        let domain = self.domains[manager].get(capa)?.as_management()?;
        domain::set_permissions(domain, &mut self.domains, permissions)
    }

    /// Seal a domain and return a switch handle for that domain.
    pub fn seal(
        &mut self,
        domain: Handle<Domain>,
        capa: LocalCapa,
    ) -> Result<(LocalCapa, Handle<Context>), CapaError> {
        let capa = self.domains[domain].get(capa)?.as_management()?;
        let context = self
            .contexts
            .allocate(Context::new())
            .ok_or(CapaError::OutOfMemory)?;
        self.domains[capa].seal()?;
        let capa = self.domains[domain].insert_capa(Capa::Switch {
            to: capa,
            ctx: context,
        })?;
        Ok((capa, context))
    }

    /// Creates a new switch handle for the current domain.
    pub fn create_switch(&mut self, domain: Handle<Domain>) -> Result<LocalCapa, CapaError> {
        domain::create_switch(domain, &mut self.domains, &mut self.contexts)
    }

    pub fn enumerate(
        &mut self,
        domain: Handle<Domain>,
        token: NextCapaToken,
    ) -> Option<(Capa, NextCapaToken)> {
        domain::next_capa(
            domain,
            token,
            &self.regions,
            &mut self.domains,
            &self.contexts,
        )
    }

    pub fn get_domain_capa(
        &self,
        domain: Handle<Domain>,
        capa: LocalCapa,
    ) -> Result<Handle<Domain>, CapaError> {
        self.domains[domain].get(capa)?.as_domain()
    }

    pub fn pop_update(&mut self) -> Option<Update> {
        self.updates.pop()
    }

    /// Returns a fresh domain ID.
    fn domain_id(&mut self) -> usize {
        self.id_counter += 1;
        self.id_counter
    }
}

impl Default for CapaEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ———————————————————————————————— Indexing ———————————————————————————————— //

impl Index<Handle<Domain>> for CapaEngine {
    type Output = Domain;

    fn index(&self, index: Handle<Domain>) -> &Self::Output {
        &self.domains[index]
    }
}

impl Index<Handle<RegionCapa>> for CapaEngine {
    type Output = RegionCapa;

    fn index(&self, index: Handle<RegionCapa>) -> &Self::Output {
        &self.regions[index]
    }
}
