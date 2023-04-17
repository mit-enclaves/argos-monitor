use crate::context::{Context, ContextPool};
use crate::free_list::FreeList;
use crate::gen_arena::GenArena;
use crate::region::{PermissionChange, RegionTracker};
use crate::update::{Update, UpdateBuffer};
use crate::{region_capa, AccessRights, CapaError, CapaPool, Handle, RegionCapa, N};

pub type DomainHandle = Handle<Domain>;
pub type DomainPool = GenArena<Domain, N>;

// —————————————————————————————— Permissions ——————————————————————————————— //

#[rustfmt::skip]
pub mod permission {
    pub const SPAWN:     u64 = 1 << 0;
    pub const SEND:      u64 = 1 << 1;
    pub const DUPLICATE: u64 = 1 << 2;

    /// All possible permissions
    pub const ALL:  u64 = SPAWN | SEND | DUPLICATE;
    /// None of the existing permissions
    pub const NONE: u64 = 0;
}

// —————————————————————————— Domain Capabilities ——————————————————————————— //

/// An index into the capability table of a domain.
#[derive(Clone, Copy)]
pub struct LocalCapa {
    idx: usize,
}

#[derive(Clone, Copy, Debug)]
pub enum Capa {
    None,
    Region(Handle<RegionCapa>),
    Management(Handle<Domain>),
    Channel(Handle<Domain>),
    Switch {
        to: Handle<Domain>,
        ctx: Handle<Context>,
    },
}

impl Capa {
    pub(crate) fn management(managee: Handle<Domain>) -> Self {
        Capa::Management(managee)
    }

    pub fn as_region(self) -> Result<Handle<RegionCapa>, CapaError> {
        match self {
            Capa::Region(region) => Ok(region),
            _ => Err(CapaError::WrongCapabilityType),
        }
    }

    pub fn as_management(self) -> Result<Handle<Domain>, CapaError> {
        match self {
            Capa::Management(domain) => Ok(domain),
            _ => Err(CapaError::WrongCapabilityType),
        }
    }

    pub fn as_channel(self) -> Result<Handle<Domain>, CapaError> {
        match self {
            Capa::Management(domain) => Ok(domain),
            Capa::Channel(domain) => Ok(domain),
            _ => Err(CapaError::WrongCapabilityType),
        }
    }

    pub fn as_domain(self) -> Result<Handle<Domain>, CapaError> {
        match self {
            Capa::Management(domain) => Ok(domain),
            Capa::Channel(domain) => Ok(domain),
            _ => Err(CapaError::WrongCapabilityType),
        }
    }
}

pub trait IntoCapa {
    fn into_capa(self) -> Capa;
}

impl IntoCapa for Handle<RegionCapa> {
    fn into_capa(self) -> Capa {
        Capa::Region(self)
    }
}

impl IntoCapa for Capa {
    #[inline]
    fn into_capa(self) -> Capa {
        self
    }
}

/// A token used to iterate capabilites of a domain.
pub struct NextCapaToken {
    idx: usize,
}

impl NextCapaToken {
    pub fn new() -> Self {
        Self { idx: 0 }
    }
}

// ————————————————————————————————— Domain ————————————————————————————————— //

pub struct Domain {
    id: usize,
    capas: [Capa; N],
    free_list: FreeList<N>,
    regions: RegionTracker,
    manager: Option<Handle<Domain>>,
    permissions: u64,
    is_being_revoked: bool,
    is_sealed: bool,
}

impl Domain {
    pub const fn new(id: usize) -> Self {
        const INVALID_CAPA: Capa = Capa::None;

        Self {
            id,
            capas: [INVALID_CAPA; N],
            free_list: FreeList::new(),
            regions: RegionTracker::new(),
            manager: None,
            permissions: permission::NONE,
            is_being_revoked: false,
            is_sealed: false,
        }
    }

    pub(crate) fn activate_region(
        &mut self,
        access: AccessRights,
    ) -> Result<PermissionChange, CapaError> {
        // Drop updates on domain in the process of being revoked
        if self.is_being_revoked {
            return Ok(PermissionChange::None);
        }

        self.regions.add_region(access.start, access.end)
    }

    pub(crate) fn deactivate_region(
        &mut self,
        access: AccessRights,
    ) -> Result<PermissionChange, CapaError> {
        // Drop updates on domain in the process of being revoked
        if self.is_being_revoked {
            return Ok(PermissionChange::None);
        }

        self.regions.remove_region(access.start, access.end)
    }

    pub(crate) fn insert_capa(&mut self, capa: impl IntoCapa) -> Result<LocalCapa, CapaError> {
        // Find a free slot
        let idx = match self.free_list.allocate() {
            Some(idx) => idx,
            None => {
                // Run the garbage collection and retry
                self.free_invalid_capas();
                let Some(idx) = self.free_list.allocate() else {
                    log::trace!("Could not insert capa in domain: out of memory");
                    return Err(CapaError::OutOfMemory);
                };
                idx
            }
        };

        // Insert the capa
        self.capas[idx] = capa.into_capa();
        Ok(LocalCapa { idx })
    }

    pub(crate) fn set_manager(&mut self, manager: Handle<Domain>) {
        self.manager = Some(manager);
    }

    /// Get a capability from a domain.
    pub(crate) fn get(&self, index: LocalCapa) -> Result<Capa, CapaError> {
        if self.free_list.is_free(index.idx) {
            log::info!("Invalid capability index: {}", index.idx);
            return Err(CapaError::CapabilityDoesNotExist);
        }
        Ok(self.capas[index.idx])
    }

    /// Remove a capability from a domain.
    pub(crate) fn remove(&mut self, index: LocalCapa) -> Result<Capa, CapaError> {
        let capa = self.get(index)?;
        self.free_list.free(index.idx);
        Ok(capa)
    }

    fn free_invalid_capas(&mut self) {
        log::trace!("Runing garbage collection");
        // TODO
    }

    pub fn regions(&self) -> &RegionTracker {
        &self.regions
    }

    pub fn id(&self) -> usize {
        self.id
    }

    pub fn seal(&mut self) -> Result<(), CapaError> {
        if self.is_sealed {
            Err(CapaError::AlreadySealed)
        } else {
            self.is_sealed = true;
            Ok(())
        }
    }

    fn is_valid(
        &self,
        idx: usize,
        regions: &CapaPool,
        domains: &DomainPool,
        contexts: &ContextPool,
    ) -> bool {
        match self.capas[idx] {
            Capa::None => false,
            Capa::Region(handle) => regions.get(handle).is_some(),
            Capa::Management(handle) => domains.get(handle).is_some(),
            Capa::Channel(handle) => domains.get(handle).is_some(),
            Capa::Switch { to, ctx } => domains.get(to).is_some() && contexts.get(ctx).is_some(),
        }
    }
}

// —————————————————————————————— Permissions ——————————————————————————————— //

/// Check wether a given domain has the expected subset of permissions.
pub fn has_permission(
    domain: Handle<Domain>,
    domains: &DomainPool,
    permission: u64,
) -> Result<(), CapaError> {
    if permission | permission::ALL != permission::ALL {
        // There are some undefined bits!
        return Err(CapaError::InvalidPermissions);
    }
    let domain_perms = domains[domain].permissions;
    if domain_perms & permission == permission {
        Ok(())
    } else {
        Err(CapaError::InsufficientPermissions)
    }
}

pub fn set_permissions(
    domain: Handle<Domain>,
    domains: &mut DomainPool,
    permissions: u64,
) -> Result<(), CapaError> {
    if permissions & !permission::ALL != 0 {
        return Err(CapaError::InvalidPermissions);
    }

    let domain = &mut domains[domain];
    if domain.is_sealed {
        return Err(CapaError::AlreadySealed);
    } else {
        domain.permissions = permissions;
        Ok(())
    }
}

// —————————————————————————————————— Send —————————————————————————————————— //

pub fn send_management(
    capa: Handle<Domain>,
    domains: &mut DomainPool,
    to: Handle<Domain>,
) -> Result<(), CapaError> {
    // Update manager
    domains[capa].set_manager(to);
    Ok(())
}

// ————————————————————————————————— Switch ————————————————————————————————— //

pub(crate) fn create_switch(
    capa: Handle<Domain>,
    domains: &mut DomainPool,
    contexts: &mut ContextPool,
) -> Result<LocalCapa, CapaError> {
    let domain = &mut domains[capa];
    let context = contexts
        .allocate(Context::new())
        .ok_or(CapaError::OutOfMemory)?;
    domain.insert_capa(Capa::Switch {
        to: capa,
        ctx: context,
    })
}

// ——————————————————————————————— Enumerate ———————————————————————————————— //

pub(crate) fn next_capa(
    domain_handle: Handle<Domain>,
    token: NextCapaToken,
    regions: &CapaPool,
    domains: &mut DomainPool,
    contexts: &ContextPool,
) -> Option<(Capa, NextCapaToken)> {
    let mut idx = token.idx;
    let len = domains[domain_handle].capas.len();
    while idx < len {
        let domain = &domains[domain_handle];
        if !domain.free_list.is_free(idx) {
            if domain.is_valid(idx, regions, domains, contexts) {
                // Found a valid capa
                let next_token = NextCapaToken { idx: idx + 1 };
                return Some((domain.capas[idx], next_token));
            } else {
                // Capa has been invalidated
                let domain = &mut domains[domain_handle];
                domain.free_list.free(idx);
            }
        }
        idx += 1;
    }

    // No more capa
    None
}

// ——————————————————————————————— Revocation ——————————————————————————————— //

pub(crate) fn revoke(
    handle: DomainHandle,
    regions: &mut CapaPool,
    domains: &mut DomainPool,
    updates: &mut UpdateBuffer,
    contexts: &mut ContextPool,
) -> Result<(), CapaError> {
    log::trace!("Revoke domain {}", handle);

    let domain = &mut domains[handle];
    if domain.is_being_revoked {
        // Already in the process of being revoked
        return Ok(());
    } else {
        // Mark as being revoked
        domain.is_being_revoked = true;
        updates.push(Update::RevokeDomain { domain: handle });
    }

    // Drop all capabilities
    let mut token = NextCapaToken::new();
    while let Some((capa, next_token)) = next_capa(handle, token, regions, domains, contexts) {
        token = next_token;
        match capa {
            // Those capa so not cause revokation
            Capa::None => (),
            Capa::Channel(_) => (),
            Capa::Switch { .. } => (),

            // Those capa cause revocation
            Capa::Region(region) => {
                region_capa::restore(region, regions, domains, updates)?;
            }
            Capa::Management(domain) => {
                revoke(domain, regions, domains, updates, contexts)?;
            }
        }
    }

    domains.free(handle);
    Ok(())
}
