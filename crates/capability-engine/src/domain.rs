use core::cell::Cell;
use core::iter::Iterator;

use attestation::hashing::HashEnclave;
use attestation::signature::EnclaveReport;

use crate::capa::{Capa, IntoCapa};
use crate::config::{NB_CAPAS_PER_DOMAIN, NB_DOMAINS};
use crate::free_list::FreeList;
use crate::gen_arena::GenArena;
use crate::permission::{self, monitor_inter_perm, PermissionIndex, Permissions};
use crate::region::{PermissionChange, RegionTracker, TrackerPool};
use crate::segment::{self, RegionPool};
use crate::update::{Update, UpdateBuffer};
use crate::{AccessRights, CapaError, Handle};

pub type DomainHandle = Handle<Domain>;
pub(crate) type DomainPool = GenArena<Domain, NB_DOMAINS>;

// —————————————————————————— Domain Capabilities ——————————————————————————— //

/// An index into the capability table of a domain.
#[derive(Debug, Clone, Copy)]
pub struct LocalCapa {
    idx: usize,
}

impl LocalCapa {
    pub fn as_usize(self) -> usize {
        self.idx
    }

    pub fn as_u64(self) -> u64 {
        self.idx as u64
    }

    pub fn new(idx: usize) -> Self {
        Self { idx }
    }
}

/// A token used to iterate capabilites of a domain.
#[derive(Clone, Copy)]
pub struct NextCapaToken {
    idx: usize,
}

impl NextCapaToken {
    pub fn new() -> Self {
        Self { idx: 0 }
    }

    pub fn from_usize(idx: usize) -> Self {
        Self { idx }
    }

    pub fn as_usize(self) -> usize {
        self.idx
    }

    pub fn as_u64(self) -> u64 {
        self.idx as u64
    }
}

// ————————————————————————————————— Domain ————————————————————————————————— //

pub struct Domain {
    /// Unique domain ID.
    id: usize,
    /// Domain capabilities.
    capas: [Capa; NB_CAPAS_PER_DOMAIN],
    /// Free list of capabilities, used for allocating new capabilities.
    free_list: FreeList<NB_CAPAS_PER_DOMAIN>,
    /// Tracker for region permissions.
    regions: RegionTracker,
    /// The (optional) manager of this domain.
    manager: Option<Handle<Domain>>,
    /// Permissions bitmaps for the domain.
    permissions: Permissions,
    /// A bitmap of cores the domain runs on.
    cores: u64,
    /// Is this domain in the process of being revoked?
    is_being_revoked: bool,
    /// Is the domain sealed?
    is_sealed: bool,
    /// attestation hash
    attestation_hash: Option<HashEnclave>,
    /// last attestation report
    attestation_report: Option<EnclaveReport>,
    /// Is it an I/O domain?
    is_io: bool,
    /// Temporary ID used for attestation
    pub(crate) temporary_id: Cell<u64>,
}

impl Domain {
    pub const fn new(id: usize, io: bool) -> Self {
        const INVALID_CAPA: Capa = Capa::None;

        Self {
            id,
            capas: [INVALID_CAPA; NB_CAPAS_PER_DOMAIN],
            free_list: FreeList::new(),
            regions: RegionTracker::new(),
            manager: None,
            permissions: permission::DEFAULT,
            cores: permission::core_bits::NONE,
            is_being_revoked: false,
            is_sealed: false,
            attestation_hash: None,
            attestation_report: None,
            is_io: io,
            temporary_id: Cell::new(0),
        }
    }

    /*pub fn get_config(&self, bitmap: Bitmaps) -> u64 {
        self.config.values[bitmap as usize]
    }

    pub fn set_config(&mut self, bitmap: Bitmaps, value: u64) -> Result<(), CapaError> {
        /*if self.is_sealed() {
            return Err(CapaError::AlreadySealed);
        }*/
        if value & !self.config.valid_masks[bitmap as usize] != 0 {
            return Err(CapaError::InvalidOperation);
        }
        self.config.values[bitmap as usize] = value;
        self.config.initialized[bitmap as usize] = true;
        Ok(())
    }*/

    pub(crate) fn get_manager(&self) -> Option<Handle<Domain>> {
        self.manager
    }

    pub(crate) fn set_manager(&mut self, manager: Handle<Domain>) {
        self.manager = Some(manager);
    }

    pub(crate) fn set_id(&mut self, id: usize) -> Result<(), CapaError> {
        if self.is_sealed() {
            return Err(CapaError::AlreadySealed);
        }
        self.id = id;
        Ok(())
    }

    /// Get a capability from a domain.
    pub(crate) fn get(&self, index: LocalCapa) -> Result<Capa, CapaError> {
        if self.free_list.is_free(index.idx) {
            log::error!("Invalid capability index: {} (get)", index.idx);
            return Err(CapaError::CapabilityDoesNotExist);
        }
        Ok(self.capas[index.idx])
    }

    /// Get a mutable reference to a capability from a domain.
    fn get_mut(&mut self, index: LocalCapa) -> Result<&mut Capa, CapaError> {
        if self.free_list.is_free(index.idx) {
            log::error!("Invalid capability index: {} (get_mut)", index.idx);
            return Err(CapaError::CapabilityDoesNotExist);
        }
        Ok(&mut self.capas[index.idx])
    }

    /// Find a capability inside the domain.
    pub(crate) fn find_capa<F: Fn(&Capa) -> bool>(&self, f: F) -> Option<LocalCapa> {
        for (i, e) in self.capas.iter().enumerate() {
            if self.free_list.is_free(i) {
                continue;
            }
            if f(e) {
                return Some(LocalCapa { idx: i });
            }
        }
        return None;
    }

    pub(crate) fn iter_capa(&self) -> DomainCapaIterator {
        DomainCapaIterator { td: self, idx: 0 }
    }

    /// Mark the domain as executing on the given core.
    pub(crate) fn execute_on_core(&mut self, core_id: usize) {
        let core_id = 1 << core_id;
        self.cores |= core_id;
    }

    /// Remove the core from the bitmap of cores runing the domain.
    pub(crate) fn remove_from_core(&mut self, core_id: usize) {
        let core_id = 1 << core_id;
        if self.cores & core_id == 0 {
            log::error!("Removing from a core in which the domains was NOT executing");
        }
        self.cores &= !core_id
    }

    pub(crate) fn regions(&self) -> &RegionTracker {
        &self.regions
    }

    pub fn id(&self) -> usize {
        self.id
    }

    pub fn traps(&self) -> u64 {
        self.permissions.perm[PermissionIndex::AllowedTraps as usize]
    }

    pub fn cores(&self) -> u64 {
        self.cores
    }

    pub fn core_map(&self) -> u64 {
        self.permissions.perm[PermissionIndex::AllowedCores as usize]
    }

    pub fn monitor_interface(&self) -> u64 {
        self.permissions.perm[PermissionIndex::MonitorInterface as usize]
    }
    /// Returns Wether or not this domain can handle the given trap
    pub fn can_handle(&self, trap: u64) -> bool {
        let traps = self.permissions.perm[PermissionIndex::AllowedTraps as usize];
        traps & trap != 0 && self.is_sealed
    }

    pub fn seal(&mut self) -> Result<(), CapaError> {
        if self.is_sealed {
            Err(CapaError::AlreadySealed)
        } else {
            self.is_sealed = true;
            Ok(())
        }
    }

    pub fn is_sealed(&self) -> bool {
        self.is_sealed
    }

    pub fn is_io(&self) -> bool {
        self.is_io
    }

    fn is_valid(&self, idx: usize, regions: &RegionPool, domains: &DomainPool) -> bool {
        match self.capas[idx] {
            Capa::None => false,
            Capa::Region(handle) => regions.get(handle).is_some(),
            Capa::RegionRevoke(handle) => regions.get(handle).is_some(),
            Capa::Management(handle) => domains.get(handle).is_some(),
            Capa::Channel(handle) => domains.get(handle).is_some(),
            Capa::Switch { to, .. } => domains.get(to).is_some(),
        }
    }

    pub fn set_hash(&mut self, hash: HashEnclave) {
        self.attestation_hash = Some(hash);
    }

    pub fn set_report(&mut self, report: EnclaveReport) {
        self.attestation_report = Some(report);
    }

    pub fn get_report(&self) -> Option<EnclaveReport> {
        if let Some(rep) = &self.attestation_report {
            Some(*rep)
        } else {
            None
        }
    }

    pub fn get_hash(&self) -> HashEnclave {
        if let Some(he) = &self.attestation_hash {
            *he
        } else {
            HashEnclave { low: 0, high: 0 }
        }
    }
}

// —————————————————————————————— Insert Capa ——————————————————————————————— //

/// insert a capability into a domain.
pub(crate) fn insert_capa(
    domain: Handle<Domain>,
    capa: impl IntoCapa,
    regions: &mut RegionPool,
    domains: &mut DomainPool,
) -> Result<LocalCapa, CapaError> {
    // Find a free slot
    let idx = match domains[domain].free_list.allocate() {
        Some(idx) => idx,
        None => {
            // Run the garbage collection and retry
            free_invalid_capas(domain, regions, domains);
            let Some(idx) = domains[domain].free_list.allocate() else {
                log::error!("Could not insert capa in domain: out of memory");
                return Err(CapaError::OutOfMemory);
            };
            idx
        }
    };

    // Insert the capa
    domains[domain].capas[idx] = capa.into_capa();
    Ok(LocalCapa { idx })
}

/// Remove a capability from a domain.
pub(crate) fn remove_capa(
    domain: Handle<Domain>,
    index: LocalCapa,
    domains: &mut DomainPool,
) -> Result<Capa, CapaError> {
    let domain = &mut domains[domain];
    let capa = domain.get(index)?;
    domain.free_list.free(index.idx);
    Ok(capa)
}

/// Return OK if the arena has enough capacity for `count` objects, Err otherwise.
pub fn has_capacity_for(
    domain: Handle<Domain>,
    count: usize,
    regions: &mut RegionPool,
    domains: &mut DomainPool,
) -> Result<(), CapaError> {
    if domains[domain].free_list.capacity() >= count {
        Ok(())
    } else {
        // Run the garbage collection and retry
        free_invalid_capas(domain, regions, domains);
        if domains[domain].free_list.capacity() >= count {
            Ok(())
        } else {
            log::error!("Domain does not have enough capacities for {:?} capas. Out of memory", count);
            Err(CapaError::OutOfMemory)
        }
    }
}

/// Run garbage collection on the domain's capabilities.
///
/// This is necessary as some capabilities are invalidated but not removed eagerly.
fn free_invalid_capas(domain: Handle<Domain>, regions: &mut RegionPool, domains: &mut DomainPool) {
    log::trace!("Runing garbage collection");
    for idx in 0..NB_CAPAS_PER_DOMAIN {
        if domains[domain].free_list.is_free(idx) {
            // Capa is already free
            continue;
        }

        // Check if capa is still valid
        let capa = domains[domain].capas[idx];
        let is_invalid = match capa {
            Capa::None => true,
            Capa::Region(h) => regions.get(h).is_none(),
            Capa::RegionRevoke(h) => regions.get(h).is_none(),
            Capa::Management(h) => domains.get(h).is_none(),
            Capa::Channel(h) => domains.get(h).is_none(),
            Capa::Switch { to, .. } => domains.get(to).is_none(),
        };

        if is_invalid {
            // We checked before that the capa exists
            remove_capa(domain, LocalCapa { idx }, domains).unwrap();
        }
    }
}

// —————————————————————————————— Permissions ——————————————————————————————— //

/// Check wether a given domain has the expected subset of permissions.
pub(crate) fn has_permission(
    domain: Handle<Domain>,
    domains: &DomainPool,
    perm: PermissionIndex,
    value: u64,
) -> Result<(), CapaError> {
    let domain = &domains[domain];
    // Let's ignore the read/write for the moment and CPUID.
    if perm >= PermissionIndex::MgmtRead16
        || domain.permissions.perm[perm as usize] & value == value
    {
        Ok(())
    } else if perm == PermissionIndex::MonitorInterface
        && (value & (domain.permissions.perm[perm as usize] | monitor_inter_perm::CPUID)) == value
    {
        Ok(())
    } else {
        Err(CapaError::InsufficientPermissions)
    }
}

pub(crate) fn set_permission(
    domain: Handle<Domain>,
    domains: &mut DomainPool,
    perm: PermissionIndex,
    value: u64,
) -> Result<(), CapaError> {
    let domain = &mut domains[domain];
    if domain.is_sealed() {
        return Err(CapaError::AlreadySealed);
    }
    domain.permissions.perm[perm as usize] = value;
    Ok(())
}

pub(crate) fn get_permission(
    domain: Handle<Domain>,
    domains: &DomainPool,
    perm: PermissionIndex,
) -> u64 {
    let domain = &domains[domain];
    domain.permissions.perm[perm as usize]
}

// —————————————————————————————————— Send —————————————————————————————————— //

pub(crate) fn send_management(
    capa: Handle<Domain>,
    domains: &mut DomainPool,
    to: Handle<Domain>,
) -> Result<(), CapaError> {
    // Update manager
    if (!domains[to].core_map()) & domains[capa].core_map() != 0 {
        log::debug!("Sending management to a domain with less cores on its map.");
        log::debug!("manager cores: {:b}", domains[to].core_map());
        log::debug!("domain  cores: {:b}", domains[capa].core_map());
        return Err(CapaError::InsufficientPermissions);
    }
    domains[capa].set_manager(to);
    Ok(())
}

// ——————————————————————————————— Duplicate ———————————————————————————————— //

pub(crate) fn duplicate_capa(
    domain: Handle<Domain>,
    capa: LocalCapa,
    regions: &mut RegionPool,
    domains: &mut DomainPool,
) -> Result<LocalCapa, CapaError> {
    let capa = domains[domain].get(capa)?;

    match capa {
        // Capa that can not be duplicated
        Capa::None | Capa::Region(_) | Capa::Management(_) | Capa::Switch { .. } => {
            return Err(CapaError::CannotDuplicate);
        }
        Capa::Channel(_) | Capa::RegionRevoke(_) => {
            // NOTE: there is no side effects when duplicating these capas
            insert_capa(domain, capa, regions, domains)
        }
    }
}

// ————————————————————————————————— Switch ————————————————————————————————— //

pub(crate) fn create_switch(
    domain: Handle<Domain>,
    core: usize,
    regions: &mut RegionPool,
    domains: &mut DomainPool,
) -> Result<LocalCapa, CapaError> {
    let capa = Capa::Switch { to: domain, core };
    insert_capa(domain, capa, regions, domains)
}

// ———————————————————————————— Activate Region ————————————————————————————— //

pub(crate) fn activate_region(
    domain: Handle<Domain>,
    access: AccessRights,
    domains: &mut DomainPool,
    updates: &mut UpdateBuffer,
    tracker: &mut TrackerPool,
) -> Result<(), CapaError> {
    let dom = &mut domains[domain];

    // Drop updates on domain in the process of being revoked
    if dom.is_being_revoked {
        return Ok(());
    }
    let change = dom
        .regions
        .add_region(access.start, access.end, access.ops, tracker)?;

    let filter = |up: Update| match up {
        Update::PermissionUpdate {
            domain: up_dom,
            core_map: _,
        } if up_dom == domain => {
            return true;
        }
        _ => false,
    };
    if let PermissionChange::Some = change {
        if !updates.contains(filter) {
            updates
                .push(Update::PermissionUpdate {
                    domain,
                    core_map: dom.cores(),
                })
                .unwrap();
        }
    };

    Ok(())
}

pub(crate) fn deactivate_region(
    domain: Handle<Domain>,
    access: AccessRights,
    domains: &mut DomainPool,
    updates: &mut UpdateBuffer,
    tracker: &mut TrackerPool,
) -> Result<(), CapaError> {
    let dom = &mut domains[domain];

    let change = dom
        .regions
        .remove_region(access.start, access.end, access.ops, tracker)?;

    // Drop updates on domain in the process of being revoked
    if dom.is_being_revoked {
        return Ok(());
    }

    let filter = |up: Update| match up {
        Update::PermissionUpdate {
            domain: up_dom,
            core_map: _,
        } if up_dom == domain => {
            return true;
        }
        _ => false,
    };

    if let PermissionChange::Some = change {
        if !updates.contains(filter) {
            updates
                .push(Update::PermissionUpdate {
                    domain,
                    core_map: dom.cores(),
                })
                .unwrap();
        }
    };

    Ok(())
}

// —————————————————————————————— Trap Handler —————————————————————————————— //

/// Find the domain's manager who is responsible for handling the provided trap.
///
/// The domain itself is assumed to not be authorized to handle the domain.
/// Return none if no suitable manager exists.
pub(crate) fn find_trap_handler(
    domain: Handle<Domain>,
    trap: u64,
    domains: &DomainPool,
) -> Option<Handle<Domain>> {
    let mut handle = domain;
    while let Some(manager) = domains.get(handle) {
        if manager.traps() & trap != 0 {
            return Some(handle);
        }
        let Some(next_handle) = manager.manager else {
            // This domain has no manager
            break;
        };
        handle = next_handle;
    }

    // Could not find a suitable manager
    None
}

// ——————————————————————————————— Enumerate ———————————————————————————————— //

pub(crate) fn next_capa(
    domain_handle: Handle<Domain>,
    token: NextCapaToken,
    regions: &RegionPool,
    domains: &mut DomainPool,
) -> Option<(LocalCapa, NextCapaToken)> {
    let mut idx = token.idx;
    let Some(domain) = &domains.get(domain_handle) else {
        return None;
    };
    let len = domain.capas.len();
    while idx < len {
        let domain = &domains[domain_handle];
        if !domain.free_list.is_free(idx) {
            if domain.is_valid(idx, regions, domains) {
                // Found a valid capa
                let next_token = NextCapaToken { idx: idx + 1 };
                return Some((LocalCapa::new(idx), next_token));
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
    regions: &mut RegionPool,
    domains: &mut DomainPool,
    tracker: &mut TrackerPool,
    updates: &mut UpdateBuffer,
) -> Result<(), CapaError> {
    log::trace!("Revoke domain {}", handle);

    let domain = &mut domains[handle];
    if domain.is_being_revoked {
        // Already in the process of being revoked
        return Ok(());
    } else {
        // Mark as being revoked
        domain.is_being_revoked = true;
        // The domain is still scheduled on some cores.
        if domain.cores() != 0 {
            return Err(CapaError::InvalidOperation);
        }
    }

    // Drop all capabilities
    let mut token = NextCapaToken::new();
    while let Some((capa, next_token)) = next_capa(handle, token, regions, domains) {
        token = next_token;
        revoke_capa(handle, capa, regions, domains, tracker, updates)?;
    }

    domains.free(handle);
    Ok(())
}

pub(crate) fn revoke_capa(
    handle: Handle<Domain>,
    local: LocalCapa,
    regions: &mut RegionPool,
    domains: &mut DomainPool,
    tracker: &mut TrackerPool,
    updates: &mut UpdateBuffer,
) -> Result<(), CapaError> {
    let domain = &mut domains[handle];
    let capa = domain.get(local)?;

    match capa {
        // Those capa so not cause revocation side effects
        Capa::None => (),
        Capa::Channel(_) => (),
        Capa::Switch { .. } => {}

        Capa::Region(region) => {
            segment::revoke(region, regions, domains, tracker, updates)?;
        }
        Capa::RegionRevoke(region) => {
            if regions.get(region).is_some() {
                segment::revoke(region, regions, domains, tracker, updates)?;
            }
        }
        Capa::Management(domain) => {
            revoke(domain, regions, domains, tracker, updates)?;
        }
    }

    // Deactivate capa
    let capa = domains[handle].get_mut(local).unwrap();
    //TODO(aghosn) this is why the capa is marked valid but none.
    *capa = Capa::None;

    Ok(())
}

// ———————————————————————————————— Iterator ———————————————————————————————— //

pub struct DomainCapaIterator<'a> {
    td: &'a Domain,
    idx: usize,
}

impl<'a> Iterator for DomainCapaIterator<'a> {
    type Item = Capa;

    fn next(&mut self) -> Option<Self::Item> {
        while self.idx < self.td.capas.len() {
            let idx = self.idx;
            self.idx += 1;

            // Skip to next if no capa there
            if self.td.free_list.is_free(idx) {
                continue;
            } else {
                return Some(self.td.capas[idx]);
            }
        }
        None
    }
}
