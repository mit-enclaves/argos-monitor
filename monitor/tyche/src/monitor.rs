use core::sync::atomic::AtomicBool;

use attestation::hashing::hash_region;
use capa_engine::config::{NB_CORES, NB_DOMAINS};
use capa_engine::{
    permission, AccessRights, Buffer, CapaEngine, CapaError, CapaInfo, Domain, Handle, LocalCapa,
    MemOps, NextCapaToken, MEMOPS_ALL, MEMOPS_EXTRAS,
};
use spin::{Mutex, MutexGuard};
use stage_two_abi::Manifest;

use crate::arch::cpuid;
use crate::attestation_domain::calculate_attestation_hash;
use crate::calls;
use crate::sync::Barrier;

// ———————————————————————————————— Updates ————————————————————————————————— //
/// Per-core updates
#[derive(Debug, Clone, Copy)]
pub enum CoreUpdate {
    TlbShootdown,
    Switch {
        domain: Handle<Domain>,
        return_capa: LocalCapa,
    },
    Trap {
        manager: Handle<Domain>,
        trap: u64,
        info: u64,
    },
}

// ————————————————————————— Statics & Backend Data ————————————————————————— //
static CAPA_ENGINE: Mutex<CapaEngine> = Mutex::new(CapaEngine::new());
static IO_DOMAIN: Mutex<Option<LocalCapa>> = Mutex::new(None);
static INITIAL_DOMAIN: Mutex<Option<Handle<Domain>>> = Mutex::new(None);
static CORE_UPDATES: [Mutex<Buffer<CoreUpdate>>; NB_CORES] = [EMPTY_UPDATE_BUFFER; NB_CORES];
const FALSE: AtomicBool = AtomicBool::new(false);
static TLB_FLUSH_BARRIERS: [Barrier; NB_DOMAINS] = [Barrier::NEW; NB_DOMAINS];
static TLB_FLUSH: [AtomicBool; NB_DOMAINS] = [FALSE; NB_DOMAINS];

// —————————————————————— Constants for initialization —————————————————————— //
const EMPTY_UPDATE_BUFFER: Mutex<Buffer<CoreUpdate>> = Mutex::new(Buffer::new());

// —————————————————————————— Trying to generalize —————————————————————————— //

pub trait PlatformState {
    type DomainData;
    type Context;
    fn find_buff(
        engine: &MutexGuard<CapaEngine>,
        domain: Handle<Domain>,
        addr: usize,
        end: usize,
    ) -> Option<usize>;
    fn remap_core_bitmap(bitmap: u64) -> u64;
    fn remap_core(core: usize) -> usize;
    fn max_cpus() -> usize;
    fn create_context(
        &mut self,
        engine: MutexGuard<CapaEngine>,
        current: Handle<Domain>,
        domain: Handle<Domain>,
        core: usize,
    ) -> Result<(), CapaError>;

    fn get_domain(domain: Handle<Domain>) -> MutexGuard<'static, Self::DomainData>;

    fn get_context(domain: Handle<Domain>, core: usize) -> MutexGuard<'static, Self::Context>;

    fn update_permission(domain: Handle<Domain>, engine: &mut MutexGuard<CapaEngine>) -> bool;

    fn create_domain(domain: Handle<Domain>);

    fn revoke_domain(_domain: Handle<Domain>);

    fn apply_core_update(
        &mut self,
        domain: &mut Handle<Domain>,
        core_id: usize,
        update: &CoreUpdate,
    );

    fn platform_shootdown(&mut self, domain: &Handle<Domain>, core: usize);

    fn set_core(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: &Handle<Domain>,
        core: usize,
        idx: usize,
        value: usize,
    ) -> Result<(), CapaError>;

    fn check_overlaps(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: Handle<Domain>,
        alias: usize,
        repeat: usize,
        region: &AccessRights,
    ) -> bool;

    fn map_region(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: Handle<Domain>,
        alias: usize,
        repeat: usize,
        region: &AccessRights,
    ) -> Result<(), CapaError>;
}

pub trait Monitor<T: PlatformState + 'static> {
    /// This function attempts to avoid deadlocks.
    /// It forces updates to be consumed upon failed attempts.
    fn lock_engine(state: &mut T, dom: &mut Handle<Domain>) -> MutexGuard<'static, CapaEngine> {
        let mut locked = CAPA_ENGINE.try_lock();
        while locked.is_none() {
            //TODO: fix me
            Self::apply_core_updates(state, dom, cpuid());
            locked = CAPA_ENGINE.try_lock();
        }
        locked.unwrap()
    }

    fn do_init(state: &mut T, manifest: &'static Manifest) {
        // No one else is running yet
        let mut engine = CAPA_ENGINE.lock();
        let domain = engine
            .create_manager_domain(permission::monitor_inter_perm::ALL)
            .unwrap();
        Self::apply_updates(state, &mut engine);
        engine
            .create_root_region(
                domain,
                AccessRights {
                    start: 0,
                    end: manifest.poffset as usize,
                    ops: MEMOPS_ALL,
                },
            )
            .unwrap();
        //TODO: call the platform?
        Self::apply_updates(state, &mut engine);
        // Save the initial domain.
        let mut initial_domain = INITIAL_DOMAIN.lock();
        *initial_domain = Some(domain);

        // Create and save the I/O domain.
        let io_domain = engine.create_io_domain(domain).unwrap();
        let mut initial_io_domain = IO_DOMAIN.lock();
        *initial_io_domain = Some(io_domain);
        //TODO figure that out.
        /*if manifest.iommu != 0 {
            let mut iommu = IOMMU.lock();
            iommu.set_addr(manifest.iommu as usize);
        }*/
    }

    fn do_create_domain(
        state: &mut T,
        current: &mut Handle<Domain>,
    ) -> Result<LocalCapa, CapaError> {
        let mut engine = Self::lock_engine(state, current);
        let mgmt = engine.create_domain(*current)?;
        Self::apply_updates(state, &mut engine);
        Ok(mgmt)
    }

    fn do_set(
        state: &mut T,
        current: &mut Handle<Domain>,
        domain: LocalCapa,
        bitmap: permission::PermissionIndex,
        value: u64,
    ) -> Result<(), CapaError> {
        let mut engine = Self::lock_engine(state, current);
        engine.set_child_permission(*current, domain, bitmap, value)?;
        Self::apply_updates(state, &mut engine);
        Ok(())
    }

    fn do_get(
        state: &mut T,
        current: &mut Handle<Domain>,
        domain: LocalCapa,
        bitmap: permission::PermissionIndex,
    ) -> Result<usize, CapaError> {
        let mut engine = Self::lock_engine(state, current);
        Ok(engine.get_child_permission(*current, domain, bitmap)? as usize)
    }

    fn do_set_core(
        state: &mut T,
        current: &mut Handle<Domain>,
        domain: LocalCapa,
        core: usize,
        idx: usize,
        value: usize,
    ) -> Result<(), CapaError> {
        let mut engine = Self::lock_engine(state, current);
        // Check the core is valid.
        let cores = engine.get_child_permission(
            *current,
            domain,
            permission::PermissionIndex::AllowedCores,
        )?;
        if cores & (1 << core) == 0 {
            return Err(CapaError::InvalidCore);
        }
        let domain = engine.get_domain_capa(*current, domain)?;
        state.set_core(&mut engine, &domain, core, idx, value)
    }

    fn do_get_core(
        state: &mut T,
        current: &mut Handle<Domain>,
        domain: LocalCapa,
        core: usize,
        idx: usize,
    ) -> Result<usize, CapaError>;

    fn do_seal(
        state: &mut T,
        current: &mut Handle<Domain>,
        domain: LocalCapa,
    ) -> Result<LocalCapa, CapaError> {
        let core = cpuid();
        let mut engine = Self::lock_engine(state, current);
        //TODO: fix that.
        let capa = engine.seal(*current, core, domain)?;
        if let Ok(domain_capa) = engine.get_domain_capa(*current, domain) {
            calculate_attestation_hash(&mut engine, domain_capa);
        }

        Self::apply_updates(state, &mut engine);
        Ok(capa)
    }

    fn do_segment_region(
        state: &mut T,
        current: &mut Handle<Domain>,
        capa: LocalCapa,
        is_shared: bool,
        start: usize,
        end: usize,
        prot: usize,
    ) -> Result<(LocalCapa, LocalCapa), CapaError> {
        let prot = MemOps::from_usize(prot)?;
        if prot.intersects(MEMOPS_EXTRAS) {
            log::error!("Invalid prots for segment region {:?}", prot);
            return Err(CapaError::InvalidOperation);
        }
        let mut engine = Self::lock_engine(state, current);
        let access = AccessRights {
            start,
            end,
            ops: prot,
        };
        let to_send = if is_shared {
            engine.alias_region(*current, capa, access)?
        } else {
            engine.carve_region(*current, capa, access)?
        };
        let to_revoke = engine.create_revoke_capa(*current, to_send)?;
        Self::apply_updates(state, &mut engine);
        Ok((to_send, to_revoke))
    }

    fn do_send(
        state: &mut T,
        current: &mut Handle<Domain>,
        capa: LocalCapa,
        to: LocalCapa,
    ) -> Result<(), CapaError> {
        let mut engine = Self::lock_engine(state, current);
        // Send is not allowed for region capa.
        // Use do_send_region instead.
        match engine.get_region_capa(*current, capa)? {
            Some(_) => return Err(CapaError::InvalidCapa),
            _ => {}
        }
        engine.send(*current, capa, to)?;
        Self::apply_updates(state, &mut engine);
        Ok(())
    }

    fn do_send_region(
        state: &mut T,
        current: &mut Handle<Domain>,
        capa: LocalCapa,
        to: LocalCapa,
        alias: usize,
        is_repeat: bool,
        size: usize,
        extra_rights: usize,
    ) -> Result<(), CapaError> {
        let mut engine = Self::lock_engine(state, current);
        let flags = MemOps::from_usize(extra_rights)?;
        if !flags.is_empty() && !flags.is_only_hcv() {
            log::error!("Invalid send region flags received: {:?}", flags);
            return Err(CapaError::InvalidPermissions);
        }
        // Get the capa first.
        let region_info = engine
            .get_region_capa(*current, capa)?
            .ok_or(CapaError::InvalidCapa)?
            .get_access_rights();
        let repeat = if is_repeat {
            let region_size = region_info.end - region_info.start;
            if size == 0 || (size % region_size) != 0 {
                return Err(CapaError::InvalidValue);
            }
            size / region_size
        } else {
            // Not a repeat, spans the entire thing.
            1
        };

        // Check for an overlap first.
        {
            let target = engine.get_domain_capa(*current, to)?;
            if state.check_overlaps(&mut engine, target, alias, repeat, &region_info) {
                return Err(CapaError::AlreadyAliased);
            }
        }

        if !flags.is_empty() {
            // NOTE: we are missing some checks here, not all memory covered by regions can be accessed
            // in the current design.
            let hash = if flags.contains(MemOps::HASH) {
                let data = unsafe {
                    core::slice::from_raw_parts(
                        region_info.start as *const u8,
                        region_info.end - region_info.start,
                    )
                };
                let hash = hash_region(data);
                Some(hash)
            } else {
                None
            };
            let opt_flags = if flags.is_empty() { None } else { Some(flags) };
            let _ = engine.send_with_flags(*current, capa, to, opt_flags, hash);
        } else {
            let _ = engine.send(*current, capa, to)?;
        }

        {
            let target = engine.get_domain_capa(*current, to)?;
            state.map_region(&mut engine, target, alias, repeat, &region_info)?;
        }

        Ok(())
    }

    fn do_enumerate(
        state: &mut T,
        current: &mut Handle<Domain>,
        token: NextCapaToken,
    ) -> Option<(CapaInfo, NextCapaToken)> {
        let mut engine = Self::lock_engine(state, current);
        engine.enumerate(*current, token)
    }

    fn do_revoke(
        state: &mut T,
        current: &mut Handle<Domain>,
        capa: LocalCapa,
    ) -> Result<(), CapaError> {
        let mut engine = Self::lock_engine(state, current);
        engine.revoke(*current, capa)?;
        Self::apply_updates(state, &mut engine);
        Ok(())
    }

    fn do_revoke_region(
        state: &mut T,
        current: &mut Handle<Domain>,
        capa: LocalCapa,
        to: LocalCapa,
        alias: usize,
        size: usize,
    ) -> Result<(), CapaError> {
        todo!("Implement");
    }

    fn do_duplicate(
        state: &mut T,
        current: &mut Handle<Domain>,
        capa: LocalCapa,
    ) -> Result<LocalCapa, CapaError> {
        let mut engine = Self::lock_engine(state, current);
        let new_capa = engine.duplicate(*current, capa)?;
        Self::apply_updates(state, &mut engine);
        Ok(new_capa)
    }

    fn do_switch(
        state: &mut T,
        current: &mut Handle<Domain>,
        capa: LocalCapa,
        cpuid: usize,
    ) -> Result<(), CapaError> {
        let mut engine = Self::lock_engine(state, current);
        engine.switch(*current, cpuid, capa)?;
        Self::apply_updates(state, &mut engine);
        Ok(())
    }

    fn do_serialize_attestation(
        state: &mut T,
        domain_handle: &mut Handle<Domain>,
        addr: usize,
        len: usize,
    ) -> Result<usize, CapaError> {
        let engine = Self::lock_engine(state, domain_handle);
        //TODO maybe we have some more arguments
        let buff = T::find_buff(&engine, *domain_handle, addr, addr + len);
        let Some(buff) = buff else {
            log::info!("Invalid buffer in serialize attestation");
            return Err(CapaError::InsufficientPermissions);
        };
        let buff = unsafe { core::slice::from_raw_parts_mut(buff as *mut u8, len) };
        engine.serialize_attestation(buff)
    }

    fn do_init_child_context(
        state: &mut T,
        current: &mut Handle<Domain>,
        domain: LocalCapa,
        core: usize,
    ) -> Result<(), CapaError> {
        let mut engine = Self::lock_engine(state, current);
        let domain = engine.get_domain_capa(*current, domain)?;
        let cores = engine.get_domain_permission(domain, permission::PermissionIndex::AllowedCores);
        if core > T::max_cpus() || (1 << core) & cores == 0 {
            log::error!("Attempt to set context on unallowed core");
            return Err(CapaError::InvalidCore);
        }
        T::create_context(state, engine, *current, domain, core)?;
        return Ok(());
    }

    fn do_monitor_call(
        state: &mut T,
        domain: &mut Handle<Domain>,
        call: usize,
        args: &[usize; 6],
        res: &mut [usize; 6],
    ) -> Result<(), CapaError> {
        match call {
            calls::CREATE_DOMAIN => {
                log::trace!("Create domain on core {}", cpuid());
                let capa = Self::do_create_domain(state, domain).expect("TODO");
                res[0] = capa.as_usize();
                return Ok(());
            }
            calls::SEAL_DOMAIN => {
                log::trace!("Seal Domain on core {}", cpuid());
                let capa = Self::do_seal(state, domain, LocalCapa::new(args[0])).expect("TODO");
                res[0] = capa.as_usize();
                return Ok(());
            }
            calls::SEND => {
                log::trace!("Send on core {}", cpuid());
                Self::do_send(
                    state,
                    domain,
                    LocalCapa::new(args[0]),
                    LocalCapa::new(args[1]),
                )
                .expect("TODO");
                return Ok(());
            }
            calls::SEGMENT_REGION => {
                log::trace!("Segment region on core {}", cpuid());
                let (to_send, to_revoke) = Self::do_segment_region(
                    state,
                    domain,
                    LocalCapa::new(args[0]),
                    args[1] != 0,
                    args[2],
                    args[3],
                    args[4],
                )
                .unwrap();
                res[0] = to_send.as_usize();
                res[1] = to_revoke.as_usize();
                return Ok(());
            }
            calls::REVOKE => {
                log::trace!("Revoke on core {}", cpuid());
                Self::do_revoke(state, domain, LocalCapa::new(args[0])).unwrap();
                return Ok(());
            }
            calls::DUPLICATE => {
                log::trace!("Duplicate");
                let capa = Self::do_duplicate(state, domain, LocalCapa::new(args[0])).unwrap();
                res[0] = capa.as_usize();
                return Ok(());
            }
            calls::ENUMERATE => {
                log::trace!("Enumerate on core {}", cpuid());
                if let Some((info, next)) =
                    Self::do_enumerate(state, domain, NextCapaToken::from_usize(args[0]))
                {
                    let (v1, v2, v3) = info.serialize();
                    res[0] = v1;
                    res[1] = v2;
                    res[2] = v3 as usize;
                    res[3] = next.as_usize();
                } else {
                    res[3] = 0;
                }
                return Ok(());
            }
            calls::SWITCH => {
                log::trace!("Switch on core {}", cpuid());
                Self::do_switch(state, domain, LocalCapa::new(args[0]), cpuid()).unwrap();
                return Ok(());
            }
            calls::EXIT => {
                todo!("Exit called")
            }
            calls::DEBUG => {
                todo!("Debug implement")
            }
            calls::CONFIGURE => {
                log::trace!("Configure on core {}", cpuid());
                let result = if let Some(bitmap) = permission::PermissionIndex::from_usize(args[0])
                {
                    let mut value = args[2] as u64;
                    if bitmap == permission::PermissionIndex::AllowedCores {
                        value = T::remap_core_bitmap(value);
                    }
                    match Self::do_set(state, domain, LocalCapa::new(args[1]), bitmap, value) {
                        Ok(_) => 0,
                        Err(e) => {
                            log::error!("Configuration error: {:?}", e);
                            1
                        }
                    }
                } else {
                    log::error!("Invalid configuration target");
                    1
                };
                res[0] = result;
                return Ok(());
            }
            calls::CONFIGURE_CORE => {
                log::trace!("Configure Core on core {}", cpuid());
                let result = match Self::do_set_core(
                    state,
                    domain,
                    LocalCapa::new(args[0]),
                    T::remap_core(args[1]),
                    args[2],
                    args[3],
                ) {
                    Ok(()) => 0,
                    Err(e) => {
                        log::error!("Configure core error: {:?}", e);
                        1
                    }
                };
                res[0] = result;
                return Ok(());
            }
            calls::GET_CONFIG_CORE => {
                log::trace!("Get config core on core {}", cpuid());
                let (value, result) = match Self::do_get_core(
                    state,
                    domain,
                    LocalCapa::new(args[0]),
                    T::remap_core(args[1]),
                    args[2],
                ) {
                    Ok(v) => (v, 0),
                    Err(e) => {
                        log::error!("Get config core error: {:?}", e);
                        (0, 1)
                    }
                };
                res[0] = result;
                res[1] = value;
                return Ok(());
            }
            calls::ALLOC_CORE_CONTEXT => {
                let result = match Self::do_init_child_context(
                    state,
                    domain,
                    LocalCapa::new(args[0]),
                    args[1],
                ) {
                    Ok(_) => 0,
                    Err(e) => {
                        log::error!("Allocating core context error: {:?}", e);
                        1
                    }
                };
                res[0] = result;
                return Ok(());
            }
            calls::READ_ALL_GP => {
                todo!("Implement!!");
            }
            calls::WRITE_ALL_GP => {
                todo!("Implement!!!");
            }
            calls::WRITE_FIELDS => {
                todo!("Implement as well!");
            }
            calls::SELF_CONFIG => {
                todo!("Implement")
            }
            calls::REVOKE_ALIASED_REGION => {
                log::trace!("Revoke aliased region on core {}", cpuid());
                Self::do_revoke_region(
                    state,
                    domain,
                    LocalCapa::new(args[0]),
                    LocalCapa::new(args[1]),
                    args[2],
                    args[3],
                )
                .unwrap();
                return Ok(());
            }
            calls::SERIALIZE_ATTESTATION => {
                let written =
                    Self::do_serialize_attestation(state, domain, args[0], args[1]).unwrap();
                res[1] = written;
                res[0] = 0;
                return Ok(());
            }
            _ => {
                return Err(CapaError::InvalidOperation);
            }
        }
    }

    fn apply_updates(state: &mut T, engine: &mut MutexGuard<CapaEngine>) {
        while let Some(update) = engine.pop_update() {
            log::trace!("Update: {}", update);
            match update {
                capa_engine::Update::PermissionUpdate { domain, core_map } => {
                    let core_id = cpuid();
                    log::trace!(
                        "cpu {} processes PermissionUpdate with core_map={:b}",
                        core_id,
                        core_map
                    );
                    // Do we have to process updates
                    if T::update_permission(domain, engine) {
                        state.platform_shootdown(&domain, core_id);
                    }
                }
                capa_engine::Update::Cleanup { start, end } => {
                    let size = end.checked_sub(start).unwrap();
                    log::trace!("Cleaning up region [{:#x}, {:#x}]", start, end);
                    // WARNING: for now we do not check that the region points to valid memory!
                    // In particular, the current root region contains more than valid ram, and also
                    // include devices.
                    unsafe {
                        let region = core::slice::from_raw_parts_mut(start as *mut u8, size);
                        region.fill(0);
                    }
                }
                capa_engine::Update::RevokeDomain { domain } => T::revoke_domain(domain),
                capa_engine::Update::CreateDomain { domain } => T::create_domain(domain),
                capa_engine::Update::Switch {
                    domain,
                    return_capa,
                    core,
                } => {
                    let mut core_updates = CORE_UPDATES[core as usize].lock();
                    core_updates
                        .push(CoreUpdate::Switch {
                            domain,
                            return_capa,
                        })
                        .unwrap();
                }
                capa_engine::Update::Trap {
                    manager,
                    trap,
                    info,
                    core,
                } => {
                    let mut core_updates = CORE_UPDATES[core as usize].lock();
                    core_updates
                        .push(CoreUpdate::Trap {
                            manager,
                            trap,
                            info,
                        })
                        .unwrap();
                }
            }
        }
    }
    fn apply_core_updates(state: &mut T, current: &mut Handle<Domain>, core_id: usize) {
        let core = cpuid();
        let mut update_queue = CORE_UPDATES[core_id].lock();
        while let Some(update) = update_queue.pop() {
            state.apply_core_update(current, core, &update);
        }
    }
}

// ———————————————————————————————— Display ————————————————————————————————— //
impl core::fmt::Display for CoreUpdate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CoreUpdate::TlbShootdown => write!(f, "TLB Shootdown"),
            CoreUpdate::Switch { domain, .. } => write!(f, "Switch({})", domain),
            CoreUpdate::Trap {
                manager,
                trap: interrupt,
                info: inf,
            } => {
                write!(f, "Trap({}, {} | {:b})", manager, interrupt, inf)
            }
        }
    }
}
