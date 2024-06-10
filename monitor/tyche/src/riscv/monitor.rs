//! Architecture specific monitor state

use core::arch::asm;
use core::sync::atomic::{AtomicUsize, Ordering};

use attestation::hashing::TycheHasher;
use attestation::signature::EnclaveReport;
use capa_engine::config::{NB_CORES, NB_DOMAINS};
use capa_engine::utils::BitmapIterator;
use capa_engine::{
    permission, AccessRights, Buffer, CapaEngine, CapaError, CapaInfo, Domain, Handle, LocalCapa,
    MemOps, NextCapaToken, MEMOPS_ALL,
};
use riscv_csrs::pmpcfg;
use riscv_pmp::csrs::{pmpaddr_csr_read, pmpaddr_csr_write, pmpcfg_csr_read, pmpcfg_csr_write};
use riscv_pmp::{
    clear_pmp, pmp_write_compute, PMPAddressingMode, PMPErrorCode, PMPWriteResponse,
    FROZEN_PMP_ENTRIES, PMP_CFG_ENTRIES, PMP_ENTRIES,
};
use riscv_sbi::ipi::aclint_mswi_send_ipi;
use riscv_utils::*;
use spin::{Mutex, MutexGuard};

use crate::arch::cpuid;
use crate::attestation_domain::{attest_domain, calculate_attestation_hash};
use crate::monitor::{CoreUpdate, PlatformState, CAPA_ENGINE, CORE_UPDATES, INITIAL_DOMAIN};
use crate::riscv::context::ContextRiscv;
use crate::riscv::filtered_fields::RiscVField;
use crate::riscv::state::{DataRiscv, StateRiscv, MONITOR_IPI_SYNC};

// ————————————————————————————— Initialization ————————————————————————————— //

pub fn init() {
    let mut engine = CAPA_ENGINE.lock();
    let domain = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    apply_updates(&mut engine);
    engine
        .create_root_region(
            domain,
            AccessRights {
                start: 0x80400000, //Linux Root Region Start Address
                end: 0x800000000, //17fffffff,   //Linux Root Region End Address - it's currently based on early
                //memory node range detected by linux.
                //TODO: It should be a part of the manifest.
                //TODO: Dom0 needs 2 regions - ram region and pcie-mmio region
                //(currently overprovisioning memory accesses)
                //(check memory tree in QEMU).
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    engine
        .create_root_region(
            domain,
            AccessRights {
                start: SIFIVE_TEST_SYSCON_BASE_ADDRESS,
                end: PCI_BASE_ADDRESS + PCI_SIZE, //Optimization: Including both PLIC and PCI regions in a single PMP
                //entry
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    apply_updates(&mut engine);

    // Save the initial domain
    let mut initial_domain = INITIAL_DOMAIN.lock();
    *initial_domain = Some(domain);
}

pub fn start_initial_domain_on_cpu() -> (Handle<Domain>) {
    let hartid = cpuid();
    log::debug!("Creating initial domain.");
    let mut engine = CAPA_ENGINE.lock();
    let initial_domain = INITIAL_DOMAIN
        .lock()
        .expect("CapaEngine is not initialized yet");
    engine
        .start_domain_on_core(initial_domain, hartid)
        .expect("Failed to allocate initial domain");

    let domain = StateRiscv::get_domain(initial_domain);
    if !domain.data_init_done {
        //update PMP permissions.
        log::debug!("Updating permissions for initial domain.");
        StateRiscv::update_permission(initial_domain, &mut engine);
    }
    StateRiscv::update_pmps(domain);

    (initial_domain)
}

// ————————————————————————————— Monitor Calls —————————————————————————————— //

pub fn do_create_domain(current: Handle<Domain>) -> Result<LocalCapa, CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let management_capa = engine.create_domain(current)?;
    apply_updates(&mut engine);
    Ok(management_capa)
}

pub fn do_set_config(
    current: Handle<Domain>,
    domain: LocalCapa,
    bitmap: permission::PermissionIndex,
    value: u64,
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    engine.set_child_permission(current, domain, bitmap, value)?;
    apply_updates(&mut engine);
    Ok(())
}

pub fn do_configure_core(
    current: Handle<Domain>,
    domain: LocalCapa,
    core: usize,
    idx: usize,
    value: usize,
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let local_capa = domain;
    let domain = engine.get_domain_capa(current, domain)?;

    //TODO(aghosn): check how we could differentiate between registers
    //that can be changed and others. For the moment allow modifications
    //post sealing too.
    // Check the domain is not seal.
    /*if engine.is_sealed(domain) {
        return Err(CapaError::AlreadySealed);
    }*/

    // Check this is a valid core for the operation.
    let core_map = engine.get_domain_permission(domain, permission::PermissionIndex::AllowedCores);
    if (1 << core) & core_map == 0 {
        log::error!(
            "Invalid core {} for coremap {:b} in configure core",
            1 << core,
            core_map
        );
        return Err(CapaError::InvalidCore);
    }

    // Check this is a valid idx for a field.
    if !RiscVField::is_valid(idx) {
        log::debug!("Attempt to set an invalid register: {:x}", idx);
        return Ok(());
    }
    let field = RiscVField::from_usize(idx).unwrap();
    //TODO @Neelu check that.
    /*if field == RiscVField::Medeleg {
        engine
            .set_child_config(current, local_capa, Bitmaps::TRAP, !(value as u64))
            .expect("Unable to set the bitmap");
    }*/

    let mut target_ctxt = StateRiscv::get_context(domain, core);

    field.set(&mut target_ctxt, value);
    Ok(())
}

pub fn do_get_config_core(
    current: Handle<Domain>,
    domain: LocalCapa,
    core: usize,
    idx: usize,
) -> Result<usize, CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let domain = engine.get_domain_capa(current, domain)?;

    // Check the domain is not seal.
    //TODO(aghosn) we will need a way to differentiate between what's readable
    //and what's not readable once the domain is sealed.
    /*if engine.is_sealed(domain) {
        return Err(CapaError::AlreadySealed);
    }*/

    // Check this is a valid core for the operation.
    let core_map = engine.get_domain_permission(domain, permission::PermissionIndex::AllowedCores);
    if (1 << core) & core_map == 0 {
        return Err(CapaError::InvalidCore);
    }

    // Check this is a valid idx for a field.
    if !RiscVField::is_valid(idx) {
        log::debug!("Attempt to get an invalid register: {:x}", idx);
        return Ok(0);
    }
    let field = RiscVField::from_usize(idx).unwrap();
    let target_ctx = StateRiscv::get_context(domain, core);
    Ok(field.get(&target_ctx))
}

pub fn do_set_field(
    current: Handle<Domain>,
    domain: LocalCapa,
    core: usize,
    field: usize,
    value: usize,
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    // Check the core.
    let domain = engine.get_domain_capa(current, domain)?;
    let core_map = engine.get_domain_permission(domain, permission::PermissionIndex::AllowedCores);
    if (1 << core) & core_map == 0 {
        log::error!("Trying to set registers on the wrong core.");
        return Err(CapaError::InvalidCore);
    }
    if !RiscVField::is_valid(field) {
        log::debug!("Attempt to get an invalid field: {:x}", field);
        return Ok(());
    }
    let field = RiscVField::from_usize(field).unwrap();
    let mut target_ctx = StateRiscv::get_context(domain, core);
    field.set(&mut target_ctx, value);
    Ok(())
}

pub fn do_set_entry(
    current: Handle<Domain>,
    domain: LocalCapa,
    core: usize,
    satp: usize,
    mepc: usize,
    sp: usize,
) -> Result<(), CapaError> {
    log::debug!(
        "satp: {:x} mepc: {:x} sp: {:x} core {:x}",
        satp,
        mepc,
        sp,
        core
    );
    let mut engine = CAPA_ENGINE.lock();
    let domain = engine.get_domain_capa(current, domain)?;
    let cores = engine.get_domain_permission(domain, permission::PermissionIndex::AllowedCores);
    if (1 << core) & cores == 0 {
        return Err(CapaError::InvalidCore);
    }
    let context = &mut StateRiscv::get_context(domain, core);

    context.satp = ((satp >> 12) | PAGING_MODE_SV48);
    context.mepc = (mepc - 0x4); //TODO: Temporarily subtracting 4, because at the end of handle_exit,
                                 //mepc+4 is the address being returned to. Need to find an elegant way
                                 //to manage this.

    context.sp = sp;
    let temp_reg_state = RegisterState::const_default();
    context.reg_state = temp_reg_state;
    Ok(())
}

pub fn do_seal(current: Handle<Domain>, domain: LocalCapa) -> Result<LocalCapa, CapaError> {
    let cpuid = cpuid();
    let mut engine = CAPA_ENGINE.lock();
    let capa = engine.seal(current, cpuid, domain)?;

    if let Ok(domain_capa) = engine.get_domain_capa(current, domain) {
        log::trace!("Calculating attestation hash");
        calculate_attestation_hash(&mut engine, domain_capa);
    }

    apply_updates(&mut engine);
    Ok(capa)
}

pub fn do_segment_region(
    current: Handle<Domain>,
    capa: LocalCapa,
    is_shared: bool,
    start: usize,
    end: usize,
    prot: usize,
) -> Result<(LocalCapa, LocalCapa), CapaError> {
    let prot = MemOps::from_usize(prot)?;
    let mut engine = CAPA_ENGINE.lock();
    let access = AccessRights {
        start,
        end,
        ops: prot,
    };
    let to_send = if is_shared {
        engine.alias_region(current, capa, access)?
    } else {
        engine.carve_region(current, capa, access)?
    };
    let to_revoke = engine.create_revoke_capa(current, to_send)?;
    apply_updates(&mut engine);
    Ok((to_send, to_revoke))
}

pub fn do_send(current: Handle<Domain>, capa: LocalCapa, to: LocalCapa) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    // Send is not allowed for region capa.
    // Use do_send_aliased instead.
    match engine.get_region_capa(current, capa)? {
        Some(_) => return Err(CapaError::InvalidCapa),
        _ => {}
    }
    engine.send(current, capa, to)?;
    apply_updates(&mut engine);
    Ok(())
}

pub fn do_send_region(
    current: Handle<Domain>,
    capa: LocalCapa,
    to: LocalCapa,
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    // send_region is only allowed for region capa.
    match engine.get_region_capa(current, capa)? {
        Some(_) => {}
        _ => return Err(CapaError::InvalidCapa),
    }
    engine.send(current, capa, to)?;
    apply_updates(&mut engine);
    Ok(())
}

pub fn do_init_child_context(
    current: Handle<Domain>,
    domain: LocalCapa,
    core: usize,
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let domain = engine.get_domain_capa(current, domain)?;

    // Check this is a valid core for the operation.
    let core_map = engine.get_domain_permission(domain, permission::PermissionIndex::AllowedCores);
    if (1 << core) & core_map == 0 {
        return Err(CapaError::InvalidCore);
    }
    Ok(())
}

pub fn do_enumerate(
    current: Handle<Domain>,
    token: NextCapaToken,
) -> Option<(CapaInfo, NextCapaToken)> {
    let mut engine = CAPA_ENGINE.lock();
    engine.enumerate(current, token)
}

pub fn do_revoke(current: Handle<Domain>, capa: LocalCapa) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    engine.revoke(current, capa)?;
    apply_updates(&mut engine);
    Ok(())
}

pub fn do_duplicate(current: Handle<Domain>, capa: LocalCapa) -> Result<LocalCapa, CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let new_capa = engine.duplicate(current, capa)?;
    apply_updates(&mut engine);
    Ok(new_capa)
}

pub fn do_switch(
    current: Handle<Domain>,
    //current_ctx: Handle<Context>,
    capa: LocalCapa,
    cpuid: usize,
    current_reg_state: &mut RegisterState,
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    engine.switch(current, cpuid, capa)?;
    apply_updates(&mut engine);
    Ok(())
}

pub fn do_debug(engine: &mut MutexGuard<CapaEngine>) {
    //let mut engine = CAPA_ENGINE.lock();
    let mut next = NextCapaToken::new();
    log::debug!("Logging domains.");
    while let Some((domain, next_next)) = engine.enumerate_domains(next) {
        next = next_next;

        log::debug!("Domain");
        let mut next_capa = NextCapaToken::new();
        while let Some((info, next_next_capa)) = engine.enumerate(domain, next_capa) {
            next_capa = next_next_capa;
            log::debug!(" - {}", info);
        }
        log::debug!("{}", engine.get_domain_regions(domain).unwrap());
    }
}

fn copy_array(dst: &mut [u8], src: &[u8], index: usize) {
    let mut ind_help = index;
    for x in src {
        dst[ind_help] = *x;
        ind_help += 1;
    }
}

pub fn do_domain_attestation(
    current: Handle<Domain>,
    nonce: usize,
    mode: usize,
) -> Option<EnclaveReport> {
    let mut engine = CAPA_ENGINE.lock();
    attest_domain(&mut engine, current, nonce, mode)
}

// ———————————————————————————————— Updates ————————————————————————————————— //

fn apply_updates(engine: &mut MutexGuard<CapaEngine>) {
    while let Some(update) = engine.pop_update() {
        match update {
            capa_engine::Update::PermissionUpdate { domain, core_map } => {
                let src_hartid = cpuid();

                StateRiscv::update_permission(domain, engine);

                if (1 << src_hartid) & core_map == 1 {
                    let mut domain_data = StateRiscv::get_domain(domain);
                    StateRiscv::update_pmps(domain_data);
                }

                for hart in BitmapIterator::new(core_map) {
                    if (hart != src_hartid) {
                        let mut per_hart_update_buffer = CORE_UPDATES[hart].lock();
                        per_hart_update_buffer.push(CoreUpdate::TlbShootdown {
                            src_core: src_hartid,
                        });
                        drop(per_hart_update_buffer);
                        log::debug!(
                            "TLB Shootdown IPI from src_hartid: {} to dest_hartid: {}",
                            src_hartid,
                            hart
                        );
                        MONITOR_IPI_SYNC[src_hartid].fetch_add(1, Ordering::SeqCst);
                        aclint_mswi_send_ipi(hart);
                    }
                }

                while MONITOR_IPI_SYNC[src_hartid].load(Ordering::SeqCst) > 0 {
                    //TODO: Should I process local-core-updates here?
                    core::hint::spin_loop();
                }

                //When it's all done then just continue!
            }
            capa_engine::Update::Cleanup { start, end } => {
                let size = end.checked_sub(start).unwrap();
                log::info!("Cleaning up region [0x{:x}, 0x{:x}]", start, end);

                // WARNING: for now we do not check that the region points to valid memory!
                // In particular, the current root region contains more than valid ram, and also
                // include devices.
                unsafe {
                    let region = core::slice::from_raw_parts_mut(start as *mut u8, size);
                    region.fill(0);
                }
            }
            capa_engine::Update::RevokeDomain { domain } => StateRiscv::revoke_domain(domain),
            capa_engine::Update::CreateDomain { domain } => StateRiscv::create_domain(domain),

            // Updates that needs to be routed to some specific cores
            capa_engine::Update::Switch {
                domain,
                return_capa,
                core,
            } => {
                let mut core_updates = CORE_UPDATES[core as usize].lock();
                core_updates.push(CoreUpdate::Switch {
                    domain,
                    return_capa,
                });
            }
            capa_engine::Update::Trap {
                manager,
                trap,
                info,
                core,
            } => {
                let mut core_updates = CORE_UPDATES[core as usize].lock();
                core_updates.push(CoreUpdate::Trap {
                    manager,
                    trap,
                    info,
                });
            } //TODO: @Neelu might have bugs since we removed that.
              /*capa_engine::Update::UpdateTraps { trap, core } => {
                  let mut core_updates = CORE_UPDATES[core as usize].lock();
                  core_updates.push(CoreUpdate::UpdateTrap { bitmap: !trap });
              }*/
        }
    }
}

/*
/// Updates that must be applied to a given core.
pub fn apply_core_updates(
    current_domain: &mut Handle<Domain>,
    core_id: usize,
    current_reg_state: &mut RegisterState,
) {
    let core = cpuid();
    let mut update_queue = CORE_UPDATES[core_id].lock();
    while let Some(update) = update_queue.pop() {
        let mut state = StateRiscv {};
        state.apply_core_update(current_domain, core_id, &update);
    }
}*/
