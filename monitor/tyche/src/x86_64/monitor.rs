//! Architecture specific monitor state, independant of the CapaEngine.

use core::sync::atomic::Ordering;

use attestation::hashing::hash_region;
use attestation::signature::EnclaveReport;
use capa_engine::utils::BitmapIterator;
use capa_engine::{
    permission, AccessRights, CapaEngine, CapaError, CapaInfo, Domain, Handle, LocalCapa, MemOps,
    NextCapaToken, MEMOPS_ALL, MEMOPS_EXTRAS,
};
use mmu::eptmapper::EPT_ROOT_FLAGS;
use mmu::{EptMapper, FrameAllocator};
use spin::MutexGuard;
use stage_two_abi::{GuestInfo, Manifest};
use utils::{GuestPhysAddr, HostPhysAddr};
use vmx::fields::{GeneralPurposeField, VmcsField, REGFILE_SIZE};
use vmx::{ActiveVmcs, VmExitInterrupt};

use super::filtered_fields::FilteredFields;
use super::init::NB_BOOTED_CORES;
use super::platform::MonitorX86;
use super::state::{StateX86, VmxState, IOMMU, RC_VMCS};
use super::vmx_helper::{dump_host_state, load_host_state};
use super::{cpuid, vmx_helper};
use crate::allocator::{allocator, PAGE_SIZE};
use crate::attestation_domain::{attest_domain, calculate_attestation_hash};
use crate::monitor::{
    CoreUpdate, Monitor, PlatformState, CAPA_ENGINE, CORE_UPDATES, INITIAL_DOMAIN, IO_DOMAIN,
};
use crate::rcframe::{drop_rc, RCFrame};
use crate::x86_64::state::{TLB_FLUSH, TLB_FLUSH_BARRIERS};

// ————————————————————————— Statics & Backend Data ————————————————————————— //

//static CAPA_ENGINE: Mutex<CapaEngine> = Mutex::new(CapaEngine::new());
//static IO_DOMAIN: Mutex<Option<LocalCapa>> = Mutex::new(None);
//static INITIAL_DOMAIN: Mutex<Option<Handle<Domain>>> = Mutex::new(None);
//static CORE_UPDATES: [Mutex<Buffer<CoreUpdate>>; NB_CORES] = [EMPTY_UPDATE_BUFFER; NB_CORES];
//const EMPTY_UPDATE_BUFFER: Mutex<Buffer<CoreUpdate>> = Mutex::new(Buffer::new());

// ————————————————————————————— Initialization ————————————————————————————— //

// This is meant to avoid deadlocks due to tlb shootdowns.
pub fn lock_engine(
    vmx_state: &mut VmxState,
    dom: &mut Handle<Domain>,
) -> MutexGuard<'static, CapaEngine> {
    let mut locked = CAPA_ENGINE.try_lock();
    while locked.is_none() {
        MonitorX86::apply_core_updates(vmx_state, dom, cpuid());
        locked = CAPA_ENGINE.try_lock();
    }
    locked.unwrap()
}
/*pub fn init(manifest: &'static Manifest) {
    let mut engine = CAPA_ENGINE.lock();
    let domain = engine
        .create_manager_domain(permission::monitor_inter_perm::ALL)
        .unwrap();
    apply_updates(&mut engine);
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
    // Call the remapper information.
    {
        let mut dom_dat = StateX86::get_domain(domain);
        let _ = dom_dat
            .remapper
            .map_range(0, 0, manifest.iommu as usize, 1)
            .unwrap();
        let s = (manifest.iommu + PAGE_SIZE) as usize;
        let _ = dom_dat
            .remapper
            .map_range(s, s, (manifest.poffset as usize) - s, 1)
            .unwrap();
    }
    apply_updates(&mut engine);

    // Save the initial domain
    let mut initial_domain = INITIAL_DOMAIN.lock();
    *initial_domain = Some(domain);

    // Create and save the I/O domain
    let io_domain = engine.create_io_domain(domain).unwrap();
    let mut initial_io_domain = IO_DOMAIN.lock();
    *initial_io_domain = Some(io_domain);

    if manifest.iommu != 0 {
        let mut iommu = IOMMU.lock();
        iommu.set_addr(manifest.iommu as usize);
    }
}*/

pub fn init_vcpu(vcpu: &mut ActiveVmcs<'static>) -> Handle<Domain> {
    let cpuid = cpuid();
    let mut engine = CAPA_ENGINE.lock();
    let initial_domain = INITIAL_DOMAIN
        .lock()
        .expect("CapaEngine is not initialized yet");
    engine
        .start_domain_on_core(initial_domain, cpuid)
        .expect("Failed to allocate initial domain");
    let domain = StateX86::get_domain(initial_domain);
    let mut ctxt = StateX86::get_context(initial_domain, cpuid);
    let rcframe = RC_VMCS
        .lock()
        .allocate(RCFrame::new(*vcpu.frame()))
        .expect("Unable to allocate rcframe");
    ctxt.vmcs = rcframe;
    vcpu.set_ept_ptr(HostPhysAddr::new(
        domain.ept.unwrap().as_usize() | EPT_ROOT_FLAGS,
    ))
    .expect("Failed to set initial EPT PTR");
    initial_domain
}

// ————————————————————————————— Monitor Calls —————————————————————————————— //

pub fn do_create_domain(
    vmx_state: &mut VmxState,
    current: &mut Handle<Domain>,
) -> Result<LocalCapa, CapaError> {
    let mut engine = lock_engine(vmx_state, current);
    let management_capa = engine.create_domain(*current)?;
    apply_updates(&mut engine);
    Ok(management_capa)
}

pub fn do_set_config(
    vmx_state: &mut VmxState,
    current: &mut Handle<Domain>,
    domain: LocalCapa,
    bitmap: permission::PermissionIndex,
    value: u64,
) -> Result<(), CapaError> {
    let mut engine = lock_engine(vmx_state, current);
    engine.set_child_permission(*current, domain, bitmap, value)?;
    apply_updates(&mut engine);
    Ok(())
}

pub fn do_configure_core(
    vmx_state: &mut VmxState,
    current: &mut Handle<Domain>,
    domain: LocalCapa,
    core: usize,
    idx: usize,
    value: usize,
) -> Result<(), CapaError> {
    let mut engine = lock_engine(vmx_state, current);
    let local_capa = domain;
    let domain = engine.get_domain_capa(*current, domain)?;

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
    if !FilteredFields::is_valid(idx, true) {
        log::error!("Attempt to set an invalid register: {:x}", idx);
        return Err(CapaError::InvalidOperation);
    }
    let field = VmcsField::from_u32(idx as u32).unwrap();
    if field == VmcsField::ExceptionBitmap {
        engine
            .set_child_permission(
                *current,
                local_capa,
                permission::PermissionIndex::AllowedTraps,
                !(value as u64),
            )
            .expect("Unable to set the bitmap");
    }

    let mut target_ctxt = StateX86::get_context(domain, core);
    if target_ctxt.vmcs.is_invalid() {
        log::error!("Target VMCS is none.");
        return Err(CapaError::InvalidOperation);
    }
    target_ctxt
        .set(field, value, None)
        .map_err(|_| CapaError::InvalidOperation)?;
    Ok(())
}

pub fn do_get_config_core(
    vmx_state: &mut VmxState,
    current: &mut Handle<Domain>,
    domain: LocalCapa,
    core: usize,
    idx: usize,
) -> Result<usize, CapaError> {
    let mut engine = lock_engine(vmx_state, current);
    let domain = engine.get_domain_capa(*current, domain)?;

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
    if !FilteredFields::is_valid(idx, false) {
        log::error!("Attempt to get an invalid register: {:x}", idx);
        return Err(CapaError::InvalidOperation);
    }
    let field = VmcsField::from_u32(idx as u32).unwrap();
    let mut target_ctx = StateX86::get_context(domain, core);
    if target_ctx.vmcs.is_invalid() {
        log::error!("Target VMCS is invalid.");
        return Err(CapaError::InvalidOperation);
    }
    target_ctx
        .get(field, None)
        .map_err(|_| CapaError::InvalidOperation)
}

pub fn do_get_all_gp(
    vmx_state: &mut VmxState,
    current: &mut Handle<Domain>,
    domain: LocalCapa,
    core: usize,
) -> Result<(), CapaError> {
    let mut engine = lock_engine(vmx_state, current);
    let domain = engine.get_domain_capa(*current, domain)?;
    let core_map = engine.get_domain_permission(domain, permission::PermissionIndex::AllowedCores);
    if (1 << core) & core_map == 0 {
        return Err(CapaError::InvalidCore);
    }
    if core != cpuid() {
        log::error!("Attempting to read gp from different core");
        return Err(CapaError::InvalidCore);
    }
    let mut curr_ctx = StateX86::get_context(*current, cpuid());
    let tgt_ctx = StateX86::get_context(domain, core);
    if curr_ctx.vmcs.is_invalid() || tgt_ctx.vmcs.is_invalid() {
        log::error!(
            "VMCs are none during a configure core {}: curr:{:?}, tgt:{:?}",
            core,
            curr_ctx.vmcs.is_invalid(),
            tgt_ctx.vmcs.is_invalid()
        );
        return Err(CapaError::InvalidOperation);
    }
    // Copy the general purpose registers.
    curr_ctx.regs.state_gp.values[0..REGFILE_SIZE - 1]
        .copy_from_slice(&tgt_ctx.regs.state_gp.values[0..REGFILE_SIZE - 1]);
    Ok(())
}

pub fn do_set_all_gp(
    vmx_state: &mut VmxState,
    current: &mut Handle<Domain>,
    domain: LocalCapa,
) -> Result<(), CapaError> {
    let mut engine = lock_engine(vmx_state, current);
    let domain = engine.get_domain_capa(*current, domain)?;
    let core = cpuid();

    let core_map = engine.get_domain_permission(domain, permission::PermissionIndex::AllowedCores);
    if (1 << core) & core_map == 0 {
        return Err(CapaError::InvalidCore);
    }

    let curr_ctx = StateX86::get_context(*current, core);
    let mut tgt_ctx = StateX86::get_context(domain, core);
    if curr_ctx.vmcs.is_invalid() || tgt_ctx.vmcs.is_invalid() {
        log::error!(
            "VMCs are none during a configure core {}: curr:{:?}, tgt:{:?}",
            core,
            curr_ctx.vmcs.is_invalid(),
            tgt_ctx.vmcs.is_invalid()
        );
        return Err(CapaError::InvalidOperation);
    }
    // Copy the general purpose registers.
    let rax = tgt_ctx.regs.state_gp.values[GeneralPurposeField::Rax as usize];
    let rdi = tgt_ctx.regs.state_gp.values[GeneralPurposeField::Rdi as usize];
    tgt_ctx.regs.state_gp.values[0..REGFILE_SIZE - 1]
        .copy_from_slice(&curr_ctx.regs.state_gp.values[0..REGFILE_SIZE - 1]);
    tgt_ctx.regs.state_gp.values[GeneralPurposeField::Rax as usize] = rax;
    tgt_ctx.regs.state_gp.values[GeneralPurposeField::Rdi as usize] = rdi;
    Ok(())
}

pub fn do_set_fields(
    vmx_state: &mut VmxState,
    current: &mut Handle<Domain>,
    domain: LocalCapa,
    core: usize,
    values: &[(usize, usize); 6],
) -> Result<(), CapaError> {
    let mut engine = lock_engine(vmx_state, current);
    // Check the core.
    let domain = engine.get_domain_capa(*current, domain)?;
    let core_map = engine.get_domain_permission(domain, permission::PermissionIndex::AllowedCores);
    if (1 << core) & core_map == 0 {
        log::error!("Trying to set registers on the wrong core.");
        return Err(CapaError::InvalidCore);
    }
    // Get and set the context.
    let mut tgt_ctx = StateX86::get_context(domain, core);
    if tgt_ctx.vmcs.is_invalid() {
        log::error!("The VMCS is none on core {}", core);
        return Err(CapaError::InvalidOperation);
    }
    for p in values {
        let field = p.0;
        let value = p.1;
        if field == !(0 as usize) {
            // We are done.
            break;
        }
        if !FilteredFields::is_valid(field, true) {
            log::error!("Invalid set field value: {:x}", field);
            return Err(CapaError::InvalidOperation);
        }
        let field = VmcsField::from_u32(field as u32).unwrap();
        tgt_ctx.set(field, value, None).unwrap();
        if field == VmcsField::ExceptionBitmap {
            engine
                .set_domain_permission(
                    domain,
                    permission::PermissionIndex::AllowedTraps,
                    !(value as u64),
                )
                .expect("Bitmap failure");
        }
    }
    Ok(())
}

pub fn do_init_child_context(
    vmx_state: &mut VmxState,
    current: &mut Handle<Domain>,
    domain: LocalCapa,
    core: usize,
) -> Result<(), CapaError> {
    let mut engine = lock_engine(vmx_state, current);
    let domain = engine
        .get_domain_capa(*current, domain)
        .expect("Unable to access child");
    let allocator = allocator();
    let max_cpus = NB_BOOTED_CORES.load(core::sync::atomic::Ordering::SeqCst) + 1;
    let mut rcvmcs = RC_VMCS.lock();
    let cores = engine.get_domain_permission(domain, permission::PermissionIndex::AllowedCores);
    // Check whether the domain is allowed on that core.
    if core > max_cpus || (1 << core) & cores == 0 {
        log::error!("Attempt to set context on unallowed core.");
        return Err(CapaError::InvalidCore);
    }
    let dest = &mut StateX86::get_context(domain, core);
    let frame = allocator
        .allocate_frame()
        .expect("Unable to allocate frame");
    let rc = RCFrame::new(frame);
    drop_rc(&mut *rcvmcs, dest.vmcs);
    dest.vmcs = rcvmcs.allocate(rc).expect("Unable to allocate rc frame");
    //Init the frame, it needs the identifier.
    vmx_state.vmxon.init_frame(frame);
    // Init the host state:
    {
        let current_ctxt = StateX86::get_context(*current, cpuid());
        let mut values: [usize; 13] = [0; 13];
        dump_host_state(&mut vmx_state.vcpu, &mut values).or(Err(CapaError::InvalidSwitch))?;

        //TODO(aghosn): we could just set it in the context if we were able to distinguish
        //writable by tyche from writable by parent.

        // Switch to the target frame.
        vmx_state
            .vcpu
            .switch_frame(rcvmcs.get(dest.vmcs).unwrap().frame)
            .unwrap();

        // Init to the default values.
        let info: GuestInfo = Default::default();
        vmx_helper::default_vmcs_config(&mut vmx_state.vcpu, &info, false);

        // Load the default values.
        load_host_state(&mut vmx_state.vcpu, &mut values).or(Err(CapaError::InvalidSwitch))?;

        // Switch back the frame.
        vmx_state
            .vcpu
            .switch_frame(rcvmcs.get(current_ctxt.vmcs).unwrap().frame)
            .unwrap();
    }
    Ok(())
}

/// TODO(aghosn) do we need to seal on all cores?
pub fn do_seal(
    vmx_state: &mut VmxState,
    current: &mut Handle<Domain>,
    domain: LocalCapa,
) -> Result<LocalCapa, CapaError> {
    let core = cpuid();
    let mut engine = lock_engine(vmx_state, current);
    let capa = engine.seal(*current, core, domain)?;
    if let Ok(domain_capa) = engine.get_domain_capa(*current, domain) {
        calculate_attestation_hash(&mut engine, domain_capa);
    }

    apply_updates(&mut engine);
    Ok(capa)
}

pub fn do_segment_region(
    vmx_state: &mut VmxState,
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
    let mut engine = lock_engine(vmx_state, current);
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
    apply_updates(&mut engine);
    Ok((to_send, to_revoke))
}

pub fn do_send(
    vmx_state: &mut VmxState,
    current: &mut Handle<Domain>,
    capa: LocalCapa,
    to: LocalCapa,
) -> Result<(), CapaError> {
    let mut engine = lock_engine(vmx_state, current);
    // Send is not allowed for region capa.
    // Use do_send_region instead.
    match engine.get_region_capa(*current, capa)? {
        Some(_) => return Err(CapaError::InvalidCapa),
        _ => {}
    }
    engine.send(*current, capa, to)?;
    apply_updates(&mut engine);
    Ok(())
}

pub fn do_send_region(
    vmx_state: &mut VmxState,
    current: &mut Handle<Domain>,
    capa: LocalCapa,
    to: LocalCapa,
    alias: usize,
    is_repeat: bool,
    size: usize,
    extra_rights: usize,
) -> Result<(), CapaError> {
    let mut engine = lock_engine(vmx_state, current);
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
    let repeat = {
        if is_repeat {
            let region_size = region_info.end - region_info.start;
            if size == 0 || (size % region_size) != 0 {
                return Err(CapaError::InvalidValue);
            }
            size / region_size
        } else {
            // Not a repeat, spans the entire thing.
            1
        }
    };
    /*log::info!(
        "In do send region!\nregion{:#x?}, alias: {:#x}, repeat: {}",
        region_info,
        alias,
        repeat
    );*/
    // Check for an overlap first.
    {
        let target = engine.get_domain_capa(*current, to)?;
        let dom_dat = StateX86::get_domain(target);
        if dom_dat
            .remapper
            .overlaps(alias, repeat * (region_info.end - region_info.start))
        {
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

    // We cannot hold the reference while apply_updates is called.
    {
        let target = engine.get_domain_capa(*current, to)?;
        let mut dom_dat = StateX86::get_domain(target);
        let _ = dom_dat
            .remapper
            .map_range(
                region_info.start,
                alias,
                region_info.end - region_info.start,
                repeat,
            )
            .unwrap(); // Overlap is checked again but should not be triggered.
        engine.conditional_permission_update(target);
    };
    apply_updates(&mut engine);
    Ok(())
}

pub fn do_enumerate(
    vmx_state: &mut VmxState,
    current: &mut Handle<Domain>,
    token: NextCapaToken,
) -> Option<(CapaInfo, NextCapaToken)> {
    let mut engine = lock_engine(vmx_state, current);
    engine.enumerate(*current, token)
}

pub fn do_revoke(
    vmx_state: &mut VmxState,
    current: &mut Handle<Domain>,
    capa: LocalCapa,
) -> Result<(), CapaError> {
    let mut engine = lock_engine(vmx_state, current);
    engine.revoke(*current, capa)?;
    apply_updates(&mut engine);
    Ok(())
}

pub fn do_revoke_region(
    vmx_state: &mut VmxState,
    current: &mut Handle<Domain>,
    capa: LocalCapa,
    to: LocalCapa,
    alias: usize,
    size: usize,
) -> Result<(), CapaError> {
    let mut engine = lock_engine(vmx_state, current);
    //TODO(aghosn): this is not really safe. We should make more checks.
    //Maybe have a cleaner interface for that after the rebuttal.
    {
        //Unmap the gpa range.
        let dom = engine.get_domain_capa(*current, to).unwrap();
        let mut dom_dat = StateX86::get_domain(dom);
        let _ = dom_dat.remapper.unmap_gpa_range(alias, size).unwrap();
    }
    engine.revoke(*current, capa)?;
    apply_updates(&mut engine);
    Ok(())
}

pub fn do_duplicate(
    vmx_state: &mut VmxState,
    current: &mut Handle<Domain>,
    capa: LocalCapa,
) -> Result<LocalCapa, CapaError> {
    let mut engine = lock_engine(vmx_state, current);
    let new_capa = engine.duplicate(*current, capa)?;
    apply_updates(&mut engine);
    Ok(new_capa)
}

pub fn do_switch(
    vmx_state: &mut VmxState,
    current: &mut Handle<Domain>,
    capa: LocalCapa,
    cpuid: usize,
) -> Result<(), CapaError> {
    let mut engine = lock_engine(vmx_state, current);
    engine.switch(*current, cpuid, capa)?;
    apply_updates(&mut engine);
    Ok(())
}

pub fn do_debug(vmx_state: &mut VmxState, current: &mut Handle<Domain>) {
    let mut engine = lock_engine(vmx_state, current);
    let mut next = NextCapaToken::new();
    while let Some((domain, next_next)) = engine.enumerate_domains(next) {
        next = next_next;

        log::info!("Domain {}", domain.idx());
        let mut next_capa = NextCapaToken::new();
        while let Some((info, next_next_capa)) = engine.enumerate(domain, next_capa) {
            next_capa = next_next_capa;
            log::info!(" - {}", info);
        }
        log::info!(
            "tracker: {}",
            engine.get_domain_regions(domain).expect("Invalid domain")
        );
        let dom_dat = StateX86::get_domain(domain);
        log::info!("remaps {}", dom_dat.remapper.iter_segments());
        let remap = dom_dat
            .remapper
            .remap(engine.get_domain_permissions(domain).unwrap());
        log::info!("remapped: {}", remap);
    }
}

#[allow(dead_code)]
pub fn do_debug_addr(dom: Handle<Domain>, addr: usize) {
    log::info!("do_debug_addr:");
    let domain = StateX86::get_domain(dom);
    let allocator = allocator();
    let mut mapper = EptMapper::new(
        allocator.get_physical_offset().as_usize(),
        domain.ept.unwrap(),
    );
    mapper.debug_range(GuestPhysAddr::new(addr), 0x10000);
}

pub fn do_serialize_attestation(
    vmx_state: &mut VmxState,
    domain_handle: &mut Handle<Domain>,
    addr: usize,
    len: usize,
) -> Result<usize, CapaError> {
    let engine = lock_engine(vmx_state, domain_handle);
    let domain = StateX86::get_domain(*domain_handle);
    log::trace!("Serializing attestation");

    // First, check if the buffer is valid and can be accessed by the current domain
    let buff_start = addr;
    let buff_end = buff_start + len;
    let mut buff = None;
    let permission_iter = engine.get_domain_permissions(*domain_handle).unwrap();
    for range in domain.remapper.remap(permission_iter) {
        let range_start = range.gpa;
        let range_end = range_start + range.size;
        if range_start <= buff_start
            && buff_start < range_end
            && range_start < buff_end
            && buff_end <= range_end
            && range.ops.contains(MemOps::WRITE)
        {
            // We found a valid region that encapsulate the buffer!
            // On x86_64 it is possible that we use some relocations, so compute the physical
            // address of the buffer.
            let gpa_to_hpa_offset = (range.gpa as isize) - (range.hpa as isize);
            let start = (buff_start as isize) - gpa_to_hpa_offset;
            buff = unsafe { Some(core::slice::from_raw_parts_mut(start as *mut u8, len)) };
            break;
        }
    }

    let Some(buff) = buff else {
        // The buffer is not accessible by the current domain
        log::info!("Invalid buffer while serializing the attestation");
        return Err(CapaError::InsufficientPermissions);
    };

    engine.serialize_attestation(buff)
}

pub fn do_domain_attestation(
    vmx_state: &mut VmxState,
    current: &mut Handle<Domain>,
    nonce: usize,
    mode: usize,
) -> Option<EnclaveReport> {
    let mut engine = lock_engine(vmx_state, current);
    attest_domain(&mut engine, *current, nonce, mode)
}

// —————————————————————— Interrupt Handling functions —————————————————————— //

#[allow(dead_code)]
pub fn handle_trap(
    current: Handle<Domain>,
    core: usize,
    trap: VmExitInterrupt,
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    engine.handle_trap(current, core, trap.get_trap_number(), trap.as_info())?;
    apply_updates(&mut engine);
    Ok(())
}

pub fn do_handle_violation(
    vmx_state: &mut VmxState,
    current: &mut Handle<Domain>,
) -> Result<(), CapaError> {
    let mut engine = lock_engine(vmx_state, current);
    let core = cpuid();
    {
        let mut current_ctx = StateX86::get_context(*current, core);
        current_ctx.interrupted = true;
    }
    engine.handle_violation(*current, core)?;
    apply_updates(&mut engine);
    Ok(())
}

// ———————————————————————————————— Updates ————————————————————————————————— //

fn post_ept_update(core_id: usize, cores_map: u64, domain: &Handle<Domain>) {
    log::trace!("core{}: post_ept_update with cores={}", cpuid(), cores_map);

    // At this point the barrier must already be initialized
    StateX86::notify_cores(domain, core_id, cores_map as usize);
    TLB_FLUSH_BARRIERS[domain.idx()].wait();

    // If I am the initiating core, then I'm responsible for freeing the original EPT
    // root.
    log::trace!(
        "core {} woke up, about to free the original domain EPT",
        core_id
    );
    free_original_ept_root(domain);

    // We're done with the current TLB flush update
    log::trace!("core {} allows more TLB flushes", core_id);
    TLB_FLUSH[domain.idx()].store(false, Ordering::SeqCst);
}

fn push_core_update(core: usize) {
    log::trace!("cpu {} pushes Tlbshootdown to core={}", cpuid(), core);
    let mut core_updates = CORE_UPDATES[core as usize].lock();
    core_updates.push(CoreUpdate::TlbShootdown).unwrap();
}

/// General updates, containing both global updates on the domain's states, and core specific
/// updates that must be routed to the different cores.
fn apply_updates(engine: &mut MutexGuard<CapaEngine>) {
    while let Some(update) = engine.pop_update() {
        log::trace!("Update: {}", update);
        match update {
            // Updates that can be handled locally
            capa_engine::Update::PermissionUpdate { domain, core_map } => {
                let core_id = cpuid();
                log::trace!(
                    "cpu {} processes PermissionUpdate with core_map={:b}",
                    core_id,
                    core_map
                );
                let ept_update = StateX86::update_permission(domain, engine);
                if ept_update {
                    log::trace!(
                        "cpu {} pushes core update with core_map={:b}",
                        cpuid(),
                        core_map
                    );
                    let mut core_count = core_map.count_ones() as usize;

                    // This relies on the fact that the cache marks dirty values.
                    // We call the tlb_shootdown which will be effective upon reentry in the
                    // domain.
                    if (1 << core_id) & core_map != 0 {
                        tlb_shootdown(core_id, &domain, None);
                    } else {
                        // We will still wait on the barrier before freeing the EPT, so count
                        // ourselves
                        core_count += 1;
                    }

                    // Setup barrier and enque updates on other cores
                    //TLB_FLUSH_BARRIERS[domain.idx()].set_count(core_count);
                    StateX86::prepare_notify(&domain, core_count);
                    for core in BitmapIterator::new(core_map) {
                        if core == core_id {
                            continue;
                        }
                        push_core_update(core);
                    }

                    // After we have pushed all TlbShootdown updates to its per cpu CORE_UPDATES, we
                    // can issue the IPI now.
                    //post_ept_update(core_id, core_map, &domain);
                    StateX86::notify_cores(&domain, core_id, core_map as usize);
                    StateX86::acknowledge_notify(&domain);
                    StateX86::finish_notify(&domain);
                }
            }
            capa_engine::Update::Cleanup { start, end } => {
                let size = end.checked_sub(start).unwrap();
                log::trace!("Cleaning up region [0x{:x}, 0x{:x}]", start, end);

                // WARNING: for now we do not check that the region points to valid memory!
                // In particular, the current root region contains more than valid ram, and also
                // include devices.
                unsafe {
                    let region = core::slice::from_raw_parts_mut(start as *mut u8, size);
                    region.fill(0);
                }
            }
            capa_engine::Update::RevokeDomain { domain } => revoke_domain(domain),
            capa_engine::Update::CreateDomain { domain } => create_domain(domain),

            // Updates that needs to be routed to some specific cores
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

fn tlb_shootdown(core_id: usize, current_domain: &Handle<Domain>, vcpu: Option<&mut ActiveVmcs>) {
    log::trace!("cpu{} processing TLB shootdown", core_id);
    // Reload the EPTs
    let domain = StateX86::get_domain(*current_domain);
    log::trace!(
        "core {}: domain.ept={:#x}",
        core_id,
        domain.ept.unwrap().as_usize()
    );
    let new_epts = domain.ept.unwrap().as_usize();
    // Update the context.
    let mut context = StateX86::get_context(*current_domain, core_id);
    context
        .set(VmcsField::EptPointer, new_epts | EPT_ROOT_FLAGS, vcpu)
        .expect("VMX error, failed to set EPT pointer");
}

fn free_original_ept_root(current_domain: &Handle<Domain>) {
    let mut domain = StateX86::get_domain(*current_domain);
    let allocator = allocator();
    if let Some(ept) = domain.ept_old {
        unsafe { StateX86::free_ept(ept, allocator) };
    }
    domain.ept_old = None;
}

/// Updates that must be applied to a given core.
/*pub fn apply_core_updates(
    vmx_state: &mut VmxState,
    current_domain: &mut Handle<Domain>,
    core_id: usize,
) {
    let core = cpuid();
    let vcpu = &mut vmx_state.vcpu;
    let mut update_queue = CORE_UPDATES[core_id].lock();
    while let Some(update) = update_queue.pop() {
        log::trace!("Core Update: {} on core {}", update, core);
        match update {
            CoreUpdate::TlbShootdown => {
                // Into a separate function so that we can drop the domain lock before starting to
                // wait on the TLB_FLUSH_BARRIER
                tlb_shootdown(core_id, current_domain, Some(vcpu));
                log::trace!("core {} waits on tlb flush barrier", core_id);
                TLB_FLUSH_BARRIERS[current_domain.idx()].wait();
                log::trace!("core {} done waiting", core_id);
            }
            CoreUpdate::Switch {
                domain,
                return_capa,
            } => {
                log::trace!("Domain Switch on core {}", core_id);

                let mut current_ctx = StateX86::get_context(*current_domain, core);
                let mut next_ctx = StateX86::get_context(domain, core);
                let next_domain = StateX86::get_domain(domain);
                StateX86::switch_domain(
                    vcpu,
                    &mut current_ctx,
                    &mut next_ctx,
                    next_domain,
                    return_capa,
                )
                .expect("Failed to perform the switch");
                // Update the current domain and context handle
                *current_domain = domain;
            }
            CoreUpdate::Trap {
                manager: _manager,
                trap,
                info: _info,
            } => {
                log::trace!("Trap {} on core {}", trap, core_id);
                log::debug!(
                    "Exception Bitmap is {:b}",
                    vcpu.get_exception_bitmap().expect("Failed to read bitmpap")
                );
                todo!("Update this code path.");

                /*let current_ctx = get_context(*current_domain, core);
                let next_ctx = get_context(manager, core);
                let next_domain = get_domain(manager);
                switch_domain(vcpu, current_ctx, next_ctx, next_domain)
                    .expect("Failed to perform switch for trap");

                log::debug!(
                    "Exception {} (bit shift {}) triggers switch from {:?} to {:?}",
                    trap,
                    Trapnr::from_u64(trap),
                    current_domain,
                    manager
                );

                // Inject exception now.
                let interrupt = VmExitInterrupt::from_info(info);
                log::debug!("The info to inject: {:b}", interrupt.as_u32(),);

                // We rewrite the value because it is cleared on every VM exit.
                vcpu.inject_interrupt(interrupt)
                    .expect("Unable to inject an exception");

                // Set parameters
                // TODO this could be a way to signal an error.
                //vcpu.set(Register::Rax, trap);

                // Update the current domain
                *current_domain = manager;*/
            }
        }
    }
}*/

fn create_domain(domain: Handle<Domain>) {
    let mut domain = StateX86::get_domain(domain);
    let allocator = allocator();
    if let Some(ept) = domain.ept {
        unsafe { StateX86::free_ept(ept, allocator) };
    }
    let ept_root = allocator
        .allocate_frame()
        .expect("Failled to allocate EPT root")
        .zeroed();
    domain.ept = Some(ept_root.phys_addr);
}

fn revoke_domain(_domain: Handle<Domain>) {
    // Noop for now, might need to send IPIs once we land multi-core
}

/*fn notify_cores(core_id: usize, domain_core_bitmap: u64) {
    // initialize lapic
    log::trace!(
        "The bitmap {:b} for notify cores on core {}",
        domain_core_bitmap,
        core_id
    );

    for core in BitmapIterator::new(domain_core_bitmap) {
        if core == core_id {
            continue;
        }
        // send ipi
        x2apic::send_init_assert(core as u32);
    }
}*/
