//! Architecture specific monitor state, independant of the CapaEngine.

use core::sync::atomic::{AtomicBool, Ordering};

use attestation::signature::EnclaveReport;
use capa_engine::config::{NB_CORES, NB_DOMAINS};
use capa_engine::utils::BitmapIterator;
use capa_engine::{
    permission, AccessRights, Alias, Bitmaps, Buffer, CapaEngine, CapaError, CapaInfo, Domain,
    GenArena, Handle, LocalCapa, MemOps, NextCapaToken, MEMOPS_ALL,
};
use mmu::eptmapper::EPT_ROOT_FLAGS;
use mmu::{EptMapper, FrameAllocator, IoPtFlag, IoPtMapper};
use spin::barrier::Barrier;
use spin::{Mutex, MutexGuard};
use stage_two_abi::Manifest;
use utils::{GuestPhysAddr, HostPhysAddr, HostVirtAddr};
use vmx::bitmaps::{EptEntryFlags, ExceptionBitmap};
use vmx::ept::PAGE_SIZE;
use vmx::errors::Trapnr;
use vmx::fields::{GeneralPurposeField, VmcsField, VmcsField, REGFILE_SIZE, REGFILE_SIZE};
use vmx::msr::{IA32_LSTAR, IA32_STAR};
use vmx::{
    ActiveVmcs, ActiveVmcs, ControlRegister, Register, Register, VmExitInterrupt, VmExitInterrupt,
    VmExitInterrupt, VmExitInterrupt, VmExitInterrupt, Vmxon, Vmxon, REGFILE_CONTEXT_SIZE,
    REGFILE_SIZE,
};
use vtd::Iommu;

use super::context::ContextData;
use super::cpuid;
use super::guest::VmxState;
use super::init::NB_BOOTED_CORES;
use super::vmx_helper::{dump_host_state, load_host_state};
use crate::allocator::{allocator, PAGE_SIZE};
use crate::attestation_domain::{attest_domain, calculate_attestation_hash};
use crate::rcframe::{drop_rc, RCFrame, RCFramePool, EMPTY_RCFRAME};
use crate::x86_64::apic;
use crate::x86_64::exposed_vmx_fields::{GuestRegisterGroups, GuestRegisters};
use crate::x86_64::filtered_fields::FilteredFields;

// ————————————————————————— Statics & Backend Data ————————————————————————— //

static CAPA_ENGINE: Mutex<CapaEngine> = Mutex::new(CapaEngine::new());
static IO_DOMAIN: Mutex<Option<LocalCapa>> = Mutex::new(None);
static INITIAL_DOMAIN: Mutex<Option<Handle<Domain>>> = Mutex::new(None);
static DOMAINS: [Mutex<DomainData>; NB_DOMAINS] = [EMPTY_DOMAIN; NB_DOMAINS];
static CORE_UPDATES: [Mutex<Buffer<CoreUpdate>>; NB_CORES] = [EMPTY_UPDATE_BUFFER; NB_CORES];
static CONTEXTS: [[Mutex<ContextData>; NB_CORES]; NB_DOMAINS] = [EMPTY_CONTEXT_ARRAY; NB_DOMAINS];
static RC_VMCS: Mutex<RCFramePool> =
    Mutex::new(GenArena::new([EMPTY_RCFRAME; { NB_DOMAINS * NB_CORES }]));
const BARRIER: Option<Barrier> = None;
const FALSE: AtomicBool = AtomicBool::new(false);
static mut TLB_FLUSH_BARRIERS: [Option<Barrier>; NB_DOMAINS] = [BARRIER; NB_DOMAINS];
static TLB_FLUSH: [AtomicBool; NB_DOMAINS] = [FALSE; NB_DOMAINS];

pub struct DomainData {
    ept: Option<HostPhysAddr>,
    ept_old: Option<HostPhysAddr>,
    iopt: Option<HostPhysAddr>,
}

pub struct ContextData {
    pub cr3: usize,
    pub rip: usize,
    pub rsp: usize,
    // General-purpose registers.
    pub regs: [u64; REGFILE_SIZE],
    // The MSR(s?) we need to save and restore.
    pub star: u64,
    pub lstar: u64,
    /// Vcpu for this core.
    pub vmcs: Handle<RCFrame>,
}

impl ContextData {
    pub fn save_partial(&mut self, vcpu: &ActiveVmcs<'static>) {
        self.cr3 = vcpu.get_cr(ControlRegister::Cr3);
        self.rip = vcpu.get(Register::Rip) as usize;
        self.rsp = vcpu.get(Register::Rsp) as usize;
    }

    pub fn save(&mut self, vcpu: &mut ActiveVmcs<'static>) {
        self.save_partial(vcpu);
        vcpu.dump_regs(&mut self.regs);
        self.lstar = unsafe { IA32_LSTAR.read() };
        self.star = unsafe { IA32_STAR.read() };
        vcpu.flush();
    }

    pub fn restore_partial(&self, vcpu: &mut ActiveVmcs<'static>) {
        log::trace!(
            "Switching info cr3 : {:#x}, rip : {:#x}, rsp : {:#x}",
            self.cr3,
            self.rip as u64,
            self.rsp as u64
        );
        vcpu.set_cr(ControlRegister::Cr3, self.cr3);
        vcpu.set(Register::Rip, self.rip as u64);
        vcpu.set(Register::Rsp, self.rsp as u64);
    }

    pub fn restore(&self, vcpu: &mut ActiveVmcs<'static>) {
        let locked = RC_VMCS.lock();
        let rc_frame = locked.get(self.vmcs).unwrap();
        vcpu.load_regs(&self.regs);
        unsafe { vmx::msr::Msr::new(IA32_LSTAR.address()).write(self.lstar) };
        unsafe { vmx::msr::Msr::new(IA32_STAR.address()).write(self.star) };
        vcpu.switch_frame(rc_frame.frame).unwrap();
        // Restore partial must be called AFTER we set a valid frame.
        self.restore_partial(vcpu);
    }
}

#[derive(PartialEq)]
#[repr(u64)]
pub enum InitVMCS {
    Shared = 1,
    Copy = 2,
    Fresh = 3,
}

impl InitVMCS {
    pub fn from_u64(v: u64) -> Result<Self, CapaError> {
        match v {
            1 => Ok(Self::Shared),
            2 => Ok(Self::Copy),
            3 => Ok(Self::Fresh),
            _ => Err(CapaError::InvalidOperation),
        }
    }
}

const EMPTY_DOMAIN: Mutex<DomainData> = Mutex::new(DomainData {
    ept: None,
    ept_old: None,
    iopt: None,
});
const EMPTY_UPDATE_BUFFER: Mutex<Buffer<CoreUpdate>> = Mutex::new(Buffer::new());
const EMPTY_CONTEXT: Mutex<ContextData> = Mutex::new(ContextData {
    cr3: usize::max_value(),
    rip: usize::max_value(),
    rsp: usize::max_value(),
    regs: [0; REGFILE_SIZE],
    lstar: u64::max_value(),
    star: u64::max_value(),
    vmcs: Handle::<RCFrame>::new_invalid(),
    regs: [usize::max_value(); REGFILE_SIZE],
    cr3: usize::max_value(),
    rip: usize::max_value(),
    rsp: usize::max_value(),
    interrupted: false,
});
const EMPTY_CONTEXT_ARRAY: [Mutex<ContextData>; NB_CORES] = [EMPTY_CONTEXT; NB_CORES];
static IOMMU: Mutex<Iommu> =
    Mutex::new(unsafe { Iommu::new(HostVirtAddr::new(usize::max_value())) });

// ————————————————————————————— Initialization ————————————————————————————— //

pub fn init(manifest: &'static Manifest) {
    let mut engine = CAPA_ENGINE.lock();
    let domain = engine.create_manager_domain(permission::ALL).unwrap();
    apply_updates(&mut engine);
    engine
        .create_root_region(
            domain,
            AccessRights {
                start: 0,
                end: manifest.iommu as usize,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();
    engine
        .create_root_region(
            domain,
            AccessRights {
                start: (manifest.iommu + PAGE_SIZE) as usize,
                end: manifest.poffset as usize,
                ops: MEMOPS_ALL,
                alias: Alias::NoAlias,
            },
        )
        .unwrap();
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
}

pub fn init_vcpu(vcpu: &mut ActiveVmcs<'static>) -> Handle<Domain> {
    let cpuid = cpuid();
    let mut engine = CAPA_ENGINE.lock();
    let initial_domain = INITIAL_DOMAIN
        .lock()
        .expect("CapaEngine is not initialized yet");
    engine
        .start_domain_on_core(initial_domain, cpuid)
        .expect("Failed to allocate initial domain");
    let domain = get_domain(initial_domain);
    let mut ctxt = get_context(initial_domain, cpuid);
    let rcframe = RC_VMCS
        .lock()
        .allocate(RCFrame::new(*vcpu.frame()))
        .expect("Unable to allocate rcframe");
    ctxt.vmcs = rcframe;
    log::info!(
        "The EPT pointer: {:x?}",
        HostPhysAddr::new(domain.ept.unwrap().as_usize() | EPT_ROOT_FLAGS)
    );
    vcpu.set_ept_ptr(HostPhysAddr::new(
        domain.ept.unwrap().as_usize() | EPT_ROOT_FLAGS,
    ))
    .expect("Failed to set initial EPT PTR");
    initial_domain
}

// ———————————————————————————————— Helpers ————————————————————————————————— //

fn get_domain(domain: Handle<Domain>) -> MutexGuard<'static, DomainData> {
    DOMAINS[domain.idx()].lock()
}

fn get_context(domain: Handle<Domain>, core: usize) -> MutexGuard<'static, ContextData> {
    CONTEXTS[domain.idx()][core].lock()
}

// ————————————————————————————— Monitor Calls —————————————————————————————— //

pub fn do_create_domain(current: Handle<Domain>, aliased: bool) -> Result<LocalCapa, CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let management_capa = engine.create_domain(current, aliased)?;
    apply_updates(&mut engine);
    Ok(management_capa)
}

pub fn do_set_config(
    current: Handle<Domain>,
    domain: LocalCapa,
    bitmap: Bitmaps,
    value: u64,
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    engine.set_child_config(current, domain, bitmap, value)?;
    apply_updates(&mut engine);
    Ok(())
}

pub fn do_configure_core(
    current: Handle<Domain>,
    domain: LocalCapa,
    core: usize,
    idx: usize,
    value: usize,
    vcpu: &mut ActiveVmcs<'static>,
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
    let core_map = engine.get_domain_config(domain, Bitmaps::CORE);
    if (1 << core) & core_map == 0 {
        log::error!(
            "Invalid core {} for coremap {:b} in configure core",
            1 << core,
            core_map
        );
        return Err(CapaError::InvalidCore);
    }

    // Check this is a valid idx for a field.
    if !FilteredFields::is_valid(idx) {
        log::error!("Attempt to set an invalid register: {:x}", idx);
        return Err(CapaError::InvalidOperation);
    }
    let field = VmcsField::from_u32(idx as u32).unwrap();
    if field == VmcsField::ExceptionBitmap {
        engine
            .set_child_config(current, local_capa, Bitmaps::TRAP, !(value as u64))
            .expect("Unable to set the bitmap");
    }

    // Check the domain has the correct vcpu type
    let switch_type = engine.get_domain_config(domain, Bitmaps::SWITCH);
    let switch_type = InitVMCS::from_u64(switch_type)?;

    if switch_type == InitVMCS::Shared && !field.is_gp_register() && !field.is_context_register() {
        log::error!("Trying to set non-GP/non-Context register on a shared vcpu.");
        return Err(CapaError::InvalidOperation);
    }

    // Now we have a complex dance to set a value on the target context.
    // TODO: I do it in a block to lazily return the error. Poor style, let's make it clean when it
    // works.
    {
        let mut current_ctx = get_context(current, cpuid());
        let mut target_ctx = get_context(domain, core);
        if current_ctx.vmcs.is_invalid() || target_ctx.vmcs.is_invalid() {
            log::error!(
                "VMCs are none during a configure core {}: curr:{:?}, tgt:{:?}",
                core,
                current_ctx.vmcs.is_invalid(),
                target_ctx.vmcs.is_invalid()
            );
            return Err(CapaError::InvalidOperation);
        }

        // 1. save the current context.
        current_ctx.save(vcpu);

        // 2. switch to the target one.
        target_ctx.restore(&RC_VMCS, vcpu);

        // 3. set the value.
        let err = FilteredFields::set_register(vcpu, field, value);

        // 4. save the target context.
        target_ctx.save(vcpu);

        // 5. switch back to the original one.
        current_ctx.restore(&RC_VMCS, vcpu);
        err
    }?;

    Ok(())
}

pub fn do_get_config_core(
    current: Handle<Domain>,
    domain: LocalCapa,
    core: usize,
    idx: usize,
    vcpu: &mut ActiveVmcs<'static>,
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
    let core_map = engine.get_domain_config(domain, Bitmaps::CORE);
    if (1 << core) & core_map == 0 {
        return Err(CapaError::InvalidCore);
    }

    // Check this is a valid idx for a field.
    if !FilteredFields::is_valid(idx) {
        log::error!("Attempt to get an invalid register: {:x}", idx);
        return Err(CapaError::InvalidOperation);
    }
    let field = VmcsField::from_u32(idx as u32).unwrap();

    // Check the domain has the correct vcpu type
    let switch_type = engine.get_domain_config(domain, Bitmaps::SWITCH);
    let switch_type = InitVMCS::from_u64(switch_type)?;

    if switch_type == InitVMCS::Shared && !field.is_gp_register() {
        log::error!("Trying to set non GP register on a shared vcpu.");
        return Err(CapaError::InvalidOperation);
    }

    // Now we have a complex dance to get a value on the target context.
    // TODO: I do it in a block to lazily return the error. Poor style, let's make it clean when it
    // works.
    let res = {
        let mut current_ctx = get_context(current, cpuid());
        let mut target_ctx = get_context(domain, core);
        if current_ctx.vmcs.is_invalid() || target_ctx.vmcs.is_invalid() {
            log::error!(
                "VMCs are none during a configure core {}: curr:{:?}, tgt:{:?}",
                core,
                current_ctx.vmcs.is_invalid(),
                target_ctx.vmcs.is_invalid()
            );
            return Err(CapaError::InvalidOperation);
        }

        // 1. save the current context.
        current_ctx.save(vcpu);

        // 2. switch to the target one.
        target_ctx.restore(&RC_VMCS, vcpu);

        // 3. set the value.
        let err = FilteredFields::get_register(vcpu, field);

        // 4. save the target context.
        target_ctx.save(vcpu);

        // 5. switch back to the original one.
        current_ctx.restore(&RC_VMCS, vcpu);
        err
    }?;

    Ok(res)
}

pub fn do_set_all_gp(
    current: Handle<Domain>,
    domain: LocalCapa,
    vcpu: &mut ActiveVmcs<'static>,
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let domain = engine.get_domain_capa(current, domain)?;
    let core = cpuid();

    let core_map = engine.get_domain_config(domain, Bitmaps::CORE);
    if (1 << core) & core_map == 0 {
        return Err(CapaError::InvalidCore);
    }

    // Check the domain has the correct vcpu type
    let switch_type = engine.get_domain_config(domain, Bitmaps::SWITCH);
    let switch_type = InitVMCS::from_u64(switch_type)?;
    if switch_type == InitVMCS::Shared {
        log::error!("Trying to get all registers from a shared vcpu.");
        return Err(CapaError::InvalidOperation);
    }
    let mut curr_ctx = get_context(current, core);
    let mut tgt_ctx = get_context(domain, core);
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
    vcpu.dump_regs(&mut curr_ctx.regs);
    let rax = tgt_ctx.regs[GeneralPurposeField::Rax as usize];
    let rdi = tgt_ctx.regs[GeneralPurposeField::Rdi as usize];
    tgt_ctx.regs[0..REGFILE_SIZE - 1].copy_from_slice(&curr_ctx.regs[0..REGFILE_SIZE - 1]);
    tgt_ctx.regs[GeneralPurposeField::Rax as usize] = rax;
    tgt_ctx.regs[GeneralPurposeField::Rdi as usize] = rdi;
    Ok(())
}

pub fn do_get_all_gp(
    current: Handle<Domain>,
    domain: LocalCapa,
    vcpu: &mut ActiveVmcs<'static>,
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let domain = engine.get_domain_capa(current, domain)?;
    let core = cpuid();

    let core_map = engine.get_domain_config(domain, Bitmaps::CORE);
    if (1 << core) & core_map == 0 {
        return Err(CapaError::InvalidCore);
    }

    // Check the domain has the correct vcpu type
    let switch_type = engine.get_domain_config(domain, Bitmaps::SWITCH);
    let switch_type = InitVMCS::from_u64(switch_type)?;
    if switch_type == InitVMCS::Shared {
        log::error!("Trying to get all registers from a shared vcpu.");
        return Err(CapaError::InvalidOperation);
    }
    let mut curr_ctx = get_context(current, core);
    let tgt_ctx = get_context(domain, core);
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
    curr_ctx.regs[0..REGFILE_SIZE - 1].copy_from_slice(&tgt_ctx.regs[0..REGFILE_SIZE - 1]);
    vcpu.load_gp_regs(&curr_ctx.regs[0..REGFILE_SIZE - 1]);

    Ok(())
}

pub fn do_init_child_context(
    current: Handle<Domain>,
    domain: LocalCapa,
    core: usize,
    vcpu: &mut ActiveVmcs<'static>,
    vmxon: &Vmxon,
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let domain = engine
        .get_domain_capa(current, domain)
        .expect("Unable to access child");
    let value = engine.get_domain_config(domain, Bitmaps::SWITCH);
    let value = InitVMCS::from_u64(value)?;
    let allocator = allocator();
    let max_cpus = NB_BOOTED_CORES.load(core::sync::atomic::Ordering::SeqCst) + 1;
    let mut rcvmcs = RC_VMCS.lock();
    let cores = engine.get_domain_config(domain, Bitmaps::CORE);
    // Check whether the domain is allowed on that core.
    if core > max_cpus || (1 << core) & cores == 0 {
        log::error!("Attempt to set context on unallowed core.");
        return Err(CapaError::InvalidCore);
    }
    match value {
        InitVMCS::Shared => {
            // Easy case, increase ref on all cores shared by the two domains.
            let orig = get_context(current, core);
            let dest = &mut get_context(domain, core);
            rcvmcs
                .get_mut(orig.vmcs)
                .expect("No vmcs on original")
                .acquire();
            if !dest.vmcs.is_invalid() {
                drop_rc(&mut rcvmcs, dest.vmcs);
            }
            dest.vmcs = orig.vmcs;
        }
        InitVMCS::Copy => {
            // Flush the current vcpu.
            let dest = &mut get_context(domain, core);
            let frame = allocator
                .allocate_frame()
                .expect("Unable to allocate frame");
            let rc = RCFrame::new(frame);
            dest.vmcs = rcvmcs.allocate(rc).expect("Unable to allocate rc frame");
            vcpu.copy_into(frame);
        }
        InitVMCS::Fresh => {
            let dest = &mut get_context(domain, core);
            let frame = allocator
                .allocate_frame()
                .expect("Unable to allocate frame");
            let rc = RCFrame::new(frame);
            dest.vmcs = rcvmcs.allocate(rc).expect("Unable to allocate rc frame");
            //Init the frame, it needs the identifier.
            vmxon.init_frame(frame);
            // Init the host state:
            {
                let mut current_ctxt = get_context(current, cpuid());
                let mut values: [usize; 13] = [0; 13];
                dump_host_state(vcpu, &mut values).or(Err(CapaError::InvalidSwitch))?;

                // 1. Save.
                current_ctxt.save(vcpu);

                // 2. Switch.
                dest.restore_locked(&rcvmcs.get(dest.vmcs).expect("Access error"), vcpu);

                // 3. Set the host state.
                load_host_state(vcpu, &mut values).or(Err(CapaError::InvalidSwitch))?;

                // 4. Save again.
                dest.save(vcpu);

                // 5. Restore the previous.
                current_ctxt
                    .restore_locked(&rcvmcs.get(current_ctxt.vmcs).expect("Access error"), vcpu);
            }
        }
    }
    Ok(())
}

/// TODO(aghosn) do we need to seal on all cores?
pub fn do_seal(current: Handle<Domain>, domain: LocalCapa) -> Result<LocalCapa, CapaError> {
    let core = cpuid();
    let mut engine = CAPA_ENGINE.lock();

    let capa = engine.seal(current, core, domain)?;

    if let Ok(domain_capa) = engine.get_domain_capa(current, domain) {
        calculate_attestation_hash(&mut engine, domain_capa);
    }

    apply_updates(&mut engine);
    Ok(capa)
}

pub fn do_segment_region(
    current: Handle<Domain>,
    capa: LocalCapa,
    start_1: usize,
    end_1: usize,
    prot_1: usize,
    start_2: usize,
    end_2: usize,
    prot_2: usize,
) -> Result<(LocalCapa, LocalCapa), CapaError> {
    //TODO introduce alias here.
    let prot_1 = MemOps::from_usize(prot_1)?;
    let prot_2 = MemOps::from_usize(prot_2)?;
    let mut engine = CAPA_ENGINE.lock();
    let access_left = AccessRights {
        start: start_1,
        end: end_1,
        ops: prot_1,
        alias: Alias::NoAlias,
    };
    let access_right = AccessRights {
        start: start_2,
        end: end_2,
        ops: prot_2,
        alias: Alias::NoAlias,
    };
    let (left, right) = engine.segment_region(current, capa, access_left, access_right)?;
    apply_updates(&mut engine);
    Ok((left, right))
}

pub fn do_send(current: Handle<Domain>, capa: LocalCapa, to: LocalCapa) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    engine.send(current, capa, to)?;
    apply_updates(&mut engine);
    Ok(())
}

pub fn do_send_aliased(
    current: Handle<Domain>,
    capa: LocalCapa,
    to: LocalCapa,
    alias: usize,
    is_repeat: bool,
    size: usize,
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let size = if is_repeat { Some(size) } else { None };
    engine.send_aliased(current, capa, to, alias, size)?;
    apply_updates(&mut engine);
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

pub fn do_switch(current: Handle<Domain>, capa: LocalCapa, cpuid: usize) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    engine.switch(current, cpuid, capa)?;
    apply_updates(&mut engine);
    Ok(())
}

pub fn do_debug() {
    let mut engine = CAPA_ENGINE.lock();
    let mut next = NextCapaToken::new();
    while let Some((domain, next_next)) = engine.enumerate_domains(next) {
        next = next_next;

        log::trace!("Domain");
        let mut next_capa = NextCapaToken::new();
        while let Some((info, next_next_capa)) = engine.enumerate(domain, next_capa) {
            next_capa = next_next_capa;
            log::trace!(" - {}", info);
        }
        log::info!("{}", engine[domain].hpa_regions());
        log::info!("{}", engine[domain].gpa_regions());
    }
}

#[allow(dead_code)]
pub fn do_print_domain(dom: Handle<Domain>) {
    let engine = CAPA_ENGINE.lock();
    let domain = &engine[dom];
    log::info!("{:?}", domain);
    log::info!("hpas: {}", domain.hpa_regions());
    log::info!("gpas: {}", domain.gpa_regions());
    {
        let domain = get_domain(dom);
        let allocator = allocator();
        let mut mapper = EptMapper::new(
            allocator.get_physical_offset().as_usize(),
            domain.ept.unwrap(),
        );
        mapper.debug_range(GuestPhysAddr::new(0), usize::max_value());
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

pub fn do_handle_violation(current: Handle<Domain>) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let core = cpuid();
    {
        let mut current_ctx = get_context(current, core);
        current_ctx.interrupted = true;
    }
    engine.handle_violation(current, core)?;
    apply_updates(&mut engine);
    Ok(())
}

// ———————————————————————————————— Updates ————————————————————————————————— //

/// Per-core updates
#[derive(Debug, Clone, Copy)]
enum CoreUpdate {
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
    UpdateTrap {
        bitmap: u64,
    },
}

fn post_ept_update(core_id: usize, cores: u64, domain: &Handle<Domain>) {
    let core_cnt = cores.count_ones();
    log::trace!(
        "core{}: post_ept_update with core_cnt={}",
        cpuid(),
        core_cnt
    );

    // Only the initiating core have access to this routine after gaining the atomic boolean
    // variable. All of the operations here are serialized until the point we release the atomic
    // boolean
    unsafe {
        TLB_FLUSH_BARRIERS[domain.idx()] = Some(spin::barrier::Barrier::new(core_cnt as usize));
    }
    notify_cores(core_id, cores);

    unsafe {
        TLB_FLUSH_BARRIERS[domain.idx()].as_mut().unwrap().wait();
    }

    // If I am the initiating core, then I'm responsible for freeing the original EPT
    // root.
    log::trace!("core {} freeing the original domain EPT", core_id);
    free_original_ept_root(domain);
    // We're done with the current TLB flush update
    log::trace!("core {} allows more TLB flushes", core_id);
    TLB_FLUSH[domain.idx()].store(false, Ordering::SeqCst);
}

fn push_core_update(core: usize) {
    log::trace!("cpu {} pushes Tlbshootdown to core={}", cpuid(), core);
    let mut core_updates = CORE_UPDATES[core as usize].lock();
    core_updates.push(CoreUpdate::TlbShootdown);
}

/// General updates, containing both global updates on the domain's states, and core specific
/// updates that must be routed to the different cores.
fn apply_updates(engine: &mut MutexGuard<CapaEngine>) {
    while let Some(update) = engine.pop_update() {
        log::trace!("Update: {}", update);
        match update {
            // Updates that can be handled locally
            capa_engine::Update::PermissionUpdate {
                domain,
                init,
                core_map,
            } => {
                let core_id = cpuid();
                log::trace!(
                    "cpu {} processes PermissionUpdate with core_map={:b}",
                    core_id,
                    core_map
                );
                let ept_update = update_permission(domain, engine, init);

                if !init && ept_update {
                    log::trace!(
                        "cpu {} pushes core update with core_map={:b}",
                        cpuid(),
                        core_map
                    );
                    // Push TlbShootdown directly into the per-core queue
                    for core in BitmapIterator::new(core_map) {
                        if core_id != core {
                            push_core_update(core);
                        }
                    }

                    // After we have pushed all TlbShootdown updates to its per cpu CORE_UPDATES, we
                    // can issue the IPI now.
                    post_ept_update(core_id, core_map, &domain);
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
            }
            capa_engine::Update::UpdateTraps { trap, core } => {
                let mut core_updates = CORE_UPDATES[core as usize].lock();
                core_updates.push(CoreUpdate::UpdateTrap { bitmap: !trap });
            }
        }
    }
}

fn tlb_shootdown(core_id: usize, current_domain: &mut Handle<Domain>, vcpu: &mut ActiveVmcs) {
    log::info!("EPT Root update on core {}", core_id);
    // Reload the EPTs
    let domain = get_domain(*current_domain);
    log::info!(
        "core {}: domain.ept={:#x}",
        core_id,
        domain.ept.unwrap().as_usize()
    );
    vcpu.set_ept_ptr(HostPhysAddr::new(
        domain.ept.unwrap().as_usize() | EPT_ROOT_FLAGS,
    ))
    .expect("VMX error, failed to set EPT pointer");
}

fn free_original_ept_root(current_domain: &Handle<Domain>) {
    let mut domain = get_domain(*current_domain);
    let allocator = allocator();
    if let Some(ept) = domain.ept_old {
        unsafe { free_ept(ept, allocator) };
    }
    domain.ept_old = None;
}

/// Updates that must be applied to a given core.
pub fn apply_core_updates(
    vmx_state: &mut VmxState,
    current_domain: &mut Handle<Domain>,
    core_id: usize,
) {
    let core = cpuid();
    let vcpu = &mut vmx_state.vcpu;
    let mut update_queue = CORE_UPDATES[core_id].lock();
    while let Some(update) = update_queue.pop() {
        log::trace!("Core Update: {}", update);
        match update {
            CoreUpdate::TlbShootdown => {
                // Into a separate function so that we can drop the domain lock before starting to
                // wait on the TLB_FLUSH_BARRIER
                tlb_shootdown(core_id, current_domain, vcpu);
                log::trace!("core {} waits on tlb flush barrier", core_id);
                unsafe {
                    TLB_FLUSH_BARRIERS[current_domain.idx()]
                        .as_mut()
                        .unwrap()
                        .wait();
                }
                log::trace!("core {} finished waiting", core_id);
            }
            CoreUpdate::Switch {
                domain,
                return_capa,
            } => {
                log::trace!("Domain Switch on core {}", core_id);

                let mut current_ctx = get_context(*current_domain, core);
                let mut next_ctx = get_context(domain, core);
                let interrupted = {
                    let v = next_ctx.interrupted;
                    next_ctx.interrupted = false;
                    v
                };
                let next_domain = get_domain(domain);
                switch_domain(vcpu, &mut current_ctx, &next_ctx, next_domain)
                    .expect("Failed to perform the switch");

                // Set switch return values if the target was not interrupted.
                if !interrupted {
                    vcpu.set(VmcsField::GuestRax, 0).unwrap();
                    vcpu.set(VmcsField::GuestRdi, return_capa.as_usize())
                        .unwrap();
                }
                // We are returning from an interruption
                if current_ctx.interrupted {
                    // Propagate the register values.
                    // TODO(aghosn) we need a clean principled way to do this.
                    // The -1 is to ignore LSTAR -> clean that seriously.
                    //vcpu.load_gp_regs(&current_ctx.regs[0..REGFILE_SIZE - 1]);
                }
                // Update the current domain and context handle
                *current_domain = domain;
            }
            CoreUpdate::Trap {
                manager,
                trap,
                info,
            } => {
                log::trace!("Trap {} on core {}", trap, core_id);
                log::debug!(
                    "Exception Bitmap is {:b}",
                    vcpu.get_exception_bitmap().expect("Failed to read bitmpap")
                );

                let mut current_ctx = get_context(*current_domain, core);
                let next_ctx = get_context(manager, core);
                let next_domain = get_domain(manager);
                switch_domain(vcpu, &mut current_ctx, &next_ctx, next_domain)
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
                *current_domain = manager;
            }
            CoreUpdate::UpdateTrap { bitmap } => {
                let value = ExceptionBitmap::from_bits_truncate(bitmap as u32);
                log::trace!("Updating trap bitmap on core {} to {:?}", core_id, value);
                //TODO: for the moment we only offer interposition on the hardware cpu exception
                //interrupts (first 32 values).
                //By instrumenting APIC and virtualizing it, we might manage to do better in the
                //future.
                vcpu.set_exception_bitmap(value)
                    .expect("Error setting the exception bitmap");
            }
        }
    }
}

fn switch_domain(
    vcpu: &mut ActiveVmcs<'static>,
    current_ctx: &mut MutexGuard<ContextData>,
    next_ctx: &MutexGuard<ContextData>,
    next_domain: MutexGuard<DomainData>,
) -> Result<(), CapaError> {
    // Safety check that both contexts have a valid vmcs.
    if current_ctx.vmcs.is_invalid() || next_ctx.vmcs.is_invalid() {
        log::error!(
            "VMCS are none during switch: curr:{:?}, next:{:?}",
            current_ctx.vmcs.is_invalid(),
            next_ctx.vmcs.is_invalid()
        );
        return Err(CapaError::InvalidSwitch);
    }
    if current_ctx.vmcs != next_ctx.vmcs {
        current_ctx.save(vcpu);
        next_ctx.restore(&RC_VMCS, vcpu);
    } else {
        current_ctx.save_partial(vcpu);
        next_ctx.restore_partial(vcpu);
    }

    vcpu.set_ept_ptr(HostPhysAddr::new(
        next_domain.ept.unwrap().as_usize() | EPT_ROOT_FLAGS,
    ))
    .expect("Failed to update EPT");
    Ok(())
}

fn create_domain(domain: Handle<Domain>) {
    let mut domain = get_domain(domain);
    let allocator = allocator();
    if let Some(ept) = domain.ept {
        unsafe { free_ept(ept, allocator) };
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

fn update_domain_ept(
    domain_handle: Handle<Domain>,
    engine: &mut MutexGuard<CapaEngine>,
    init: bool,
) -> bool {
    let mut domain = get_domain(domain_handle);
    let allocator = allocator();
    let ept_root = allocator
        .allocate_frame()
        .expect("Failled to allocate EPT root")
        .zeroed();
    let mut mapper = EptMapper::new(
        allocator.get_physical_offset().as_usize(),
        ept_root.phys_addr,
    );

    let regions = if engine[domain_handle].aliased {
        engine[domain_handle].gpa_regions()
    } else {
        engine[domain_handle].hpa_regions()
    };

    for range in regions.permissions() {
        if !range.ops.contains(MemOps::READ) {
            log::error!("there is a region without read permission: {}", range);
            continue;
        }
        let mut flags = EptEntryFlags::READ;
        if range.ops.contains(MemOps::WRITE) {
            flags |= EptEntryFlags::WRITE;
        }
        if range.ops.contains(MemOps::EXEC) {
            if range.ops.contains(MemOps::SUPER) {
                flags |= EptEntryFlags::SUPERVISOR_EXECUTE;
            } else {
                flags |= EptEntryFlags::USER_EXECUTE;
            }
        }
        let (gpa, hpa, size, repeat) = match range.alias {
            Alias::NoAlias => (range.start, range.start, range.size(), false),
            Alias::Alias(a) => (range.start, a, range.size(), false),
            Alias::Repeat(a, s) => (range.start, a, s, true),
        };

        if repeat {
            // Map all the addresses to the same page.
            for i in 0..size {
                mapper.map_range(
                    allocator,
                    GuestPhysAddr::new(gpa + i * PAGE_SIZE),
                    HostPhysAddr::new(hpa),
                    PAGE_SIZE,
                    flags,
                )
            }
        } else {
            mapper.map_range(
                allocator,
                GuestPhysAddr::new(gpa),
                HostPhysAddr::new(hpa),
                size,
                flags,
            )
        }
    }

    if !init {
        loop {
            match TLB_FLUSH[domain_handle.idx()].compare_exchange(
                false,
                true,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(false) => break,
                _ => continue,
            }
        }
    }

    // The core needs exclusive access before updating the domain's EPT. Otherwise, we might have
    // miss freeing some EPT roots.
    domain.ept_old = domain.ept;
    domain.ept = Some(ept_root.phys_addr);

    true
}

fn notify_cores(core_id: usize, domain_core_bitmap: u64) {
    // initialize lapic
    for core in BitmapIterator::new(domain_core_bitmap) {
        if core == core_id {
            continue;
        }
        // send ipi
        let apic_id = apic::ApicId::XApic(core as u8);
        unsafe {
            apic::ipi_init(apic_id);
        }
    }
}

fn update_domain_iopt(domain_handle: Handle<Domain>, engine: &mut MutexGuard<CapaEngine>) -> bool {
    let mut domain = get_domain(domain_handle);
    let allocator = allocator();
    if let Some(iopt) = domain.iopt {
        unsafe { free_iopt(iopt, allocator) };
        // TODO: global invalidate context cache, PASID cache, and flush the IOTLB
    }

    let iopt_root = allocator
        .allocate_frame()
        .expect("Failed to allocate I/O PT root")
        .zeroed();
    let mut iopt_mapper = IoPtMapper::new(
        allocator.get_physical_offset().as_usize(),
        iopt_root.phys_addr,
    );

    // Traverse all regions of the I/O domain and maps them into the new iopt
    for range in engine.get_domain_permissions(domain_handle).unwrap() {
        if !range.ops.contains(MemOps::READ) {
            log::error!("there is a region without read permission: {}", range);
            continue;
        }
        let gpa = range.start;
        iopt_mapper.map_range(
            allocator,
            GuestPhysAddr::new(gpa),
            HostPhysAddr::new(range.start),
            range.size(),
            IoPtFlag::READ | IoPtFlag::WRITE | IoPtFlag::EXECUTE,
        )
    }

    domain.iopt = Some(iopt_root.phys_addr);

    // Update the IOMMU
    // TODO: @yuchen ideally we only need to change the 2nd stage page translation pointer on the
    //               context table, instead of reallocating the whole root table
    // Remap the DMA region on IOMMU
    let mut iommu = IOMMU.lock();
    let root_addr: HostPhysAddr = vtd::setup_iommu_context(iopt_mapper.get_root(), allocator);
    iommu.set_root_table_addr(root_addr.as_u64() | (0b00 << 10)); // Set legacy mode
    iommu.update_root_table_addr();
    iommu.enable_translation();
    log::info!("I/O MMU: {:?}", iommu.get_global_status());
    log::warn!("I/O MMU Fault: {:?}", iommu.get_fault_status());

    false
}

fn update_permission(
    domain_handle: Handle<Domain>,
    engine: &mut MutexGuard<CapaEngine>,
    init: bool,
) -> bool {
    if engine[domain_handle].is_io() {
        update_domain_iopt(domain_handle, engine)
    } else {
        update_domain_ept(domain_handle, engine, init)
    }
}

unsafe fn free_ept(ept: HostPhysAddr, allocator: &impl FrameAllocator) {
    let mapper = EptMapper::new(allocator.get_physical_offset().as_usize(), ept);
    mapper.free_all(allocator);
}

unsafe fn free_iopt(iopt: HostPhysAddr, allocator: &impl FrameAllocator) {
    let mapper = IoPtMapper::new(allocator.get_physical_offset().as_usize(), iopt);
    mapper.free_all(allocator);
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
            CoreUpdate::UpdateTrap { bitmap } => {
                write!(f, "UpdateTrap({:b})", bitmap)
            }
        }
    }
}
