//! Architecture specific monitor state, independant of the CapaEngine.

use capa_engine::config::{NB_CONTEXTS, NB_DOMAINS};
use capa_engine::{
    permission, AccessRights, Buffer, CapaEngine, CapaError, CapaInfo, Context, Domain, Handle,
    LocalCapa, NextCapaToken,
};
use mmu::eptmapper::EPT_ROOT_FLAGS;
use mmu::{EptMapper, FrameAllocator};
use spin::{Mutex, MutexGuard};
use stage_two_abi::Manifest;
use utils::{GuestPhysAddr, HostPhysAddr};
use vmx::bitmaps::EptEntryFlags;
use vmx::{ActiveVmcs, ControlRegister, Register};

use super::cpuid;
use crate::allocator::allocator;
use crate::statics::NB_CORES;

// ————————————————————————— Statics & Backend Data ————————————————————————— //

static CAPA_ENGINE: Mutex<CapaEngine> = Mutex::new(CapaEngine::new());
static INITIAL_DOMAIN: Mutex<Option<Handle<Domain>>> = Mutex::new(None);
static DOMAINS: [Mutex<DomainData>; NB_DOMAINS] = [EMPTY_DOMAIN; NB_DOMAINS];
static CORE_UPDATES: [Mutex<Buffer<CoreUpdate>>; NB_CORES] = [EMPTY_UPDATE_BUFFER; NB_CORES];
static CONTEXTS: [Mutex<ContextData>; NB_CONTEXTS] = [EMPTY_CONTEXT; NB_CONTEXTS];

pub struct DomainData {
    ept: Option<HostPhysAddr>,
}

pub struct ContextData {
    pub cr3: usize,
    pub rip: usize,
    pub rsp: usize,
}

const EMPTY_DOMAIN: Mutex<DomainData> = Mutex::new(DomainData { ept: None });
const EMPTY_UPDATE_BUFFER: Mutex<Buffer<CoreUpdate>> = Mutex::new(Buffer::new());
const EMPTY_CONTEXT: Mutex<ContextData> = Mutex::new(ContextData {
    cr3: 0,
    rip: 0,
    rsp: 0,
});

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
                end: manifest.poffset as usize,
            },
        )
        .unwrap();
    apply_updates(&mut engine);

    // Save the initial domain
    let mut initial_domain = INITIAL_DOMAIN.lock();
    *initial_domain = Some(domain);
}

pub fn init_vcpu(vcpu: &mut ActiveVmcs<'static>) -> (Handle<Domain>, Handle<Context>) {
    let cpuid = cpuid();
    let mut engine = CAPA_ENGINE.lock();
    let initial_domain = INITIAL_DOMAIN
        .lock()
        .expect("CapaEngine is not initialized yet");
    let ctx = engine
        .start_domain_on_core(initial_domain, cpuid)
        .expect("Failed to allocate initial domain");
    let domain = get_domain(initial_domain);
    vcpu.set_ept_ptr(HostPhysAddr::new(
        domain.ept.unwrap().as_usize() | EPT_ROOT_FLAGS,
    ))
    .expect("Failed to set initial EPT PTR");
    (initial_domain, ctx)
}

// ———————————————————————————————— Helpers ————————————————————————————————— //

fn get_domain(domain: Handle<Domain>) -> MutexGuard<'static, DomainData> {
    DOMAINS[domain.idx()].lock()
}

fn get_context(context: Handle<Context>) -> MutexGuard<'static, ContextData> {
    CONTEXTS[context.idx()].lock()
}

// ————————————————————————————— Monitor Calls —————————————————————————————— //

pub fn do_create_domain(current: Handle<Domain>) -> Result<LocalCapa, CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let management_capa = engine.create_domain(current)?;
    apply_updates(&mut engine);
    Ok(management_capa)
}

pub fn do_seal(
    current: Handle<Domain>,
    domain: LocalCapa,
    cr3: usize,
    rip: usize,
    rsp: usize,
) -> Result<LocalCapa, CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let (capa, context) = engine.seal(current, domain)?;
    let mut context = get_context(context);
    context.cr3 = cr3;
    context.rip = rip;
    context.rsp = rsp;
    apply_updates(&mut engine);
    Ok(capa)
}

pub fn do_segment_region(
    current: Handle<Domain>,
    capa: LocalCapa,
    start_1: usize,
    end_1: usize,
    _prot_1: usize,
    start_2: usize,
    end_2: usize,
    _prot_2: usize,
) -> Result<(LocalCapa, LocalCapa), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let access_left = AccessRights {
        start: start_1,
        end: end_1,
    };
    let access_right = AccessRights {
        start: start_2,
        end: end_2,
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
    current_ctx: Handle<Context>,
    capa: LocalCapa,
    cpuid: usize,
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    engine.switch(current, current_ctx, capa, cpuid)?;
    apply_updates(&mut engine);
    Ok(())
}

pub fn do_debug() {
    let mut engine = CAPA_ENGINE.lock();
    let mut next = NextCapaToken::new();
    while let Some((domain, next_next)) = engine.enumerate_domains(next) {
        next = next_next;

        log::info!("Domain");
        let mut next_capa = NextCapaToken::new();
        while let Some((info, next_next_capa)) = engine.enumerate(domain, next_capa) {
            next_capa = next_next_capa;
            log::info!(" - {}", info);
        }
        log::info!("{}", engine[domain].regions());
    }
}

// ———————————————————————————————— Updates ————————————————————————————————— //

/// Per-core updates
#[derive(Debug, Clone, Copy)]
enum CoreUpdate {
    TlbShootdown,
    Switch {
        domain: Handle<Domain>,
        context: Handle<Context>,
        return_capa: LocalCapa,
    },
}

/// General updates, containing both global updates on the domain's states, and core specific
/// updates that must be routed to the different cores.
fn apply_updates(engine: &mut MutexGuard<CapaEngine>) {
    while let Some(update) = engine.pop_update() {
        log::trace!("Update: {}", update);
        match update {
            // Updates that can be handled locally
            capa_engine::Update::PermissionUpdate { domain } => update_permission(domain, engine),
            capa_engine::Update::RevokeDomain { domain } => revoke_domain(domain),
            capa_engine::Update::CreateDomain { domain } => create_domain(domain),

            // Updates that needs to be routed to some specific cores
            capa_engine::Update::Switch {
                domain,
                context,
                return_capa,
                core,
            } => {
                let mut core_updates = CORE_UPDATES[core as usize].lock();
                core_updates.push(CoreUpdate::Switch {
                    domain,
                    context,
                    return_capa,
                });
            }
            capa_engine::Update::TlbShootdown { core } => {
                let mut core_updates = CORE_UPDATES[core as usize].lock();
                core_updates.push(CoreUpdate::TlbShootdown);
            }
        }
    }
}

/// Updates that must be applied to a given core.
pub fn apply_core_updates(
    vcpu: &mut ActiveVmcs<'static>,
    current_domain: &mut Handle<Domain>,
    current_context: &mut Handle<Context>,
    core_id: usize,
) {
    let mut update_queue = CORE_UPDATES[core_id].lock();
    while let Some(update) = update_queue.pop() {
        log::trace!("Core Update: {}", update);
        match update {
            CoreUpdate::TlbShootdown => {
                log::trace!("TLB Shootdown on core {}", core_id);

                // Reload the EPTs
                let domain = get_domain(*current_domain);
                vcpu.set_ept_ptr(HostPhysAddr::new(
                    domain.ept.unwrap().as_usize() | EPT_ROOT_FLAGS,
                ))
                .expect("VMX error, failed to set EPT pointer");
            }
            CoreUpdate::Switch {
                domain,
                context,
                return_capa,
            } => {
                log::trace!("Domain Switch on core {}", core_id);

                let mut current_ctx = get_context(*current_context);
                let next_ctx = get_context(context);
                let next_domain = get_domain(domain);

                // Save current context
                current_ctx.cr3 = vcpu.get_cr(ControlRegister::Cr3);
                current_ctx.rip = vcpu.get(Register::Rip) as usize;
                current_ctx.rsp = vcpu.get(Register::Rsp) as usize;

                // Switch domain
                vcpu.set_cr(ControlRegister::Cr3, next_ctx.cr3);
                vcpu.set(Register::Rip, next_ctx.rip as u64);
                vcpu.set(Register::Rsp, next_ctx.rsp as u64);
                vcpu.set_ept_ptr(HostPhysAddr::new(
                    next_domain.ept.unwrap().as_usize() | EPT_ROOT_FLAGS,
                ))
                .expect("Failed to update EPT");

                // Set switch return values
                vcpu.set(Register::Rax, 0);
                vcpu.set(Register::Rdi, return_capa.as_u64());

                // Update the current domain and context handle
                *current_domain = domain;
                *current_context = context;
            }
        }
    }
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

fn update_permission(domain_handle: Handle<Domain>, engine: &mut MutexGuard<CapaEngine>) {
    // TODO: handle granular access rights
    let flags = EptEntryFlags::USER_EXECUTE
        | EptEntryFlags::SUPERVISOR_EXECUTE
        | EptEntryFlags::READ
        | EptEntryFlags::WRITE
        | EptEntryFlags::SUPERVISOR_EXECUTE;

    let mut domain = get_domain(domain_handle);
    let allocator = allocator();
    if let Some(ept) = domain.ept {
        unsafe { free_ept(ept, allocator) };
    }

    let ept_root = allocator
        .allocate_frame()
        .expect("Failled to allocate EPT root")
        .zeroed();
    let mut mapper = EptMapper::new(
        allocator.get_physical_offset().as_usize(),
        ept_root.phys_addr,
    );

    for range in engine[domain_handle].regions().permissions() {
        mapper.map_range(
            allocator,
            GuestPhysAddr::new(range.start),
            HostPhysAddr::new(range.start),
            range.size(),
            flags,
        )
    }

    domain.ept = Some(ept_root.phys_addr);
}

unsafe fn free_ept(ept: HostPhysAddr, allocator: &impl FrameAllocator) {
    let mapper = EptMapper::new(allocator.get_physical_offset().as_usize(), ept);
    mapper.free_all(allocator);
}

// ———————————————————————————————— Display ————————————————————————————————— //

impl core::fmt::Display for CoreUpdate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CoreUpdate::TlbShootdown => write!(f, "TLB Shootdown"),
            CoreUpdate::Switch {
                domain, context, ..
            } => write!(f, "Switch({}, {})", domain, context),
        }
    }
}
