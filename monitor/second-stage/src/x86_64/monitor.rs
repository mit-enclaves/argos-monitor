//! Architecture specific monitor state, independant of the CapaEngine.

use capa_engine::{permission, AccessRights, CapaEngine, Domain, Handle, N};
use mmu::{EptMapper, FrameAllocator};
use spin::{Mutex, MutexGuard};
use stage_two_abi::Manifest;
use utils::{GuestPhysAddr, HostPhysAddr, HostVirtAddr};
use vmx::bitmaps::EptEntryFlags;

use crate::allocator::allocator;
use crate::println;

// ————————————————————————— Statics & Backend Data ————————————————————————— //

static CAPA_ENGINE: Mutex<CapaEngine> = Mutex::new(CapaEngine::new());
static DOMAINS: [Mutex<DomainData>; N] = [EMPTY_DOMAIN; N];

pub struct DomainData {
    ept: Option<HostPhysAddr>,
}

const EMPTY_DOMAIN: Mutex<DomainData> = Mutex::new(DomainData { ept: None });

// ————————————————————————————— Initialization ————————————————————————————— //

pub fn init(manifest: &'static Manifest) {
    let mut engine = CAPA_ENGINE.lock();
    let domain = engine.create_manager_domain(permission::ALL).unwrap();
    apply_updates(&mut engine);
    engine
        .create_region(
            domain,
            AccessRights {
                start: 0,
                end: manifest.poffset as usize,
            },
        )
        .unwrap();
    apply_updates(&mut engine);
}

// ———————————————————————————————— Helpers ————————————————————————————————— //

fn get_domain(domain: Handle<Domain>) -> MutexGuard<'static, DomainData> {
    DOMAINS[domain.idx()].lock()
}

// ———————————————————————————————— Updates ————————————————————————————————— //

fn apply_updates(engine: &mut MutexGuard<CapaEngine>) {
    while let Some(update) = engine.pop_update() {
        match update {
            capa_engine::Update::PermissionUpdate { domain } => update_permission(domain, engine),
            capa_engine::Update::RevokeDomain { domain } => todo!(),
            capa_engine::Update::CreateDomain { domain } => create_domain(domain),
            capa_engine::Update::None => todo!(),
        }
    }
}

fn create_domain(domain: Handle<Domain>) {
    let mut domain = get_domain(domain);
    let allocator = allocator();
    if let Some(ept) = domain.ept {
        // TODO: free all frames.
        // unsafe {
        //     allocator.free_frame(ept).unwrap();
        // }
    }

    let ept_root = allocator
        .allocate_frame()
        .expect("Failled to allocate EPT root")
        .zeroed();
    domain.ept = Some(ept_root.phys_addr);
}

fn update_permission(domain_handle: Handle<Domain>, engine: &mut MutexGuard<CapaEngine>) {
    // TODO: handle granular access rights
    let flags = EptEntryFlags::USER_EXECUTE
        | EptEntryFlags::SUPERVISOR_EXECUTE
        | EptEntryFlags::READ
        | EptEntryFlags::SUPERVISOR_EXECUTE;

    let mut domain = get_domain(domain_handle);
    let allocator = allocator();
    if let Some(ept) = domain.ept {
        // TODO: free all frames.
        // unsafe {
        //     allocator.free_frame(ept).unwrap();
        // }
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
