//! Architecture specific monitor state 

use capa_engine::config::{NB_CONTEXTS, NB_DOMAINS};
use capa_engine::{
    permission, AccessRights, CapaEngine, CapaError, CapaInfo, Context, Domain, Handle, LocalCapa,
    NextCapaToken,
};
use riscv_utils::{RegisterState, PAGING_MODE_SV48};
use spin::{Mutex, MutexGuard};
use riscv_pmp::{pmp_write, clear_pmp, PMPAddressingMode, PMPErrorCode, FROZEN_PMP_ENTRIES, PMP_ENTRIES};

static CAPA_ENGINE: Mutex<CapaEngine> = Mutex::new(CapaEngine::new());
static INITIAL_DOMAIN: Mutex<Option<Handle<Domain>>> = Mutex::new(None);
static DOMAINS: [Mutex<DomainData>; NB_DOMAINS] = [EMPTY_DOMAIN; NB_DOMAINS];
static CONTEXTS: [Mutex<ContextData>; NB_CONTEXTS] = [EMPTY_CONTEXT; NB_CONTEXTS];

const XWR_PERM: usize = 7;

pub struct DomainData {
    //Todo  
    //Can add a PMP snapshot here, so PMP entries can be written directly without going
    //through the pmp_write function every time! 
} 

pub struct ContextData {
    pub reg_state: RegisterState, 
    pub satp: usize,
    pub ra: usize,
    pub sp: usize,
}

const EMPTY_DOMAIN: Mutex<DomainData> = Mutex::new(DomainData { }); //Todo Init the domain data
                                                                    //once done. 
const EMPTY_CONTEXT: Mutex<ContextData> = Mutex::new(ContextData {
    reg_state: RegisterState::const_default(),
    satp: 0,
    ra: 0,  //TODO: Is ra the one or should it be mepc?  
    sp: 0,
});

// ————————————————————————————— Initialization ————————————————————————————— //

pub fn init() {
    let mut engine = CAPA_ENGINE.lock();
    let domain = engine.create_manager_domain(permission::ALL).unwrap();
    apply_updates(&mut engine);
    engine
        .create_root_region(
            domain,
            AccessRights {
                start: 0x80200000, //Linux Starting Address
                end: 0x9fffffff,   //Todo: double check this - it's currently based on early
                                   //memory node range detected by linux. 
                                   //Todo: It should be a part of the manifest. 
            },
        )
        .unwrap();
    apply_updates(&mut engine);

    // Save the initial domain
    let mut initial_domain = INITIAL_DOMAIN.lock();
    *initial_domain = Some(domain);
}

pub fn start_initial_domain_on_cpu() -> (Handle<Domain>, Handle<Context>) { 
    let mut engine = CAPA_ENGINE.lock();
    let initial_domain = INITIAL_DOMAIN
        .lock()
        .expect("CapaEngine is not initialized yet");
   let ctx = engine
        .start_cpu_on_domain(initial_domain)
        .expect("Failed to allocate initial domain");
   //let domain = get_domain(initial_domain);
   
   //update PMP permissions.
   update_permission(initial_domain, &mut engine); 

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
    satp: usize, 
    ra: usize,
    sp: usize,
) -> Result<LocalCapa, CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let (capa, context) = engine.seal(current, domain)?;
    let mut context = get_context(context);
    //Todo: Populate context with the input context
    context.satp = (satp | PAGING_MODE_SV48);  
    context.ra = ra;
    context.sp = sp;
    let temp_reg_state = RegisterState::const_default(); 
    context.reg_state = temp_reg_state; 
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
    //cpuid: usize,
) -> Result<
    (
        MutexGuard<'static, ContextData>,
        Handle<Domain>,
        Handle<Context>,
        MutexGuard<'static, ContextData>,
        LocalCapa,
    ),
    CapaError,
> {
    // TODO: check that the domain is not already running! Maybe this should be done in the engine?
    let mut engine = CAPA_ENGINE.lock();
    let (next_domain, next_context, return_capa) = engine.switch(current, current_ctx, capa)?;
    //get_core(cpuid).domain = next_domain;
    apply_updates(&mut engine);
    Ok((
        get_context(current_ctx),
        next_domain,
        next_context,
        get_context(next_context),
        return_capa,
    ))
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

fn apply_updates(engine: &mut MutexGuard<CapaEngine>) {
    while let Some(update) = engine.pop_update() {
        match update {
            capa_engine::Update::PermissionUpdate { domain } => update_permission(domain, engine),
            capa_engine::Update::RevokeDomain { domain } => revoke_domain(domain),
            capa_engine::Update::CreateDomain { domain } => create_domain(domain),
            capa_engine::Update::None => todo!(),
        }
    }
}

fn create_domain(domain: Handle<Domain>) {
    //let mut domain = get_domain(domain);
    //Todo: Is there anything that needs to be done here? 
    //
    //For instance do a prior check on the number of memory regions for the domain? (I am not sure
    //if number of regions per domain is updated by this point - I think it happens after the send
    //call). 
    //Also, in the x86 equivalent, what happens when EPT root fails to be allocated? 
}

fn revoke_domain(_domain: Handle<Domain>) {
    //Todo 
}

fn update_permission(domain_handle: Handle<Domain>, engine: &mut MutexGuard<CapaEngine>) {
    //Update PMPs
    let mut domain = get_domain(domain_handle); 
    //First clean current PMP settings - this should internally cause the appropriate flushes 
    clear_pmp();
    //Currently assuming that the number of regions are less than number of PMP entries. 
    let mut pmp_write_result: Result<PMPAddressingMode, PMPErrorCode>;
    let mut pmp_index = FROZEN_PMP_ENTRIES; 
    for range in engine[domain_handle].regions().permissions() {
       
        log::info!("Protecting Domain: {:x} {:x}", range.start, range.size());
 
        pmp_write_result = pmp_write(pmp_index, range.start, range.size(), XWR_PERM);
        //Check the PMP addressing mode so the index can be advanced by 1
        //(NAPOT) or 2 (TOR). 
        if pmp_write_result.is_ok() { 
        
            if pmp_write_result.unwrap() == PMPAddressingMode::NAPOT {
                pmp_index = pmp_index + 1; 
            }
            else if pmp_write_result.unwrap() == PMPAddressingMode::TOR {
                pmp_index = pmp_index + 2; 
            }

            if pmp_index > PMP_ENTRIES {
                // TODO: PMPOverflow Handling 
                // Panic for now. 
                panic!("Cannot continue running this domain: PMPOverflow");
            }
        }
        else {
            //Todo: Check error codes and manage appropriately. 
        }
    }
}
