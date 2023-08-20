//! Architecture specific monitor state, independant of the CapaEngine.

use capa_engine::config::{NB_CORES, NB_DOMAINS};
use capa_engine::{
    permission, AccessRights, Bitmaps, Buffer, CapaEngine, CapaError, CapaInfo, Domain, GenArena,
    Handle, LocalCapa, MemOps, NextCapaToken, MEMOPS_ALL,
};
use mmu::eptmapper::EPT_ROOT_FLAGS;
use mmu::{EptMapper, FrameAllocator};
use spin::{Mutex, MutexGuard};
use stage_two_abi::Manifest;
use utils::{GuestPhysAddr, HostPhysAddr};
use vmx::bitmaps::{EptEntryFlags, ExceptionBitmap};
use vmx::errors::Trapnr;
use vmx::msr::IA32_LSTAR;
use vmx::{ActiveVmcs, ControlRegister, Register, VmExitInterrupt, VmxError, REGFILE_SIZE};

use super::cpuid;
use super::guest::VmxState;
use super::init::NB_BOOTED_CORES;
use crate::allocator::allocator;
use crate::rcframe::{drop_rc, RCFrame, RCFramePool, EMPTY_RCFRAME};

// ————————————————————————— Statics & Backend Data ————————————————————————— //

static CAPA_ENGINE: Mutex<CapaEngine> = Mutex::new(CapaEngine::new());
static INITIAL_DOMAIN: Mutex<Option<Handle<Domain>>> = Mutex::new(None);
static DOMAINS: [Mutex<DomainData>; NB_DOMAINS] = [EMPTY_DOMAIN; NB_DOMAINS];
static CORE_UPDATES: [Mutex<Buffer<CoreUpdate>>; NB_CORES] = [EMPTY_UPDATE_BUFFER; NB_CORES];
static CONTEXTS: [[Mutex<ContextData>; NB_CORES]; NB_DOMAINS] = [EMPTY_CONTEXT_ARRAY; NB_DOMAINS];
static RC_VMCS: Mutex<RCFramePool> =
    Mutex::new(GenArena::new([EMPTY_RCFRAME; { NB_DOMAINS * NB_CORES }]));

pub struct DomainData {
    ept: Option<HostPhysAddr>,
}

pub struct ContextData {
    pub cr3: usize,
    pub rip: usize,
    pub rsp: usize,
    // General-purpose registers.
    pub regs: [u64; REGFILE_SIZE],
    // The MSR(s?) we need to save and restore.
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
        vcpu.flush();
    }

    pub fn restore_partial(&self, vcpu: &mut ActiveVmcs<'static>) {
        vcpu.set_cr(ControlRegister::Cr3, self.cr3);
        vcpu.set(Register::Rip, self.rip as u64);
        vcpu.set(Register::Rsp, self.rsp as u64);
    }

    pub fn restore(&self, vcpu: &mut ActiveVmcs<'static>) {
        let locked = RC_VMCS.lock();
        let rc_frame = locked.get(self.vmcs).unwrap();
        vcpu.load_regs(&self.regs);
        unsafe { vmx::msr::Msr::new(IA32_LSTAR.address()).write(self.lstar) };
        vcpu.switch_frame(rc_frame.frame).unwrap();
        // Restore partial must be called AFTER we set a valid frame.
        self.restore_partial(vcpu);
    }
}

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

const EMPTY_DOMAIN: Mutex<DomainData> = Mutex::new(DomainData { ept: None });
const EMPTY_UPDATE_BUFFER: Mutex<Buffer<CoreUpdate>> = Mutex::new(Buffer::new());
const EMPTY_CONTEXT: Mutex<ContextData> = Mutex::new(ContextData {
    cr3: usize::max_value(),
    rip: usize::max_value(),
    rsp: usize::max_value(),
    regs: [0; REGFILE_SIZE],
    lstar: u64::max_value(),
    vmcs: Handle::<RCFrame>::new_invalid(),
});
const EMPTY_CONTEXT_ARRAY: [Mutex<ContextData>; NB_CORES] = [EMPTY_CONTEXT; NB_CORES];

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
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();
    apply_updates(&mut engine);

    // Save the initial domain
    let mut initial_domain = INITIAL_DOMAIN.lock();
    *initial_domain = Some(domain);
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

pub fn do_create_domain(current: Handle<Domain>) -> Result<LocalCapa, CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let management_capa = engine.create_domain(current)?;
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

pub fn do_init_child_contexts(
    current: Handle<Domain>,
    domain: LocalCapa,
    vcpu: &mut ActiveVmcs<'static>,
) {
    let mut engine = CAPA_ENGINE.lock();
    let domain = engine
        .get_domain_capa(current, domain)
        .expect("Unable to access child");
    let value = engine.get_domain_config(domain, Bitmaps::SWITCH);
    let value = InitVMCS::from_u64(value).unwrap();
    let allocator = allocator();
    // Init on all the cores.
    let cpus = 0..(NB_BOOTED_CORES.load(core::sync::atomic::Ordering::SeqCst) + 1);
    let mut rcvmcs = RC_VMCS.lock();
    let cores = engine.get_domain_config(domain, Bitmaps::CORE);
    match value {
        InitVMCS::Shared => {
            // Easy case, increase ref on all cores shared by the two domains.
            for c in cpus {
                if (1 << c) & cores == 0 {
                    continue;
                }
                let orig = get_context(current, c);
                let dest = &mut get_context(domain, c);
                rcvmcs
                    .get_mut(orig.vmcs)
                    .expect("No vmcs on original")
                    .acquire();
                if !dest.vmcs.is_invalid() {
                    drop_rc(&mut rcvmcs, dest.vmcs);
                }
                dest.vmcs = orig.vmcs;
            }
        }
        InitVMCS::Copy => {
            // Flush the current vcpu.
            for c in cpus {
                if (1 << c) & cores == 0 {
                    continue;
                }
                let dest = &mut get_context(domain, c);
                let frame = allocator
                    .allocate_frame()
                    .expect("Unable to allocate frame");
                let rc = RCFrame::new(frame);
                dest.vmcs = rcvmcs.allocate(rc).expect("Unable to allocate rc frame");
                vcpu.copy_into(frame);
            }
        }
        InitVMCS::Fresh => {
            for c in cpus {
                if (1 << c) & cores == 0 {
                    continue;
                }
                let dest = &mut get_context(domain, c);
                let frame = allocator
                    .allocate_frame()
                    .expect("Unable to allocate frame");
                let rc = RCFrame::new(frame);
                //TODO do an init;
                dest.vmcs = rcvmcs.allocate(rc).expect("Unable to allocate rc frame");
            }
        }
    }
}

pub fn do_set_entry(
    current: Handle<Domain>,
    domain: LocalCapa,
    core: usize,
    cr3: usize,
    rip: usize,
    rsp: usize,
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let domain = engine.get_domain_capa(current, domain)?;
    let cores = engine.get_domain_config(domain, Bitmaps::CORE);
    if (1 << core) & cores == 0 {
        return Err(CapaError::InvalidCore);
    }
    let context = &mut get_context(domain, core);
    if context.vmcs.is_invalid() {
        log::error!("Set the switch type first!");
        return Err(CapaError::InvalidOperation);
    }
    context.cr3 = cr3;
    context.rip = rip;
    context.rsp = rsp;
    Ok(())
}

/// TODO(aghosn) do we need to seal on all cores?
pub fn do_seal(current: Handle<Domain>, domain: LocalCapa) -> Result<LocalCapa, CapaError> {
    let core = cpuid();
    let mut engine = CAPA_ENGINE.lock();
    let capa = engine.seal(current, core, domain)?;
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
    let prot_1 = MemOps::from_usize(prot_1)?;
    let prot_2 = MemOps::from_usize(prot_2)?;
    let mut engine = CAPA_ENGINE.lock();
    let access_left = AccessRights {
        start: start_1,
        end: end_1,
        ops: prot_1,
    };
    let access_right = AccessRights {
        start: start_2,
        end: end_2,
        ops: prot_2,
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

        log::info!("Domain");
        let mut next_capa = NextCapaToken::new();
        while let Some((info, next_next_capa)) = engine.enumerate(domain, next_capa) {
            next_capa = next_next_capa;
            log::info!(" - {}", info);
        }
        log::info!("{}", engine[domain].regions());
    }
}
// —————————————————————— Interrupt Handling functions —————————————————————— //

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
    Init {
        init_state: InitVmcs,
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
            capa_engine::Update::TlbShootdown { core } => {
                let mut core_updates = CORE_UPDATES[core as usize].lock();
                core_updates.push(CoreUpdate::TlbShootdown);
            }
            capa_engine::Update::UpdateTraps { trap, core } => {
                let mut core_updates = CORE_UPDATES[core as usize].lock();
                core_updates.push(CoreUpdate::UpdateTrap { bitmap: !trap });
            }
            capa_engine::Update::CoreInit { core, state } => {
                // FIXME: the vmcs changes should be applied on another core
                //        double check here as I'm pretty sure this one is using the current core
                let mut core_updates = CORE_UPDATES[core as usize].lock();

                // FIXME: read the content of the address through hypercall
                let raw_ptr = state as *mut InitVmcs;
                let state_ref: &mut InitVmcs = unsafe { raw_ptr.as_mut().unwrap() };
                crate::println!("{:?}", state_ref);
                let state: InitVmcs = *state_ref;
                crate::println!("state = {:?}", state);

                core_updates.push(CoreUpdate::Init { init_state: state });
            }
        }
    }
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
                return_capa,
            } => {
                log::trace!("Domain Switch on core {}", core_id);

                let current_ctx = get_context(*current_domain, core);
                let next_ctx = get_context(domain, core);
                let next_domain = get_domain(domain);
                switch_domain(vcpu, current_ctx, next_ctx, next_domain)
                    .expect("Failed to perform the switch");

                // Set switch return values
                vcpu.set(Register::Rax, 0);
                vcpu.set(Register::Rdi, return_capa.as_u64());

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

                let current_ctx = get_context(*current_domain, core);
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
                *current_domain = manager;
            }
            CoreUpdate::UpdateTrap { bitmap } => {
                log::trace!("Updating trap bitmap on core {} to {:b}", core_id, bitmap);
                let value = bitmap as u32;
                //TODO: for the moment we only offer interposition on the hardware cpu exception
                //interrupts (first 32 values).
                //By instrumenting APIC and virtualizing it, we might manage to do better in the
                //future.
                vcpu.set_exception_bitmap(ExceptionBitmap::from_bits_truncate(value))
                    .expect("Error setting the exception bitmap");
            }
            CoreUpdate::Init { init_state } => {
                log::trace!(
                    "Init core {} VMCS configuration with state: {:?}",
                    core_id,
                    init_state
                );

                apply_state(vcpu, init_state).expect("Error setting initial state");
            }
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct InitVmcs {
    pin_based_vm_exec_control: u64,
    cpu_based_vm_exec_control: u64,
    secondary_vm_exec_control: u64,
    exception_bitmap: u64,
    eoi_exit_bitmap0: u64,
    eoi_exit_bitmap1: u64,
    eoi_exit_bitmap2: u64,
    eoi_exit_bitmap3: u64,
    posted_intr_desc_addr: u64,
    page_fault_error_code_mask: u64,
    page_fault_error_code_match: u64,
    cr3_target_count: u64,
    vmcs_link_pointer: u64,
    vm_exit_msr_load_addr: u64,
    vm_entry_msr_load_addr: u64,
    vm_exit_controls: u64,
    vm_entry_controls: u64,
    virtual_apic_page_addr: u64,
    apic_access_addr: u64,
    ept_pointer: u64,
    tpr_threshold: u64,
    guest_pending_dbg_exceptions: u64,
    vm_entry_intr_info_field: u64,
    tsc_offset: u64,
    guest_intr_status: u64,
    guest_rip: u64,
    guest_cr0: u64,
    guest_cr3: u64,
    guest_rsp: u64,
    guest_cr4: u64,
    guest_dr7: u64,
    guest_ia32_efer: u64,
    cr0_read_shadow: u64,
    cr4_read_shadow: u64,
    cr0_guest_host_mask: u64,
    cr4_guest_host_mask: u64,
    guest_sysenter_cs: u64,
    guest_sysenter_esp: u64,
    guest_sysenter_eip: u64,
    guest_ia32_debugctl: u64,
    guest_ia32_pat: u64,
}

fn apply_state(vcpu: &mut ActiveVmcs<'static>, state: InitVmcs) -> Result<(), VmxError> {
    use vmx::fields;
    use vmx::fields::traits::*;

    log::trace!("apply state on vcpu {:?} with state {:?}", vcpu, state);

    // Ctrl state
    unsafe {
        fields::Ctrl32::PinBasedExecCtrls.vmwrite(state.pin_based_vm_exec_control as u32)?;
        fields::Ctrl32::PrimaryProcBasedExecCtrls
            .vmwrite(state.cpu_based_vm_exec_control as u32)?;
        fields::Ctrl32::SecondaryProcBasedVmExecCtrls
            .vmwrite(state.secondary_vm_exec_control as u32)?;
        fields::Ctrl32::ExceptionBitmap.vmwrite(state.exception_bitmap as u32)?;
        // fields::Ctrl64::MsrBitmaps.vmwrite(state.msr_bitmap)?;
        fields::Ctrl64::EoiExitBitmap0.vmwrite(state.eoi_exit_bitmap0)?;
        fields::Ctrl64::EoiExitBitmap1.vmwrite(state.eoi_exit_bitmap1)?;
        fields::Ctrl64::EoiExitBitmap2.vmwrite(state.eoi_exit_bitmap2)?;
        fields::Ctrl64::EoiExitBitmap3.vmwrite(state.eoi_exit_bitmap3)?;
        fields::Ctrl64::PostedIntDescAddr.vmwrite(state.posted_intr_desc_addr)?;

        fields::Ctrl32::PageFaultErrCodeMask.vmwrite(state.page_fault_error_code_mask as u32)?;
        fields::Ctrl32::PageFaultErrCodeMatch.vmwrite(state.page_fault_error_code_match as u32)?;
        fields::Ctrl32::Cr3TargetCount.vmwrite(state.cr3_target_count as u32)?;

        fields::GuestState64::VmcsLinkPtr.vmwrite(state.vmcs_link_pointer)?;
    }

    // Binary-dependent Guest States
    vcpu.set64(fields::GuestState64::Ia32Efer, state.guest_ia32_efer)?;
    vcpu.set_nat(fields::GuestStateNat::Rflags, 0x2)?;
    vcpu.set_nat(fields::GuestStateNat::Rip, state.guest_rip as usize)?;
    vcpu.set_nat(fields::GuestStateNat::Cr0, state.guest_cr0 as usize)?;
    vcpu.set_nat(fields::GuestStateNat::Cr3, state.guest_cr3 as usize)?;
    vcpu.set_nat(fields::GuestStateNat::Rsp, state.guest_rsp as usize)?;
    // vcpu.set(Register::Rsi, state.guest_rsi as u64);
    // VMXE flags, required during VMX operations.
    vcpu.set_nat(fields::GuestStateNat::Cr4, state.guest_cr4 as usize)?;
    vcpu.set_cr4_mask(state.cr4_guest_host_mask as usize)?;
    vcpu.set_cr4_shadow(state.cr4_read_shadow as usize)?;
    vcpu.set_cr0_mask(state.cr0_guest_host_mask as usize)?;
    vcpu.set_cr0_shadow(state.cr0_read_shadow as usize)?;
    vcpu.set_nat(fields::GuestStateNat::Dr7, state.guest_dr7 as usize)?;

    //   nested_vmx_set_vmcs_shadowing_bitmap: vmcs_write: field 0x00002026 (VMREAD_BITMAP), value 0x104a8b000
    //   nested_vmx_set_vmcs_shadowing_bitmap: vmcs_write: field 0x00002028 (VMWRITE_BITMAP), value 0x104bb0000

    // Default States
    // CS
    vcpu.set_nat(fields::GuestStateNat::CsBase, 0xffff0000)?;
    vcpu.set32(fields::GuestState32::CsLimit, 0x0000ffff)?;
    vcpu.set16(fields::GuestState16::CsSelector, 0x0000f000)?;
    vcpu.set32(fields::GuestState32::CsAccessRights, 0x0000009b)?;
    // DS
    vcpu.set_nat(fields::GuestStateNat::DsBase, 0x0)?;
    vcpu.set32(fields::GuestState32::DsLimit, 0x0000ffff)?;
    vcpu.set16(fields::GuestState16::DsSelector, 0)?;
    vcpu.set32(fields::GuestState32::DsAccessRights, 0x93)?;
    // ES
    vcpu.set_nat(fields::GuestStateNat::EsBase, 0x0)?;
    vcpu.set32(fields::GuestState32::EsLimit, 0x0000ffff)?;
    vcpu.set16(fields::GuestState16::EsSelector, 0)?;
    vcpu.set32(fields::GuestState32::EsAccessRights, 0x93)?;
    // FS
    vcpu.set_nat(fields::GuestStateNat::FsBase, 0x0)?;
    vcpu.set32(fields::GuestState32::FsLimit, 0x0000ffff)?;
    vcpu.set16(fields::GuestState16::FsSelector, 0)?;
    vcpu.set32(fields::GuestState32::FsAccessRights, 0x93)?;
    // GS
    vcpu.set_nat(fields::GuestStateNat::GsBase, 0x0)?;
    vcpu.set32(fields::GuestState32::GsLimit, 0x0)?;
    vcpu.set16(fields::GuestState16::GsSelector, 0)?;
    vcpu.set32(fields::GuestState32::GsAccessRights, 0x93)?;
    // SS
    vcpu.set_nat(fields::GuestStateNat::SsBase, 0x0)?;
    vcpu.set32(fields::GuestState32::SsLimit, 0x0000ffff)?;
    vcpu.set16(fields::GuestState16::SsSelector, 0)?;
    vcpu.set32(fields::GuestState32::SsAccessRights, 0x93)?;
    // TR
    vcpu.set_nat(fields::GuestStateNat::TrBase, 0x0)?;
    vcpu.set32(fields::GuestState32::TrLimit, 0x0000ffff)?; // At least 0x67
    vcpu.set16(fields::GuestState16::TrSelector, 0)?;
    vcpu.set32(fields::GuestState32::TrAccessRights, 0x8b)?;
    // LDTR
    vcpu.set_nat(fields::GuestStateNat::LdtrBase, 0x0)?;
    vcpu.set32(fields::GuestState32::LdtrLimit, 0x0000ffff)?;
    vcpu.set16(fields::GuestState16::LdtrSelector, 0)?;
    vcpu.set32(fields::GuestState32::LdtrAccessRights, 0x82)?;
    // GDTR
    vcpu.set_nat(fields::GuestStateNat::GdtrBase, 0x0)?;
    vcpu.set32(fields::GuestState32::GdtrLimit, 0x0000ffff)?;
    // IDTR
    vcpu.set_nat(fields::GuestStateNat::IdtrBase, 0x0)?;
    vcpu.set32(fields::GuestState32::IdtrLimit, 0x0000ffff)?;

    vcpu.set32(fields::GuestState32::ActivityState, 0)?;
    vcpu.set64(fields::GuestState64::VmcsLinkPtr, u64::max_value())?;
    vcpu.set16(fields::GuestState16::InterruptStatus, 0)?;
    vcpu.set32(fields::GuestState32::VmxPreemptionTimerValue, 0xffffffff)?;
    vcpu.set_nat(fields::GuestStateNat::Rflags, 0x2)?;

    unsafe {
        fields::Ctrl32::VmExitMsrLoadCount.vmwrite(0)?;
        fields::Ctrl32::VmExitMsrStoreCount.vmwrite(0)?;
        fields::Ctrl32::VmEntryMsrLoadCount.vmwrite(0)?;
        fields::Ctrl64::VmExitMsrLoadAddr.vmwrite(state.vm_exit_msr_load_addr)?;
        fields::Ctrl64::VmEntryMsrLoadAddr.vmwrite(state.vm_entry_msr_load_addr)?;
        fields::GuestState64::Ia32Pat.vmwrite(state.guest_ia32_pat)?;

        fields::Ctrl32::VmExitCtrls.vmwrite(state.vm_exit_controls as u32)?;
        fields::Ctrl32::VmEntryCtrls.vmwrite(state.vm_entry_controls as u32)?;
        fields::CtrlNat::Cr0Mask.vmwrite(state.cr0_guest_host_mask as usize)?;
        fields::CtrlNat::Cr4Mask.vmwrite(state.cr4_guest_host_mask as usize)?;

        fields::GuestState32::Ia32SysenterCs.vmwrite(state.guest_sysenter_cs as u32)?;
        fields::GuestStateNat::Ia32SysenterEsp.vmwrite(state.guest_sysenter_esp as usize)?;
        fields::GuestStateNat::Ia32SysenterEip.vmwrite(state.guest_sysenter_eip as usize)?;
        fields::GuestState64::Ia32Debugctl.vmwrite(state.guest_ia32_debugctl as u64)?;

        fields::Ctrl64::VirtApicAddr.vmwrite(state.virtual_apic_page_addr)?;
        fields::Ctrl64::ApicAccessAddr.vmwrite(state.apic_access_addr)?;
        fields::Ctrl64::EptPtr.vmwrite(state.ept_pointer)?;

        fields::Ctrl32::TprThreshold.vmwrite(state.tpr_threshold as u32)?;

        fields::GuestStateNat::PendingDebugExcept
            .vmwrite(state.guest_pending_dbg_exceptions as usize)?;

        fields::Ctrl32::VmEntryIntInfoField.vmwrite(state.vm_entry_intr_info_field as u32)?;
        fields::CtrlNat::Cr0ReadShadow.vmwrite(state.cr0_read_shadow as usize)?;
        fields::CtrlNat::Cr4ReadShadow.vmwrite(state.cr4_read_shadow as usize)?;

        fields::Ctrl32::ExceptionBitmap.vmwrite(state.exception_bitmap as u32)?;

        fields::Ctrl64::TscOffset.vmwrite(state.tsc_offset)?;

        fields::GuestState32::InterruptibilityState.vmwrite(state.guest_intr_status as u32)?;
    }

    // Host State
    // HOST_TR_BASE
    // HOST_GDTR_BASE
    // HOST_IA32_SYSENTER_ESP
    // HOST_FS_SELECTOR
    // HOST_GS_SELECTOR
    // HOST_CR0
    // HOST_CR3
    // HOST_CR4
    // HOST_CS_SELECTOR
    // HOST_DS_SELECTOR
    // HOST_ES_SELECTOR
    // HOST_SS_SELECTOR
    // HOST_TR_SELECTOR
    // HOST_IDTR_BASE
    // HOST_RIP
    // HOST_IA32_SYSENTER_CS
    // HOST_IA32_SYSENTER_EIP
    // HOST_IA32_PAT
    // HOST_IA32_EFER
    // HOST_FS_BASE
    // HOST_GS_BASE
    // HOST_FS_BASE
    // HOST_GS_BASE
    // HOST_RSP
    //

    Ok(())
}

fn switch_domain(
    vcpu: &mut ActiveVmcs<'static>,
    mut current_ctx: MutexGuard<ContextData>,
    next_ctx: MutexGuard<ContextData>,
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
        next_ctx.restore(vcpu);
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

fn update_permission(domain_handle: Handle<Domain>, engine: &mut MutexGuard<CapaEngine>) {
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
            CoreUpdate::Init { init_state } => {
                write!(f, "CoreUpdate({:p})", init_state)
            }
        }
    }
}
