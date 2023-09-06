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
use utils::{Frame, GuestPhysAddr, HostPhysAddr};
use vmx::bitmaps::{EptEntryFlags, ExceptionBitmap};
use vmx::errors::Trapnr;
use vmx::fields::traits::VmcsField64;
use vmx::msr::IA32_LSTAR;
use vmx::{fields, ActiveVmcs, ControlRegister, Register, VmExitInterrupt, VmxError, REGFILE_SIZE};

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
                    .expect("Unable to allocate frame")
                    .zeroed();
                vmx::init_frame(frame);

                let rc = RCFrame::new(frame);
                //TODO do an init;
                dest.vmcs = rcvmcs.allocate(rc).expect("Unable to allocate rc frame");
                // Save the original vmcs frame address
                let orig_frame = Frame {
                    phys_addr: vcpu.frame().phys_addr,
                    virt_addr: vcpu.frame().virt_addr,
                };
                // Switch to the new vmcs frame
                let rc_frame = rcvmcs.get(dest.vmcs).unwrap();
                vcpu.switch_frame(rc_frame.frame).unwrap();
                // Setup default vmcs fields
                if let Err(e) = set_default_vmcs(vcpu) {
                    log::error!("Failed to setup default vmcs on fresh vCPU: {:?}", e);
                }
                // Switch back
                vcpu.switch_frame(orig_frame).unwrap();
            }
        }
    }
}

fn set_default_vmcs(vcpu: &mut ActiveVmcs<'static>) -> Result<(), vmx::VmxError> {
    use vmx::fields::traits::*;
    // one call to setup as many non-binary dependant registers as possible
    unsafe {
        fields::Ctrl32::PinBasedExecCtrls.vmwrite(0x000000ff)?;
        fields::Ctrl32::PrimaryProcBasedExecCtrls.vmwrite(0xb5a06dfa)?;
        fields::Ctrl32::SecondaryProcBasedVmExecCtrls.vmwrite(0x00000be3)?;
        fields::Ctrl32::ExceptionBitmap.vmwrite(0xffffffff)?;
        fields::Ctrl64::MsrBitmaps.vmwrite(0x109ab0000)?;
        fields::Ctrl64::EoiExitBitmap0.vmwrite(0x00000001)?;
        fields::Ctrl64::EoiExitBitmap1.vmwrite(0x00000000)?;
        fields::Ctrl64::EoiExitBitmap2.vmwrite(0x00000000)?;
        fields::Ctrl64::EoiExitBitmap3.vmwrite(0x00000000)?;
        fields::Ctrl64::PostedIntDescAddr.vmwrite(0x109aa9f40)?;
        fields::Ctrl32::PageFaultErrCodeMask.vmwrite(0x0)?;
        fields::Ctrl32::PageFaultErrCodeMatch.vmwrite(0x0)?;
        fields::Ctrl32::Cr3TargetCount.vmwrite(0x0)?;
        fields::GuestState64::VmcsLinkPtr.vmwrite(0xffffffffffffffff)?;
        fields::Ctrl32::VmExitMsrLoadCount.vmwrite(0)?;
        fields::Ctrl32::VmExitMsrStoreCount.vmwrite(0)?;
        fields::Ctrl32::VmEntryMsrLoadCount.vmwrite(0)?;

        fields::HostStateNat::Cr0.vmwrite(0x80050033)?;
        fields::HostStateNat::Cr3.vmwrite(0x1027c0001)?;
        fields::HostStateNat::Cr4.vmwrite(0x00172ef0)?;

        fields::HostState16::CsSelector.vmwrite(0x00000010)?;
        fields::HostState16::DsSelector.vmwrite(0x00000000)?;
        fields::HostState16::EsSelector.vmwrite(0x00000000)?;
        fields::HostState16::FsSelector.vmwrite(0x00000000)?;
        fields::HostState16::GsSelector.vmwrite(0x00000000)?;
        fields::HostState16::SsSelector.vmwrite(0x00000018)?;
        fields::HostState16::TrSelector.vmwrite(0x00000040)?;

        fields::HostStateNat::IdtrBase.vmwrite(0xfffffe0000000000)?;
    }

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
    // vmx::check::check().expect("check error");
    Ok(())
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

pub fn do_vmread(
    current: Handle<Domain>,
    domain: LocalCapa,
    vcpu: &mut ActiveVmcs<'static>,
    core: usize,
    field: usize,
) -> Result<u64 , CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let domain = engine.get_domain_capa(current, domain)?;
    let cores = engine.get_domain_config(domain, Bitmaps::CORE);
    log::trace!("core={}, cores={}", core, cores);
    if (1 << core) & cores == 0 {
        return Err(CapaError::InvalidCore);
    }
    let context = &mut get_context(domain, core);
    if context.vmcs.is_invalid() {
        log::error!("Set the switch type first!");
        return Err(CapaError::InvalidOperation);
    }

    let locked = RC_VMCS.lock();
    // Save the original vmcs frame address
    let orig_frame = Frame {
        phys_addr: vcpu.frame().phys_addr,
        virt_addr: vcpu.frame().virt_addr,
    };
    log::trace!("vcpu: getting the context.vmcs frame from RC_VMCS arena lock");
    let rc_frame = locked.get(context.vmcs).unwrap();
    log::trace!("vcpu: trying to switch to the context.vmcs frame");
    vcpu.switch_frame(rc_frame.frame).unwrap();

    if let Ok(val) = vmcs_read(field) {
        log::trace!("do_vmread: field={:#x} => value={:#x}", field, val);
        log::trace!("vcpu: trying to switch back to the original frame");
        vcpu.switch_frame(orig_frame).unwrap();
        log::trace!("vcpu: switched back");
        Ok(val)
    } else {
        log::error!("failed to read vmcs field={:#x}", field);
        vcpu.switch_frame(orig_frame).unwrap();
        log::trace!("vcpu: switched back");
        Err(CapaError::InvalidOperation)
    }
}

pub fn do_vmwrite(
    current: Handle<Domain>,
    domain: LocalCapa,
    vcpu: &mut ActiveVmcs<'static>,
    core: usize,
    field: usize,
    value: usize,
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let domain = engine.get_domain_capa(current, domain)?;
    let cores = engine.get_domain_config(domain, Bitmaps::CORE);
    log::trace!("core={}, cores={}", core, cores);
    if (1 << core) & cores == 0 {
        return Err(CapaError::InvalidCore);
    }
    let context = &mut get_context(domain, core);
    if context.vmcs.is_invalid() {
        log::error!("Set the switch type first!");
        return Err(CapaError::InvalidOperation);
    }

    let locked = RC_VMCS.lock();
    // Save the original vmcs frame address
    let orig_frame = Frame {
        phys_addr: vcpu.frame().phys_addr,
        virt_addr: vcpu.frame().virt_addr,
    };
    log::trace!("vcpu: getting the context.vmcs frame from RC_VMCS arena lock");
    let rc_frame = locked.get(context.vmcs).unwrap();
    log::trace!("vcpu: trying to switch to the context.vmcs frame");
    vcpu.switch_frame(rc_frame.frame).unwrap();
    log::trace!("do_vmwrite: field={:#x}, value={:#x}", field, value);
    if let Err(e) = vmcs_write(field, value) {
        log::error!("failed to write vmcs field={:#x}: {:?}", field, e);
    }
    log::trace!("vcpu: trying to switch back to the original frame");
    vcpu.switch_frame(orig_frame).unwrap();
    log::trace!("vcpu: switched back");
    Ok(())
}

pub fn do_vmclear(
    current: Handle<Domain>,
    domain: LocalCapa,
    vcpu: &mut ActiveVmcs<'static>,
    core: usize,
    addr: usize,
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let domain = engine.get_domain_capa(current, domain)?;
    let cores = engine.get_domain_config(domain, Bitmaps::CORE);
    log::trace!("core={}, cores={}", core, cores);
    if (1 << core) & cores == 0 {
        return Err(CapaError::InvalidCore);
    }
    let context = &mut get_context(domain, core);
    if context.vmcs.is_invalid() {
        log::error!("Set the switch type first!");
        return Err(CapaError::InvalidOperation);
    }

    let locked = RC_VMCS.lock();
    // Save the original vmcs frame address
    let orig_frame = Frame {
        phys_addr: vcpu.frame().phys_addr,
        virt_addr: vcpu.frame().virt_addr,
    };
    log::trace!("vcpu: getting the context.vmcs frame from RC_VMCS arena lock");
    let rc_frame = locked.get(context.vmcs).unwrap();
    log::trace!("vcpu: trying to switch to the context.vmcs frame");
    vcpu.switch_frame(rc_frame.frame).unwrap();
    log::trace!("do_vmclear");
    if let Err(e) = vmclear(addr) {
        log::error!("failed to vmclear: {:?}", e);
    }
    log::trace!("vcpu: trying to switch back to the original frame");
    vcpu.switch_frame(orig_frame).unwrap();
    log::trace!("vcpu: switched back");
    Ok(())
}

pub fn do_vmptrld(
    current: Handle<Domain>,
    domain: LocalCapa,
    vcpu: &mut ActiveVmcs<'static>,
    core: usize,
    addr: usize,
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let domain = engine.get_domain_capa(current, domain)?;
    let cores = engine.get_domain_config(domain, Bitmaps::CORE);
    log::trace!("core={}, cores={}", core, cores);
    if (1 << core) & cores == 0 {
        return Err(CapaError::InvalidCore);
    }
    let context = &mut get_context(domain, core);
    if context.vmcs.is_invalid() {
        log::error!("Set the switch type first!");
        return Err(CapaError::InvalidOperation);
    }

    let locked = RC_VMCS.lock();
    // Save the original vmcs frame address
    let orig_frame = Frame {
        phys_addr: vcpu.frame().phys_addr,
        virt_addr: vcpu.frame().virt_addr,
    };
    log::trace!("vcpu: getting the context.vmcs frame from RC_VMCS arena lock");
    let rc_frame = locked.get(context.vmcs).unwrap();
    log::trace!("vcpu: trying to switch to the context.vmcs frame");
    vcpu.switch_frame(rc_frame.frame).unwrap();
    log::trace!("do_vmclear");
    if let Err(e) = vmptrld(addr) {
        log::error!("failed to vmptrld: {:?}", e);
    }
    log::trace!("vcpu: trying to switch back to the original frame");
    vcpu.switch_frame(orig_frame).unwrap();
    log::trace!("vcpu: switched back");
    Ok(())
}

pub fn do_invpid(
    current: Handle<Domain>,
    domain: LocalCapa,
    vcpu: &mut ActiveVmcs<'static>,
    core: usize,
    ext: usize,
    vpid: usize,
    gva: usize,
) -> Result<(), CapaError>{
    Ok(())
}

pub fn do_invept(
    current: Handle<Domain>,
    domain: LocalCapa,
    vcpu: &mut ActiveVmcs<'static>,
    core: usize,
    ext: usize,
    eptp: usize,
    gpa: usize,
) -> Result<(), CapaError> {
    Ok(())
}

pub fn do_vmlaunch(
    current: &mut Handle<Domain>,
    domain: LocalCapa,
    vcpu: &mut ActiveVmcs<'static>,
    core: usize,
) -> Result<(), CapaError> {
    let mut engine = CAPA_ENGINE.lock();
    let domain = engine.get_domain_capa(*current, domain)?;
    let current_ctx = get_context(*current, core);
    let next_ctx = get_context(domain, core);
    let next_domain = get_domain(domain);

    log::info!("switching the domain");
    switch_domain(vcpu, current_ctx, next_ctx, next_domain)
        .expect("Failed to perform the switch");
    *current = domain;
    log::info!("vmlaunch on vcpu: {:?}", vcpu);
    if let Err(e) = vmlaunch(vcpu) {
         log::error!("failed to vmlaunch: {:?}", e);
         log::debug!("fresh vcpu: {:#?}", vcpu);
    }
    log::debug!("after vmlaunch");

    Ok(())
}

fn vmcs_read(field: usize) -> Result<u64, VmxError> {
    unsafe { vmx::raw::vmread(field as u64).map(|value| value as u64) }
}

fn vmcs_write(field: usize, value: usize) -> Result<(), VmxError> {
    unsafe { vmx::raw::vmwrite(field as u64, value as u64) }
}

fn vmclear(addr: usize) -> Result<(), VmxError> {
    unsafe { vmx::raw::vmclear(addr as u64) }
}

fn vmptrld(addr: usize) -> Result<(), VmxError> {
    unsafe { vmx::raw::vmptrld(addr as u64) }
}

// TODO
fn invpid() -> Result<(), VmxError> {
    Ok(())
}

// TODO
fn invept() -> Result<(), VmxError> {
    Ok(())
}

fn vmlaunch(vcpu: &mut ActiveVmcs<'static>) -> Result<(), VmxError> {
    unsafe { vmx::raw::vmlaunch(vcpu) }
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
    UpdateVmcs32 {
        field: u64,
        value: u32,
    },
    UpdateVmcs64 {
        field: u64,
        value: u64,
    },
    UpdateVmcsDefault {},
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
            capa_engine::Update::UpdateVmcs32 { core, field, value } => {
                let mut core_updates = CORE_UPDATES[core as usize].lock();
                core_updates.push(CoreUpdate::UpdateVmcs32 {
                    field: field,
                    value: value,
                });
            }
            capa_engine::Update::UpdateVmcs64 { core, field, value } => {
                let mut core_updates = CORE_UPDATES[core as usize].lock();
                core_updates.push(CoreUpdate::UpdateVmcs64 {
                    field: field,
                    value: value,
                });
            }
            capa_engine::Update::UpdateVmcsDefault { core } => {
                let mut core_updates = CORE_UPDATES[core as usize].lock();
                core_updates.push(CoreUpdate::UpdateVmcsDefault {});
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
            CoreUpdate::UpdateVmcs32 { field, value } => {
                use fields::traits::*;
                log::trace!("Update VMCS32 field {:#x} to value {:#x}", field, value);
                if let Ok(ctrl32) = fields::Ctrl32::try_from(field) {
                    unsafe { ctrl32.vmwrite(value) };
                }
            }
            CoreUpdate::UpdateVmcs64 { field, value } => {
                use fields::traits::*;
                log::trace!("Update VMCS64 field {:#x} to value {:#x}", field, value);
                if let Ok(ctrl64) = fields::Ctrl64::try_from(field) {
                    unsafe { ctrl64.vmwrite(value) };
                } else if let Ok(ctrl_nat) = fields::CtrlNat::try_from(field) {
                    unsafe { ctrl_nat.vmwrite(value as usize) };
                }
                // TODO: probably need these
                /*
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
                */
            }
            CoreUpdate::UpdateVmcsDefault {} => {
                use fields::traits::*;
                // one call to setup as many non-binary dependant registers as possible
                unsafe {
                    fields::Ctrl32::PinBasedExecCtrls.vmwrite(0x000000ff);
                    fields::Ctrl32::PrimaryProcBasedExecCtrls.vmwrite(0xb5a06dfa);
                    fields::Ctrl32::SecondaryProcBasedVmExecCtrls.vmwrite(0x00000be3);
                    fields::Ctrl32::ExceptionBitmap.vmwrite(0xffffffff);
                    fields::Ctrl64::MsrBitmaps.vmwrite(0x109ab0000);
                    fields::Ctrl64::EoiExitBitmap0.vmwrite(0x00000001);
                    fields::Ctrl64::EoiExitBitmap1.vmwrite(0x00000000);
                    fields::Ctrl64::EoiExitBitmap2.vmwrite(0x00000000);
                    fields::Ctrl64::EoiExitBitmap3.vmwrite(0x00000000);
                    fields::Ctrl64::PostedIntDescAddr.vmwrite(0x109aa9f40);
                    fields::Ctrl32::PageFaultErrCodeMask.vmwrite(0x0);
                    fields::Ctrl32::PageFaultErrCodeMatch.vmwrite(0x0);
                    fields::Ctrl32::Cr3TargetCount.vmwrite(0x0);
                    fields::GuestState64::VmcsLinkPtr.vmwrite(0xffffffffffffffff);
                    fields::Ctrl32::VmExitMsrLoadCount.vmwrite(0);
                    fields::Ctrl32::VmExitMsrStoreCount.vmwrite(0);
                    fields::Ctrl32::VmEntryMsrLoadCount.vmwrite(0);
                }
                // Default States
                // CS
                vcpu.set_nat(fields::GuestStateNat::CsBase, 0xffff0000);
                vcpu.set32(fields::GuestState32::CsLimit, 0x0000ffff);
                vcpu.set16(fields::GuestState16::CsSelector, 0x0000f000);
                vcpu.set32(fields::GuestState32::CsAccessRights, 0x0000009b);
                // DS
                vcpu.set_nat(fields::GuestStateNat::DsBase, 0x0);
                vcpu.set32(fields::GuestState32::DsLimit, 0x0000ffff);
                vcpu.set16(fields::GuestState16::DsSelector, 0);
                vcpu.set32(fields::GuestState32::DsAccessRights, 0x93);
                // ES
                vcpu.set_nat(fields::GuestStateNat::EsBase, 0x0);
                vcpu.set32(fields::GuestState32::EsLimit, 0x0000ffff);
                vcpu.set16(fields::GuestState16::EsSelector, 0);
                vcpu.set32(fields::GuestState32::EsAccessRights, 0x93);
                // FS
                vcpu.set_nat(fields::GuestStateNat::FsBase, 0x0);
                vcpu.set32(fields::GuestState32::FsLimit, 0x0000ffff);
                vcpu.set16(fields::GuestState16::FsSelector, 0);
                vcpu.set32(fields::GuestState32::FsAccessRights, 0x93);
                // GS
                vcpu.set_nat(fields::GuestStateNat::GsBase, 0x0);
                vcpu.set32(fields::GuestState32::GsLimit, 0x0);
                vcpu.set16(fields::GuestState16::GsSelector, 0);
                vcpu.set32(fields::GuestState32::GsAccessRights, 0x93);
                // SS
                vcpu.set_nat(fields::GuestStateNat::SsBase, 0x0);
                vcpu.set32(fields::GuestState32::SsLimit, 0x0000ffff);
                vcpu.set16(fields::GuestState16::SsSelector, 0);
                vcpu.set32(fields::GuestState32::SsAccessRights, 0x93);
                // TR
                vcpu.set_nat(fields::GuestStateNat::TrBase, 0x0);
                vcpu.set32(fields::GuestState32::TrLimit, 0x0000ffff); // At least 0x67
                vcpu.set16(fields::GuestState16::TrSelector, 0);
                vcpu.set32(fields::GuestState32::TrAccessRights, 0x8b);
                // LDTR
                vcpu.set_nat(fields::GuestStateNat::LdtrBase, 0x0);
                vcpu.set32(fields::GuestState32::LdtrLimit, 0x0000ffff);
                vcpu.set16(fields::GuestState16::LdtrSelector, 0);
                vcpu.set32(fields::GuestState32::LdtrAccessRights, 0x82);
                // GDTR
                vcpu.set_nat(fields::GuestStateNat::GdtrBase, 0x0);
                vcpu.set32(fields::GuestState32::GdtrLimit, 0x0000ffff);
                // IDTR
                vcpu.set_nat(fields::GuestStateNat::IdtrBase, 0x0);
                vcpu.set32(fields::GuestState32::IdtrLimit, 0x0000ffff);

                vcpu.set32(fields::GuestState32::ActivityState, 0);
                vcpu.set64(fields::GuestState64::VmcsLinkPtr, u64::max_value());
                vcpu.set16(fields::GuestState16::InterruptStatus, 0);
                vcpu.set32(fields::GuestState32::VmxPreemptionTimerValue, 0xffffffff);
                vcpu.set_nat(fields::GuestStateNat::Rflags, 0x2);
            }
        }
    }
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
            CoreUpdate::UpdateVmcs32 { field, value } => {
                write!(f, "UpdateVmcs32(field={:#x}, value={:#})", field, value)
            }
            CoreUpdate::UpdateVmcs64 { field, value } => {
                write!(f, "UpdateVmcs64(field={:#x}, value={:#})", field, value)
            }
            CoreUpdate::UpdateVmcsDefault {} => {
                write!(f, "UpdateVmcsDefault")
            }
        }
    }
}
