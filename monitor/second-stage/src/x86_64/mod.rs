//! x86_64 backend for stage 2

mod arch;
pub mod backend;
pub mod guest;

use core::arch as platform;
use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};

use capabilities::State;
use mmu::FrameAllocator;
use monitor::MonitorState;
use stage_two_abi::{GuestInfo, Manifest};
use vmx::bitmaps::{
    EntryControls, ExceptionBitmap, ExitControls, PinbasedControls, PrimaryControls,
    SecondaryControls,
};
use vmx::fields::traits::*;
use vmx::{fields, secondary_controls_capabilities, ActiveVmcs, Register, VmxError};

use crate::allocator::Allocator;
use crate::arch::backend::BackendX86;
use crate::debug::qemu;
use crate::debug::qemu::ExitCode;
//use crate::guest::{Guest, HandlerResult};
use crate::println;
use crate::statics::{allocator as get_allocator, pool as get_pool};

pub use vmx::VmxError as Error;

// ————————————————————————————— Configuration —————————————————————————————— //

/// Maximum number of CPU supported.
const MAX_NB_CPU: usize = 128;

// ————————————————————————————— Entry Barrier —————————————————————————————— //

/// APs will wait for the entry barrier to be `true` before jumping into stage 2.
#[used]
#[export_name = "__entry_barrier"]
static ENTRY_BARRIER: AtomicBool = AtomicBool::new(false);

// —————————————————————————————— x86_64 Arch ——————————————————————————————— //

pub fn launch_guest(manifest: &'static Manifest) {
    if !manifest.info.loaded {
        println!("No guest found, exiting");
        return;
    }

    // Create the capability state.
    let mut capas = State::<BackendX86> {
        backend: BackendX86 {
            allocator: Allocator::new(
                get_allocator(),
                (manifest.voffset - manifest.poffset) as usize,
            ),
            guest_info: manifest.info,
            iommu: None,
            vmxon: None,
        },
        pools: get_pool(),
    };
    capas.backend.set_iommu(manifest.iommu);
    capas.backend.init();

    // Create the MonitorState.
    // This call creates:
    // 1) The default domain.
    // 2) The default memory region.
    // 3) The default vcpus.
    // The state is then passed to the guest.
    let _tyche_state = match MonitorState::<BackendX86>::new(manifest.poffset as usize, capas) {
        Ok(ts) => ts,
        Err(e) => {
            println!("Unable to create MonitorState {:?}", e);
            qemu::exit(qemu::ExitCode::Failure);
        }
    };

    //TODO create guestx86 and call mainloop

    qemu::exit(qemu::ExitCode::Success);
}

pub unsafe fn init_vcpu<'vmx>(
    vcpu: &mut ActiveVmcs<'vmx>,
    info: &GuestInfo,
    allocator: &impl FrameAllocator,
) {
    default_vmcs_config(vcpu, info, false);
    let bit_frame = allocator
        .allocate_frame()
        .expect("Failed to allocate MSR bitmaps")
        .zeroed();
    let msr_bitmaps = vcpu
        .initialize_msr_bitmaps(bit_frame)
        .expect("Failed to install MSR bitmaps");
    msr_bitmaps.allow_all();
    vcpu.set_nat(fields::GuestStateNat::Rip, info.rip).ok();
    vcpu.set_nat(fields::GuestStateNat::Cr3, info.cr3).ok();
    vcpu.set_nat(fields::GuestStateNat::Rsp, info.rsp).ok();
    vcpu.set(Register::Rsi, info.rsi as u64);
    // Zero out the gdt and idt.
    vcpu.set_nat(fields::GuestStateNat::GdtrBase, 0x0).ok();
    vcpu.set_nat(fields::GuestStateNat::IdtrBase, 0x0).ok();
    // VMXE flags, required during VMX operations.
    let vmxe = 1 << 13;
    let cr4 = 0xA0 | vmxe;
    vcpu.set_nat(fields::GuestStateNat::Cr4, cr4).unwrap();
    vcpu.set_cr4_mask(vmxe).unwrap();
    vcpu.set_cr4_shadow(vmxe).unwrap();
    vmx::check::check().expect("check error");
}

pub fn default_vmcs_config(vmcs: &mut ActiveVmcs, info: &GuestInfo, switching: bool) {
    // Look for XSAVES capabilities
    let capabilities =
        secondary_controls_capabilities().expect("Secondary controls are not supported");
    let xsaves = capabilities.contains(SecondaryControls::ENABLE_XSAVES_XRSTORS);

    let err = vmcs
        .set_pin_based_ctrls(PinbasedControls::empty())
        .and_then(|_| {
            vmcs.set_vm_exit_ctrls(
                ExitControls::HOST_ADDRESS_SPACE_SIZE
                    | ExitControls::LOAD_IA32_EFER
                    | ExitControls::SAVE_IA32_EFER,
            )
        })
        .and_then(|_| {
            vmcs.set_vm_entry_ctrls(EntryControls::IA32E_MODE_GUEST | EntryControls::LOAD_IA32_EFER)
        })
        .and_then(|_| vmcs.set_exception_bitmap(ExceptionBitmap::INVALID_OPCODE))
        .and_then(|_| save_host_state(vmcs, info))
        .and_then(|_| setup_guest(vmcs, info));
    println!("Config: {:?}", err);
    println!("MSRs:   {:?}", configure_msr());
    println!(
        "1'Ctrl: {:?}",
        vmcs.set_primary_ctrls(
            PrimaryControls::SECONDARY_CONTROLS | PrimaryControls::USE_MSR_BITMAPS
        )
    );

    let mut secondary_ctrls = SecondaryControls::ENABLE_RDTSCP | SecondaryControls::ENABLE_EPT;
    if switching {
        secondary_ctrls |= SecondaryControls::ENABLE_VM_FUNCTIONS
    }
    if xsaves {
        secondary_ctrls |= SecondaryControls::ENABLE_XSAVES_XRSTORS;
    }
    secondary_ctrls |= cpuid_secondary_controls();
    println!("2'Ctrl: {:?}", vmcs.set_secondary_ctrls(secondary_ctrls));
}

fn configure_msr() -> Result<(), VmxError> {
    unsafe {
        fields::Ctrl32::VmExitMsrLoadCount.vmwrite(0)?;
        fields::Ctrl32::VmExitMsrStoreCount.vmwrite(0)?;
        fields::Ctrl32::VmEntryMsrLoadCount.vmwrite(0)?;
    }

    Ok(())
}

fn setup_guest(vcpu: &mut ActiveVmcs, info: &GuestInfo) -> Result<(), VmxError> {
    // Mostly copied from https://nixhacker.com/developing-hypervisor-from-scratch-part-4/

    // Control registers
    let cr0: usize;
    let cr3: usize;
    let cr4: usize;
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        vcpu.set_nat(fields::GuestStateNat::Cr0, cr0)?;
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        vcpu.set_nat(fields::GuestStateNat::Cr3, cr3)?;
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        vcpu.set_nat(fields::GuestStateNat::Cr4, cr4)?;
    }

    // Segments selectors
    vcpu.set16(fields::GuestState16::EsSelector, 0)?;
    vcpu.set16(fields::GuestState16::CsSelector, 0)?;
    vcpu.set16(fields::GuestState16::SsSelector, 0)?;
    vcpu.set16(fields::GuestState16::DsSelector, 0)?;
    vcpu.set16(fields::GuestState16::FsSelector, 0)?;
    vcpu.set16(fields::GuestState16::GsSelector, 0)?;
    vcpu.set16(fields::GuestState16::TrSelector, 0)?;
    vcpu.set16(fields::GuestState16::LdtrSelector, 0)?;
    // Segments access rights
    vcpu.set32(fields::GuestState32::EsAccessRights, 0xC093)?;
    vcpu.set32(fields::GuestState32::CsAccessRights, 0xA09B)?;
    vcpu.set32(fields::GuestState32::SsAccessRights, 0x10000)?;
    vcpu.set32(fields::GuestState32::DsAccessRights, 0xC093)?;
    vcpu.set32(fields::GuestState32::FsAccessRights, 0x10000)?;
    vcpu.set32(fields::GuestState32::GsAccessRights, 0x10000)?;
    vcpu.set32(fields::GuestState32::TrAccessRights, 0x8B)?;
    vcpu.set32(fields::GuestState32::LdtrAccessRights, 0x10000)?;
    // Segments limits
    vcpu.set32(fields::GuestState32::EsLimit, 0xFFFF)?;
    vcpu.set32(fields::GuestState32::CsLimit, 0xFFFF)?;
    vcpu.set32(fields::GuestState32::SsLimit, 0xFFFF)?;
    vcpu.set32(fields::GuestState32::DsLimit, 0xFFFF)?;
    vcpu.set32(fields::GuestState32::FsLimit, 0xFFFF)?;
    vcpu.set32(fields::GuestState32::GsLimit, 0xFFFF)?;
    vcpu.set32(fields::GuestState32::TrLimit, 0xFF)?; // At least 0x67
    vcpu.set32(fields::GuestState32::LdtrLimit, 0xFFFF)?;
    vcpu.set32(fields::GuestState32::GdtrLimit, 0xFFFF)?;
    vcpu.set32(fields::GuestState32::IdtrLimit, 0xFFFF)?;
    // Segments bases
    vcpu.set_nat(fields::GuestStateNat::EsBase, 0)?;
    vcpu.set_nat(fields::GuestStateNat::CsBase, 0)?;
    vcpu.set_nat(fields::GuestStateNat::SsBase, 0)?;
    vcpu.set_nat(fields::GuestStateNat::DsBase, 0)?;
    vcpu.set_nat(fields::GuestStateNat::FsBase, 0)?;
    vcpu.set_nat(fields::GuestStateNat::GsBase, 0)?;
    vcpu.set_nat(fields::GuestStateNat::TrBase, 0)?;
    vcpu.set_nat(fields::GuestStateNat::LdtrBase, 0)?;
    vcpu.set_nat(fields::GuestStateNat::GdtrBase, 0)?;
    vcpu.set_nat(fields::GuestStateNat::IdtrBase, 0)?;

    // MSRs
    if fields::GuestState64::Ia32Efer.is_unsupported() {
        println!("Ia32Efer field is not supported");
    }
    vcpu.set64(fields::GuestState64::Ia32Efer, info.efer)?;
    vcpu.set_nat(fields::GuestStateNat::Rflags, 0x2)?;

    vcpu.set32(fields::GuestState32::ActivityState, 0)?;
    vcpu.set64(fields::GuestState64::VmcsLinkPtr, u64::max_value())?;
    vcpu.set16(fields::GuestState16::InterruptStatus, 0)?;
    // vcpu.set16(fields::GuestState16::PmlIndex, 0)?; // <- Not supported on dev server
    vcpu.set32(fields::GuestState32::VmxPreemptionTimerValue, 0)?;

    Ok(())
}

/// Returns optional secondary controls depending on the host cpuid.
fn cpuid_secondary_controls() -> SecondaryControls {
    let mut controls = SecondaryControls::empty();
    let cpuid = unsafe { platform::x86_64::__cpuid(7) };
    if cpuid.ebx & vmx::CPUID_EBX_X64_FEATURE_INVPCID != 0 {
        controls |= SecondaryControls::ENABLE_INVPCID;
    }
    return controls;
}

/// Saves the host state (control registers, segments...), so that they are restored on VM Exit.
pub fn save_host_state<'vmx>(
    _vmcs: &mut ActiveVmcs<'vmx>,
    info: &GuestInfo,
) -> Result<(), VmxError> {
    // NOTE: See section 24.5 of volume 3C.

    let tr: u16;
    let gdt = arch::get_gdt_descriptor();
    let idt = arch::get_idt_descriptor();

    unsafe {
        // There is no nice wrapper to read `tr` in the x86_64 crate.
        asm!("str {0:x}",
                out(reg) tr,
                options(att_syntax, nostack, nomem, preserves_flags));
    }

    unsafe {
        fields::HostState16::CsSelector.vmwrite(info.cs)?;
        fields::HostState16::DsSelector.vmwrite(info.ds)?;
        fields::HostState16::EsSelector.vmwrite(info.es)?;
        fields::HostState16::FsSelector.vmwrite(info.fs)?;
        fields::HostState16::GsSelector.vmwrite(info.gs)?;
        fields::HostState16::SsSelector.vmwrite(info.ss)?;
        fields::HostState16::TrSelector.vmwrite(tr)?;

        // NOTE: those might throw an exception depending on the CPU features, let's just
        // ignore them for now.
        // VmcsHostStateNat::FsBase.vmwrite(FS::read_base().as_u64() as usize)?;
        // VmcsHostStateNat::GsBase.vmwrite(GS::read_base().as_u64() as usize)?;

        fields::HostStateNat::IdtrBase.vmwrite(idt.base as usize)?;
        fields::HostStateNat::GdtrBase.vmwrite(gdt.base as usize)?;

        // Save TR base
        // let tr_offset = (tr >> 3) as usize;
        // let gdt = gdt::gdt().as_raw_slice();
        // let low = gdt[tr_offset];
        // let high = gdt[tr_offset + 1];
        // let tr_base = get_tr_base(high, low);
        // fields::HostStateNat::TrBase.vmwrite(tr_base as usize)?;
    }

    // MSRs
    unsafe {
        fields::HostState64::Ia32Efer.vmwrite(info.efer)?;
    }

    // Control registers
    let cr0: usize;
    let cr3: usize;
    let cr4: usize;
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        fields::HostStateNat::Cr0.vmwrite(cr0)?;
        fields::HostStateNat::Cr3.vmwrite(cr3)?;
        fields::HostStateNat::Cr4.vmwrite(cr4)
    }
}

// —————————————————————————————— x86_64 Arch ——————————————————————————————— //
/*
pub struct Arch {
    iommu: Option<Iommu>,
}

pub struct Context {
    cr3: GuestPhysAddr,
    entry: GuestVirtAddr,
    stack: GuestVirtAddr,
}

pub struct Store {
    ept: HostPhysAddr,
}

impl Arch {
    pub fn new(iommu_addr: u64) -> Self {
        let iommu = if iommu_addr != 0 {
            unsafe { Some(Iommu::new(HostVirtAddr::new(iommu_addr as usize))) }
        } else {
            None
        };
        Self { iommu }
    }

    pub fn convert_to_ept(&self, rights: usize) -> EptEntryFlags {
        let mut def = EptEntryFlags::READ;
        if (rights & access::WRITE) != 0 {
            def |= EptEntryFlags::WRITE;
        }
        if (rights & access::EXEC) != 0 {
            def |= EptEntryFlags::USER_EXECUTE | EptEntryFlags::SUPERVISOR_EXECUTE;
        }
        if (rights & access::WRITE) != 0 {
            def |= EptEntryFlags::WRITE;
        }
        def
    }
}

impl Backend for Arch {
    type Vcpu<'a> = ActiveVmcs<'a>;

    type Store = Store;

    type Context = Context;

    const EMPTY_STORE: Self::Store = Store {
        ept: HostPhysAddr::new(0),
    };

    const EMPTY_CONTEXT: Self::Context = Context {
        cr3: GuestPhysAddr::new(0),
        entry: GuestVirtAddr::new(0),
        stack: GuestVirtAddr::new(0),
    };

    fn debug_iommu(&mut self) -> HypercallResult {
        let iommu = match &mut self.iommu {
            Some(iommu) => iommu,
            None => {
                println!("Missing I/O MMU");
                return Err(ErrorCode::Failure);
            }
        };

        for fault in iommu.iter_fault() {
            println!(
                "I/O MMU fault:\n  addr:   0x{:x}\n  reason: 0x{:x}\n  record: {:?}",
                fault.addr,
                fault.record.reason(),
                fault.record
            );
        }

        Ok(Default::default())
    }

    fn add_region(
        &mut self,
        store: &mut Store,
        region: &Region,
        rights: usize,
        allocator: &impl FrameAllocator,
    ) -> Result<(), ErrorCode> {
        let mut mapper = EptMapper::new(allocator.get_physical_offset().as_usize(), store.ept);
        let flags: EptEntryFlags = self.convert_to_ept(rights);
        mapper.map_range(
            allocator,
            GuestPhysAddr::new(region.start),
            HostPhysAddr::new(region.start),
            region.end - region.start,
            flags,
            //EptEntryFlags::READ | EptEntryFlags::WRITE | EptEntryFlags::USER_EXECUTE | EPT_PRESENT,
        );
        Ok(())
    }

    fn remove_region(
        &mut self,
        store: &mut Store,
        region: &Region,
        allocator: &impl FrameAllocator,
    ) -> Result<(), ErrorCode> {
        let root = store.ept;
        let offset = allocator.get_physical_offset();
        let mut mapper = EptMapper::new(offset.as_usize(), root);
        mapper.unmap_range(
            allocator,
            GuestPhysAddr::new(region.start),
            region.end - region.start,
            root,
            allocator.get_physical_offset().as_usize(),
        );
        Ok(())
    }

    fn domain_create(
        &mut self,
        store: &mut Store,
        allocator: &impl FrameAllocator,
    ) -> Result<(), ErrorCode> {
        let ept = allocator
            .allocate_frame()
            .ok_or(ErrorCode::OutOfMemory)?
            .zeroed();
        store.ept = ept.phys_addr;
        Ok(())
    }

    fn domain_save<'a>(
        &mut self,
        context: &mut Self::Context,
        vcpu: &mut Self::Vcpu<'a>,
    ) -> Result<(), ErrorCode> {
        vcpu.next_instruction()
            .expect("Failed to advance instruction");
        context.cr3 = GuestPhysAddr::new(vcpu.get_cr(ControlRegister::Cr3));
        context.entry = GuestVirtAddr::new(vcpu.get(Register::Rip) as usize);
        context.stack = GuestVirtAddr::new(vcpu.get(Register::Rsp) as usize);
        Ok(())
    }

    fn domain_restore<'a>(
        &mut self,
        store: &Self::Store,
        context: &Self::Context,
        vcpu: &mut Self::Vcpu<'a>,
    ) -> Result<(), ErrorCode> {
        vcpu.set_ept_ptr(HostPhysAddr::new(store.ept.as_usize() | EPT_ROOT_FLAGS))
            .map_err(|_| ErrorCode::DomainSwitchFailed)?;
        vcpu.set_cr(ControlRegister::Cr3, context.cr3.as_usize());
        vcpu.set(Register::Rip, context.entry.as_u64());
        vcpu.set(Register::Rsp, context.stack.as_u64());
        Ok(())
    }

    fn domain_seal(
        &mut self,
        target: usize,
        current: &mut Domain<Self>,
        reg_1: usize,
        reg_2: usize,
        reg_3: usize,
    ) -> HypercallResult {
        let switch_handle = current.switches.allocate()?;
        let mut switch = current.switches.get_mut(switch_handle);
        switch.domain = target;
        switch.context.cr3 = GuestPhysAddr::new(reg_1);
        switch.context.entry = GuestVirtAddr::new(reg_2);
        switch.context.stack = GuestVirtAddr::new(reg_3);
        switch.is_valid = true;
        Ok(Registers {
            value_1: switch_handle.into(),
            ..Default::default()
        })
    }
}*/

/// Architecture specific initialization.
pub fn init(manifest: &Manifest, cpuid: usize) {
    unsafe {
        asm!(
            "mov cr3, {}",
            in(reg) manifest.cr3,
            options(nomem, nostack, preserves_flags)
        );
        if cpuid == 0 {
            arch::init();
        }
        arch::setup(cpuid);
    }

    // In case we use VGA, setup the VGA driver
    #[cfg(feature = "vga")]
    if manifest.vga.is_valid {
        let framebuffer =
            unsafe { core::slice::from_raw_parts_mut(manifest.vga.framebuffer, manifest.vga.len) };
        let writer = vga::Writer::new(
            framebuffer,
            manifest.vga.h_rez,
            manifest.vga.v_rez,
            manifest.vga.stride,
            manifest.vga.bytes_per_pixel,
        );
        vga::init_print(writer);
    }

    // The ENTRY_BARRIER is consumed (set to false) when an AP enters stage 2, once stage 2
    // initialization is done, the AP set the ENTRY_BARRIER back to true.
    ENTRY_BARRIER
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .expect("Unexpected ENTRY_BARRIER value");
}

pub fn cpuid() -> usize {
    let cpuid = unsafe { core::arch::x86_64::__cpuid(0x01) };
    ((cpuid.ebx & 0xffffffff) >> 24) as usize
}

/// Halt the CPU in a spinloop;
pub fn hlt() -> ! {
    loop {
        unsafe { platform::x86_64::_mm_pause() };
    }
}

pub fn exit_qemu(exit_code: ExitCode) {
    const QEMU_EXIT_PORT: u16 = 0xf4;

    unsafe {
        let exit_code = exit_code as u32;
        asm!(
            "out dx, eax",
            in("dx") QEMU_EXIT_PORT,
            in("eax") exit_code,
            options(nomem, nostack, preserves_flags)
        );
    }
}
