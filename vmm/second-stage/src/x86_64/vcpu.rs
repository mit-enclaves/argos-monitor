use super::guest::VMX_GUEST;
use crate::debug::qemu;
use crate::hypercalls::{self, ErrorCode, Parameters};
use crate::println;
use crate::vcpu::HandlerResult;
use crate::vcpu::Vcpu;
use crate::x86_64::guest::get_allocator_static;
use crate::x86_64::MAX_NB_CPU;
use core::arch::asm;
use core::sync::atomic::*;
use mmu::FrameAllocator;
use stage_two_abi::{GuestInfo, Manifest};
use utils::{Frame, GuestPhysAddr, GuestVirtAddr, HostPhysAddr};
use vmx::bitmaps::{
    exit_qualification, EntryControls, ExceptionBitmap, ExitControls, PinbasedControls,
    PrimaryControls, SecondaryControls,
};
use vmx::fields::traits::*;
use vmx::{bitmaps, ept, fields, msr};
use vmx::{
    ControlRegister, Register, VmExitInterrupt, VmxError, VmxExitQualification, VmxExitReason,
};

const FALSE: AtomicBool = AtomicBool::new(false);
pub static mut VCPU_INIT: [AtomicBool; MAX_NB_CPU] = [FALSE; MAX_NB_CPU];
const INITCPU: Option<X86Vcpu> = None;
pub static mut VCPUS: [Option<X86Vcpu>; MAX_NB_CPU] = [INITCPU; MAX_NB_CPU];

pub unsafe fn new(manifest: &Manifest, cpuid: usize) -> &'static Option<X86Vcpu> {
    VCPUS[cpuid] = Some(X86Vcpu::new(cpuid));
    VCPUS[cpuid].as_mut().unwrap().setup(manifest);
    assert_eq!(
        VCPU_INIT[cpuid].compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst),
        Ok(false),
        "CPU {} already initialized",
        cpuid
    );
    &VCPUS[cpuid]
}

pub struct X86Vcpu<'active, 'vmx> {
    // Virtual identifier for VCPU
    pub vcpu_id: usize,
    // VMXON Region
    pub vmxon_region: Option<vmx::Vmxon>,
    // VMCS Region
    pub vmcs_region: Option<vmx::VmcsRegion<'vmx>>,
    // Current active VMCS: one active VMCS per logical processor
    pub active_vmcs: Option<vmx::ActiveVmcs<'active, 'vmx>>,
}

impl<'active, 'vmx> Vcpu for X86Vcpu<'active, 'vmx>
where
    'active: 'vmx,
{
    type ExitReason = vmx::VmxExitReason;

    type Error = vmx::VmxError;

    /// Launch the VM.
    ///
    /// SAFETY: the VMCS must be properly configured so that the host can resume execution in a
    /// sensible environment. A simple way of ensuring that is to save the current environment as
    /// host state.
    fn launch(&mut self) -> Result<VmxExitReason, VmxError> {
        unsafe { self.active_vmcs.as_mut().unwrap().launch() }
    }

    /// Resume the VM.
    ///
    /// SAFETY: the VMCS must be properly configured so that the host can resume execution in a
    /// sensible environment. A simple way of ensuring that is to save the current environment as
    /// host state.
    fn resume(&mut self) -> Result<VmxExitReason, VmxError> {
        unsafe { self.active_vmcs.as_mut().unwrap().resume() }
    }

    fn handle_exit(&mut self, reason: VmxExitReason) -> Result<HandlerResult, Self::Error> {
        let dump = |vcpu: &mut X86Vcpu<'active, 'vmx>| {
            let rip = vcpu.get(Register::Rip);
            let rax = vcpu.get(Register::Rax);
            let rcx = vcpu.get(Register::Rcx);
            let rbp = vcpu.get(Register::Rbp);
            println!(
                "VM Exit: {:?} - rip: 0x{:x} - rbp: 0x{:x} - rax: 0x{:x} - rcx: 0x{:x}",
                reason, rip, rbp, rax, rcx
            );
        };

        match reason {
            VmxExitReason::Vmcall => {
                let params = Parameters {
                    vmcall: self.get(Register::Rax) as usize,
                    arg_1: self.get(Register::Rcx) as usize,
                    arg_2: self.get(Register::Rdx) as usize,
                    arg_3: self.get(Register::Rsi) as usize,
                    arg_4: self.get(Register::R9) as usize,
                };
                let vmx_guest = unsafe { VMX_GUEST[self.vcpu_id].as_mut().unwrap() };
                if vmx_guest.hypercalls.is_exit(&params) {
                    dump(self);
                    Ok(HandlerResult::Exit)
                } else {
                    let advance =
                        match vmx_guest
                            .hypercalls
                            .dispatch(vmx_guest.allocator, self, params)
                        {
                            Ok(values) => {
                                self.set(Register::Rax, ErrorCode::Success as u64);
                                self.set(Register::Rcx, values.value_1 as u64);
                                self.set(Register::Rdx, values.value_2 as u64);
                                self.set(Register::Rsi, values.value_3 as u64);
                                self.set(Register::R9, values.value_4 as u64);
                                values.next_instr
                            }
                            Err(err) => {
                                dump(self);
                                println!("The error: {:?}", err);
                                self.set(Register::Rax, err as u64);
                                true
                            }
                        };
                    if advance {
                        self.next_instruction()?;
                    }
                    Ok(HandlerResult::Resume)
                }
            }
            VmxExitReason::Cpuid => {
                let input_eax = self.get(Register::Rax);
                let input_ecx = self.get(Register::Rcx);
                let eax: u64;
                let ebx: u64;
                let ecx: u64;
                let edx: u64;

                unsafe {
                    // Note: LLVM reserves %rbx for its internal use, so we need to use a scratch
                    // register for %rbx here.
                    asm!(
                        "mov rbx, {tmp}",
                        "cpuid",
                        "mov {tmp}, rbx",
                        tmp = out(reg) ebx ,
                        inout("rax") input_eax => eax,
                        inout("rcx") input_ecx => ecx,
                        out("rdx") edx,
                    )
                }

                self.set(Register::Rax, eax);
                self.set(Register::Rbx, ebx);
                self.set(Register::Rcx, ecx);
                self.set(Register::Rdx, edx);

                self.next_instruction()?;
                Ok(HandlerResult::Resume)
            }
            VmxExitReason::ControlRegisterAccesses => {
                let qualification = self.exit_qualification()?.control_register_accesses();
                match qualification {
                    exit_qualification::ControlRegisterAccesses::MovToCr(cr, reg) => {
                        if cr != ControlRegister::Cr4 {
                            todo!("Handle {:?}", cr);
                        }
                        let value = self.get(reg) as usize;
                        self.set_cr4_shadow(value)?;
                        let real_value = value | (1 << 13); // VMXE
                        self.set_cr(cr, real_value);

                        self.next_instruction()?;
                    }
                    _ => todo!(
                        "vCPU{}: Emulation not yet implemented for {:?}",
                        self.vcpu_id,
                        qualification
                    ),
                };
                Ok(HandlerResult::Resume)
            }
            VmxExitReason::InitSignal => {
                println!("vCPU{} (Host) received IPI", self.vcpu_id);
                Ok(HandlerResult::Resume)
            }
            VmxExitReason::EptViolation => {
                let addr = self.guest_phys_addr()?;
                println!(
                    "EPT Violation! virt: 0x{:x}, phys: 0x{:x}",
                    self.guest_linear_addr()
                        .expect("unable to get the virt addr")
                        .as_u64(),
                    addr.as_u64()
                );
                println!("The vcpu {:x?}", self.active_vmcs);
                Ok(HandlerResult::Crash)
            }
            VmxExitReason::Xsetbv => {
                let ecx = self.get(Register::Rcx);
                let eax = self.get(Register::Rax);
                let edx = self.get(Register::Rdx);

                let xrc_id = ecx & 0xFFFFFFFF; // Ignore 32 high-order bits
                if xrc_id != 0 {
                    println!("Xsetbv: invalid rcx 0x{:x}", ecx);
                    return Ok(HandlerResult::Crash);
                }

                unsafe {
                    asm!(
                        "xsetbv",
                        in("ecx") ecx,
                        in("eax") eax,
                        in("edx") edx,
                    );
                }

                self.next_instruction()?;
                Ok(HandlerResult::Resume)
            }
            VmxExitReason::Wrmsr => {
                let ecx = self.get(Register::Rcx);

                if ecx == 0x832 || ecx == 0x838 || ecx == 0x839 || ecx == 0x83e {
                    let mut msr = msr::Msr::new(ecx as u32);
                    let rax = self.get(Register::Rax);
                    let rdx = self.get(Register::Rdx);

                    println!("rax={}, rdx={}", rax, rdx);

                    // let low = value as u32;
                    // let high = (value >> 32) as u32;
                    unsafe { msr.write(((rdx as u64) << 32) | (rax as u64)) };

                    // msr.read();
                    Ok(HandlerResult::Resume)
                } else if ecx >= 0x4B564D00 && ecx <= 0x4B564DFF {
                    // Custom MSR range, used by KVM
                    // See https://docs.kernel.org/virt/kvm/x86/msr.html
                    // TODO: just ignore them for now, should add support in the future
                    self.next_instruction()?;
                    Ok(HandlerResult::Resume)
                } else {
                    println!("Unknown MSR: 0x{:x}", ecx);
                    Ok(HandlerResult::Crash)
                }
            }
            VmxExitReason::Rdmsr => {
                let ecx = self.get(Register::Rcx);
                if ecx == 0x832 || ecx == 0x838 || ecx == 0x839 || ecx == 0x83e {
                    let msr = msr::Msr::new(ecx as u32);
                    // let rax = self.get(Register::Rax);
                    // let rdx = self.get(Register::Rdx);
                    // let low = value as u32;
                    // let high = (value >> 32) as u32;
                    let result = unsafe { msr.read() };
                    println!("result={}", result);
                    self.set(Register::Rax, result);
                    self.set(Register::Rdx, result << 32);
                }
                println!("MSR: {:#x}", ecx);
                self.next_instruction()?;
                Ok(HandlerResult::Resume)
            }
            VmxExitReason::Exception => {
                match self.interrupt_info() {
                    Ok(Some(exit)) => {
                        println!("Exception: {:?}", self.interrupt_info());
                        println!("VM received an exception on vector {}", exit.vector);
                        println!("{:?}", self.active_vmcs);
                        self.next_instruction()?;
                        // Inject the fault back into the guest.
                        let injection = exit.as_injectable_u32();
                        self.set_vm_entry_interruption_information(injection)?;
                        Ok(HandlerResult::Resume)
                    }
                    _ => {
                        println!("VM received an exception");
                        println!("{:?}", self.active_vmcs);
                        Ok(HandlerResult::Crash)
                    }
                }
            }
            VmxExitReason::VmxPreemptionTimerExpired => {
                self.set32(
                    fields::GuestState32::VmxPreemptionTimerValue,
                    24_000_000,
                    /* u32::max_value() */
                )?;
                unsafe {
                    println!(
                        "VCPU{}: Rip={:#x}, Timer Interrupt Count={}",
                        self.vcpu_id,
                        self.active_vmcs.as_ref().unwrap().get(Register::Rip),
                        hypercalls::TIMER_INTERRUPT_COUNTER
                    );
                }
                Ok(HandlerResult::Resume)
            }
            _ => {
                println!(
                    "vCPU{}: Emulation is not yet implemented for exit reason: {:?}",
                    self.vcpu_id, reason
                );
                println!("{:?}", self.active_vmcs);
                Ok(HandlerResult::Crash)
            }
        }
    }

    fn main_loop(&mut self) {
        let mut result = self.launch();
        //let mut counter = 0;
        loop {
            let exit_reason = match result {
                Ok(exit_reason) => self
                    .handle_exit(exit_reason)
                    .expect("Failed to handle VM exit"),
                Err(err) => {
                    println!("vCPU{} crashed: {:?}", self.vcpu_id, err);
                    println!("{:?}", self.active_vmcs);
                    HandlerResult::Crash
                }
            };

            if exit_reason != HandlerResult::Resume {
                println!("Exiting guest: {:?}", exit_reason);
                break;
            }

            // Shutdown after too many VM exits
            /*counter += 1;
            if counter >= 200000 {
                println!("Too many iterations: stoping guest");
                break;
            }*/

            // Resume VM
            result = self.resume();
        }
    }
}

impl<'active, 'vmx> X86Vcpu<'active, 'vmx> {
    unsafe fn new(cpuid: usize) -> Self {
        Self {
            vcpu_id: cpuid,
            vmxon_region: None,
            vmcs_region: None,
            active_vmcs: None,
        }
    }

    unsafe fn setup(&'static mut self, _manifest: &Manifest) {
        use vmx::Vmxon;

        let allocator = get_allocator_static().as_ref().unwrap();

        // VMXON
        let frame = allocator
            .allocate_frame()
            .expect("Failed to allocate VMXON")
            .zeroed();
        self.vmxon_region = {
            let vmxon = match vmx::vmxon(frame) {
                Ok(vmxon) => {
                    println!("VMXON: ok(vmxon)");
                    vmxon
                }
                Err(err) => {
                    println!("VMXON: {:?}", err);
                    qemu::exit(qemu::ExitCode::Failure)
                }
            };
            Some(vmxon)
        };

        // VMCS
        let frame = allocator
            .allocate_frame()
            .expect("Failed to allocate VMCS")
            .zeroed();
        self.vmcs_region = {
            match Vmxon::create_vm(self.vmxon_region.as_mut().unwrap(), frame) {
                Err(err) => {
                    println!("VMCS: Err({:?})", err);
                    qemu::exit(qemu::ExitCode::Failure);
                }
                Ok(vmcs) => {
                    println!("VMCS: Ok()");
                    Some(vmcs)
                }
            }
        };

        println!("Done with the guest init");

        // VMPTRLD
        self.active_vmcs = Some(
            self.vmcs_region
                .as_mut()
                .unwrap()
                .set_as_active()
                .expect("Failed to activate VMCS"),
        );

        // Self::init_vcpu(
        //     self.active_vmcs.as_mut().unwrap(),
        //     &manifest.info,
        //     allocator,
        // );
    }

    pub unsafe fn init_vcpu(
        &mut self,
        info: &GuestInfo,
        allocator: &impl FrameAllocator,
        _vcpu_id: usize,
    ) {
        self.default_vmcs_config(info, false);
        let bit_frame = allocator
            .allocate_frame()
            .expect("Failed to allocate MSR bitmaps")
            .zeroed();
        let msr_bitmaps = self
            .initialize_msr_bitmaps(bit_frame)
            .expect("Failed to install MSR bitmaps");
        msr_bitmaps.allow_all();
        // msr_bitmaps.deny_read(msr::IA32_X2APIC_LVT_TIMER);
        // msr_bitmaps.deny_read(msr::IA32_X2APIC_INIT_COUNT);
        // msr_bitmaps.deny_read(msr::IA32_X2APIC_CUR_COUNT);
        // msr_bitmaps.deny_read(msr::IA32_X2APIC_DIV_CONF);
        // msr_bitmaps.deny_write(msr::IA32_X2APIC_LVT_TIMER);
        // msr_bitmaps.deny_write(msr::IA32_X2APIC_INIT_COUNT);
        // msr_bitmaps.deny_write(msr::IA32_X2APIC_CUR_COUNT);
        // msr_bitmaps.deny_write(msr::IA32_X2APIC_DIV_CONF);

        self.set_nat(fields::GuestStateNat::Rip, info.rip).ok();
        self.set_nat(fields::GuestStateNat::Cr3, info.cr3).ok();
        self.set_nat(fields::GuestStateNat::Rsp, info.rsp).ok();
        self.set(Register::Rsi, info.rsi as u64);
        // Zero out the gdt and idt.
        self.set_nat(fields::GuestStateNat::GdtrBase, 0x0).ok();
        self.set_nat(fields::GuestStateNat::IdtrBase, 0x0).ok();
        // FIXME
        // VMXE flags, required during VMX operations.
        let vmxe = 1 << 13;
        let cr4 = 0xA0 | vmxe;
        self.set_nat(fields::GuestStateNat::Cr4, cr4).unwrap();
        self.set_cr4_mask(vmxe).unwrap();
        self.set_cr4_shadow(vmxe).unwrap();
        vmx::check::check().expect("check error");
    }

    fn default_vmcs_config(&mut self, info: &GuestInfo, switching: bool) {
        // Look for XSAVES capabilities
        let capabilities =
            vmx::secondary_controls_capabilities().expect("Secondary controls are not supported");
        let xsaves = capabilities.contains(SecondaryControls::ENABLE_XSAVES_XRSTORS);

        let err = self
            .set_pin_based_ctrls(PinbasedControls::VMX_PREEMPTION_TIMER)
            .and_then(|_| {
                self.set_vm_exit_ctrls(
                    ExitControls::HOST_ADDRESS_SPACE_SIZE
                        | ExitControls::LOAD_IA32_EFER
                        | ExitControls::SAVE_IA32_EFER
                        | ExitControls::SAVE_VMX_PREEMPTION_TIMER,
                )
            })
            .and_then(|_| {
                self.set_vm_entry_ctrls(
                    EntryControls::IA32E_MODE_GUEST | EntryControls::LOAD_IA32_EFER,
                )
            })
            .and_then(|_| self.set_exception_bitmap(ExceptionBitmap::INVALID_OPCODE))
            .and_then(|_| self.save_host_state(info))
            .and_then(|_| self.setup_guest(info));
        println!("Config: {:?}", err);
        println!("MSRs:   {:?}", configure_msr());
        println!(
            "1'Ctrl: {:?}",
            self.set_primary_ctrls(
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

        secondary_ctrls |= unrestricted_guest_secondary_controls();
        secondary_ctrls |= cpuid_secondary_controls();
        println!("2'Ctrl: {:?}", self.set_secondary_ctrls(secondary_ctrls));
        println!("VMX Preemption Timer Rate={}", vmx_preemption_timer_rate());
    }

    /// Saves the host state (control registers, segments...), so that they are restored on VM Exit.
    fn save_host_state(&mut self, info: &GuestInfo) -> Result<(), VmxError> {
        // NOTE: See section 24.5 of volume 3C.

        let tr: u16;
        let gdt = super::arch::get_gdt_descriptor();
        let idt = super::arch::get_idt_descriptor();

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

    fn setup_guest(&mut self, info: &GuestInfo) -> Result<(), VmxError> {
        // Mostly copied from https://nixhacker.com/developing-hypervisor-from-scratch-part-4/

        // Control registers
        let cr0: usize;
        let cr3: usize;
        let cr4: usize;
        unsafe {
            asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));

            self.set_nat(fields::GuestStateNat::Cr0, cr0)?;
            asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
            self.set_nat(fields::GuestStateNat::Cr3, cr3)?;
            asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
            self.set_nat(fields::GuestStateNat::Cr4, cr4)?;
        }

        // Segments selectors
        self.set16(fields::GuestState16::EsSelector, 0)?;
        self.set16(fields::GuestState16::CsSelector, 0)?;
        self.set16(fields::GuestState16::SsSelector, 0)?;
        self.set16(fields::GuestState16::DsSelector, 0)?;
        self.set16(fields::GuestState16::FsSelector, 0)?;
        self.set16(fields::GuestState16::GsSelector, 0)?;
        self.set16(fields::GuestState16::TrSelector, 0)?;
        self.set16(fields::GuestState16::LdtrSelector, 0)?;
        // Segments access rights
        self.set32(fields::GuestState32::CsAccessRights, 0xA09B)?;
        self.set32(fields::GuestState32::DsAccessRights, 0xA093)?;
        self.set32(fields::GuestState32::EsAccessRights, 0xA093)?;
        self.set32(fields::GuestState32::FsAccessRights, 0xA093)?;
        self.set32(fields::GuestState32::GsAccessRights, 0xA093)?;
        self.set32(fields::GuestState32::SsAccessRights, 0xA093)?;


        self.set32(fields::GuestState32::TrAccessRights, 0x0080 | 11)?;
        self.set32(fields::GuestState32::LdtrAccessRights, 0x0082)?;
        // Segments limits
        self.set32(fields::GuestState32::EsLimit, 0xFFFFFFFF)?;
        self.set32(fields::GuestState32::CsLimit, 0xFFFFFFFF)?;
        self.set32(fields::GuestState32::SsLimit, 0xFFFFFFFF)?;
        self.set32(fields::GuestState32::DsLimit, 0xFFFFFFFF)?;
        self.set32(fields::GuestState32::FsLimit, 0xFFFFFFFF)?;
        self.set32(fields::GuestState32::GsLimit, 0xFFFFFFFF)?;
        self.set32(fields::GuestState32::TrLimit, 0xFF)?; // At least 0x67
        self.set32(fields::GuestState32::LdtrLimit, 0)?;
        self.set32(fields::GuestState32::GdtrLimit, 0)?;
        self.set32(fields::GuestState32::IdtrLimit, 0)?;
        // Segments bases
        self.set_nat(fields::GuestStateNat::EsBase, 0)?;
        self.set_nat(fields::GuestStateNat::CsBase, 0)?;
        self.set_nat(fields::GuestStateNat::SsBase, 0)?;
        self.set_nat(fields::GuestStateNat::DsBase, 0)?;
        self.set_nat(fields::GuestStateNat::FsBase, 0)?;
        self.set_nat(fields::GuestStateNat::GsBase, 0)?;
        self.set_nat(fields::GuestStateNat::TrBase, 0)?;
        self.set_nat(fields::GuestStateNat::LdtrBase, 0)?;
        self.set_nat(fields::GuestStateNat::GdtrBase, 0)?;
        self.set_nat(fields::GuestStateNat::IdtrBase, 0)?;

        // MSRs
        if fields::GuestState64::Ia32Efer.is_unsupported() {
            println!("Ia32Efer field is not supported");
        }
        self.set64(fields::GuestState64::Ia32Efer, info.efer)?;
        self.set_nat(fields::GuestStateNat::Rflags, 0x2 | 0x0200)?;

        self.set32(fields::GuestState32::ActivityState, 0)?;
        self.set64(fields::GuestState64::VmcsLinkPtr, u64::max_value())?;
        self.set16(fields::GuestState16::InterruptStatus, 0)?;
        // vcpu.set16(fields::GuestState16::PmlIndex, 0)?; // <- Not supported on dev server
        self.set32(
            fields::GuestState32::VmxPreemptionTimerValue,
            24_000_000, /* u32::max_value() */
        )?;

        Ok(())
    }

    /// Deactivates the region.
    pub fn deactivate(self) -> Result<(), VmxError> {
        self.active_vmcs.unwrap().deactivate()
    }

    /// Returns a given register.
    pub fn get(&self, register: Register) -> u64 {
        self.active_vmcs.as_ref().unwrap().get(register)
    }

    ///s Set a given register.
    pub fn set(&mut self, register: Register, value: u64) {
        self.active_vmcs.as_mut().unwrap().set(register, value)
    }

    /// Sets a given control register.
    pub fn set_cr(&mut self, register: ControlRegister, value: usize) {
        self.active_vmcs.as_mut().unwrap().set_cr(register, value)
    }

    /// Returns a given control register.
    pub fn get_cr(&self, register: ControlRegister) -> usize {
        self.active_vmcs.as_ref().unwrap().get_cr(register)
    }

    pub fn set16(&mut self, field: fields::GuestState16, value: u16) -> Result<(), VmxError> {
        self.active_vmcs.as_mut().unwrap().set16(field, value)
    }

    pub fn set32(&mut self, field: fields::GuestState32, value: u32) -> Result<(), VmxError> {
        self.active_vmcs.as_mut().unwrap().set32(field, value)
    }

    pub fn set64(&mut self, field: fields::GuestState64, value: u64) -> Result<(), VmxError> {
        self.active_vmcs.as_mut().unwrap().set64(field, value)
    }

    pub fn set_nat(&mut self, field: fields::GuestStateNat, value: usize) -> Result<(), VmxError> {
        self.active_vmcs.as_mut().unwrap().set_nat(field, value)
    }

    pub fn next_instruction(&mut self) -> Result<(), VmxError> {
        self.active_vmcs.as_mut().unwrap().next_instruction()
    }

    /// Returns the exit reason.
    pub fn exit_reason(&self) -> Result<VmxExitReason, VmxError> {
        self.active_vmcs.as_ref().unwrap().exit_reason()
    }

    /// Returns the exit qualification.
    pub fn exit_qualification(&self) -> Result<VmxExitQualification, VmxError> {
        self.active_vmcs.as_ref().unwrap().exit_qualification()
    }

    /// Returns the guest physical address.
    ///
    /// This field is set on VM exits due to EPT violations and EPT misconfigurations.
    /// See section 27.2.1 for details of when and how this field is used.
    pub fn guest_phys_addr(&self) -> Result<GuestPhysAddr, VmxError> {
        self.active_vmcs.as_ref().unwrap().guest_phys_addr()
    }

    /// Returns the guest virtual address.
    ///
    /// This field is set for some VM exits. See section 27.2.1 for details of when and how this
    /// field is used.
    pub fn guest_linear_addr(&self) -> Result<GuestVirtAddr, VmxError> {
        self.active_vmcs.as_ref().unwrap().guest_linear_addr()
    }

    pub fn interrupt_info(&self) -> Result<Option<VmExitInterrupt>, VmxError> {
        self.active_vmcs.as_ref().unwrap().interrupt_info()
    }

    /// Initializes the MSR bitmaps, default to deny all reads and writes.
    ///
    /// SAFETY: The frame must be valid and becomes entirely owned by the VMCS, that is any future
    /// access to the frame while the VMCS is still alive is undefined behavior.
    pub unsafe fn initialize_msr_bitmaps(
        &mut self,
        frame: Frame,
    ) -> Result<&mut msr::MsrBitmaps, VmxError> {
        self.active_vmcs
            .as_mut()
            .unwrap()
            .initialize_msr_bitmaps(frame)
    }

    /// Returns a mutable reference to the MSR bitmaps, if any.
    pub fn get_msr_bitmaps(&mut self) -> Option<&mut msr::MsrBitmaps> {
        self.active_vmcs.as_mut().unwrap().get_msr_bitmaps()
    }

    /// Sets the pin-based controls.
    pub fn set_pin_based_ctrls(&mut self, flags: PinbasedControls) -> Result<(), VmxError> {
        self.active_vmcs
            .as_mut()
            .unwrap()
            .set_pin_based_ctrls(flags)
    }

    /// Sets the primary processor-based controls.
    pub fn set_primary_ctrls(&mut self, flags: PrimaryControls) -> Result<(), VmxError> {
        self.active_vmcs.as_mut().unwrap().set_primary_ctrls(flags)
    }

    /// Sets the secondary processor-based controls.
    pub fn set_secondary_ctrls(&mut self, flags: SecondaryControls) -> Result<(), VmxError> {
        self.active_vmcs
            .as_mut()
            .unwrap()
            .set_secondary_ctrls(flags)
    }

    /// Sets the VM exit controls.
    pub fn set_vm_exit_ctrls(&mut self, flags: ExitControls) -> Result<(), VmxError> {
        self.active_vmcs.as_mut().unwrap().set_vm_exit_ctrls(flags)
    }

    /// Sets the VM entry controls.
    pub fn set_vm_entry_ctrls(&mut self, flags: EntryControls) -> Result<(), VmxError> {
        self.active_vmcs.as_mut().unwrap().set_vm_entry_ctrls(flags)
    }

    /// Returns the VM entry controls.
    pub fn get_vm_entry_cntrls(&self) -> Result<EntryControls, VmxError> {
        self.active_vmcs.as_ref().unwrap().get_vm_entry_cntrls()
    }

    /// Sets the VM Entry interruption information field.
    pub fn set_vm_entry_interruption_information(&mut self, flags: u32) -> Result<(), VmxError> {
        self.active_vmcs
            .as_mut()
            .unwrap()
            .set_vm_entry_interruption_information(flags)
    }

    /// Sets the Cr0 guest/host mask.
    ///
    /// Bits set to 1 will be read from the Cr0 shadow and modification attempt wills cause VM
    /// exits.
    pub fn set_cr0_mask(&mut self, cr0_mask: usize) -> Result<(), VmxError> {
        self.active_vmcs.as_mut().unwrap().set_cr0_mask(cr0_mask)
    }

    /// Sets the Cr4 guest/host mask.
    ///
    /// Bits set to 1 will be read from the Cr4 shadow and modification attempt wills cause VM
    /// exits.
    pub fn set_cr4_mask(&mut self, cr4_mask: usize) -> Result<(), VmxError> {
        self.active_vmcs.as_mut().unwrap().set_cr4_mask(cr4_mask)
    }

    /// Sets the Cr0 read shadow.
    pub fn set_cr0_shadow(&mut self, cr0_shadow: usize) -> Result<(), VmxError> {
        self.active_vmcs
            .as_mut()
            .unwrap()
            .set_cr0_shadow(cr0_shadow)
    }

    /// Sets the Cr4 read shadow.
    pub fn set_cr4_shadow(&mut self, cr4_shadow: usize) -> Result<(), VmxError> {
        self.active_vmcs
            .as_mut()
            .unwrap()
            .set_cr4_shadow(cr4_shadow)
    }

    /// Sets the exception bitmap.
    pub fn set_exception_bitmap(&mut self, bitmap: ExceptionBitmap) -> Result<(), VmxError> {
        self.active_vmcs
            .as_mut()
            .unwrap()
            .set_exception_bitmap(bitmap)
    }

    /// Gets the exception bitmap.
    pub fn get_exception_bitmap(&self) -> Result<ExceptionBitmap, VmxError> {
        self.active_vmcs.as_ref().unwrap().get_exception_bitmap()
    }

    /// Sets the extended page table (EPT) pointer.
    pub fn set_ept_ptr(&mut self, ept_ptr: HostPhysAddr) -> Result<(), VmxError> {
        self.active_vmcs.as_mut().unwrap().set_ept_ptr(ept_ptr)
    }

    /// Sets the EPTP address list.
    pub fn set_eptp_list(&mut self, eptp_list: &ept::EptpList) -> Result<(), VmxError> {
        self.active_vmcs.as_mut().unwrap().set_eptp_list(eptp_list)
    }

    /// Enable the vmfunc controls.
    pub fn set_vmfunc_ctrls(&mut self, flags: bitmaps::VmFuncControls) -> Result<(), VmxError> {
        self.active_vmcs.as_mut().unwrap().set_vmfunc_ctrls(flags)
    }
}

fn configure_msr() -> Result<(), VmxError> {
    unsafe {
        fields::Ctrl32::VmExitMsrLoadCount.vmwrite(0)?;
        fields::Ctrl32::VmExitMsrStoreCount.vmwrite(0)?;
        fields::Ctrl32::VmEntryMsrLoadCount.vmwrite(0)?;
    }

    Ok(())
}

fn unrestricted_guest_secondary_controls() -> SecondaryControls {
    let mut controls = SecondaryControls::empty();
    let vmx_misc = unsafe { msr::VMX_MISC.read() };
    if vmx_misc & (1 << 5) != 0 {
        controls |= SecondaryControls::UNRESTRICTED_GUEST;
    }
    controls
}

fn vmx_preemption_timer_rate() -> u8 {
    let vmx_misc = unsafe { msr::VMX_MISC.read() };
    (vmx_misc & 0x1F) as u8
}

/// Returns optional secondary controls depending on the host cpuid.
fn cpuid_secondary_controls() -> SecondaryControls {
    let mut controls = SecondaryControls::empty();
    let cpuid = unsafe { core::arch::x86_64::__cpuid(7) };
    if cpuid.ebx & vmx::CPUID_EBX_X64_FEATURE_INVPCID != 0 {
        controls |= SecondaryControls::ENABLE_INVPCID;
    }
    return controls;
}
