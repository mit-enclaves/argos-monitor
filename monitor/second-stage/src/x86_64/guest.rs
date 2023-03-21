//! VMX guest backend

use core::arch::asm;
use core::cell::RefMut;

use capabilities::cpu::CPU;
use monitor::tyche::Tyche;
use monitor::{Monitor, MonitorState, Parameters};
use vmx::bitmaps::exit_qualification;
use vmx::{ActiveVmcs, ControlRegister, Register, VmxExitReason};

use super::backend::BackendX86;
use crate::error::TycheError;
use crate::guest::{Guest, HandlerResult};
use crate::println;

pub struct GuestX86<'a> {
    pub state: MonitorState<'a, BackendX86>,
    pub monitor: Tyche,
}

impl<'active> GuestX86<'active> {
    pub fn new(s: MonitorState<'active, BackendX86>) -> Self {
        Self {
            state: s,
            monitor: Tyche {},
        }
    }

    pub fn get_local_cpu(&self) -> RefMut<CPU<BackendX86>> {
        let current = self.state.get_current_cpu();
        self.state.resources.pools.cpus.get_mut(current.handle)
    }
}

impl<'active> Guest for GuestX86<'active> {
    type Error = TycheError;
    type ExitReason = vmx::VmxExitReason;

    fn launch(&mut self) -> Result<Self::ExitReason, Self::Error> {
        let mut cpu = self.get_local_cpu();
        let vcpu = cpu.core.get_active_mut()?;
        unsafe {
            let exit_reason = vcpu.launch()?;
            Ok(exit_reason)
        }
    }

    fn resume(&mut self) -> Result<Self::ExitReason, Self::Error> {
        let mut cpu = self.get_local_cpu();
        let vcpu = cpu.core.get_active_mut()?;
        unsafe {
            let exit_reason = vcpu.resume()?;
            Ok(exit_reason)
        }
    }

    fn handle_exit(
        &mut self,
        reason: Self::ExitReason,
    ) -> Result<crate::guest::HandlerResult, Self::Error> {
        let dump = |vcpu: &mut ActiveVmcs| {
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
                let mut cpu = self.get_local_cpu();
                let vcpu = cpu.core.get_active_mut()?;
                let params = Parameters {
                    vmcall: vcpu.get(Register::Rax) as usize,
                    arg_1: vcpu.get(Register::Rdx) as usize,
                    arg_2: vcpu.get(Register::Rsi) as usize,
                    arg_3: vcpu.get(Register::Rdx) as usize,
                    arg_4: vcpu.get(Register::Rcx) as usize,
                    arg_5: vcpu.get(Register::R8) as usize,
                    arg_6: vcpu.get(Register::R9) as usize,
                    arg_7: vcpu.get(Register::R10) as usize,
                };
                drop(vcpu);
                drop(cpu);
                if self.monitor.is_exit(&self.state, &params) {
                    let mut cpu = self.get_local_cpu();
                    let mut vcpu = cpu.core.get_active_mut()?;
                    dump(&mut vcpu);
                    Ok(HandlerResult::Exit)
                } else {
                    let advance = match self.monitor.dispatch(&mut self.state, &params) {
                        Ok(values) => {
                            let mut cpu = self.get_local_cpu();
                            let vcpu = cpu.core.get_active_mut()?;
                            vcpu.set(Register::Rax, 0);
                            vcpu.set(Register::Rcx, values.value_1 as u64);
                            vcpu.set(Register::Rdx, values.value_2 as u64);
                            vcpu.set(Register::Rsi, values.value_3 as u64);
                            vcpu.set(Register::R9, values.value_4 as u64);
                            values.next_instr
                        }
                        Err(err) => {
                            let mut cpu = self.get_local_cpu();
                            let mut vcpu = cpu.core.get_active_mut()?;
                            dump(&mut vcpu);
                            println!("The error: {:?}", err);
                            match err {
                                capabilities::error::Error::Capability(code) => {
                                    vcpu.set(Register::Rax, code as u64);
                                }
                                capabilities::error::Error::Backend(_) => panic!("Backend error"),
                            };
                            true
                        }
                    };
                    if advance {
                        let mut cpu = self.get_local_cpu();
                        let vcpu = cpu.core.get_active_mut()?;
                        vcpu.next_instruction()?;
                    }
                    Ok(HandlerResult::Resume)
                }
            }
            VmxExitReason::Cpuid => {
                let mut cpu = self.get_local_cpu();
                let vcpu = cpu.core.get_active_mut()?;
                let input_eax = vcpu.get(Register::Rax);
                let input_ecx = vcpu.get(Register::Rcx);
                let eax: u64;
                let ebx: u64;
                let ecx: u64;
                let edx: u64;

                unsafe {
                    // Note: LLVM reserves %rbx for its internal use, so we need to use a scratch
                    // register for %rbx here.
                    asm!(
                        "mov {tmp}, rbx",
                        "cpuid",
                        "mov rbx, {tmp}",
                        tmp = out(reg) ebx ,
                        inout("rax") input_eax => eax,
                        inout("rcx") input_ecx => ecx,
                        out("rdx") edx,
                    )
                }
                vcpu.set(Register::Rax, eax);
                vcpu.set(Register::Rbx, ebx);
                vcpu.set(Register::Rcx, ecx);
                vcpu.set(Register::Rdx, edx);
                vcpu.next_instruction()?;
                Ok(HandlerResult::Resume)
            }
            VmxExitReason::ControlRegisterAccesses => {
                let mut cpu = self.get_local_cpu();
                let vcpu = cpu.core.get_active_mut()?;
                let qualification = vcpu.exit_qualification()?.control_register_accesses();
                match qualification {
                    exit_qualification::ControlRegisterAccesses::MovToCr(cr, reg) => {
                        if cr != ControlRegister::Cr4 {
                            todo!("Handle {:?}", cr);
                        }
                        let value = vcpu.get(reg) as usize;
                        vcpu.set_cr4_shadow(value)?;
                        let real_value = value | (1 << 13); // VMXE
                        vcpu.set_cr(cr, real_value);

                        vcpu.next_instruction()?;
                    }
                    _ => todo!("Emulation not yet implemented for {:?}", qualification),
                };
                Ok(HandlerResult::Resume)
            }
            VmxExitReason::EptViolation => {
                let mut cpu = self.get_local_cpu();
                let vcpu = cpu.core.get_active_mut()?;
                let addr = vcpu.guest_phys_addr()?;
                println!(
                    "EPT Violation! virt: 0x{:x}, phys: 0x{:x}",
                    vcpu.guest_linear_addr()
                        .expect("unable to get the virt addr")
                        .as_u64(),
                    addr.as_u64()
                );
                println!("The vcpu {:x?}", vcpu);
                Ok(HandlerResult::Crash)
            }
            VmxExitReason::Xsetbv => {
                let mut cpu = self.get_local_cpu();
                let vcpu = cpu.core.get_active_mut()?;
                let ecx = vcpu.get(Register::Rcx);
                let eax = vcpu.get(Register::Rax);
                let edx = vcpu.get(Register::Rdx);

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

                vcpu.next_instruction()?;
                Ok(HandlerResult::Resume)
            }
            VmxExitReason::Wrmsr => {
                let mut cpu = self.get_local_cpu();
                let vcpu = cpu.core.get_active_mut()?;
                let ecx = vcpu.get(Register::Rcx);
                if ecx >= 0x4B564D00 && ecx <= 0x4B564DFF {
                    // Custom MSR range, used by KVM
                    // See https://docs.kernel.org/virt/kvm/x86/msr.html
                    // TODO: just ignore them for now, should add support in the future
                    vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                } else {
                    println!("Unknown MSR: 0x{:x}", ecx);
                    Ok(HandlerResult::Crash)
                }
            }
            VmxExitReason::Rdmsr => {
                let mut cpu = self.get_local_cpu();
                let vcpu = cpu.core.get_active_mut()?;
                let ecx = vcpu.get(Register::Rcx);
                if ecx == 0xc0011029 {
                    // Reading an AMD specifig register, just ignore it
                    vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                } else {
                    println!("Unexpected rdmsr number: {:#x}", ecx);
                    Ok(HandlerResult::Crash)
                }
            }
            VmxExitReason::Exception => {
                let mut cpu = self.get_local_cpu();
                let vcpu = cpu.core.get_active_mut()?;
                match vcpu.interrupt_info() {
                    Ok(Some(exit)) => {
                        println!("Exception: {:?}", vcpu.interrupt_info());
                        dump(vcpu);
                        // Inject the fault back into the guest.
                        let injection = exit.as_injectable_u32();
                        vcpu.set_vm_entry_interruption_information(injection)?;
                        Ok(HandlerResult::Resume)
                    }
                    _ => {
                        println!("VM received an exception");
                        println!("{:?}", vcpu);
                        Ok(HandlerResult::Crash)
                    }
                }
            }
            _ => {
                println!(
                    "Emulation is not yet implemented for exit reason: {:?}",
                    reason
                );
                let cpu = self.get_local_cpu();
                let vcpu = cpu.core.get_active()?;
                println!("{:?}", vcpu);
                Ok(HandlerResult::Crash)
            }
        }
    }
}

/*
use core::arch;
use core::arch::asm;

use capabilities::State;
use mmu::FrameAllocator;
use stage_two_abi::{GuestInfo, Manifest};
use vmx::bitmaps::{
    EntryControls, ExceptionBitmap, ExitControls, PinbasedControls, PrimaryControls,
    SecondaryControls,
};
use vmx::fields::traits::*;
use vmx::{fields, secondary_controls_capabilities, ActiveVmcs, Register, VmxError};

//use super::Arch;
use crate::allocator::Allocator;
use crate::arch::backend::BackendX86;
use crate::debug::qemu;
use crate::monitor_state::MonitorState;
//use crate::guest::{Guest, HandlerResult};
use crate::println;
use crate::statics::{allocator as get_allocator, pool as get_pool};

pub fn launch_guest(manifest: &'static Manifest) {
    if !manifest.info.loaded {
        println!("No guest found, exiting");
        return;
    }
    // Create the backend.
    let mut backend = BackendX86 {
        allocator: Allocator::new(
            get_allocator(),
            (manifest.voffset - manifest.poffset) as usize,
        ),
        manifest: &manifest,
        iommu: None,
        vmxon: None,
    };
    // Setup the iommu.
    backend.set_iommu(manifest.iommu);

    // Initialize the backend, this creates the vmxon.
    backend.init();

    // Create the capability state.
    let capas = State::<BackendX86> {
        backend: &mut backend,
        pools: get_pool(),
    };

    // Create the MonitorState.
    // This call creates:
    // 1) The default domain.
    // 2) The default memory region.
    // 3) The default vcpus.
    // The state is then passed to the guest.
    let tyche_state = match MonitorState::<BackendX86>::new(&manifest, &capas) {
        Ok(ts) => ts,
        Err(e) => {
            println!("Unable to create MonitorState {:?}", e);
            qemu::exit(qemu::ExitCode::Failure);
        }
    };

    /*let frame = backend
        .allocator
        .allocate_frame()
        .expect("Failed to allocate VMXON")
        .zeroed();
    unsafe {
        println!("Init the guest");
        let vmxon = match vmx::vmxon(frame) {
            Ok(vmxon) => {
                println!("VMXON: ok(vmxon)");
                vmxon
            }
            Err(err) => {
                println!("VMXON: {:?}", err);
                qemu::exit(qemu::ExitCode::Failure);
            }
        };

        let mut vmcs = init_vm(&vmxon, &mut backend.allocator);
        let vmcs = init_vm(&vmxon, &mut allocator);
        println!("Done with the guest init");
        let _vcpu = vmcs.set_as_active().expect("Failed to activate VMCS");
        //let _arch = Arch::new(manifest.iommu);

        /*let domains_arena = get_domains_arena();
        let regions_arena = get_regions_arena();
        let hypercalls = Hypercalls::new(
            &manifest,
            arch,
            &mut vcpu,
            &mut allocator,
            domains_arena,
            regions_arena,
        );
        init_vcpu(&mut vcpu, &manifest.info, &mut allocator);

        // Hook for debugging.
        debug::tyche_hook_stage2(1);

        println!("Launching");
        let mut guest = VmxGuest::new(&mut vcpu, hypercalls, &mut allocator);
        guest.main_loop();*/
    }*/

    qemu::exit(qemu::ExitCode::Success);
}
*/

/*

pub struct VmxGuest<'vmx, const N: usize> {
    vcpu: &'vmx mut vmx::ActiveVmcs<'vmx>,
    hypercalls: Hypercalls<Arch>,
    allocator: &'vmx Allocator<N>,
}

impl<'vmx, const N: usize> VmxGuest<'vmx, N> {
    pub fn new(
        vcpu: &'vmx mut ActiveVmcs<'vmx>,
        hypercalls: Hypercalls<Arch>,
        allocator: &'vmx Allocator<N>,
    ) -> Self {
        Self {
            vcpu,
            hypercalls,
            allocator,
        }
    }
}

impl<'vcpu, const N: usize> Guest for VmxGuest<'vcpu, N> {
    type ExitReason = vmx::VmxExitReason;

    type Error = vmx::VmxError;

    fn launch(&mut self) -> Result<Self::ExitReason, Self::Error> {
        unsafe { self.vcpu.launch() }
    }

    fn resume(&mut self) -> Result<Self::ExitReason, Self::Error> {
        unsafe { self.vcpu.resume() }
    }

    fn handle_exit(&mut self, reason: VmxExitReason) -> Result<HandlerResult, Self::Error> {
        let vcpu = &mut *self.vcpu;
        let dump = |vcpu: &mut ActiveVmcs| {
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
                    vmcall: vcpu.get(Register::Rax) as usize,
                    arg_1: vcpu.get(Register::Rcx) as usize,
                    arg_2: vcpu.get(Register::Rdx) as usize,
                    arg_3: vcpu.get(Register::Rsi) as usize,
                    arg_4: vcpu.get(Register::R9) as usize,
                };
                if self.hypercalls.is_exit(&params) {
                    dump(vcpu);
                    Ok(HandlerResult::Exit)
                } else {
                    let advance = match self.hypercalls.dispatch(self.allocator, vcpu, params) {
                        Ok(values) => {
                            vcpu.set(Register::Rax, ErrorCode::Success as u64);
                            vcpu.set(Register::Rcx, values.value_1 as u64);
                            vcpu.set(Register::Rdx, values.value_2 as u64);
                            vcpu.set(Register::Rsi, values.value_3 as u64);
                            vcpu.set(Register::R9, values.value_4 as u64);
                            values.next_instr
                        }
                        Err(err) => {
                            dump(vcpu);
                            println!("The error: {:?}", err);
                            vcpu.set(Register::Rax, err as u64);
                            true
                        }
                    };
                    if advance {
                        vcpu.next_instruction()?;
                    }
                    Ok(HandlerResult::Resume)
                }
            }
            VmxExitReason::Cpuid => {
                let input_eax = vcpu.get(Register::Rax);
                let input_ecx = vcpu.get(Register::Rcx);
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

                vcpu.set(Register::Rax, eax);
                vcpu.set(Register::Rbx, ebx);
                vcpu.set(Register::Rcx, ecx);
                vcpu.set(Register::Rdx, edx);

                vcpu.next_instruction()?;
                Ok(HandlerResult::Resume)
            }
            VmxExitReason::ControlRegisterAccesses => {
                let qualification = vcpu.exit_qualification()?.control_register_accesses();
                match qualification {
                    exit_qualification::ControlRegisterAccesses::MovToCr(cr, reg) => {
                        if cr != ControlRegister::Cr4 {
                            todo!("Handle {:?}", cr);
                        }
                        let value = vcpu.get(reg) as usize;
                        vcpu.set_cr4_shadow(value)?;
                        let real_value = value | (1 << 13); // VMXE
                        vcpu.set_cr(cr, real_value);

                        vcpu.next_instruction()?;
                    }
                    _ => todo!("Emulation not yet implemented for {:?}", qualification),
                };
                Ok(HandlerResult::Resume)
            }
            VmxExitReason::EptViolation => {
                let addr = vcpu.guest_phys_addr()?;
                println!(
                    "EPT Violation! virt: 0x{:x}, phys: 0x{:x}",
                    vcpu.guest_linear_addr()
                        .expect("unable to get the virt addr")
                        .as_u64(),
                    addr.as_u64()
                );
                println!("The vcpu {:x?}", vcpu);
                Ok(HandlerResult::Crash)
            }
            VmxExitReason::Xsetbv => {
                let ecx = vcpu.get(Register::Rcx);
                let eax = vcpu.get(Register::Rax);
                let edx = vcpu.get(Register::Rdx);

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

                vcpu.next_instruction()?;
                Ok(HandlerResult::Resume)
            }
            VmxExitReason::Wrmsr => {
                let ecx = vcpu.get(Register::Rcx);
                if ecx >= 0x4B564D00 && ecx <= 0x4B564DFF {
                    // Custom MSR range, used by KVM
                    // See https://docs.kernel.org/virt/kvm/x86/msr.html
                    // TODO: just ignore them for now, should add support in the future
                    vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                } else {
                    println!("Unknown MSR: 0x{:x}", ecx);
                    Ok(HandlerResult::Crash)
                }
            }
            VmxExitReason::Exception => {
                match vcpu.interrupt_info() {
                    Ok(Some(exit)) => {
                        println!("Exception: {:?}", vcpu.interrupt_info());
                        // Inject the fault back into the guest.
                        let injection = exit.as_injectable_u32();
                        vcpu.set_vm_entry_interruption_information(injection)?;
                        Ok(HandlerResult::Resume)
                    }
                    _ => {
                        println!("VM received an exception");
                        println!("{:?}", vcpu);
                        Ok(HandlerResult::Crash)
                    }
                }
            }
            _ => {
                println!(
                    "Emulation is not yet implemented for exit reason: {:?}",
                    reason
                );
                println!("{:?}", vcpu);
                Ok(HandlerResult::Crash)
            }
        }
    }
}
*/

/*pub unsafe fn init_vm<'vmx>(
    vmxon: &'vmx vmx::Vmxon,
    allocator: &impl FrameAllocator,
) -> vmx::VmcsRegion<'vmx> {
    let frame = allocator
        .allocate_frame()
        .expect("Failed to allocate VMCS")
        .zeroed();
    match vmxon.create_vm(frame) {
        Err(err) => {
            println!("VMCS: Err({:?})", err);
            qemu::exit(qemu::ExitCode::Failure);
        }
        Ok(vmcs) => {
            println!("VMCS: Ok()");
            vmcs
        }
    }
}*/

/*
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
    secondary_ctrls |= unrestricted_guest_secondary_controls();
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
    let cpuid = unsafe { arch::x86_64::__cpuid(7) };
    if cpuid.ebx & vmx::CPUID_EBX_X64_FEATURE_INVPCID != 0 {
        controls |= SecondaryControls::ENABLE_INVPCID;
    }
    return controls;
}

fn unrestricted_guest_secondary_controls() -> SecondaryControls {
    let mut controls = SecondaryControls::empty();
    let vmx_misc = unsafe { vmx::msr::VMX_MISC.read() };
    if vmx_misc & (1 << 5) != 0 {
        controls |= SecondaryControls::UNRESTRICTED_GUEST;
    }
    controls
}

/// Saves the host state (control registers, segments...), so that they are restored on VM Exit.
pub fn save_host_state<'vmx>(
    _vmcs: &mut ActiveVmcs<'vmx>,
    info: &GuestInfo,
) -> Result<(), VmxError> {
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
*/
