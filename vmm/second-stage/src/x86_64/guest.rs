//! VMX guest backend

use super::{Arch, MAX_NB_CPU};
use crate::allocator::Allocator;
use crate::debug::qemu;
use crate::guest::Guest;
use crate::hypercalls::Hypercalls;
use crate::println;
use crate::statics::{
    allocator as get_allocator, domains_arena as get_domains_arena,
    regions_arena as get_regions_arena, NB_PAGES,
};
use crate::vcpu::Vcpu;
use crate::x86_64::vcpu;
use core::sync::atomic::{AtomicBool, Ordering};
use debug;
use stage_two_abi::Manifest;

static mut ALLOCATOR: Option<Allocator<NB_PAGES>> = None;
static ALLOCATOR_IS_LOCKED: AtomicBool = AtomicBool::new(false);
static ALLOCATOR_IS_INITIALIZED: AtomicBool = AtomicBool::new(false);

fn init_allocator(manifest: &Manifest) {
    if ALLOCATOR_IS_LOCKED.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        == Ok(false)
    {
        unsafe {
            ALLOCATOR = Some(Allocator::new(
                get_allocator(),
                (manifest.voffset - manifest.poffset) as usize,
            ));
        }

        ALLOCATOR_IS_INITIALIZED.store(true, Ordering::SeqCst);
    }
}

pub fn get_allocator_static() -> &'static Option<Allocator<NB_PAGES>> {
    while ALLOCATOR_IS_INITIALIZED.load(Ordering::SeqCst) == false {}

    unsafe { &ALLOCATOR }
}

static BSP_GUEST_INIT_DONE: AtomicBool = AtomicBool::new(false);
static mut HYPERCALLS: Option<Hypercalls<Arch>> = None;
pub static mut VMX_GUEST: [Option<VmxGuest<200>>; 8] =
    [None, None, None, None, None, None, None, None];

pub fn launch(manifest: &'static mut Manifest, cpuid: usize) {
    if !manifest.info.loaded {
        println!("No guest found, exiting");
        return;
    }

    init_allocator(&manifest);
    let mut allocator = get_allocator_static().as_ref().unwrap();
    let mut arch = Arch::new(manifest.iommu);
    let mp_mailbox = manifest.mp_mailbox as usize;

    let mut cpus: [i32; MAX_NB_CPU] = [-1; MAX_NB_CPU];
    cpus[0] = cpuid as i32;

    unsafe {
        vcpu::new(manifest, cpuid);

        if cpuid == 0 {
            // Barrier to ensure all vcpus are initialized properly
            for id in 0..manifest.smp {
                while !vcpu::VCPU_INIT[id].load(Ordering::SeqCst) {}
            }

            // Initialize hypercalls
            let domains_arena = get_domains_arena();
            let regions_arena = get_regions_arena();
            HYPERCALLS = Some(Hypercalls::new(
                &manifest,
                arch,
                &mut vcpu::VCPUS,
                allocator,
                domains_arena,
                regions_arena,
            ));

            vcpu::VCPUS[cpuid]
                .as_mut()
                .unwrap()
                .init_vcpu(&manifest.info, allocator, cpuid);

            // Create VmxGuest
            VMX_GUEST[cpuid] = Some(VmxGuest::new(
                cpus,
                HYPERCALLS.as_mut().unwrap(),
                &mut allocator,
            ));

            // Hook for debugging.
            debug::tyche_hook_stage2(1);

            BSP_GUEST_INIT_DONE.store(true, Ordering::SeqCst);

            println!("Launching CPU {}", cpuid);
            VMX_GUEST[cpuid].as_mut().unwrap().start();
        } else {
            // Barrier to ensure the BSP has finished initializing the guest
            while !BSP_GUEST_INIT_DONE.load(Ordering::SeqCst) {}

            HYPERCALLS
                .as_mut()
                .unwrap()
                .init(&mut arch, vcpu::VCPUS[cpuid].as_mut().unwrap());

            vcpu::VCPUS[cpuid]
                .as_mut()
                .unwrap()
                .init_vcpu(&manifest.info, allocator, cpuid);

            // Create VmxGuest
            VMX_GUEST[cpuid] = Some(VmxGuest::new(
                cpus.clone(),
                HYPERCALLS.as_mut().unwrap(),
                &mut allocator,
            ));

            // Spin on the MP Wakeup Page command
            let command = mp_mailbox as *const u16;
            let apic_id = (mp_mailbox + 4) as *const u32;
            let wakeup_vector = (mp_mailbox + 8) as *const u64;
            loop {
                if command.read_volatile() == 1 && apic_id.read_volatile() == (cpuid as u32) {
                    break;
                }
            }

            let wakeup_vector = wakeup_vector.read_volatile();
            println!("Launching CPU {} on wakeup_vector {:#x}", cpuid, wakeup_vector);
            vcpu::VCPUS[cpuid].as_mut().unwrap().set_nat(vmx::fields::GuestStateNat::Rip, wakeup_vector as usize).ok();

            (mp_mailbox as *mut u16).write_volatile(0);

            VMX_GUEST[cpuid].as_mut().unwrap().start();
        }
    }
    qemu::exit(qemu::ExitCode::Success);
}

pub struct VmxGuest<'vmx, const N: usize> {
    vcpus: [i32; MAX_NB_CPU], // directly maps to the static VCPU array
    pub hypercalls: &'static mut Hypercalls<Arch>,
    pub allocator: &'vmx Allocator<N>,
}

impl<'vmx, const N: usize> VmxGuest<'vmx, N> {
    pub fn new(
        vcpus: [i32; MAX_NB_CPU],
        hypercalls: &'static mut Hypercalls<Arch>,
        allocator: &'vmx Allocator<N>,
    ) -> Self {
        Self {
            vcpus,
            hypercalls,
            allocator,
        }
    }
}

impl<'vcpu, const N: usize> Guest for VmxGuest<'static, N> {
    type ExitReason = vmx::VmxExitReason;

    type Error = vmx::VmxError;

    fn start(&mut self) {
        for i in self.vcpus {
            if i == -1 {
                break;
            }
            let vcpu = unsafe { vcpu::VCPUS[i as usize].as_mut().unwrap() };
            vcpu.main_loop();
        }
    }
}
