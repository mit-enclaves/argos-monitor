//! x86_64 backend for stage 2

mod arch;
pub mod backend;
pub mod guest;
mod init;
mod vmx_helper;

use core::arch::asm;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};
use core::{arch as platform, mem};

use arena::Handle;
use capabilities::State;
pub use init::arch_entry_point;
use monitor::MonitorState;
use spin::{Mutex, MutexGuard};
use stage_two_abi::Manifest;
pub use vmx::VmxError as BackendError;

use crate::allocator::Allocator;
use crate::arch::backend::{BackendX86, LocalState};
use crate::debug::qemu;
use crate::debug::qemu::ExitCode;
use crate::println;
use crate::statics::{allocator as get_allocator, pool as get_pool, NB_CORES};

// ————————————————————————————— Configuration —————————————————————————————— //

/// Maximum number of CPU supported.
const MAX_NB_CPU: usize = 128;

// —————————————————————————————— Shared State —————————————————————————————— //

static GUEST_IS_INITIALIZED: AtomicBool = AtomicBool::new(false);
static GUEST: Mutex<X86State> = Mutex::new(X86State(mem::MaybeUninit::uninit()));

pub struct X86State(mem::MaybeUninit<MonitorState<'static, BackendX86>>);

// SAFETY: GuestX86 is not Send because of pointers in the VMCS. This implementaiton is safe as
// long as VMCS are not moving or being sent between cores.
//
// WARNING: actually there are some RefCells that are !Sync, which makes the whole thing !Send.
// This will be fixed with the upcoming capability refactor, so I guest for now we just hack around
// it unsafely.
unsafe impl Send for X86State {}

impl Deref for X86State {
    type Target = MonitorState<'static, BackendX86>;

    fn deref(&self) -> &Self::Target {
        unsafe { self.0.assume_init_ref() }
    }
}

impl DerefMut for X86State {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.0.assume_init_mut() }
    }
}

pub fn get_state() -> MutexGuard<'static, X86State> {
    if !GUEST_IS_INITIALIZED.load(Ordering::SeqCst) {
        panic!("Guest is not yet initialized");
    }
    let state = GUEST.lock();
    state
}

fn set_state(state: MonitorState<'static, BackendX86>) {
    if GUEST_IS_INITIALIZED.load(Ordering::SeqCst) {
        panic!("Guest is already initialized");
    }

    let mut guard = GUEST.lock();
    *MutexGuard::deref_mut(&mut guard) = X86State(mem::MaybeUninit::new(state));

    GUEST_IS_INITIALIZED.store(true, Ordering::SeqCst);
}

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
            locals: [LocalState {
                current_domain: Handle::new_unchecked(usize::MAX),
                current_cpu: Handle::new_unchecked(usize::MAX),
            }; NB_CORES],
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
    let tyche_state = MonitorState::<BackendX86>::new(manifest.poffset as usize, capas)
        .expect("Unable to create monitor state");
    set_state(tyche_state);
    let cpuid = cpuid();

    if cpuid != 0 {
        unsafe {
            // Spin on the MP Wakeup Page command
            let mp_mailbox = manifest.mp_mailbox as usize;
            let command = mp_mailbox as *const u16;
            let apic_id = (mp_mailbox + 4) as *const u32;
            loop {
                if command.read_volatile() == 1 && apic_id.read_volatile() == (cpuid as u32) {
                    break;
                }
            }

            let wakeup_vector = (mp_mailbox + 8) as *const u64;
            println!(
                "Launching CPU {} on wakeup_vector {:#?}",
                cpuid, wakeup_vector
            );
            let state = get_state();
            let mut cpu = guest::get_local_cpu(state.deref());
            let vcpu = cpu.core.get_active_mut().unwrap();
            vcpu.set_nat(vmx::fields::GuestStateNat::Rip, wakeup_vector as usize)
                .ok();

            (mp_mailbox as *mut u16).write_volatile(0);
        }
    }

    println!("Starting main loop");
    guest::main_loop();

    qemu::exit(qemu::ExitCode::Success);
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
