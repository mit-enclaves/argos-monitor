//! Stage 2 initialization on x86_64

use core::arch::asm;
use core::mem;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use arena::Handle;
use capabilities::State;
use mmu::FrameAllocator;
use monitor::MonitorState;
use spin::{Mutex, MutexGuard};
use stage_two_abi::{GuestInfo, Manifest};
pub use vmx::{ActiveVmcs, VmxError as BackendError};

use super::vmx_helper::init_vcpu;
use super::{arch, cpuid, launch_guest};
use crate::allocator::Allocator;
use crate::arch::backend::{BackendX86, LocalState};
use crate::debug::qemu;
use crate::println;
use crate::statics::{allocator as get_allocator, get_manifest, pool as get_pool, NB_CORES};

// ————————————————————————————— Entry Barrier —————————————————————————————— //

/// APs will wait for the entry barrier to be `true` before jumping into stage 2.
#[used]
#[export_name = "__entry_barrier"]
static ENTRY_BARRIER: AtomicBool = AtomicBool::new(false);

// ————————————————————————————— Initialization ————————————————————————————— //

const FALSE: AtomicBool = AtomicBool::new(false);
static BSP_READY: AtomicBool = FALSE;
static NB_BOOTED_CORES: AtomicUsize = AtomicUsize::new(0);
static mut MANIFEST: Option<&'static Manifest> = None;

pub fn arch_entry_point() -> ! {
    let cpuid = cpuid();

    if cpuid == 0 {
        println!("CPU{}: Hello from second stage!", cpuid);
        // SAFETY: The BSP is responsible for retrieving the manifest
        let manifest = unsafe {
            MANIFEST = Some(get_manifest());
            MANIFEST.as_ref().unwrap()
        };

        init(manifest, 0);
        init_state(manifest);

        println!("Waiting for {} cores", manifest.smp);
        while NB_BOOTED_CORES.load(Ordering::SeqCst) + 1 < manifest.smp {
            core::hint::spin_loop();
        }
        println!("Stage 2 initialized");

        // Mark the BSP as ready to launch guest on all APs.
        BSP_READY.store(true, Ordering::SeqCst);

        // SAFETY: only called once on the BSP
        let mut vcpu = unsafe { create_vcpu(&manifest.info) };
        init_cpu(&mut vcpu);

        // Launch guest and exit
        launch_guest(manifest, vcpu);
        qemu::exit(qemu::ExitCode::Success);
    }
    // The APs spin until the manifest is fetched, and then initialize the second stage
    else {
        println!("CPU{}: Hello from second stage!", cpuid);

        // SAFETY: we only perform read accesses and we ensure the BSP initialized the manifest.
        let manifest = unsafe {
            assert!(!MANIFEST.is_none());
            MANIFEST.as_ref().unwrap()
        };

        init(manifest, cpuid);

        // Wait until the BSP mark second stage as initialized (e.g. all APs are up).
        NB_BOOTED_CORES.fetch_add(1, Ordering::SeqCst);
        while !BSP_READY.load(Ordering::SeqCst) {
            core::hint::spin_loop();
        }

        println!("CPU{}: Waiting on mailbox", cpuid);

        // SAFETY: only called once on the BSP
        let vcpu = unsafe {
            let mut vcpu = create_vcpu(&manifest.info);
            wait_on_mailbox(manifest, &mut vcpu, cpuid);
            init_cpu(&mut vcpu);
            vcpu
        };

        // Launch guest and exit
        launch_guest(manifest, vcpu);
        qemu::exit(qemu::ExitCode::Success);
    }
}

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

fn init_state(manifest: &'static Manifest) {
    // Create the capability state.
    let mut capas = State::<BackendX86> {
        backend: BackendX86 {
            allocator: Allocator::new(
                get_allocator(),
                (manifest.voffset - manifest.poffset) as usize,
            ),
            guest_info: manifest.info,
            iommu: None,
            locals: [LocalState {
                current_domain: Handle::new_unchecked(usize::MAX),
                current_cpu: Handle::new_unchecked(usize::MAX),
            }; NB_CORES],
        },
        pools: get_pool(),
    };

    capas.backend.set_iommu(manifest.iommu);
    capas.backend.init();

    let tyche_state = MonitorState::<BackendX86>::new(manifest.poffset as usize, capas)
        .expect("Unable to create monitor state");
    set_state(tyche_state);
}

fn init_cpu(cpu: &mut ActiveVmcs<'static>) {
    let mut state = get_state();
    state.add_cpu(cpu).expect("Failed to initialize vCPU");
}

unsafe fn wait_on_mailbox(manifest: &Manifest, vcpu: &mut ActiveVmcs<'static>, cpuid: usize) {
    // Spin on the MP Wakeup Page command
    let mp_mailbox = manifest.mp_mailbox as usize;
    let command = mp_mailbox as *const u16;
    let apic_id = (mp_mailbox + 4) as *const u32;
    loop {
        if command.read_volatile() == 1 && apic_id.read_volatile() == (cpuid as u32) {
            break;
        }
        core::hint::spin_loop();
    }

    let wakeup_vector = (mp_mailbox + 8) as *const u64;
    println!(
        "Launching CPU {} on wakeup_vector {:#?}",
        cpuid, wakeup_vector
    );

    // Set RIP entry point
    vcpu.set_nat(vmx::fields::GuestStateNat::Rip, wakeup_vector as usize)
        .ok();

    (mp_mailbox as *mut u16).write_volatile(0);
}

// —————————————————————————————————— VCPU —————————————————————————————————— //

/// SAFETY: should only be called once per physical core
unsafe fn create_vcpu(info: &GuestInfo) -> vmx::ActiveVmcs<'static> {
    let state = get_state();
    let allocator = &state.resources.backend.allocator;
    let vmxon_frame = allocator
        .allocate_frame()
        .expect("Failed to allocate VMXON frame")
        .zeroed();
    let vmxon = vmx::vmxon(vmxon_frame).expect("Failed to execute VMXON");
    let vmcs_frame = allocator
        .allocate_frame()
        .expect("Failed to allocate VMCS frame")
        .zeroed();
    let vmcs = vmxon
        .create_vm_unsafe(vmcs_frame)
        .expect("Failed to create VMCS");
    let mut vcpu = vmcs.set_as_active().expect("Failed to set VMCS as active");
    init_vcpu(&mut vcpu, info, allocator);
    vcpu
}
