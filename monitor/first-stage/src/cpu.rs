use crate::println;
use crate::{apic, gdt::Gdt};
use core::sync::atomic::*;
use x86::apic::xapic;
use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};

pub const MAX_CPU_NUM: usize = 256;
const FALSE: AtomicBool = AtomicBool::new(false);
static mut CPU_INIT: [AtomicBool; MAX_CPU_NUM] = [FALSE; MAX_CPU_NUM];
const INITCPU: Option<Cpu> = None;
static mut CPUS: [Option<Cpu>; MAX_CPU_NUM] = [INITCPU; MAX_CPU_NUM];

pub struct Cpu {
    pub local_apic_id: usize,
    pub gdt: Gdt,
    pub lapic: xapic::XAPIC,
}

impl Cpu {
    pub fn new() -> Self {
        Self {
            local_apic_id: id(),
            gdt: Gdt::new(),
            // FIXME: it's amazing that this doesn't crash before the memory allocator is
            //        initialized on CPU0...
            lapic: apic::lapic_new(apic::LAPIC_VIRT_ADDRESS),
        }
    }

    pub fn setup(&'static mut self) {
        self.gdt.setup();
        apic::lapic_setup(&mut self.lapic);

        initialize_cpu();
        print_vmx_info();
    }

    pub fn gdt(&self) -> &Gdt {
        &self.gdt
    }
}

fn initialize_cpu() {
    // Set CPU in a valid state for VMX operations.
    let cr0 = Cr0::read();
    let cr4 = Cr4::read();
    unsafe {
        Cr0::write(cr0 | Cr0Flags::NUMERIC_ERROR);
        Cr4::write(cr4 | Cr4Flags::OSXSAVE);
    };
}

fn print_vmx_info() {
    println!("CPU{}: VMX:    {:?}", id(), vmx::vmx_available());
    println!("CPU{}: EPT:    {:?}", id(), vmx::ept_capabilities());
    println!("CPU{}: VMFunc: {:?}", id(), vmx::available_vmfuncs());
}

pub unsafe fn current() -> &'static mut Option<Cpu> {
    return &mut CPUS[id()];
}

pub fn init() {
    let lapic_id = id();
    unsafe {
        assert_eq!(
            CPU_INIT[lapic_id].compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst),
            Ok(false),
            "CPU {} already initialized",
            lapic_id
        );
        CPUS[lapic_id] = Some(Cpu::new());
        CPUS[lapic_id].as_mut().unwrap().setup();
    }
}

pub fn cores() -> usize {
    unsafe {
        CPUS.iter().fold(0, |sum, cpu| match &cpu {
            Some(_) => sum + 1,
            _ => sum,
        })
    }
}

pub fn id() -> usize {
    let cpuid = unsafe { core::arch::x86_64::__cpuid(0x01) };
    ((cpuid.ebx & 0xffffffff) >> 24) as usize
}
