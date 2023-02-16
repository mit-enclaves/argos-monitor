use crate::{apic, gdt::Gdt};
use x86::apic::xapic;

pub const MAX_CPU_NUM: usize = 256;
const INITCPU: Option<Cpu> = None;
static mut CPUS: [Option<Cpu>; MAX_CPU_NUM] = [INITCPU; MAX_CPU_NUM];

pub struct Cpu {
    pub id: usize,
    pub gdt: Gdt,
    pub lapic: xapic::XAPIC,
}

impl Cpu {
    pub fn new() -> Self {
        Self {
            id: id(),
            gdt: Gdt::new(),
            // FIXME: it's amazing that this doesn't crash before the memory allocator is
            //        initialized on CPU0...
            lapic: apic::lapic_new(apic::get_lapic_virt_address()),
        }
    }

    pub fn setup(&'static mut self) {
        self.gdt.setup();
        apic::lapic_setup(&mut self.lapic);
    }

    pub fn gdt(&self) -> &Gdt {
        &self.gdt
    }
}

pub unsafe fn current() -> &'static mut Option<Cpu> {
    return &mut CPUS[id()];
}

pub fn init() {
    let lapic_id = id();
    unsafe {
        match CPUS[lapic_id] {
            Some(_) => panic!("CPU {} already initialized", lapic_id),
            None => {
                CPUS[lapic_id] = Some(Cpu::new());
                CPUS[lapic_id].as_mut().unwrap().setup();
            }
        }
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
