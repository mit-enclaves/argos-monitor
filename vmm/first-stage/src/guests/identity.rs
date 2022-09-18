use stage_two_abi::GuestInfo;

use super::Guest;
use super::HandlerResult;
use crate::acpi::AcpiInfo;
use crate::mmu::{FrameAllocator, MemoryMap};
use crate::println;
use crate::vmx;
use core::arch::asm;

/// Allows to map tyche itself inside a VM.
pub struct Identity {}

impl Guest for Identity {
    unsafe fn instantiate<'vmx>(
        &self,
        _acpi: &AcpiInfo,
        _host_allocator: &impl FrameAllocator,
        _guest_allocator: &impl FrameAllocator,
        _memory_map: MemoryMap,
    ) -> GuestInfo {
        Default::default()
    }

    unsafe fn vmcall_handler(
        &self,
        _vcpu: &mut vmx::ActiveVmcs,
    ) -> Result<HandlerResult, vmx::VmxError> {
        Ok(HandlerResult::Exit)
    }
}

#[inline(always)]
unsafe fn rdtsc() -> u64 {
    let mut _hi: u64 = 0;
    let mut _lo: u64 = 0;
    asm!("rdtsc", "mov {_hi}, rdx", "mov {_lo}, rax",
                        _hi = out(reg) _hi,
                        _lo = out(reg) _lo, out("rdx") _, out("rax") _);
    _lo | (_hi << 32)
}

#[no_mangle]
unsafe fn _guest_code_vmfunc() {
    asm!("nop", "nop", "nop", "nop", "nop", "nop");
    asm!("nop", "nop", "nop", "nop", "nop", "nop");
    println!("Hello from guest!");
    for i in 0..5 {
        let start = rdtsc();
        if i % 2 == 0 {
            asm!("mov eax, 0", "mov ecx, 1", "vmfunc", out("rax") _, out("rcx") _);
        } else {
            asm!("mov eax, 0", "mov ecx, 0", "vmfunc", out("rax") _, out("rcx") _);
        }
        let end = rdtsc();
        println!("After the vmfunc {} - {} = {}", end, start, (end - start));
    }
    asm!(
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "mov eax, 0x666 ",
        "vmcall",
    );
}

unsafe fn _guest_code() {
    asm!("nop", "nop", "nop", "nop", "nop", "nop");
    asm!("nop", "nop", "nop", "nop", "nop", "nop");
    println!("Hello from guest!");
    asm!(
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "mov eax, 0x666",
        "vmcall",
    );
}
