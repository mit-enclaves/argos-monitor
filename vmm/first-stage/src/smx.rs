//! Safer Mode Extension

use core::arch::asm;
// use x86_64::registers::control::{Cr4, Cr4Flags};

/// Returns true if SMX is available on the current CPU.
///
/// See manual volume 2B, Section 6.2.1.
pub fn smx_is_available() -> bool {
    let ecx: u64;
    unsafe {
        // Read left 1 of CPUID
        // NOTE: we should not clobber %rbx
        asm!(
            "push rbx", // Save %rbx
            "cpuid",
            "pop rbx",  // Restore %rbx
            inout("rax") 1 => _,
            out("rcx") ecx,
            out("rdx") _,
            options(nomem, preserves_flags)
        );
    }

    // If bit 6 is set, there is SMX support.
    (ecx & (1 << 6)) != 0
}

/// Executes GETSEC[SENTER].
pub unsafe fn senter() {
    asm!(
        "mov rax, 4", // To execute SENTER we need to set EAX to 4
        "getsec",
    );
}
