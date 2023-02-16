//! RISC-V 64 implementation

use core::fmt;

use crate::ExitCode;

/// Internal function used to print to stdout when running in Qemu.
pub fn _print(_args: fmt::Arguments) {
    // TODO
}

// —————————————————————————————— Exiting QEMU —————————————————————————————— //

/// Exit QEMU.
pub fn exit(_exit_code: ExitCode) {
    const _QEMU_EXIT_PORT: u16 = 0xf4;

    // TODO
}
