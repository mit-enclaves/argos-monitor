//! x86_64 implementation

use core::arch::asm;
use core::fmt;
use core::fmt::Write;

use spin::Mutex;
use uart_16550::SerialPort;

use crate::ExitCode;

/// Internal function used to print to stdout when running in Qemu.
pub fn _print(args: fmt::Arguments) {
    /// Serial port used to log to stdout when running in Qemu.
    //  TODO: wrap port in mutex
    static mut SERIAL_PORT: Mutex<SerialPort> = unsafe { Mutex::new(SerialPort::new(0x3F8)) };

    // SAFETY:
    //
    // For now we are running in single-threaded mode, and the interrupts are disabled within the
    // VMM.
    unsafe {
        SERIAL_PORT
            .lock()
            .write_fmt(args)
            .expect("Printing to serial failed");
    }
}

// —————————————————————————————— Exiting QEMU —————————————————————————————— //

/// Exit QEMU.
///
/// For this function to properly exit QEMU must be configured with the following debug device:
/// `-device isa-debug-exit,iobase=0xf4,iosize=0x04`. Otherwise, the function write to the port
/// corresponding port and return, in which case behavior is undefined.
pub fn exit(exit_code: ExitCode) {
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
