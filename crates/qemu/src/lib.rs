#![no_std]

use core::arch::asm;
use core::fmt;
use core::fmt::Write;
use uart_16550::SerialPort;

// ———————————————————————————— Print Utilities ————————————————————————————— //

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::_print(core::format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", core::format_args!($($arg)*)));
}

/// Internal function used to print to stdout when running in Qemu.
pub fn _print(args: fmt::Arguments) {
    /// Serial port used to log to stdout when running in Qemu.
    //  TODO: wrap port in mutex
    static mut SERIAL_PORT: SerialPort = unsafe { SerialPort::new(0x3F8) };

    // SAFETY:
    //
    // For now we are running in single-threaded mode, and the interrupts are disabled within the
    // VMM.
    unsafe {
        SERIAL_PORT
            .write_fmt(args)
            .expect("Printing to serial failed");
    }
}

// —————————————————————————————— Exiting QEMU —————————————————————————————— //

/// Qemu exit codes
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(u32)]
pub enum ExitCode {
    Success = 0x10,
    Failure = 0x11,
}

impl ExitCode {
    pub fn to_str(self) -> &'static str {
        match self {
            ExitCode::Success => "Success",
            ExitCode::Failure => "Failure",
        }
    }
}

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
