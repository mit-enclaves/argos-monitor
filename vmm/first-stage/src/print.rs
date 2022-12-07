//! Printing utilities
//!
//! This modules enables printing on different devices, depending on the features selected at
//! compilation time.

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        #[cfg(feature = "vga")]
        vga::_print(core::format_args!($($arg)*));
        #[cfg(not(feature = "vga"))]
        $crate::serial::_print(core::format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", core::format_args!($($arg)*)))
}
