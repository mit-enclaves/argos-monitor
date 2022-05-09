use bootloader::boot_info::{FrameBuffer, FrameBufferInfo, PixelFormat};
use core::fmt;
use core::fmt::Write;
use core::ptr;
use font8x8::UnicodeFonts;
use spin::Mutex;
use x86_64::instructions::interrupts::without_interrupts;

/// Additional vertical space between lines
const LINE_SPACING: usize = 0;

/// The global writer, must be initialized with a frame buffer, otherwise writes are ignored.
pub static WRITER: Mutex<Option<Writer>> = Mutex::new(None);

/// Initializes the VGA writer.
pub fn init(boot_info: &'static mut FrameBuffer) {
    let mut writer = WRITER.lock();
    let mut new_writer = Writer::new(boot_info);
    new_writer.clear_screen();
    writer.replace(new_writer);
}

pub struct Writer {
    framebuffer: &'static mut [u8],
    info: FrameBufferInfo,
    x_pos: usize,
    y_pos: usize,
}

impl Writer {
    pub fn new(buffer: &'static mut FrameBuffer) -> Self {
        let info = buffer.info();
        let framebuffer = buffer.buffer_mut();
        Writer {
            framebuffer,
            info,
            x_pos: 0,
            y_pos: 0,
        }
    }

    fn clear_screen(&mut self) {
        for y in 0..self.info.vertical_resolution {
            for x in 0..self.info.horizontal_resolution {
                self.write_pixel(x, y, 0);
            }
        }
    }

    fn newline(&mut self) {
        self.y_pos += 8 + LINE_SPACING;
        self.carriage_return()
    }

    fn carriage_return(&mut self) {
        self.x_pos = 0;
    }

    /// Erases all text on the screen.
    pub fn clear(&mut self) {
        self.x_pos = 0;
        self.y_pos = 0;
        self.framebuffer.fill(0);
    }

    fn width(&self) -> usize {
        self.info.horizontal_resolution
    }

    fn height(&self) -> usize {
        self.info.vertical_resolution
    }

    fn write_char(&mut self, c: char) {
        match c {
            '\n' => self.newline(),
            '\r' => self.carriage_return(),
            c => {
                if self.x_pos >= self.width() {
                    self.newline();
                }
                if self.y_pos >= (self.height() - 8) {
                    self.clear();
                }
                let rendered = font8x8::BASIC_FONTS
                    .get(c)
                    .expect("character not found in basic font");
                self.write_rendered_char(rendered);
            }
        }
    }

    fn write_rendered_char(&mut self, rendered_char: [u8; 8]) {
        for (y, byte) in rendered_char.iter().enumerate() {
            for (x, bit) in (0..8).enumerate() {
                let alpha = if *byte & (1 << bit) == 0 { 0 } else { 255 };
                self.write_pixel(self.x_pos + x, self.y_pos + y, alpha);
            }
        }
        self.x_pos += 8;
    }

    fn write_pixel(&mut self, x: usize, y: usize, intensity: u8) {
        let pixel_offset = y * self.info.stride + x;
        let color = self.get_color(intensity);
        let bytes_per_pixel = self.info.bytes_per_pixel;
        let byte_offset = pixel_offset * bytes_per_pixel;
        self.framebuffer[byte_offset..(byte_offset + bytes_per_pixel)]
            .copy_from_slice(&color[..bytes_per_pixel]);
        let _ = unsafe { ptr::read_volatile(&self.framebuffer[byte_offset]) };
    }

    fn get_color(&self, intensity: u8) -> [u8; 4] {
        if intensity > 200 {
            [255, 255, 255, 0]
        } else {
            match self.info.pixel_format {
                PixelFormat::RGB => [171, 0, 171, 0],
                PixelFormat::BGR => [171, 0, 171, 0],
                PixelFormat::U8 => [255, 0, 0, 0],
                _ => [171, 0, 171, 0],
            }
        }
    }
}

impl fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for c in s.chars() {
            self.write_char(c);
        }
        Ok(())
    }
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    without_interrupts(|| {
        let mut writer = WRITER.lock();
        if let Some(writer) = writer.as_mut() {
            writer.write_fmt(args).unwrap();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn print_simple() {
        _print(core::format_args!("test_println_simple output\n"));
    }

    #[test_case]
    fn println_many() {
        for _ in 0..200 {
            _print(core::format_args!("test_println many output\n"));
        }
    }

    // #[test_case]
    // fn println_output() {
    //     let s = "Some test string that fits on a single line";
    //     without_interrupts(|| {
    //         let mut writer = WRITER.lock();
    //         writeln!(writer, "\n").expect("writeln failed"); // Clear the current line
    //         writeln!(writer, "{}", s).expect("writeln failed");
    //         for (i, c) in s.chars().enumerate() {
    //             let screen_char = writer.buffer.chars[BUFFER_HEIGHT - 2][i].read();
    //             assert_eq!(char::from(screen_char.ascii_character), c);
    //         }
    //     });
    // }
}
