use bootloader::boot_info::{FrameBuffer, FrameBufferInfo, PixelFormat};
use core::fmt;
use core::fmt::Write;
use core::ptr;
use font8x8::UnicodeFonts;
use spin::Mutex;
use x86_64::instructions::interrupts::without_interrupts;

/// Additional vertical space between lines
const LINE_SPACING: usize = 1;
/// Zoom to make text big enough on screens with high pixel density
const ZOOM_FACTOR: usize = 1;

/// The global writer, must be initialized with a frame buffer, otherwise writes are ignored.
pub static WRITER: Mutex<Option<Writer>> = Mutex::new(None);

/// Initializes the VGA writer.
pub fn init(boot_info: &'static mut FrameBuffer) {
    let mut writer = WRITER.lock();
    let mut new_writer = Writer::new(boot_info);
    new_writer.clear();
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
            x_pos: LINE_SPACING,
            y_pos: LINE_SPACING,
        }
    }

    fn newline(&mut self) {
        self.y_pos += (8 + LINE_SPACING) * ZOOM_FACTOR;
        self.carriage_return()
    }

    fn carriage_return(&mut self) {
        self.x_pos = LINE_SPACING;
    }

    /// Erases all text on the screen.
    pub fn clear(&mut self) {
        self.x_pos = LINE_SPACING;
        self.y_pos = LINE_SPACING;

        // TODO: can we use an optimized method?
        // self.framebuffer.fill(0);

        for y in 0..self.info.vertical_resolution {
            for x in 0..self.info.horizontal_resolution {
                self.write_pixel(x, y, 0);
            }
        }
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
                if self.y_pos >= (self.height() - 8 * ZOOM_FACTOR) {
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
                for i in 0..ZOOM_FACTOR {
                    for j in 0..ZOOM_FACTOR {
                        self.write_pixel(
                            self.x_pos + x * ZOOM_FACTOR + i,
                            self.y_pos + y * ZOOM_FACTOR + j,
                            alpha,
                        );
                    }
                }
            }
        }
        self.x_pos += 8 * ZOOM_FACTOR;
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
