use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use log::info;
use object::read::elf::FileHeader;
use object::Endianness;

fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    unsafe {
        ::core::slice::from_raw_parts((p as *const T) as *const u8, ::core::mem::size_of::<T>())
    }
}

pub fn parse_headers(data: &[u8], out: &mut object::write::elf::Writer) -> usize {
    let in_hdr =
        object::elf::FileHeader64::<Endianness>::parse(data).expect("Unable to parse the data");

    /*for i in in_hdr.program_headers(Endianness::Little, data) {
        info!("Header {:?}", i);
    }*/
    // Write the beginning of the header.
    // TODO we will fix this eventually to add some sections/segments.
    let in_hdr_ident = in_hdr.e_ident();
    let ident_bytes: &[u8] = any_as_u8_slice(in_hdr_ident);
    out.write(ident_bytes);
    ident_bytes.len()
}

pub fn copy_binary(src: &PathBuf, dest: &PathBuf) {
    // Read the data.
    let data = std::fs::read(src).expect("Unable to read source file");

    // TODO do some kind of parsing.

    // Initialize our output.
    // TODO Later on we need to parse the output first, compute how much memory to put there.
    // Then reserve the right capacity.
    let mut dest_content: Vec<u8> = Vec::with_capacity(data.len());
    let mut writer = object::write::elf::Writer::new(Endianness::Little, true, &mut dest_content);

    // Parse and copy the file header.
    let hdr_size = parse_headers(&*data, &mut writer);

    info!(
        "The value of the header {:x?}, size: {}",
        dest_content, hdr_size
    );

    //... TODO there is a lot more to do.

    // Write to the dest file.
    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(dest)
        .expect("Unable to open dest file");
    file.write(&*dest_content)
        .expect("Unable to write the file");
}
