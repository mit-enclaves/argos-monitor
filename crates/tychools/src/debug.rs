use std::fs::OpenOptions;
use std::io::Write;
use std::mem;
use std::path::PathBuf;

use elfloader::*;
use log::{debug, error, info};
use mmu::walker::Level;
use mmu::{FrameAllocator, PtMapper};
use object::elf::FileHeader64;
use object::read::elf::FileHeader;
use object::write::Object as OutObject;
use object::{write, Architecture, BinaryFormat, Endianness, Object, ObjectSection, ObjectSegment};
use utils::{HostPhysAddr, HostVirtAddr};

use crate::allocator::{Allocator, BumpAllocator, DEFAULT_BUMP_SIZE, PAGE_SIZE};

pub fn print_elf_segments(path: &PathBuf) {
    let file_data = std::fs::read(path).expect("Could not read file.");
    let slice = file_data.as_slice();
    let binary = ElfBinary::new(slice).expect("Unable to parse elf.");
    for ph in binary.program_headers() {
        info!(
            "base = {:#x} size = {:#x} type = {:?} flags = {}",
            ph.virtual_addr(),
            ph.mem_size(),
            ph.get_type().unwrap(),
            ph.flags()
        );
    }
}

pub fn printf_elf_with_obj(path: &PathBuf, dest: &PathBuf) {
    /*let file_data = std::fs::read(path).expect("Could not read file");
    let data = file_data.as_slice();
    let elf = FileHeader64::<Endianness>::parse(data).expect("Unable to parse elf.");
    let endian = elf.endian().expect("Unable to get endianness");
    for s in elf.program_headers(endian, data).expect("No segments") {
        info!("We have a segment {:?}", s);
    }
    let obj = Object::new(BinaryFormat::Elf, Architecture::X86_64, endian);*/
    let bin_data = std::fs::read(path).expect("Could not read file");
    let obj = object::File::parse(&*bin_data).expect("urf");

    let mut my_out: Vec<u8> = Vec::new();

    let _writer = write::elf::Writer::new(obj.endianness(), true, &mut my_out);

    let _headers =
        FileHeader64::<Endianness>::parse(&*bin_data).expect("Impossible to read header.");

    //writer.write_file_header(&headers);
    let mut out = OutObject::new(BinaryFormat::Elf, Architecture::X86_64, obj.endianness());
    for seg in obj.segments() {
        let new_seg: Vec<u8> = Vec::new();
        for sec in obj.sections() {
            if sec.address() >= seg.address() && sec.address() < seg.address() + seg.size() {
                let name = sec.name().expect("No name in the section");
                let kind = sec.kind();
                let id = out.add_section(new_seg.clone(), Vec::from(name.as_bytes()), kind);
                out.set_section_data(id, sec.data().expect("fuck"), sec.align());
            }
        }
    }
    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(dest)
        .expect("Unable to parse dest");
    file.write(my_out.as_slice()).expect("oups");
    file.write(out.write().expect("Unable to get bytes").as_slice())
        .expect("couldn't write to the file");
}

pub fn print_page_tables(path: &PathBuf) {
    let file_data = std::fs::read(path).expect("Could not read file.");
    let slice = file_data.as_slice();
    let size = slice.len();
    let offset_size = mem::size_of::<usize>();
    debug!("The file {:?}'s size is {}", path, size);
    if size % PAGE_SIZE != offset_size {
        error!("{:?} is not a multiple of page size.", path);
    }

    // Parse the offset.

    let phys_offset = {
        let tmp: [u8; 8] = match slice[0..offset_size].try_into() {
            Ok(v) => v,
            Err(e) => {
                error!("Unable to transform the slice into a vector: {}", e);
                return;
            }
        };
        usize::from_ne_bytes(tmp)
    };

    // Create a fake bump allocator.
    let mut bump = BumpAllocator::<DEFAULT_BUMP_SIZE>::new(phys_offset);
    let nb_pages = size / PAGE_SIZE;
    for i in 0..nb_pages {
        let idx = offset_size + i * PAGE_SIZE;
        let end = idx + PAGE_SIZE;
        bump.pages[i].data.copy_from_slice(&slice[idx..end]);
    }

    if bump.get_virt_offset() < phys_offset {
        error!(
            "The virtual offset is smaller than the phys_offset {:x} -- {:x}",
            bump.get_virt_offset(),
            phys_offset
        );
        return;
    }
    // Converting fake phys_addr to virt_addr by adding this offset.
    let offset = bump.get_virt_offset() - phys_offset;
    let allocator = Allocator::new(&mut bump);
    let root = match allocator.allocate_frame() {
        Some(f) => f,
        None => {
            error!("Unable to allocate root!");
            return;
        }
    };
    let mut mapper = PtMapper::<HostPhysAddr, HostVirtAddr>::new(offset, 0, root.phys_addr);
    mapper.debug_range(HostVirtAddr::new(0), usize::MAX, Level::L1, |args| {
        info!("{}", args.to_string());
    })
}
