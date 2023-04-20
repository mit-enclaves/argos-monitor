use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use elfloader::*;
use log::{debug, error, info};
use mmu::{FrameAllocator, PtFlag, PtMapper};
use object::Endianness;
use utils::{HostPhysAddr, HostVirtAddr};
use xmas_elf::program::Type;

use crate::allocator::{Allocator, BumpAllocator, DEFAULT_BUMP_SIZE, PAGE_SIZE};
use crate::instr::{ModifiedELF, TychePhdrTypes};

fn align_address(addr: usize) -> usize {
    if addr % PAGE_SIZE == 0 {
        return addr;
    }
    (PAGE_SIZE + addr) & !(PAGE_SIZE - 1)
}

fn translate_flags(flags: Flags) -> PtFlag {
    let mut ptflags: PtFlag = PtFlag::PRESENT;
    if flags.is_write() {
        ptflags = ptflags.union(PtFlag::WRITE);
    }
    if !flags.is_execute() {
        ptflags = ptflags.union(PtFlag::EXEC_DISABLE);
    }
    ptflags
}

/// Attempt to build page tables for the binary and just dump them on the screen for now.
pub fn dump_page_tables(src: &PathBuf, dest: &PathBuf) {
    // Check if the dest file exists.
    if dest.exists() {
        error!("The file {:?} already exists!", dest);
        return;
    }

    // Read the file.
    let file_data = match std::fs::read(src) {
        Err(e) => {
            error!("Unable to read {:?} : {}", dest, e);
            return;
        }
        Ok(v) => v,
    };
    let slice = file_data.as_slice();

    // Parse the binary.
    let binary = ElfBinary::new(slice).expect("Unable to parse elf.");

    // Compute the overall memory necessary to host the entire binary.
    let mut mem_size: usize = 0;
    for ph in binary.program_headers() {
        if ph.get_type().unwrap() != Type::Load {
            continue;
        }
        let mem = ph.mem_size() as usize;
        let size = align_address(mem);
        mem_size += size;
    }

    debug!(
        "{:?} requires {:?} bytes of memory for the segments.",
        dest, mem_size
    );

    // Pages for the page table start at phys_addr offset == mem_size.
    let mut bump = BumpAllocator::<DEFAULT_BUMP_SIZE>::new(mem_size);
    if bump.get_virt_offset() < mem_size {
        error!(
            "The virtual offset is smaller than the mem_size {:x} -- {:x}",
            bump.get_virt_offset(),
            mem_size
        );
        return;
    }
    // Converting fake phys_addr to virt_addr by adding this offset.
    let offset = bump.get_virt_offset() - mem_size;
    let allocator = Allocator::new(&mut bump);
    let root = allocator.allocate_frame().unwrap();
    let mut mapper = PtMapper::<HostPhysAddr, HostVirtAddr>::new(offset, 0, root.phys_addr);
    let mut curr_phys: usize = 0;
    for ph in binary.program_headers() {
        if ph.get_type().unwrap() != Type::Load {
            continue;
        }
        let mem_size = ph.mem_size() as usize;
        let virt = HostVirtAddr::new(ph.virtual_addr() as usize);
        let size: usize = align_address(mem_size);
        let flags = translate_flags(ph.flags());
        mapper.map_range(&allocator, virt, HostPhysAddr::new(curr_phys), size, flags);
        curr_phys += size;
    }

    debug!(
        "Done mapping all the segments from {:?}, we consumed {} extra pages!",
        src, bump.idx
    );

    // Dump the content of page tables as a new segmen in the binary.
    let mut file = match OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(dest)
    {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to reopen the file {:?}: {}", dest, e);
            return;
        }
    };

    // Add the content to the file.
    // First write the offset.
    if let Err(e) = file.write(&bump.phys_offset.to_ne_bytes()) {
        error!("Unable to write the size to {:?}: {}", dest, e);
        return;
    }
    for i in 0..bump.idx {
        if let Err(e) = file.write(&bump.pages[i].data) {
            error!("Unable to write {}th page to {:?}: {}", i, dest, e);
            return;
        }
    }
    info!(
        "The binary {:?} page tables have been generated and dumped into {:?}",
        src, dest
    );
}

pub fn modify_binary(src: &PathBuf, dst: &PathBuf) {
    let data = std::fs::read(src).expect("Unable to read source file");
    info!("We read {} bytes from the file", data.len());
    let mut elf = ModifiedELF::new(&*data);
    elf.add_empty_segment(
        None,
        TychePhdrTypes::PtPageTables as u32,
        object::elf::PF_R | object::elf::PF_W,
        0x1000,
        None,
    );

    // Let's write that thing out.
    let mut out: Vec<u8> = Vec::with_capacity(elf.len());
    let mut writer = object::write::elf::Writer::new(Endianness::Little, true, &mut out);
    elf.dump(&mut writer);

    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(dst)
        .expect("Unable to open dest file");
    file.write(&*out).expect("Unable to dump the content");
    // TODO Let's add a bss section for tyche_shared2.
}
