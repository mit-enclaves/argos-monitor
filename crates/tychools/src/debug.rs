use std::path::PathBuf;

use elfloader::*;
use log::info;
use mmu::{FrameAllocator, PtMapper};
use utils::{HostPhysAddr, HostVirtAddr};
use xmas_elf::program::Type;

use crate::allocator::{Allocator, BumpAllocator, PAGE_SIZE};

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

/// Attempt to build page tables for the binary and just dump them on the screen for now.
/// Later we'll add them into a section.
/// TODO change the approach, first compute exactly how many pages we need just for
/// the content.
pub fn print_page_tables(path: &PathBuf) {
    let file_data = std::fs::read(path).expect("Could not read file");
    let slice = file_data.as_slice();
    let binary = ElfBinary::new(slice).expect("Unable to parse elf.");

    // Compute the overall memory necessary to host the entire binary.
    let mut mem_size: usize = 0;
    for ph in binary.program_headers() {
        if ph.get_type().unwrap() != Type::Load {
            continue;
        }
        let mem = ph.mem_size() as usize;
        let size = if mem % PAGE_SIZE == 0 {
            mem
        } else {
            (PAGE_SIZE + mem) & !(PAGE_SIZE - 1)
        };
        mem_size += size;
    }
    println!("The mem_size is {:x} bytes!", mem_size);

    // We know how much memory is needed for loadable segments.
    // The page table offset is thus known and we can start building them now.
    let mut bump = BumpAllocator::<500>::new(mem_size);
    let allocator = Allocator::new(&mut bump);
    let root = allocator.allocate_frame().unwrap();
    let mapper = PtMapper::<HostPhysAddr, HostVirtAddr>::new(0, 0, root.phys_addr);
    /*for ph in binary.program_headers() {
        if ph.get_type().unwrap() != Type::Load {
            continue;
        }
        let virt = HostVirtAddr::new(ph.virtual_addr() as usize);
        let size = if ((0x1000 - 1) & ph.mem_size()) == 0 {
            ph.mem_size()
        } else {
            ph.mem_size() + 0x1000
        };
    }*/
}
