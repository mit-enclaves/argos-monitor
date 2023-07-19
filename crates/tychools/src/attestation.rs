use std::path::PathBuf;

use object::read::elf::ProgramHeader;
use sha2::{Digest, Sha256};

use crate::elf_modifier::{ModifiedELF, ModifiedSegment, TychePhdrTypes, DENDIAN};

/// For the moment we only measure confidential segments.
pub fn attest(src: &PathBuf, offset: u64) {
    let data = std::fs::read(src).expect("Unable to read source file");
    let mut hasher = Sha256::default();
    let mut enclave = ModifiedELF::new(&data);
    enclave.fix_page_tables(offset);
    let mut real_size = 0;
    let mut cnt_bytes = 0;
    let _bytes_limit = 0xd000;
    for seg in &enclave.segments {
        if ModifiedSegment::is_loadable(seg.program_header.p_type(DENDIAN)) {
            if let Some(tpe) = TychePhdrTypes::from_u32(seg.program_header.p_type(DENDIAN)) {
                let memsz = seg.program_header.p_memsz(DENDIAN);
                let align = seg.program_header.p_align(DENDIAN);
                log::info!("Sz from the header {:#x}", memsz);
                log::info!("Align from the header {:#x}", align);
                log::info!("Size of the region {:#x}", seg.data.len());
                for u8_data in &seg.data {
                    let arr_u8 : [u8;1] = [*u8_data];
                    hasher.input(&arr_u8);
                    cnt_bytes+=1;
                }
                let mut diff = (memsz + align - 1) / align * align;
                real_size+=diff;
                log::info!("Alligned address {:#x}", diff);
                diff = diff - (seg.data.len() as u64);
                log::info!("Diff - number of zeros to be added to the hash {:#x}", diff);
                for _ in 0..diff {
                    cnt_bytes+=1;
                    let arr_u8 : [u8;1] = [0];
                    hasher.input(&arr_u8);
                }
            }
        }
    }
    log::info!("Number of bytes {:#x}", cnt_bytes);
    log::info!("Real size {:#x}", real_size);
    let result = hasher.result();
    log::info!("Computed hash:");
    log::info!("{}", format!("{:x}", result));
}
