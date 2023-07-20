use std::path::PathBuf;

use object::read::elf::ProgramHeader;
use sha2::{Digest, Sha256};

use crate::elf_modifier::{ModifiedELF, ModifiedSegment, TychePhdrTypes, DENDIAN};

fn hash_segment_data(enclave : & Box<ModifiedELF>, hasher : & mut Sha256) {
    let mut real_size = 0;
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
                }
                let mut diff = (memsz + align - 1) / align * align;
                real_size+=diff;
                log::info!("Alligned address {:#x}", diff);
                diff = diff - (seg.data.len() as u64);
                log::info!("Diff - number of zeros to be added to the hash {:#x}", diff);
                for _ in 0..diff {
                    let arr_u8 : [u8;1] = [0];
                    hasher.input(&arr_u8);
                }
            }
        }
    }
    log::info!("Real size {:#x}", real_size);
}

//todo why are segments not in order
fn hash_segments_info(enclave : & Box<ModifiedELF>, hasher : & mut Sha256, offset : u64) {
    let dom_id : u64=2;
    hasher.input(&u64::to_le_bytes(dom_id));
    let mut segment_off = offset;
    for seg in &enclave.segments {
        if ModifiedSegment::is_loadable(seg.program_header.p_type(DENDIAN)) {
            if let Some(tpe) = TychePhdrTypes::from_u32(seg.program_header.p_type(DENDIAN)) {
                let start = segment_off;
                let memsz = seg.program_header.p_memsz(DENDIAN);
                let align = seg.program_header.p_align(DENDIAN);
                let sz = (memsz + align - 1) / align * align;
                log::trace!("Region start {:#x}", start);
                log::trace!("Region end {:#x}", start + sz);
                hasher.input(&u64::to_le_bytes(start));
                hasher.input(&u64::to_le_bytes(start + sz));

                if tpe.is_confidential() {
                    log::trace!("Conf = 1");
                    hasher.input(&u8::to_le_bytes(1 as u8));
                }
                else {
                    log::trace!("Conf = 0");
                    hasher.input(&u8::to_le_bytes(0 as u8));
                }

                segment_off+=sz;
            }
        }
    }
}

pub fn attest(src: &PathBuf, offset: u64) {
    let data = std::fs::read(src).expect("Unable to read source file");
    let mut hasher = Sha256::default();
    let mut enclave = ModifiedELF::new(&data);
    enclave.fix_page_tables(offset);
    
    hash_segment_data(&enclave, &mut hasher);

    hash_segments_info(&enclave, &mut hasher, offset);
    
    let result = hasher.result();
    log::info!("Computed hash:");
    log::info!("{}", format!("{:x}", result));
}
