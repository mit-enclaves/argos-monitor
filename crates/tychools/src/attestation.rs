use std::path::PathBuf;

use object::read::elf::ProgramHeader;
use sha2::{Digest, Sha256};

use crate::elf_modifier::{ModifiedELF, ModifiedSegment, TychePhdrTypes, DENDIAN};

/// For the moment we only measure confidential segments.
pub fn attest(src: &PathBuf, offset: u64) {
    let data = std::fs::read(src).expect("Unable to read source file");
    // let mut hasher = Sha256::new();
    let mut hasher = Sha256::default();
    let mut enclave = ModifiedELF::new(&data);
    enclave.fix_page_tables(offset);
    log::info!("Elf data size is {:#x}", enclave.data.len());
    let mut cnt = 0;
    let mut cnt_nz = 0;
    for u8_data in &enclave.data {
        if *u8_data != 0 {
            log::info!("{:#x}", *u8_data);
            cnt_nz+=1;
        }
        else {
            cnt+=1;
        }
        let arr_u8 : [u8;1] = [*u8_data];   
        hasher.input(&arr_u8);
    }
    
    // for seg in &enclave.segments {
    //     if ModifiedSegment::is_loadable(seg.program_header.p_type(DENDIAN)) {
    //         if let Some(tpe) = TychePhdrTypes::from_u32(seg.program_header.p_type(DENDIAN)) {
    //             // if (!tpe.is_confidential()) || seg.data.is_empty() {
    //             //     continue;
    //             // }
    //             // hasher.update(&seg.data);
    //             log::info!("Size of the region {:#x}", seg.data.len());
    //             log::info!("Updating hash");
    //             for u8_data in &seg.data {
    //                 if *u8_data != 0 {
    //                     log::info!("{:#x}", *u8_data);
    //                     cnt_nz+=1;
    //                 }
    //                 else {
    //                     cnt+=1;
    //                 }
    //                 let arr_u8 : [u8;1] = [*u8_data];
    //                 hasher.input(&arr_u8);
    //             }
    //         }
    //     }
    // }
    // let result = hasher.finalize();
    log::info!("Zero counter {:#x}", cnt);
    log::info!("Non zero counter {:#x}", cnt_nz);
    let result = hasher.result();
    log::info!("Computed hash:");
    log::info!("{}", format!("{:x}", result));
}
