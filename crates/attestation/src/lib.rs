#![no_std]
use sha2::{Digest, Sha256};

pub type TycheHasher = Sha256;

pub mod attestation_hash {
    
    use sha2::{Digest, Sha256};

    use super::TycheHasher;

    pub fn get_hasher() -> TycheHasher {
        Sha256::default()
    }

    pub fn hash_segment(hasher: & mut TycheHasher, segment_data : &[u8]) {
        hasher.input(segment_data);
    }

    //todo return value of this function
    pub fn get_hash(hasher : & mut TycheHasher) -> u32 {
        let result = hasher.result();
        //todo check the length of this result
        let result_arr = result.as_slice();
        log::trace!("Computed hash: ");
        log::info!("{:x}", result);
        let mut hash : u32 = 0;
        for element in result_arr {
            hash = (hash << 8) + (*element as u32);
        }
        hash
    }
}

pub mod attestation_keys {
    pub fn get_keys(){
        todo!("Find crate for enc/dec that is no_std");
    }
}