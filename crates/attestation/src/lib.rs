#![no_std]

use sha2::Sha256;

pub type TycheHasher = Sha256;

pub struct hash_enclave {
    low : u128,
    high : u128,
}

pub mod attestation_hash {
    
    use sha2::{Digest, Sha256};

    use crate::hash_enclave;

    use super::TycheHasher;

    pub fn get_hasher() -> TycheHasher {
        Sha256::default()
    }

    pub fn hash_segment(hasher: & mut TycheHasher, segment_data : &[u8]) {
        hasher.input(segment_data);
    }

    //todo return value of this function
    pub fn get_hash(hasher : & mut TycheHasher) -> hash_enclave {
        let result = hasher.result();
        //todo check the length of this result
        log::trace!("Computed hash: ");
        log::trace!("{:x}", result);
        let mut hash_low : u128 = 0;
        let mut hash_high : u128 = 0;
        let mut cnt = 0;
        let limit = 16;
        for element in result {
            if cnt < limit {
                hash_high = (hash_high << 8) + (element as u128);
            }
            else {
                hash_low = (hash_low << 8) + (element as u128);
            }
            cnt+=1;
        }
        let henc = hash_enclave{
            low : hash_low,
            high: hash_high
        };
        henc
    }
}


pub mod attestation_keys {

    pub fn get_keys()  { 
        
    }
}
