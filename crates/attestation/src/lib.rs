#![no_std]

extern crate alloc;

use core::alloc::GlobalAlloc;
use alloc::alloc::Layout;
pub mod signature;
use sha2::Sha256;

pub type TycheHasher = Sha256;

#[derive(Copy,Clone)]
pub struct hash_enclave {
    pub low : u128,
    pub high : u128,
}

impl hash_enclave {
    pub fn bytes_size(&self) -> u64 {
        u128::BITS as u64 / 8
    }
    pub fn to_byte_arr(&self, arr : & mut [u8], index : usize) {
        let arr_low = u128::to_le_bytes(self.low);
        let arr_high = u128::to_le_bytes(self.high);
        let mut ind_help = index;
        for i in 0..(self.bytes_size() / 2) {
            arr[ind_help] = arr_low[i as usize];
            ind_help+=1;
        }
        for i in 0..(self.bytes_size() / 2) {
            arr[ind_help] = arr_high[i as usize];
            ind_help+=1;
        }
    }
    
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


