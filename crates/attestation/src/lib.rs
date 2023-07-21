#![no_std]

extern crate alloc;

use sha2::Sha256;

use core::alloc::GlobalAlloc;
use alloc::alloc::Layout;

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
    pub fn get_hash(hasher : & mut TycheHasher) -> u128 {
        let result = hasher.result();
        //todo check the length of this result
        let result_arr = result.as_slice();
        log::trace!("Computed hash: ");
        log::trace!("{:x}", result);
        let mut hash : u128 = 0;
        for element in result_arr {
            hash = (hash << 8) + (*element as u128);
        }
        hash
    }
}


pub mod attestation_keys {

    // use ed25519::signature::{Signer,Verifier};
    // use ed25519::Signature;

    // use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

    // use libsecp256k1::{PublicKey, SecretKey};

    pub fn get_keys()  { 
        // -> (Signer<ed25519::Signature>, Verifier<ed25519::Signature>) {
        // todo!("Find crate for enc/dec that is no_std");

        // let sec_key = SecretKey::default();
        // let pub_key = PublicKey::from_secret_key(&sec_key);

        // libsecp256k1.sign()

        // let bits = 160;
        // let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        // let pub_key = RsaPublicKey::from(&priv_key);

        // Encrypt
        // let data = b"hello world";
        // let enc_data = pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, &data[..]).expect("failed to encrypt");
        // log::trace!("{:x}", enc_data);

        // Decrypt
        // let dec_data = priv_key.decrypt(Pkcs1v15Encrypt, &enc_data).expect("failed to decrypt");
        // log::trace!("{:x}", dec_data);
    }
}

static mut arr : [u8;256] = [0;256];
static mut index : usize = 0;

#[derive(Default)]
pub struct Allocator;

unsafe impl GlobalAlloc for Allocator {
     unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        index = (index + layout.size()) % 1024;
        unsafe {
            let x = &arr[index] as * const u8;
            x as * mut u8
        }
        
     }
     unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        //todo
     }
}

/// The static global allocator.
#[global_allocator]
static GLOBAL_ALLOCATOR: Allocator = Allocator;
