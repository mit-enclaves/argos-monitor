extern crate alloc;

use core::alloc::GlobalAlloc;
use alloc::alloc::Layout;

pub type DeviceKey = u128;
pub type DevicePublicKey = DeviceKey;
pub type DevicePrivateKey = DeviceKey;
pub type AttestationKey = DeviceKey;

pub type AttestationSignature = u128;

pub const MAX_ATTESTATION_DATA_SZ : usize = 64;
pub const ATTESTATION_DATA_SZ : usize = MAX_ATTESTATION_DATA_SZ + 256;

pub const DEVICE_PRIVATE : DevicePrivateKey = 0x1000;
pub const DEVICE_PUBLIC : DevicePublicKey = 0x2000;

pub struct EnclaveReport {
    // pub signed_attestation_key : AttestationSignature,
    // pub signed_enclave_data : AttestationSignature
    pub hash_low : AttestationSignature,
    pub hash_high : AttestationSignature,
    pub nonce : u64,
}
// use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt};

pub fn get_attestation_keys() -> (AttestationKey, AttestationKey) { 
    // let bits = 16;
    // let mut rng = RndTyche{};
    // let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    // let pub_key = RsaPublicKey::from(&priv_key);

    // // Encrypt
    // let data = b"hello world";
    // log::trace!("data");
    // for x in data {
    //     log::trace!("u8 {:#x}", x);
    // }
    // let enc_data = pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, &data[..]).expect("failed to encrypt");
    // log::trace!("Enc data");
    // for x in &enc_data {
    //     log::trace!("u8 {:#x}", *x);
    // }

    // // Decrypt
    // let dec_data = priv_key.decrypt(Pkcs1v15Encrypt, &enc_data).expect("failed to decrypt");
    // log::trace!("Dec data");
    // for x in &dec_data {
    //     log::trace!("u8 {:#x}", *x);
    // }

    (0,0)
}

pub fn sign_attestation_data(_data : &[u8], _key : AttestationKey) -> AttestationSignature {
    0
}

pub fn sign_by_device(_data : &[u8], _key : DevicePrivateKey) -> AttestationSignature {
    0
}

use rand_core::{RngCore, Error, CryptoRng};

pub struct RndTyche {
    
}

impl RngCore for RndTyche {
    fn next_u32(&mut self) -> u32 {
        log::trace!("next u32");
        0
    }  
    fn next_u64(&mut self) -> u64 {
        log::trace!("next u64");
        0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        log::trace!("fill bytes");
        let mut cnt : u8 = 0;
        for x in dest {
            *x = cnt;
            cnt+=1;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        log::trace!("try fill bytes");
        let mut cnt : u8 = 0;
        for x in dest {
            *x = cnt;
            cnt+=1;
        }
        Ok(())
    }
}

impl CryptoRng for RndTyche {

}

static SZ : usize = 0x5000;
static mut ARR : [u8;0x5000] = [0;0x5000];
static mut INDEX : usize = 0;

#[derive(Default)]
pub struct Allocator;

unsafe impl GlobalAlloc for Allocator {
     unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        log::trace!("allocating");
        log::trace!("{:#x}", layout.size());
        INDEX = (INDEX + layout.size()) % SZ;
        unsafe {
            let x = (&ARR[INDEX]) as * const u8;
            x as * mut u8
        }

     }
     unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static GLOBAL_ALLOCATOR: Allocator = Allocator;