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
use ed25519_compact::{KeyPair, PublicKey, Seed, Noise};
pub fn get_attestation_keys() -> (AttestationKey, AttestationKey) { 
    let msg = b"test";
    let key_pair = KeyPair::from_seed(Seed::default());

    let s = key_pair.sk.sign(msg, Some(Noise::default()));
    if let Ok(r) = key_pair.pk.verify(msg, &s) {
        log::trace!("Message verified");
    }
    else {
        log::trace!("Didn't verify the message");
    }
    (0,0)
}

pub fn sign_attestation_data(_data : &[u8], _key : AttestationKey) -> AttestationSignature {
    0
}

pub fn sign_by_device(_data : &[u8], _key : DevicePrivateKey) -> AttestationSignature {
    0
}