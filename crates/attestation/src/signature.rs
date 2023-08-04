use ed25519_compact::{KeyPair, SecretKey, PublicKey, Seed, Noise, Signature};
pub type DevicePublicKey = PublicKey;
pub type DevicePrivateKey = SecretKey;
pub type AttestationPublicKey = PublicKey;
pub type AttestationPrivateKey = SecretKey;

pub type AttestationSignature = Signature;

pub const MAX_ATTESTATION_DATA_SZ : usize = 8;
pub const ATTESTATION_DATA_SZ : usize = MAX_ATTESTATION_DATA_SZ + 32;

// pub const DEVICE_PRIVATE : DevicePrivateKey = 0x1000;
// pub const DEVICE_PUBLIC : DevicePublicKey = 0x2000;

#[derive(Copy,Clone)]
pub struct EnclaveReport {
    // pub dev_public_key : DevicePublicKey,
    // pub attestation_public_key : AttestationPublicKey,
    pub public_key : PublicKey,
    pub signed_enclave_data : AttestationSignature,
    // pub signed_attestation_key : AttestationSignature,
    // pub hash_low : AttestationSignature,
    // pub hash_high : AttestationSignature,
    // pub nonce : u64,
}

pub fn get_attestation_keys() -> (AttestationPublicKey, AttestationPrivateKey) { 
    let key_pair = KeyPair::from_seed(Seed::default());
    (key_pair.pk, key_pair.sk)
}

pub fn sign_attestation_data(data : &[u8], key : AttestationPrivateKey) -> AttestationSignature {
    let sig = key.sign(data, Some(Noise::default()));
    sig
}

pub fn sign_by_device(data : &[u8], key : DevicePrivateKey) -> AttestationSignature {
    let sig = key.sign(data, Some(Noise::default()));
    sig
}