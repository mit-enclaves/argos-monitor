#![no_std]

use p256::ecdsa::{SigningKey, VerifyingKey, Signature, signature::Signer};

type PublicKey = VerifyingKey;
type SecretKey = SigningKey;

pub type DevicePublicKey = PublicKey;
pub type DevicePrivateKey = SecretKey;
pub type AttestationPublicKey = PublicKey;
pub type AttestationPrivateKey = SecretKey;

pub type AttestationSignature = Signature;

pub const MAX_ATTESTATION_DATA_SZ: usize = 8;
pub const ATTESTATION_DATA_SZ: usize = MAX_ATTESTATION_DATA_SZ + 32;

const KEY_SEED: [u8; 64] = [0; 64];

#[derive(Copy, Clone)]
pub struct EnclaveReport {
    pub public_key: PublicKey,
    pub signed_enclave_data: AttestationSignature,
}

pub fn get_attestation_keys() -> (AttestationPublicKey, AttestationPrivateKey) {
    let secret_key = SecretKey::from_slice(&KEY_SEED).unwrap();
    let public_key = PublicKey::from(&secret_key);
    (public_key, secret_key)
}

pub fn sign_attestation_data(data: &[u8], key: AttestationPrivateKey) -> AttestationSignature {
    let sig = key.sign(data);
    sig
}

pub fn sign_by_device(data: &[u8], key: DevicePrivateKey) -> AttestationSignature {
    let sig = key.sign(data);
    sig
}
