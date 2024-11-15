use ed25519_compact::{KeyPair, Noise, PublicKey, SecretKey, Seed, Signature};
pub type DevicePublicKey = PublicKey;
pub type DevicePrivateKey = SecretKey;
pub type AttestationPublicKey = PublicKey;
pub type AttestationPrivateKey = SecretKey;

pub type AttestationSignature = Signature;

pub const MAX_ATTESTATION_DATA_SZ: usize = 8;
pub const ATTESTATION_DATA_SZ: usize = MAX_ATTESTATION_DATA_SZ + 32;

#[derive(Copy, Clone)]
pub struct EnclaveReport {
    pub public_key: PublicKey,
    pub signed_enclave_data: AttestationSignature,
}

pub fn get_attestation_keys() -> (AttestationPublicKey, AttestationPrivateKey) {
    let key_pair = KeyPair::from_seed(Seed::default());
    (key_pair.pk, key_pair.sk)
}

pub fn vtpm_sign(data: &[u8], dest: &mut [u8]) -> usize {
    let key = AttestationPrivateKey::new([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 3, 161, 7, 191, 243, 206, 16, 190, 29, 112, 221, 24, 231, 75, 192, 153, 103, 228, 214, 48, 155, 165, 13, 95, 29, 220, 134, 100, 18, 85, 49, 184]);
    dest[..Signature::BYTES].copy_from_slice(key.sign(data, Some(Noise::default())).as_ref());
    Signature::BYTES as usize
}

pub fn sign_attestation_data(data: &[u8], key: AttestationPrivateKey) -> AttestationSignature {
    let sig = key.sign(data, Some(Noise::default()));
    sig
}

pub fn sign_by_device(data: &[u8], key: DevicePrivateKey) -> AttestationSignature {
    let sig = key.sign(data, Some(Noise::default()));
    sig
}
