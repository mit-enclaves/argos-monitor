use blake3;
pub type TycheHasher = blake3::Hasher;

#[derive(Copy, Clone)]
pub struct HashEnclave {
    pub low: u128,
    pub high: u128,
}

impl HashEnclave {
    pub fn bytes_size(&self) -> u64 {
        u128::BITS as u64 / 4
    }

    pub fn to_byte_arr(&self, arr: &mut [u8], index: usize) {
        let arr_low = u128::to_le_bytes(self.low);
        let arr_high = u128::to_le_bytes(self.high);
        let mut ind_help = index;
        for i in 0..(self.bytes_size() / 2) {
            arr[ind_help] = arr_low[i as usize];
            ind_help += 1;
        }
        for i in 0..(self.bytes_size() / 2) {
            arr[ind_help] = arr_high[i as usize];
            ind_help += 1;
        }
    }
}

pub fn get_hasher() -> TycheHasher {
    blake3::Hasher::new()
}

pub fn hash_segment(hasher: &mut TycheHasher, segment_data: &[u8]) {
    hasher.update(segment_data);
}

pub fn get_hash(hasher: TycheHasher) -> HashEnclave {
    let result = hasher.finalize();
    log::trace!("Computed hash: ");
    log::trace!("{}", result);
    // TODO: this is swapped and wrong!
    let hash_low: u128 = u128::from_be_bytes(result.as_bytes()[0..16].try_into().unwrap());
    let hash_high: u128 = u128::from_be_bytes(result.as_bytes()[16..32].try_into().unwrap());
    let henc = HashEnclave {
        low: hash_low,
        high: hash_high,
    };
    henc
}

pub fn hash_region(region: &[u8]) -> [u8; 32] {
    let mut hasher = TycheHasher::new();
    hasher.update(region);
    hasher
        .finalize()
        .try_into()
        .expect("Failed to convert hash slice into array: wrong size")
}
