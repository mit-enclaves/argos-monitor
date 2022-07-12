pub mod rawc;

pub struct GuestBytes {
    pub start: u64,
    pub offset: u64,
    pub bytes: &'static [u8],
}
