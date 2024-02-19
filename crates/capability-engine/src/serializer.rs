//! Serializer
//!
//! This module expose an interface to serialize the internal capa-engine representation into a
//! inter-operable attestation format.

use crate::segment::{HandleIterator, NewRegionCapa, NewRegionPool};
use crate::{CapaError, Handle};

/// Serialization-Deserialization constants
#[rustfmt::skip]
pub mod serde {
    pub const MAGIC: [u8; 4] = *b"capa";
    pub const REGION_HEADER: u8 = 0b1;
    pub const END_MARKER:    u8 = 0b0;

    pub const REGION_ROOT:  u8 = 0b00;
    pub const REGION_ALIAS: u8 = 0b01;
    pub const REGION_CARVE: u8 = 0b10;
}

// ————————————————————————————————— Buffer ————————————————————————————————— //

struct Buffer<'a> {
    buff: &'a mut [u8],
    idx: usize,
}

impl<'a> Buffer<'a> {
    fn new(buff: &'a mut [u8]) -> Self {
        Self { buff, idx: 0 }
    }

    fn write_bytes<const N: usize>(&mut self, bytes: [u8; N]) -> Result<(), CapaError> {
        if self.idx + N > self.buff.len() {
            return Err(CapaError::OutOfMemory);
        }
        self.buff[self.idx..(self.idx + N)].copy_from_slice(&bytes);
        self.idx += N;
        Ok(())
    }

    fn u8(&mut self, val: u8) -> Result<(), CapaError> {
        self.write_bytes(val.to_le_bytes())
    }

    // fn u16(&mut self, val: u16) -> Result<(), CapaError> {
    //     self.write_bytes(val.to_le_bytes())
    // }

    fn u32(&mut self, val: u32) -> Result<(), CapaError> {
        self.write_bytes(val.to_le_bytes())
    }

    fn u64(&mut self, val: u64) -> Result<(), CapaError> {
        self.write_bytes(val.to_le_bytes())
    }
}

// ————————————————————————————— Serialization —————————————————————————————— //

pub(crate) fn serialize(buff: &mut [u8], regions: &NewRegionPool) -> Result<usize, CapaError> {
    let mut buff = Buffer::new(buff);
    buff.write_bytes(serde::MAGIC)?;
    serialize_regions(&mut buff, regions)?;
    buff.u8(serde::END_MARKER)?;

    // TODO: serialize domains
    Ok(buff.idx + 1)
}

fn serialize_regions(buff: &mut Buffer, regions: &NewRegionPool) -> Result<(), CapaError> {
    buff.u8(serde::REGION_HEADER)?;
    let mut region_idx = 0;
    for h in regions {
        // Recursively serialize each tree, starting from the root
        if regions[h].is_root() {
            serialize_region(buff, h, &mut region_idx, u32::MAX, regions)?;
        }
    }
    buff.u8(serde::END_MARKER)?;

    Ok(())
}

/// Serialize a region and all its children.
fn serialize_region(
    buff: &mut Buffer,
    handle: Handle<NewRegionCapa>,
    idx: &mut u32,
    parent_idx: u32,
    regions: &NewRegionPool,
) -> Result<(), CapaError> {
    let region = &regions[handle];
    let region_idx = *idx;
    *idx += 1;

    // Serialize region
    let kind = match region.kind {
        crate::segment::RegionKind::Root => serde::REGION_ROOT,
        crate::segment::RegionKind::Alias(_) => serde::REGION_ALIAS,
        crate::segment::RegionKind::Carve(_) => serde::REGION_CARVE,
    };
    buff.u8(kind)?;
    if !region.is_root() {
        buff.u32(parent_idx)?;
    }
    buff.u8(region.access.ops.bits())?;
    buff.u64(region.access.start as u64)?;
    buff.u64(region.access.end as u64)?;

    // Serialize children
    for child in HandleIterator::child_list(handle, regions) {
        serialize_region(buff, child, idx, region_idx, regions)?;
    }

    Ok(())
}
