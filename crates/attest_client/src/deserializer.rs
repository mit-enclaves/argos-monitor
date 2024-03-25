use capa_engine::serializer::serde;

use crate::{Context, RegionKind, Region};

pub fn deserialize(buff: &[u8]) -> Result<Context, ()> {
    let mut ctx = Context::new();
    let mut buff = Buffer::new(buff);

    // Check magic value
    let magic = buff.u32();
    assert_eq!(serde::MAGIC, magic.to_le_bytes());
    deserialize_regions(&mut ctx, &mut buff);
    deserialize_domains(&mut ctx, &mut buff);

    Ok(ctx)
}

fn deserialize_regions(ctx: &mut Context, buff: &mut Buffer) {
    assert_eq!(serde::REGION_HEADER, buff.u8());
    while buff.peek_u8() != serde::END_MARKER {
        let kind = match buff.u8() {
            serde::REGION_ROOT => RegionKind::Root,
            serde::REGION_ALIAS => {
                let idx = buff.u32() as usize;
                let handle = ctx.regions.as_handle(idx).unwrap();
                RegionKind::Alias(handle)
            }
            serde::REGION_CARVE => {
                let idx = buff.u32() as usize;
                let handle = ctx.regions.as_handle(idx).unwrap();
                RegionKind::Carve(handle)
            }
            _ => panic!("Invalid region kind")
        };
        let ops = buff.u8();
        let start = buff.u64();
        let end = buff.u64();
        ctx.regions.push(Region { start, end, kind, ops });
    }
    assert_eq!(serde::END_MARKER, buff.u8());
}

fn deserialize_domains(_ctx: &mut Context, _buff: &mut Buffer) {
    // TODO
}

// ————————————————————————————————— Buffer ————————————————————————————————— //

struct Buffer<'a> {
    buff: &'a [u8],
    cursor: usize,
}

impl<'a> Buffer<'a> {
    fn new(buff: &'a [u8]) -> Self {
        Self { buff, cursor: 0 }
    }

    fn u8(&mut self) -> u8 {
        let val = self.buff[self.cursor];
        self.cursor += 1;
        val
    }

    fn u32(&mut self) -> u32 {
        let val = &self.buff[self.cursor..(self.cursor + 4)];
        let val = u32::from_le_bytes(val.try_into().unwrap());
        self.cursor += 4;
        val
    }

    fn u64(&mut self) -> u64 {
        let val = &self.buff[self.cursor..(self.cursor + 8)];
        let val = u64::from_le_bytes(val.try_into().unwrap());
        self.cursor += 8;
        val
    }

    fn peek_u8(&self) -> u8 {
        self.buff[self.cursor]
    }
}

// ————————————————————————————————— Tests —————————————————————————————————— //

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn region() {
        // TODO
    }
}
