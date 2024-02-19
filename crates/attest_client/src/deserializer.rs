use capa_engine::serializer::serde;
use nom::branch::alt;
use nom::bytes::complete::{tag, take};
use nom::number::complete::{le_u32, le_u64, le_u8};
use nom::sequence::tuple;
use nom::IResult;

use crate::{Context, Handle, Region, RegionKind};

enum RegionTag {
    Root,
    Alias,
    Carve,
}

fn root(buff: &[u8], ctx: &mut Context) -> IResult<&[u8], ()> {
    let (i, (_, ops, start, end)) =
        tuple((tag([serde::REGION_ROOT]), le_u8, le_u64, le_u64))(buff)?;
    let _ = ops;
    ctx.regions.push(Region {
        start: start as usize,
        end: end as usize,
        kind: RegionKind::Root,
    });
    Ok((i, ()))
}

fn alias(buff: &[u8]) -> IResult<&[u8], Region> {
    let (i, (_, parent, ops, start, end)) =
        tuple((tag([serde::REGION_ALIAS]), le_u32, le_u8, le_u64, le_u64))(buff)?;
    let _ = ops;
    Ok((
        i,
        Region {
            start: start as usize,
            end: end as usize,
            kind: RegionKind::Alias(parent),
        },
    ))
}

fn region_tag(buff: &[u8]) -> IResult<&[u8], Option<RegionTag>> {
    // let (next, val) = le_u8(buff)?;
    // let access = (le_u8, le_u64, le_u64);
    // let root = tag([serde::REGION_ROOT]);
    // let alias = (tag([serde::REGION_ALIAS]), le_u32);
    // let carvd = (tag([serde::REGION_CARVE]), le_u32);

    todo!()
}

fn parser(buff: &[u8]) -> IResult<&[u8], Region> {
    todo!()
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
