use clap::Parser;
use libtyche::{
    domain_create, duplicate, enumerate, exit, revoke, seal_domain, segment_region, send, switch,
};

#[derive(clap::Parser)]
struct Args {
    #[command(subcommand)]
    subcommand: Subcommand,
}

#[derive(clap::Subcommand)]
enum Subcommand {
    CreateDomain,
    SealDomain {
        domain: usize,
        core_map: usize,
        arg1: usize,
        arg2: usize,
        arg3: usize,
    },
    Send {
        target: usize,
        capa: usize,
    },
    SegmentRegion {
        capa: usize,
        start_1: usize,
        end_1: usize,
        prot_1: usize,
        start_2: usize,
        end_2: usize,
        prot_2: usize,
    },
    Revoke {
        capa: usize,
    },
    Duplicate {
        capa: usize,
    },
    Enumerate {
        capa: usize,
    },
    Switch {
        handle: usize,
        cpu: usize,
    },
    Exit,
    List,
}

pub fn main() {
    let args = Args::parse();
    match args.subcommand {
        Subcommand::Send { target, capa } => {
            send(target, capa).unwrap();
        }
        Subcommand::SegmentRegion {
            capa,
            start_1,
            end_1,
            prot_1,
            start_2,
            end_2,
            prot_2,
        } => {
            segment_region(capa, start_1, end_1, prot_1, start_2, end_2, prot_2).unwrap();
        }
        Subcommand::Revoke { capa } => {
            revoke(capa).unwrap();
        }
        Subcommand::Duplicate { capa } => {
            duplicate(capa).unwrap();
        }
        Subcommand::Enumerate { capa } => {
            enumerate(capa).unwrap();
        }
        Subcommand::Switch { handle, cpu } => {
            switch(handle, cpu).unwrap();
        }

        Subcommand::CreateDomain => {
            domain_create().unwrap();
        }
        Subcommand::SealDomain {
            domain,
            core_map,
            arg1,
            arg2,
            arg3,
        } => {
            seal_domain(domain, core_map, arg1, arg2, arg3).unwrap();
        }
        Subcommand::Exit => {
            exit().unwrap();
        }
        Subcommand::List => list_all_capas(),
    };
}

fn list_all_capas() {
    let mut token = 0;
    while let Some((capa, next)) = enumerate(token).unwrap() {
        if next == 0 {
            break;
        }

        println!("{}: {}", next - 1, capa);
        token = next;
    }
}
