use clap::Parser;
use libtyche::{
    domain_create, duplicate, enumerate, exit, give, grant, revoke, seal_domain, share, switch,
};

#[derive(clap::Parser)]
struct Args {
    #[command(subcommand)]
    subcommand: Subcommand,
}

#[derive(clap::Subcommand)]
enum Subcommand {
    DomainCreate {
        spawn: usize,
        comm: usize,
    },
    SealDomain {
        domain: usize,
        core_map: usize,
        arg1: usize,
        arg2: usize,
        arg3: usize,
    },
    Share {
        target: usize,
        capa: usize,
        arg1: usize,
        arg2: usize,
        arg3: usize,
    },
    Grant {
        target: usize,
        capa: usize,
        arg1: usize,
        arg2: usize,
        arg3: usize,
    },
    Give {
        target: usize,
        capa: usize,
    },
    Revoke {
        capa: usize,
    },
    Duplicate {
        capa: usize,
        arg_1_1: usize,
        arg_1_2: usize,
        arg_1_3: usize,
        arg_2_1: usize,
        arg_2_2: usize,
        arg_2_3: usize,
    },
    Enumerate {
        capa: usize,
    },
    Switch {
        handle: usize,
        cpu: usize,
    },
    Exit,
}

pub fn main() {
    let args = Args::parse();
    match args.subcommand {
        Subcommand::Share {
            target,
            capa,
            arg1,
            arg2,
            arg3,
        } => {
            share(target, capa, arg1, arg2, arg3).unwrap();
        }
        Subcommand::Grant {
            target,
            capa,
            arg1,
            arg2,
            arg3,
        } => {
            grant(target, capa, arg1, arg2, arg3).unwrap();
        }
        Subcommand::Give { target, capa } => {
            give(target, capa).unwrap();
        }
        Subcommand::Revoke { capa } => {
            revoke(capa).unwrap();
        }
        Subcommand::Duplicate {
            capa,
            arg_1_1,
            arg_1_2,
            arg_1_3,
            arg_2_1,
            arg_2_2,
            arg_2_3,
        } => {
            duplicate(capa, arg_1_1, arg_1_2, arg_1_3, arg_2_1, arg_2_2, arg_2_3).unwrap();
        }
        Subcommand::Enumerate { capa } => {
            enumerate(capa).unwrap();
        }
        Subcommand::Switch { handle, cpu } => {
            switch(handle, cpu).unwrap();
        }

        Subcommand::DomainCreate { spawn, comm } => {
            domain_create(spawn, comm).unwrap();
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
    };
}
