use clap::Parser;
use libtyche::ErrorCode;
use libtyche::{domain_create, domain_get_own_id, domain_grant_region, exit, region_split};

#[derive(clap::Parser)]
struct Args {
    #[command(subcommand)]
    subcommand: Subcommand,
}

#[derive(clap::Subcommand)]
enum Subcommand {
    #[command(subcommand)]
    Domain(Domain),
    #[command(subcommand)]
    Region(Region),
    Exit,
}

#[derive(clap::Subcommand)]
enum Domain {
    Id,
    Create,
    GrantRegion { domain: usize, region: usize },
}

#[derive(clap::Subcommand)]
enum Region {
    Split { region: usize, addr: usize },
}

pub fn main() {
    let args = Args::parse();
    let result = match args.subcommand {
        Subcommand::Domain(cmd) => handle_domain(cmd),
        Subcommand::Region(cmd) => handle_region(cmd),
        Subcommand::Exit => exit(),
    };
    if let Err(err) = result {
        println!("Error: {:?}", err);
    }
}

fn handle_domain(cmd: Domain) -> Result<(), ErrorCode> {
    match cmd {
        Domain::Id => {
            let id = domain_get_own_id()?;
            println!("Own domain id: {}", id.0);
        }
        Domain::Create => {
            let id = domain_create()?;
            println!("New domain id: {}", id.0);
        }
        Domain::GrantRegion { domain, region } => {
            let handle = domain_grant_region(domain, region)?;
            println!(
                "Granted region to domain {} with region id: {}",
                domain, handle.0
            );
        }
    };

    Ok(())
}

fn handle_region(cmd: Region) -> Result<(), ErrorCode> {
    match cmd {
        Region::Split { region, addr } => {
            let handle = region_split(region, addr)?;
            println!("Split region at 0x{:x}, new region id: {}", addr, handle.0);
        }
    }

    Ok(())
}
