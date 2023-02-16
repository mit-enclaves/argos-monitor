use clap::Parser;
use libtyche::{
    config_nb_regions, config_read_region, debug_iommu, domain_create, domain_get_own_id,
    domain_grant_region, domain_share_region, exit, region_get_info, region_split, ErrorCode,
};

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
    #[command(subcommand)]
    Config(Config),
    #[command(subcommand)]
    Debug(Debug),
    Exit,
}

#[derive(clap::Subcommand)]
enum Domain {
    Id,
    Create,
    GrantRegion { domain: usize, region: usize },
    ShareRegion { domain: usize, region: usize },
}

#[derive(clap::Subcommand)]
enum Region {
    Split { region: usize, addr: usize },
    GetInfo { region: usize },
}

#[derive(clap::Subcommand)]
enum Config {
    NbRegions,
    ReadRegion { offset: usize, nb_items: usize },
}

#[derive(clap::Subcommand)]
enum Debug {
    Iommu,
}

pub fn main() {
    let args = Args::parse();
    let result = match args.subcommand {
        Subcommand::Domain(cmd) => handle_domain(cmd),
        Subcommand::Region(cmd) => handle_region(cmd),
        Subcommand::Config(cmd) => handle_store(cmd),
        Subcommand::Debug(cmd) => handle_debug(cmd),
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
        Domain::ShareRegion { domain, region } => {
            let handle = domain_share_region(domain, region)?;
            println!(
                "Shared region to domain {} with region id: {}",
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
        Region::GetInfo { region } => {
            let info = region_get_info(region)?;
            let mut flags = String::new();
            if info.flags & 0b001 != 0 {
                flags.push_str("OWNED ");
            }
            if info.flags & 0b010 != 0 {
                flags.push_str("SHARED ");
            }
            println!(
                "Region {}:\n  start: 0x{:x}\n  end:   0x{:x}\n  flags: {}",
                region, info.start, info.end, flags
            );
        }
    }

    Ok(())
}

fn handle_store(cmd: Config) -> Result<(), ErrorCode> {
    match cmd {
        Config::NbRegions => {
            let nb_reg = config_nb_regions()?;
            println!("Number of initial regions: {}", nb_reg);
        }
        Config::ReadRegion { offset, nb_items } => {
            let (val_1, val_2, val_3) = config_read_region(offset, nb_items)?;
            if nb_items == 1 {
                println!("Store offset {}:\n  {}", offset, val_1);
            } else if nb_items == 2 {
                println!("Store offset {}:\n  {}\n  {}", offset, val_1, val_2);
            } else {
                println!(
                    "Store offset {}:\n  {}\n  {}\n  {}",
                    offset, val_1, val_2, val_3
                );
            }
        }
    }

    Ok(())
}

fn handle_debug(cmd: Debug) -> Result<(), ErrorCode> {
    match cmd {
        Debug::Iommu => debug_iommu()?,
    }

    Ok(())
}
