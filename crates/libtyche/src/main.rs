use clap::Parser;
use libtyche::ErrorCode;
use libtyche::{domain_create, domain_get_own_id, exit};

#[derive(clap::Parser)]
struct Args {
    #[command(subcommand)]
    subcommand: Subcommand,
}

#[derive(clap::Subcommand)]
enum Subcommand {
    #[command(subcommand)]
    Domain(Domain),
    Exit,
}

#[derive(clap::Subcommand)]
enum Domain {
    Id,
    Create,
}

pub fn main() {
    let args = Args::parse();
    let result = match args.subcommand {
        Subcommand::Domain(cmd) => handle_domain(cmd),
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
    };

    Ok(())
}
