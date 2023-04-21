mod allocator;
mod elf_modifier;
mod instrument;
mod page_table_mapper;

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use instrument::modify_binary;
use simple_logger;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    TychefyBinary(SrcDestArgs),
}

#[derive(Args)]
struct SrcDestArgs {
    #[arg(short, long, value_name = "SRC")]
    src: PathBuf,
    #[arg(short, long, value_name = "DST")]
    dst: PathBuf,
}

fn main() {
    simple_logger::init().unwrap();
    let cli = Cli::parse();
    match &cli.command {
        Commands::TychefyBinary(args) => {
            modify_binary(&args.src, &args.dst);
        }
    }
}
