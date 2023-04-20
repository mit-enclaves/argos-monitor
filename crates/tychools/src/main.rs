mod allocator;
mod debug;
mod instr;
mod instrument;
mod objcopy;

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use debug::{print_elf_segments, print_page_tables, printf_elf_with_obj};
use instrument::{dump_page_tables, modify_binary};
use objcopy::copy_binary;
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
    PrintELFSegments(FileArg),
    PrintELFWithObj(SrcDestArgs),
    CopyBinary(SrcDestArgs),
    DumpPageTables(SrcDestArgs),
    PrintPageTables(FileArg),
    ModifyBinary(SrcDestArgs),
}

#[derive(Args)]
struct FileArg {
    #[arg(short, long, value_name = "FILE")]
    path: PathBuf,
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
        Commands::PrintELFSegments(args) => {
            print_elf_segments(&args.path);
        }
        Commands::PrintELFWithObj(args) => {
            printf_elf_with_obj(&args.src, &args.dst);
        }
        Commands::CopyBinary(args) => {
            copy_binary(&args.src, &args.dst);
        }
        Commands::DumpPageTables(args) => {
            dump_page_tables(&args.src, &args.dst);
        }
        Commands::PrintPageTables(args) => {
            print_page_tables(&args.path);
        }
        Commands::ModifyBinary(args) => {
            modify_binary(&args.src, &args.dst);
        }
    }
}
