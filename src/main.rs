mod command;
mod injector;
mod proc_maps;
mod readelf_dynsym;
mod shellcodes;

use clap::{Parser, Subcommand, ValueEnum};
use nix::unistd::Pid;

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("Error: this injector only works on x86_64 Linux.");

#[derive(Parser)]
#[command(about = "A dynamic library injector/ejector for AMD64 Linux.")]
#[command(author = "GuillaumeMZ (github.com/GuillaumeMZ)")]
#[command(version = "1.0")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, ValueEnum)]
pub enum Action {
    Inject,
    Eject,
}

fn parse_pid(arg: &str) -> Result<Pid, std::num::ParseIntError> {
    Ok(Pid::from_raw(arg.parse()?))
}

#[derive(Subcommand)]
enum Command {
    /// Directly inject or eject a shared library 
    Cli {
        /// Choose between injection and ejection
        #[arg(short, long, value_enum)]
        action: Action,

        /// The PID of the target process
        #[arg(short, long, value_parser = parse_pid)]
        pid: Pid,

        /// The path (absolute or relative) of the dynamic library to inject/eject
        #[arg(short, long)]
        dl: String,

        /// The library providing dlopen/dlclose-like functions. It must already be loaded in the target process 
        #[arg(short, long, default_value = "libc.so.6")]
        libdl: String,

        /// The name of the dlopen-like function
        #[arg(long, default_value = "dlopen")]
        dlopen_name: String,

        /// The name of the dlclose-like function
        #[arg(long, default_value = "dlclose")]
        dlclose_name: String,
    },

    /// Start the Terminal User Interface (TUI)
    Tui
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Cli { action, pid, dl, libdl, dlopen_name, dlclose_name } => {
            command::cli(action, pid, dl, libdl, dlopen_name, dlclose_name)?;
        }

        Command::Tui => {
            command::tui()?;
        }
    }

    Ok(())
}
