//! WinLLDP service executable.
//!
//! Runs as a Windows Service by default. `--console` runs in the
//! foreground for development, and `install`, `uninstall`, and `harden`
//! manage the SCM registration (the MSI performs these in production).

#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[cfg(windows)]
mod app;
#[cfg(windows)]
mod handler;
#[cfg(windows)]
mod service;
#[cfg(windows)]
mod sink;

/// Service name registered with the SCM.
pub const SERVICE_NAME: &str = "WinLLDP";
/// Display name.
pub const DISPLAY_NAME: &str = "WinLLDP Link Layer Discovery Protocol Agent";

/// Default configuration path.
pub fn default_config_path() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map_or_else(|| PathBuf::from("C:\\ProgramData"), PathBuf::from);
    base.join("WinLLDP").join("config.yaml")
}

#[derive(Parser, Debug)]
#[command(name = "winlldp-service", version, about = "WinLLDP service")]
struct Cli {
    /// Configuration file path.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Run in the foreground with console logging instead of as a service.
    #[arg(long)]
    console: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Register the service with the Service Control Manager.
    Install,
    /// Remove the service registration.
    Uninstall,
    /// Apply the service SID and minimal privileges.
    Harden,
    /// Validate the configuration file and exit.
    Validate,
}

fn main() {
    let cli = Cli::parse();
    let config_path = cli.config.clone().unwrap_or_else(default_config_path);
    let code = match cli.command {
        Some(Command::Validate) => validate(&config_path),
        #[cfg(windows)]
        Some(Command::Install) => report(service::install(&config_path)),
        #[cfg(windows)]
        Some(Command::Uninstall) => report(service::uninstall()),
        #[cfg(windows)]
        Some(Command::Harden) => report(service::harden()),
        #[cfg(windows)]
        None if cli.console => report(app::run_console(config_path)),
        #[cfg(windows)]
        None => report(service::run(config_path)),
        #[cfg(not(windows))]
        _ => {
            eprintln!("winlldp-service only runs on Windows; use `validate` elsewhere");
            2
        }
    };
    std::process::exit(code);
}

fn validate(path: &std::path::Path) -> i32 {
    match std::fs::read_to_string(path) {
        Err(e) => {
            eprintln!("cannot read {}: {e}", path.display());
            2
        }
        Ok(text) => match lldp_config::Config::from_yaml(&text) {
            Ok(_) => {
                println!("{}: valid", path.display());
                0
            }
            Err(e) => {
                eprintln!("{}: {e}", path.display());
                1
            }
        },
    }
}

#[cfg(windows)]
fn report(r: Result<(), String>) -> i32 {
    match r {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}
