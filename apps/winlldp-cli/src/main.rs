//! `winlldp`: administration and troubleshooting for the WinLLDP service.

#![forbid(unsafe_code)]

mod client;
mod render;
mod timefmt;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use lldp_ipc::{
    InterfaceModeView, InterfaceView, LocalAdvertisementView, NeighborView, Request,
    ServiceStatusView, StatisticsView,
};

#[derive(Parser, Debug)]
#[command(name = "winlldp", version, about = "WinLLDP administration")]
struct Cli {
    /// Named pipe to connect to.
    #[arg(long, global = true, default_value = lldp_ipc::PIPE_NAME, hide = true)]
    pipe: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Args, Debug, Clone)]
struct Output {
    /// Emit JSON instead of text.
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug, Clone)]
struct IfaceFilter {
    /// Limit to one interface, by alias or GUID.
    #[arg(long, short = 'i')]
    interface: Option<String>,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
enum Mode {
    Disabled,
    RxOnly,
    TxOnly,
    RxTx,
}

impl From<Mode> for InterfaceModeView {
    fn from(m: Mode) -> Self {
        match m {
            Mode::Disabled => Self::Disabled,
            Mode::RxOnly => Self::RxOnly,
            Mode::TxOnly => Self::TxOnly,
            Mode::RxTx => Self::RxTx,
        }
    }
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Show LLDP neighbors.
    Neighbors {
        #[command(flatten)]
        out: Output,
        #[command(flatten)]
        filter: IfaceFilter,
        /// Show every decoded TLV.
        #[arg(long)]
        detail: bool,
    },
    /// List network interfaces and their LLDP mode.
    Interfaces {
        #[command(flatten)]
        out: Output,
    },
    /// Show what this system advertises.
    Local {
        #[command(flatten)]
        out: Output,
        #[command(flatten)]
        filter: IfaceFilter,
    },
    /// Show service status.
    Status {
        #[command(flatten)]
        out: Output,
    },
    /// Show per-interface counters.
    Statistics {
        #[command(flatten)]
        out: Output,
        #[command(flatten)]
        filter: IfaceFilter,
    },
    /// Manage an interface (administrators only).
    Interface {
        #[command(subcommand)]
        action: InterfaceAction,
    },
    /// Run a set of checks and print a report.
    Diagnostics {
        #[command(flatten)]
        out: Output,
    },
    /// Configuration commands.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Watch an interface and print decoded TLVs as neighbors change.
    Debug {
        #[command(flatten)]
        filter: IfaceFilter,
        /// Poll interval in seconds.
        #[arg(long, default_value_t = 2)]
        interval: u64,
    },
}

#[derive(Subcommand, Debug)]
enum InterfaceAction {
    /// Set the interface to receive and transmit.
    Enable {
        /// Alias or GUID.
        name: String,
    },
    /// Disable LLDP on the interface.
    Disable {
        /// Alias or GUID.
        name: String,
    },
    /// Set the administrative mode.
    Mode {
        /// Alias or GUID.
        name: String,
        /// Mode.
        mode: Mode,
    },
}

#[derive(Subcommand, Debug)]
enum ConfigAction {
    /// Validate a configuration file without the service.
    Validate {
        /// Path; defaults to the installed configuration.
        path: Option<PathBuf>,
    },
    /// Ask the running service to reload its configuration (administrators only).
    Reload,
}

fn default_config_path() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map_or_else(|| PathBuf::from("C:\\ProgramData"), PathBuf::from);
    base.join("WinLLDP").join("config.yaml")
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    match rt.block_on(run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn print_json<T: serde::Serialize>(v: &T) -> Result<(), String> {
    let s = serde_json::to_string_pretty(v).map_err(|e| e.to_string())?;
    println!("{s}");
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn run(cli: Cli) -> Result<(), String> {
    let pipe = cli.pipe.clone();
    match cli.command {
        Command::Config {
            action: ConfigAction::Validate { path },
        } => {
            let path = path.unwrap_or_else(default_config_path);
            let text = std::fs::read_to_string(&path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            match lldp_config::Config::from_yaml(&text) {
                Ok(_) => {
                    println!("{}: valid", path.display());
                    Ok(())
                }
                Err(e) => Err(format!("{}: {e}", path.display())),
            }
        }
        Command::Config {
            action: ConfigAction::Reload,
        } => {
            let v: serde_json::Value = client::call(&pipe, Request::ReloadConfiguration).await?;
            println!("reload requested: {v}");
            Ok(())
        }
        Command::Status { out } => {
            let s: ServiceStatusView = client::call(&pipe, Request::GetServiceStatus).await?;
            if out.json {
                print_json(&s)
            } else {
                {
                    render::status(&s);
                    Ok(())
                }
            }
        }
        Command::Interfaces { out } => {
            let v: Vec<InterfaceView> = client::call(&pipe, Request::ListInterfaces).await?;
            if out.json {
                print_json(&v)
            } else {
                {
                    render::interfaces(&v);
                    Ok(())
                }
            }
        }
        Command::Neighbors {
            out,
            filter,
            detail,
        } => {
            let v: Vec<NeighborView> = client::call(
                &pipe,
                Request::ListNeighbors {
                    interface: filter.interface,
                },
            )
            .await?;
            if out.json {
                print_json(&v)
            } else {
                {
                    render::neighbors(&v, detail);
                    Ok(())
                }
            }
        }
        Command::Local { out, filter } => {
            let v: Vec<LocalAdvertisementView> = client::call(
                &pipe,
                Request::GetLocalAdvertisement {
                    interface: filter.interface,
                },
            )
            .await?;
            if out.json {
                print_json(&v)
            } else {
                {
                    render::local(&v);
                    Ok(())
                }
            }
        }
        Command::Statistics { out, filter } => {
            let v: Vec<StatisticsView> = client::call(
                &pipe,
                Request::GetStatistics {
                    interface: filter.interface,
                },
            )
            .await?;
            if out.json {
                print_json(&v)
            } else {
                {
                    render::statistics(&v);
                    Ok(())
                }
            }
        }
        Command::Interface { action } => {
            let (name, mode) = match action {
                InterfaceAction::Enable { name } => (name, InterfaceModeView::RxTx),
                InterfaceAction::Disable { name } => (name, InterfaceModeView::Disabled),
                InterfaceAction::Mode { name, mode } => (name, mode.into()),
            };
            let v: serde_json::Value = client::call(
                &pipe,
                Request::SetInterfaceMode {
                    interface: name,
                    mode,
                },
            )
            .await?;
            println!("{v}");
            Ok(())
        }
        Command::Diagnostics { out } => {
            let report = diagnostics(&pipe).await;
            if out.json {
                print_json(&report)
            } else {
                {
                    render::diagnostics(&report);
                    Ok(())
                }
            }
        }
        Command::Debug { filter, interval } => {
            let mut last: Option<Vec<NeighborView>> = None;
            loop {
                let v: Vec<NeighborView> = client::call(
                    &pipe,
                    Request::ListNeighbors {
                        interface: filter.interface.clone(),
                    },
                )
                .await?;
                if last.as_ref() != Some(&v) {
                    println!("---- {} ----", timefmt::now_utc());
                    render::neighbors(&v, true);
                    last = Some(v);
                }
                tokio::time::sleep(std::time::Duration::from_secs(interval.max(1))).await;
            }
        }
    }
}

/// One diagnostic check.
#[derive(Debug, serde::Serialize)]
pub struct Check {
    /// Name.
    pub name: String,
    /// `ok`, `warn`, or `fail`.
    pub result: &'static str,
    /// Explanation.
    pub detail: String,
}

/// The diagnostics report.
#[derive(Debug, serde::Serialize)]
pub struct Report {
    /// Checks in order.
    pub checks: Vec<Check>,
}

#[allow(clippy::too_many_lines)]
async fn diagnostics(pipe: &str) -> Report {
    let mut checks = Vec::new();
    let push = |checks: &mut Vec<Check>, name: &str, result: &'static str, detail: String| {
        checks.push(Check {
            name: name.into(),
            result,
            detail,
        });
    };

    let cfg_path = default_config_path();
    match std::fs::read_to_string(&cfg_path) {
        Ok(text) => match lldp_config::Config::from_yaml(&text) {
            Ok(_) => push(
                &mut checks,
                "configuration",
                "ok",
                format!("{} is valid", cfg_path.display()),
            ),
            Err(e) => push(&mut checks, "configuration", "fail", e.to_string()),
        },
        Err(e) => push(
            &mut checks,
            "configuration",
            "warn",
            format!("{}: {e}", cfg_path.display()),
        ),
    }

    let npcap = std::env::var_os("SystemRoot")
        .map_or_else(|| PathBuf::from("C:\\Windows"), PathBuf::from)
        .join("System32")
        .join("Npcap")
        .join("wpcap.dll");
    if npcap.exists() {
        push(
            &mut checks,
            "npcap",
            "ok",
            format!("{} present", npcap.display()),
        );
    } else {
        push(
            &mut checks,
            "npcap",
            "fail",
            format!("{} not found; install Npcap", npcap.display()),
        );
    }

    match client::call::<ServiceStatusView>(pipe, Request::GetServiceStatus).await {
        Err(e) => push(
            &mut checks,
            "service",
            "fail",
            format!("cannot reach the service: {e}"),
        ),
        Ok(s) => {
            push(
                &mut checks,
                "service",
                "ok",
                format!(
                    "WinLLDP {} up {}",
                    s.version,
                    timefmt::duration(s.uptime_secs)
                ),
            );
            match &s.npcap_version {
                Some(v) => push(&mut checks, "backend", "ok", v.clone()),
                None => push(&mut checks, "backend", "fail", s.backend_status.clone()),
            }
            push(
                &mut checks,
                "interfaces",
                if s.interfaces_managed > 0 {
                    "ok"
                } else {
                    "warn"
                },
                format!(
                    "{} managed of {} known",
                    s.interfaces_managed, s.interfaces_known
                ),
            );
            push(
                &mut checks,
                "neighbors",
                if s.neighbors_total > 0 { "ok" } else { "warn" },
                format!(
                    "{} neighbor(s); none can mean a switch without LLDP, a NIC firmware LLDP agent, or no link",
                    s.neighbors_total
                ),
            );
            if s.policy_applied {
                push(
                    &mut checks,
                    "policy",
                    "ok",
                    "registry policy overrides are in effect".into(),
                );
            }
            if let Ok(stats) = client::call::<Vec<StatisticsView>>(
                pipe,
                Request::GetStatistics { interface: None },
            )
            .await
            {
                for st in stats {
                    if st.rx_frames_errors > 0 || st.rx_queue_overflow > 0 {
                        push(
                            &mut checks,
                            &format!("errors on {}", st.interface_alias),
                            "warn",
                            format!(
                                "{} malformed frames, {} queue overflows",
                                st.rx_frames_errors, st.rx_queue_overflow
                            ),
                        );
                    }
                }
            }
        }
    }
    Report { checks }
}
