//! Service Control Manager integration.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Notify, watch};
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceSidType, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::{DISPLAY_NAME, SERVICE_NAME};

static CONFIG_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

/// Starts the service dispatcher; blocks until the service stops.
pub fn run(config_path: PathBuf) -> Result<(), String> {
    let _ = CONFIG_PATH.set(config_path);
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|e| format!("service dispatcher: {e}"))
}

fn status(state: ServiceState, accept: ServiceControlAccept, wait_hint: Duration) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint,
        process_id: None,
    }
}

fn service_main(_args: Vec<OsString>) {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let reload = Arc::new(Notify::new());
    let resume = Arc::new(Notify::new());
    let shutdown_for_handler = shutdown_tx.clone();
    let reload_for_handler = Arc::clone(&reload);
    let resume_for_handler = Arc::clone(&resume);

    let status_cell = Arc::new(std::sync::OnceLock::new());
    let status_for_handler = Arc::clone(&status_cell);

    let handler = move |control: ServiceControl| -> ServiceControlHandlerResult {
        match control {
            ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
                // Shutdown sends TTL 0 frames and restores MsLldp bindings,
                // which takes seconds; without this the SCM reports the
                // stop request as failed.
                if let Some(h) = status_for_handler.get() {
                    let h: &service_control_handler::ServiceStatusHandle = h;
                    let _ = h.set_service_status(status(
                        ServiceState::StopPending,
                        ServiceControlAccept::empty(),
                        Duration::from_secs(30),
                    ));
                }
                let _ = shutdown_for_handler.send(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::ParamChange => {
                reload_for_handler.notify_one();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::UserEvent(code) if code.to_raw() == crate::app::RELOAD_CONTROL_CODE => {
                reload_for_handler.notify_one();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::PowerEvent(
                windows_service::service::PowerEventParam::ResumeAutomatic
                | windows_service::service::PowerEventParam::ResumeSuspend,
            ) => {
                resume_for_handler.notify_one();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate | ServiceControl::PowerEvent(_) => {
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let Ok(status_handle) = service_control_handler::register(SERVICE_NAME, handler) else {
        return;
    };
    let _ = status_cell.set(status_handle);
    let accept = ServiceControlAccept::STOP
        | ServiceControlAccept::SHUTDOWN
        | ServiceControlAccept::PRESHUTDOWN
        | ServiceControlAccept::PARAM_CHANGE
        | ServiceControlAccept::POWER_EVENT;
    let _ = status_handle.set_service_status(status(
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        Duration::from_secs(10),
    ));

    let config_path = CONFIG_PATH
        .get()
        .cloned()
        .unwrap_or_else(crate::default_config_path);
    let _ = status_handle.set_service_status(status(ServiceState::Running, accept, Duration::ZERO));

    let outcome = crate::app::run_service(config_path, shutdown_rx, reload, resume);

    let _ = status_handle.set_service_status(status(
        ServiceState::StopPending,
        ServiceControlAccept::empty(),
        Duration::from_secs(5),
    ));
    let mut final_status = status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        Duration::ZERO,
    );
    if outcome.is_err() {
        final_status.exit_code = ServiceExitCode::ServiceSpecific(1);
    }
    let _ = status_handle.set_service_status(final_status);
}

/// Registers the service: automatic start, LocalSystem, restart on failure.
pub fn install(config_path: &Path) -> Result<(), String> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CREATE_SERVICE | ServiceManagerAccess::CONNECT,
    )
    .map_err(|e| format!("open SCM: {e}"))?;
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![
            OsString::from("--config"),
            config_path.as_os_str().to_owned(),
        ],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .map_err(|e| format!("create service: {e}"))?;
    service
        .set_description("Advertises this workstation to directly connected switches with IEEE 802.1AB LLDP and records LLDP neighbors.")
        .map_err(|e| format!("set description: {e}"))?;
    service
        .set_delayed_auto_start(false)
        .map_err(|e| format!("set start: {e}"))?;
    drop(service);
    harden()?;
    lldp_windows::eventlog::register_source().map_err(|e| format!("event source: {e}"))?;
    println!("{SERVICE_NAME} installed");
    Ok(())
}

/// Applies the service SID, minimal privileges, and failure
/// actions. Safe to run repeatedly.
pub fn harden() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("open SCM: {e}"))?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            // START is required to set a restart failure action.
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::QUERY_CONFIG | ServiceAccess::START,
        )
        .map_err(|e| format!("open service: {e}"))?;
    // Unrestricted, not restricted: a write-restricted token is not an
    // administrator to Npcap's Admin-only mode and cannot create further
    // instances of its own pipe (lab result, decision I2).
    service
        .set_config_service_sid_info(ServiceSidType::Unrestricted)
        .map_err(|e| format!("set SID type: {e}"))?;
    lldp_windows::svcconfig::set_required_privileges(SERVICE_NAME, &["SeChangeNotifyPrivilege"])?;
    let actions = windows_service::service::ServiceFailureActions {
        reset_period: windows_service::service::ServiceFailureResetPeriod::After(
            Duration::from_hours(24),
        ),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            windows_service::service::ServiceAction {
                action_type: windows_service::service::ServiceActionType::Restart,
                delay: Duration::from_secs(10),
            },
            windows_service::service::ServiceAction {
                action_type: windows_service::service::ServiceActionType::Restart,
                delay: Duration::from_secs(60),
            },
            windows_service::service::ServiceAction {
                action_type: windows_service::service::ServiceActionType::None,
                delay: Duration::ZERO,
            },
        ]),
    };
    service
        .update_failure_actions(actions)
        .map_err(|e| format!("failure actions: {e}"))?;
    println!(
        "{SERVICE_NAME} hardened: service SID, SeChangeNotifyPrivilege only, restart on failure"
    );
    Ok(())
}

/// Stops and deletes the service.
pub fn uninstall() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("open SCM: {e}"))?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
        )
        .map_err(|e| format!("open service: {e}"))?;
    if service
        .query_status()
        .is_ok_and(|s| s.current_state != ServiceState::Stopped)
    {
        let _ = service.stop();
        for _ in 0..50 {
            std::thread::sleep(Duration::from_millis(200));
            if service
                .query_status()
                .map_or(true, |s| s.current_state == ServiceState::Stopped)
            {
                break;
            }
        }
    }
    service
        .delete()
        .map_err(|e| format!("delete service: {e}"))?;
    restore_bindings()?;
    lldp_windows::eventlog::unregister_source().map_err(|e| format!("event source: {e}"))?;
    println!("{SERVICE_NAME} uninstalled");
    Ok(())
}

/// Restores Microsoft LLDP driver bindings the service left disabled and
/// removes its registry state. Run at uninstall; never fails, so it cannot
/// block one.
#[allow(clippy::unnecessary_wraps)] // same shape as the other subcommands
pub fn restore_bindings() -> Result<(), String> {
    for (guid, e) in lldp_windows::mslldp::restore_all() {
        eprintln!(
            "warning: {guid}: {e}; its record is kept under HKLM\\{}",
            lldp_windows::mslldp::STATE_KEY
        );
    }
    println!("{SERVICE_NAME} bindings restored");
    Ok(())
}
