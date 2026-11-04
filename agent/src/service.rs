//! Windows service plumbing: install (or upgrade in place), uninstall, and the SCM entry point.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceFailureActions,
    ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::{config, logger::log, run, Result};

const NAME: &str = "BearWatchAgent";
const DISPLAY: &str = "BearWatch Agent";
const DESCRIPTION: &str = "Reports installed software and Windows updates to BearWatch for vulnerability tracking. Bearium Networks.";

fn install_dir() -> PathBuf {
    let pf = std::env::var_os("ProgramFiles").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));
    pf.join("BearWatch")
}

fn manager(access: ServiceManagerAccess) -> Result<ServiceManager> {
    ServiceManager::local_computer(None::<&str>, access).map_err(|e| format!("cannot open the service manager (run as administrator): {e}").into())
}

fn stop_and_wait(svc: &windows_service::service::Service) -> Result<()> {
    if svc.query_status()?.current_state != ServiceState::Stopped {
        let _ = svc.stop();
        let start = Instant::now();
        while svc.query_status()?.current_state != ServiceState::Stopped {
            if start.elapsed() > Duration::from_secs(30) {
                return Err("the service did not stop within 30 seconds".into());
            }
            thread::sleep(Duration::from_millis(300));
        }
    }
    Ok(())
}

/// Copy this exe to Program Files and register it as a delayed-start service running as
/// LocalSystem. Running it again on an installed PC upgrades the exe in place.
pub fn install() -> Result<()> {
    if !config::path(None).exists() {
        return Err("enroll first: bw-agent enroll --server URL --key KEY".into());
    }
    let mgr = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    let target = install_dir().join("bw-agent.exe");
    let existing = mgr.open_service(NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::START).ok();
    if let Some(svc) = &existing {
        stop_and_wait(svc)?;
    }
    let me = std::env::current_exe()?;
    if me != target {
        std::fs::create_dir_all(install_dir())?;
        std::fs::copy(&me, &target)?;
    }
    let svc = match existing {
        Some(svc) => {
            println!("upgraded {}", target.display());
            svc
        }
        None => {
            let info = ServiceInfo {
                name: OsString::from(NAME),
                display_name: OsString::from(DISPLAY),
                service_type: ServiceType::OWN_PROCESS,
                start_type: ServiceStartType::AutoStart,
                error_control: ServiceErrorControl::Normal,
                executable_path: target.clone(),
                launch_arguments: vec![OsString::from("service")],
                dependencies: vec![],
                account_name: None, // LocalSystem: needed to read every user's installs and HKLM servicing data
                account_password: None,
            };
            let svc = mgr.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS)?;
            svc.set_description(DESCRIPTION)?;
            // Start after the boot rush, and restart after a crash (1 minute, at most 3 times a day).
            svc.set_delayed_auto_start(true)?;
            svc.update_failure_actions(ServiceFailureActions {
                reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
                reboot_msg: None,
                command: None,
                actions: Some(vec![ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(60) }; 3]),
            })?;
            println!("installed {}", target.display());
            svc
        }
    };
    svc.start::<&OsStr>(&[])?;
    println!("service {NAME} started");
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let mgr = manager(ServiceManagerAccess::CONNECT)?;
    match mgr.open_service(NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE) {
        Ok(svc) => {
            stop_and_wait(&svc)?;
            svc.delete()?;
            println!("service removed");
        }
        Err(_) => println!("service was not installed"),
    }
    // The device token lives here; remove it so nothing can report as this PC afterwards.
    let dir = config::default_dir();
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
        println!("removed {}", dir.display());
    }
    println!("{} can be deleted once this command exits", install_dir().display());
    Ok(())
}

define_windows_service!(ffi_service_main, service_main);

pub fn dispatch() -> Result<()> {
    service_dispatcher::start(NAME, ffi_service_main).map_err(|e| format!("not started by the service manager ({e}); use run-once to test").into())
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        log(&format!("service failed: {e}"));
    }
}

fn run_service() -> Result<()> {
    let (tx, rx) = mpsc::channel();
    let handler = move |event| match event {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = service_control_handler::register(NAME, handler)?;
    let set = |state, accept| {
        status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
    };
    set(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN)?;
    run::service_loop(&config::path(None), &rx);
    set(ServiceState::Stopped, ServiceControlAccept::empty())?;
    Ok(())
}
