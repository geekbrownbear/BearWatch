//! bw-agent: the BearWatch Windows agent.
//!
//! It only collects. Everything heavy (CVE matching, scoring) runs on the server, so the
//! agent reads the registry, hashes what it found, and uploads only when that hash changes.
//!
//!   bw-agent enroll --server https://bearwatch.example.com --key bwe_...
//!   bw-agent install | uninstall        register or remove the Windows service
//!   bw-agent run-once [--wua] [--force] one check-in now (for testing or an RMM script)
//!   bw-agent inventory [--reads FILE]    print what would be sent, plus resource use; no network
//!   bw-agent sensor [--out FILE]         one network scan now, printed or saved; sends nothing
//!   bw-agent service                     entry point used by the Service Control Manager

mod client;
mod config;
mod inventory;
mod logger;
mod posture;
mod run;
mod sensor;
mod service;
mod system;
mod wua;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

const USAGE: &str = "bw-agent (BearWatch agent)

usage:
  bw-agent enroll --server URL --key ENROLLMENT_KEY [--config PATH]
  bw-agent install            install and start the Windows service (run as administrator)
  bw-agent uninstall          stop and remove the service and its stored token
  bw-agent run-once [--wua] [--force] [--config PATH]
  bw-agent inventory [--reads FILE] [--config PATH]
                              print the inventory as JSON with timing; sends nothing. Settings
                              come from the read list the server last sent, or from FILE (a
                              JSON list of reads, for testing posture rules)
  bw-agent sensor [--out FILE]
                              scan this PC's local networks now, as the site's sensor does, and
                              write the result as JSON to FILE or the console; sends nothing
  bw-agent version";

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");
    let config_path = flag(&args, "--config").map(PathBuf::from);
    let result = match cmd {
        "enroll" => cmd_enroll(&args, config_path),
        "install" => service::install(),
        "uninstall" => service::uninstall(),
        "run-once" => run::once(&config::path(config_path.as_deref()), has(&args, "--wua"), has(&args, "--force")),
        "inventory" => cmd_inventory(&args, config_path),
        "sensor" => cmd_sensor(&args),
        "service" => service::dispatch(),
        "wua-scan" => cmd_wua_scan(),
        "version" | "--version" => {
            println!("bw-agent {VERSION}");
            Ok(())
        }
        _ => {
            println!("{USAGE}");
            return if matches!(cmd, "help" | "--help" | "-h") { ExitCode::SUCCESS } else { ExitCode::from(2) };
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_enroll(args: &[String], config_path: Option<PathBuf>) -> Result<()> {
    let server = flag(args, "--server").ok_or("--server is required")?;
    let key = flag(args, "--key").ok_or("--key is required")?;
    let path = config::path(config_path.as_deref());
    let api = client::Api::new(&server)?;
    let os = inventory::identity()?;
    let resp = api.enroll(key.trim(), &os.machine_guid, &os.hostname)?;
    let cfg = config::Config { server: api.base().to_string(), device_id: resp.device_id, token: resp.token, ..Default::default() };
    config::save(&path, &cfg)?;
    println!("enrolled {} as device {} with {}", os.hostname, cfg.device_id, cfg.server);
    println!("config: {}", path.display());
    Ok(())
}

/// Internal: the Windows Update search in its own process (see wua::search_isolated).
fn cmd_wua_scan() -> Result<()> {
    system::background_process();
    println!("{}", serde_json::to_string(&wua::search())?);
    Ok(())
}

fn cmd_inventory(args: &[String], config_path: Option<PathBuf>) -> Result<()> {
    let reads: Option<(String, Vec<String>)> = match flag(args, "--reads") {
        Some(file) => Some(("local-file".into(),serde_json::from_slice(&std::fs::read(&file).map_err(|e| format!("cannot read {file}: {e}"))?)?)),
        // The saved list, when this account can read the config (it is locked to administrators).
        None => config::load(&config::path(config_path.as_deref())).ok().and_then(|c| c.posture_hash.map(|h| (h, c.posture_reads))),
    };
    let t = Instant::now();
    let inv = system::background(|| inventory::collect(None, reads.as_ref().map(|(h, r)| (h.as_str(), r.as_slice()))))?;
    let wall = t.elapsed();
    let json = serde_json::to_vec(&inv)?;
    let gz = client::gzip(&json)?;
    println!("{}", serde_json::to_string_pretty(&inv)?);
    let (cpu_ms, peak) = system::self_usage();
    eprintln!(
        "programs {}  kbs {}  settings {}  wall {} ms  cpu {} ms  peak memory {:.1} MB  upload {} bytes json / {} bytes gzip",
        inv.software.len(),
        inv.kbs.len(),
        inv.posture.as_ref().map_or(0, |p| p.values.len()),
        wall.as_millis(),
        cpu_ms,
        peak as f64 / 1_048_576.0,
        json.len(),
        gz.len()
    );
    Ok(())
}

fn cmd_sensor(args: &[String]) -> Result<()> {
    std::env::set_var("BW_AGENT_CONSOLE", "1"); // progress lines to the console, not the log
    let payload = sensor::scan();
    let json = serde_json::to_string_pretty(&payload)?;
    match flag(args, "--out") {
        Some(file) => {
            std::fs::write(&file, &json).map_err(|e| format!("cannot write {file}: {e}"))?;
            eprintln!("wrote {file}");
        }
        None => println!("{json}"),
    }
    let gz = client::gzip(serde_json::to_vec(&payload)?.as_slice())?;
    eprintln!("networks {}  hosts {}  duration {} ms  upload {} bytes gzip", payload.networks.len(), payload.hosts.len(), payload.duration_ms, gz.len());
    Ok(())
}
