//! The check-in cycle, shared by the service loop and `bw-agent run-once`.
//!
//! Every heartbeat (15 min): one small request carrying the hash of the last inventory.
//! Every collect interval (4 h, jittered): re-read the registry in background mode; the
//! server answers whether it wants the upload (only when the hash changed).
//! When the heartbeat's posture hash differs from the one the agent holds, it fetches the new
//! read list, reads again and uploads.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::client::{Api, Plan, Revoked};
use crate::config::{self, Config};
use crate::inventory::{self, Inventory};
use crate::logger::log;
use crate::{posture, system, wua, Result};

pub struct Agent {
    path: PathBuf,
    cfg: Config,
    api: Api,
    inv: Option<Inventory>,
}

impl Agent {
    pub fn load(path: &Path) -> Result<Self> {
        let cfg = config::load(path)?;
        let api = Api::new(&cfg.server)?;
        Ok(Self { path: path.to_path_buf(), cfg, api, inv: None })
    }

    fn collect(&mut self) -> Result<()> {
        let wua = self.cfg.wua.clone();
        let reads = self.cfg.posture_hash.as_deref().map(|h| (h, self.cfg.posture_reads.as_slice()));
        self.inv = Some(system::background(|| inventory::collect(wua, reads))?);
        Ok(())
    }

    /// The server's posture rules changed (or this agent has none yet): fetch the new read list.
    fn refresh_posture(&mut self) -> Result<()> {
        let mut p = self.api.posture(&self.cfg.token)?;
        p.reads.truncate(posture::MAX_READS);
        log(&format!("posture rules {}: {} values to read", p.hash, p.reads.len()));
        self.cfg.posture_hash = Some(p.hash);
        self.cfg.posture_reads = p.reads;
        config::save(&self.path, &self.cfg)
    }

    /// One heartbeat, plus whatever the server asks for. Returns the server's schedule.
    pub fn cycle(&mut self, collect: bool, force_wua: bool, force_upload: bool) -> Result<Plan> {
        if collect || self.inv.is_none() {
            self.collect()?;
        }
        let hash = self.inv.as_ref().map(|i| i.hash.clone());
        let plan = self.api.heartbeat(&self.cfg.token, hash.as_deref())?;
        let mut upload = plan.upload || force_upload;
        let new_rules = plan.posture_hash.is_some() && plan.posture_hash != self.cfg.posture_hash;
        if new_rules {
            self.refresh_posture()?;
        }
        if (plan.collect_now && !collect) || new_rules {
            self.collect()?;
            upload = true;
        }
        if force_wua || (plan.wua_due && system::quiet()) {
            log("running the Windows Update cross-check");
            let r = wua::search_isolated();
            log(&format!("Windows Update cross-check: {} missing{}", r.missing.len(), r.error.as_deref().map(|e| format!(", error: {e}")).unwrap_or_default()));
            self.cfg.wua = Some(r);
            config::save(&self.path, &self.cfg)?;
            self.collect()?;
            upload = true;
        }
        if upload {
            let inv = self.inv.as_ref().expect("collected above");
            let bytes = self.api.upload(&self.cfg.token, inv)?;
            let settings = inv.posture.as_ref().map_or(0, |p| p.values.len());
            log(&format!("uploaded inventory: {} programs, {} KBs, {settings} settings, {bytes} bytes", inv.software.len(), inv.kbs.len()));
            self.cfg.last_upload_hash = Some(inv.hash.clone());
            config::save(&self.path, &self.cfg)?;
        }
        Ok(plan)
    }
}

/// Spread check-ins by +/- 10% so a whole site never phones home in the same second.
fn jitter(secs: u64) -> Duration {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0) as u64;
    let spread = secs / 10;
    Duration::from_secs(secs - spread + if spread > 0 { nanos % (2 * spread + 1) } else { 0 })
}

/// Sleep until the timeout or a stop request. Returns true when the service should stop.
fn wait(stop: &Receiver<()>, d: Duration) -> bool {
    !matches!(stop.recv_timeout(d), Err(RecvTimeoutError::Timeout))
}

pub fn service_loop(path: &Path, stop: &Receiver<()>) {
    log(&format!("bw-agent {} started", crate::VERSION));
    let mut agent: Option<Agent> = None;
    let mut next_collect = Instant::now();
    let mut heartbeat = 900;
    loop {
        if agent.is_none() {
            match Agent::load(path) {
                Ok(a) => agent = Some(a),
                Err(e) => log(&format!("not enrolled yet: {e}")),
            }
        }
        if let Some(a) = agent.as_mut() {
            let due = Instant::now() >= next_collect;
            match a.cycle(due, false, false) {
                Ok(plan) => {
                    heartbeat = plan.heartbeat_seconds.clamp(60, 86_400);
                    if due {
                        next_collect = Instant::now() + jitter(plan.collect_seconds.clamp(600, 7 * 86_400));
                    }
                }
                Err(e) if e.is::<Revoked>() => {
                    log(&e.to_string());
                    agent = None; // reload the config next time, in case it was re-enrolled
                    heartbeat = 3600;
                }
                Err(e) => log(&format!("check-in failed: {e}")),
            }
        } else {
            heartbeat = 300;
        }
        if wait(stop, jitter(heartbeat)) {
            log("stopping");
            return;
        }
    }
}

pub fn once(path: &Path, force_wua: bool, force_upload: bool) -> Result<()> {
    std::env::set_var("BW_AGENT_CONSOLE", "1");
    let t = Instant::now();
    let mut agent = Agent::load(path)?;
    let plan = agent.cycle(true, force_wua, force_upload)?;
    let (cpu, peak) = system::self_usage();
    println!(
        "check-in ok in {} ms (cpu {} ms, peak memory {:.1} MB). Server schedule: heartbeat {} s, collect {} s, Windows Update check due: {}",
        t.elapsed().as_millis(),
        cpu,
        peak as f64 / 1_048_576.0,
        plan.heartbeat_seconds,
        plan.collect_seconds,
        plan.wua_due
    );
    Ok(())
}
