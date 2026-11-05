//! The check-in cycle, shared by the service loop and `bw-agent run-once`.
//!
//! Every heartbeat (15 min): one small request carrying the hash of the last inventory.
//! Every collect interval (4 h, jittered): re-read the registry in background mode; the
//! server answers whether it wants the upload (only when the hash changed).
//! When the heartbeat's posture hash differs from the one the agent holds, it fetches the new
//! read list, reads again and uploads.
//! When the heartbeat's plan names this PC the site's sensor and a scan is due, a network scan
//! starts on its own thread (see Agent::sensor_step).

use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::client::{Api, NotSensor, Plan, Revoked};
use crate::config::{self, Config};
use crate::inventory::{self, Inventory};
use crate::logger::log;
use crate::{posture, sensor, system, wua, Result};

pub struct Agent {
    path: PathBuf,
    cfg: Config,
    api: Api,
    inv: Option<Inventory>,
    /// A sensor scan running on its own thread; its result is the host count the server stored.
    sensor: Option<JoinHandle<Result<u64>>>,
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Never scanned, or the last scan started at least an interval ago. A last scan in the
/// future means the clock went back; scan rather than wait for it.
fn sensor_due(last: Option<u64>, now: u64, interval_minutes: u64) -> bool {
    last.is_none_or(|t| now < t || now - t >= interval_minutes.saturating_mul(60))
}

impl Agent {
    pub fn load(path: &Path) -> Result<Self> {
        let cfg = config::load(path)?;
        let api = Api::new(&cfg.server)?;
        Ok(Self { path: path.to_path_buf(), cfg, api, inv: None, sensor: None })
    }

    /// Start a sensor scan when the plan says this PC is the sensor and one is due.
    ///
    /// Why a thread: the service loop is a single thread that heartbeats and then sleeps until
    /// the next heartbeat or a stop request. A scan takes up to a couple of minutes. Inline, it
    /// would push heartbeats back and make a service stop (or a Windows shutdown) wait for it.
    /// So the loop only starts the scan here and picks up its result at a later heartbeat; the
    /// thread scans and uploads on its own, with its own handle to the HTTPS client. At most one
    /// scan runs at a time, and a service stop simply ends it with the process.
    fn sensor_step(&mut self, plan: &Plan) -> Result<()> {
        self.finish_sensor(false)?;
        let Some(sp) = &plan.sensor else {
            // Not (or no longer) the sensor: forget the schedule and any earlier 409.
            if self.cfg.sensor_last_scan.is_some() || self.cfg.sensor_declined {
                self.cfg.sensor_last_scan = None;
                self.cfg.sensor_declined = false;
                config::save(&self.path, &self.cfg)?;
            }
            return Ok(());
        };
        if self.cfg.sensor_declined || self.sensor.is_some() {
            return Ok(());
        }
        let now = unix_now();
        if !sensor_due(self.cfg.sensor_last_scan, now, sp.interval_minutes) {
            return Ok(());
        }
        // Recorded before the scan, so a failed scan or upload waits for the next interval
        // instead of retrying at every heartbeat.
        self.cfg.sensor_last_scan = Some(now);
        config::save(&self.path, &self.cfg)?;
        let (api, token) = (self.api.clone(), self.cfg.token.clone());
        let spawned = std::thread::Builder::new().name("sensor".into()).spawn(move || {
            let payload = sensor::scan();
            match api.sensor(&token, &payload) {
                Ok(hosts) => {
                    log(&format!("uploaded sensor scan: server stored {hosts} hosts"));
                    Ok(hosts)
                }
                Err(e) => {
                    if !e.is::<NotSensor>() {
                        log(&format!("sensor upload failed, next try in one interval: {e}"));
                    }
                    Err(e)
                }
            }
        });
        match spawned {
            Ok(h) => self.sensor = Some(h),
            Err(e) => log(&format!("could not start the sensor scan: {e}")),
        }
        Ok(())
    }

    /// Pick up a finished sensor scan (or wait for a running one when `wait`). A 409 means the
    /// server moved the sensor role elsewhere: stop until the plan asks again.
    fn finish_sensor(&mut self, wait: bool) -> Result<()> {
        if !self.sensor.as_ref().is_some_and(|h| wait || h.is_finished()) {
            return Ok(());
        }
        let Some(handle) = self.sensor.take() else { return Ok(()) };
        match handle.join() {
            Ok(Err(e)) if e.is::<NotSensor>() => {
                log(&e.to_string());
                self.cfg.sensor_last_scan = None;
                self.cfg.sensor_declined = true;
                config::save(&self.path, &self.cfg)?;
            }
            Ok(_) => {} // logged by the scan thread
            Err(_) => log("the sensor scan stopped unexpectedly"),
        }
        Ok(())
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
        self.sensor_step(&plan)?;
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
    if agent.sensor.is_some() {
        eprintln!("this PC is the site's sensor and a scan was due; waiting for it to finish");
        agent.finish_sensor(true)?;
    }
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

#[cfg(test)]
mod tests {
    use super::sensor_due;

    #[test]
    fn sensor_schedule() {
        let t = 1_800_000_000;
        assert!(sensor_due(None, t, 360));
        assert!(!sensor_due(Some(t), t + 359 * 60, 360));
        assert!(sensor_due(Some(t), t + 360 * 60, 360));
        assert!(sensor_due(Some(t + 100), t, 360)); // clock went back
        assert!(sensor_due(Some(t), t, 0));
        assert!(!sensor_due(Some(t), t + 60, u64::MAX));
    }
}
