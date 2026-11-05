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

use crate::client::{Api, NotSensor, Plan, Revoked, SensorPlan};
use crate::config::{self, Config};
use crate::inventory::{self, Inventory};
use crate::logger::log;
use crate::{posture, sensor, system, wua, Result};

pub struct Agent {
    path: PathBuf,
    cfg: Config,
    api: Api,
    inv: Option<Inventory>,
    /// A sensor scan running on its own thread. Its result: when the upload got its answer, and
    /// the host count the server stored.
    sensor: Option<JoinHandle<(Instant, Result<u64>)>>,
    /// When this process saw the server's 409 to a sensor upload. None while there is no
    /// decline, or when it was loaded from disk (it then predates every heartbeat to come).
    declined_at: Option<Instant>,
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Never scanned, or the last scan started at least an interval ago. A last scan in the
/// future means the clock went back; scan rather than wait for it.
fn sensor_due(last: Option<u64>, now: u64, interval_minutes: u64) -> bool {
    last.is_none_or(|t| now < t || now - t >= interval_minutes.saturating_mul(60))
}

/// Apply one heartbeat plan to the sensor schedule in `cfg`. Returns true when a scan should
/// start now (and records `now` as its attempt time). Kept free of I/O so the order of events
/// can be tested.
///
/// - No `sensor` in the plan: not the sensor (any more). Forget the schedule and any 409.
/// - `sensor` in a plan whose heartbeat was sent after the 409 (`sent`, compared with
///   `declined_at`): the server only names the PC it accepts uploads from, so this is
///   authoritative. The decline is cleared and the normal schedule resumes. A decline loaded
///   from disk happened before this process started, so the first heartbeat naming the PC
///   clears it and a restart can never leave the sensor stuck.
/// - `sensor` in a plan requested before the 409 arrived: stale, stay off until the next one.
/// - Otherwise scan when due and none is running.
fn sensor_plan(cfg: &mut Config, plan: Option<&SensorPlan>, declined_at: Option<Instant>, sent: Instant, now: u64, running: bool) -> bool {
    let Some(sp) = plan else {
        cfg.sensor_last_scan = None;
        cfg.sensor_declined = false;
        return false;
    };
    if cfg.sensor_declined {
        if declined_at.is_some_and(|at| sent <= at) {
            return false;
        }
        cfg.sensor_declined = false;
    }
    if running || !sensor_due(cfg.sensor_last_scan, now, sp.interval_minutes) {
        return false;
    }
    // Recorded before the scan, so a failed scan or upload waits for the next interval
    // instead of retrying at every heartbeat.
    cfg.sensor_last_scan = Some(now);
    true
}

impl Agent {
    pub fn load(path: &Path) -> Result<Self> {
        let cfg = config::load(path)?;
        let api = Api::new(&cfg.server)?;
        Ok(Self { path: path.to_path_buf(), cfg, api, inv: None, sensor: None, declined_at: None })
    }

    /// Start a sensor scan when the plan says this PC is the sensor and one is due.
    ///
    /// Why a thread: the service loop is a single thread that heartbeats and then sleeps until
    /// the next heartbeat or a stop request. A scan takes up to a couple of minutes. Inline, it
    /// would push heartbeats back and make a service stop (or a Windows shutdown) wait for it.
    /// So the loop only starts the scan here and picks up its result at a later heartbeat; the
    /// thread scans and uploads on its own, with its own handle to the HTTPS client. At most one
    /// scan runs at a time, and a service stop simply ends it with the process.
    /// `sent`: when the heartbeat that returned `plan` was sent.
    fn sensor_step(&mut self, plan: &Plan, sent: Instant) -> Result<()> {
        self.finish_sensor(false)?;
        let before = (self.cfg.sensor_last_scan, self.cfg.sensor_declined);
        let start = sensor_plan(&mut self.cfg, plan.sensor.as_ref(), self.declined_at, sent, unix_now(), self.sensor.is_some());
        if !self.cfg.sensor_declined {
            if before.1 && plan.sensor.is_some() {
                log("this PC is the site's sensor again; scanning resumes on the normal schedule");
            }
            self.declined_at = None;
        }
        if before != (self.cfg.sensor_last_scan, self.cfg.sensor_declined) {
            config::save(&self.path, &self.cfg)?;
        }
        if !start {
            return Ok(());
        }
        let (api, token) = (self.api.clone(), self.cfg.token.clone());
        let spawned = std::thread::Builder::new().name("sensor".into()).spawn(move || {
            let payload = sensor::scan();
            let result = api.sensor(&token, &payload);
            let answered = Instant::now();
            match &result {
                Ok(hosts) => log(&format!("uploaded sensor scan: server stored {hosts} hosts")),
                Err(e) if !e.is::<NotSensor>() => log(&format!("sensor upload failed, next try in one interval: {e}")),
                Err(_) => {} // logged by finish_sensor
            }
            (answered, result)
        });
        match spawned {
            Ok(h) => self.sensor = Some(h),
            Err(e) => log(&format!("could not start the sensor scan: {e}")),
        }
        Ok(())
    }

    /// Pick up a finished sensor scan (or wait for a running one when `wait`). A 409 means the
    /// server does not take uploads from this PC right now: no scan until a heartbeat sent
    /// after it names this PC again. The attempt time stays, so a resumed schedule is the
    /// normal one.
    fn finish_sensor(&mut self, wait: bool) -> Result<()> {
        if !self.sensor.as_ref().is_some_and(|h| wait || h.is_finished()) {
            return Ok(());
        }
        let Some(handle) = self.sensor.take() else { return Ok(()) };
        match handle.join() {
            Ok((at, Err(e))) if e.is::<NotSensor>() => {
                log(&format!("{e}; no scans until a heartbeat names it again"));
                self.cfg.sensor_declined = true;
                self.declined_at = Some(at);
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
        let sent = Instant::now();
        let plan = self.api.heartbeat(&self.cfg.token, hash.as_deref())?;
        self.sensor_step(&plan, sent)?;
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
    use super::{sensor_due, sensor_plan};
    use crate::client::SensorPlan;
    use crate::config::Config;
    use std::time::{Duration, Instant};

    const SENSOR: Option<&SensorPlan> = Some(&SensorPlan { interval_minutes: 360 });

    /// 409, then a heartbeat naming the PC, then the scan falls due on the normal schedule.
    #[test]
    fn heartbeat_after_409_resumes_scanning() {
        let (mut cfg, t0, now) = (Config::default(), Instant::now(), 1_800_000_000);
        assert!(sensor_plan(&mut cfg, SENSOR, None, t0, now, false)); // first scan starts
        assert!(!sensor_plan(&mut cfg, SENSOR, None, t0, now + 60, true)); // still running
        // Its upload gets a 409 (what finish_sensor records).
        let at = t0 + Duration::from_secs(90);
        cfg.sensor_declined = true;
        // A plan from a heartbeat sent before the 409 arrived is stale: stay off, even if due.
        assert!(!sensor_plan(&mut cfg, SENSOR, Some(at), t0 + Duration::from_secs(80), now + 400 * 60, false));
        assert!(cfg.sensor_declined);
        // The next heartbeat names this PC: resume, on the normal schedule (not due yet).
        let hb = at + Duration::from_secs(900);
        assert!(!sensor_plan(&mut cfg, SENSOR, Some(at), hb, now + 15 * 60, false));
        assert!(!cfg.sensor_declined);
        assert_eq!(cfg.sensor_last_scan, Some(now));
        // An interval after the last attempt, the scan is due again.
        assert!(sensor_plan(&mut cfg, SENSOR, Some(at), hb + Duration::from_secs(900), now + 360 * 60, false));
        assert_eq!(cfg.sensor_last_scan, Some(now + 360 * 60));
    }

    /// A heartbeat after the 409 without `sensor` keeps it off and forgets the schedule.
    #[test]
    fn heartbeat_without_sensor_after_409_stays_off() {
        let (t0, now) = (Instant::now(), 1_800_000_000);
        let mut cfg = Config { sensor_last_scan: Some(now), sensor_declined: true, ..Default::default() };
        assert!(!sensor_plan(&mut cfg, None, Some(t0), t0 + Duration::from_secs(900), now + 400 * 60, false));
        assert_eq!((cfg.sensor_last_scan, cfg.sensor_declined), (None, false));
    }

    /// A decline persisted before a restart is cleared by the first heartbeat naming the PC.
    #[test]
    fn restart_with_persisted_decline_resumes() {
        let now = 1_800_000_000;
        let mut cfg = Config { sensor_last_scan: Some(now - 400 * 60), sensor_declined: true, ..Default::default() };
        // A new process has no 409 time of its own: every heartbeat it sends comes after the 409.
        assert!(sensor_plan(&mut cfg, SENSOR, None, Instant::now(), now, false));
        assert!(!cfg.sensor_declined);
        assert_eq!(cfg.sensor_last_scan, Some(now));
        // Cleared even when the next scan is not due yet; it then waits for its interval.
        let mut cfg = Config { sensor_last_scan: Some(now - 60), sensor_declined: true, ..Default::default() };
        assert!(!sensor_plan(&mut cfg, SENSOR, None, Instant::now(), now, false));
        assert!(!cfg.sensor_declined);
    }

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
