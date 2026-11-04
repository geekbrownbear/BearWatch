//! Staying out of the user's way: background priority, power and idle checks, self-measurement.

use std::thread;
use std::time::Duration;

use windows::Win32::Foundation::FILETIME;
use windows::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};
use windows::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, GetProcessTimes, GetSystemTimes, SetPriorityClass, SetThreadPriority, PROCESS_MODE_BACKGROUND_BEGIN,
    THREAD_MODE_BACKGROUND_BEGIN, THREAD_MODE_BACKGROUND_END,
};

/// Run f with this thread in background mode: lowest CPU priority plus low I/O and memory
/// priority, so the user's own work always wins.
pub fn background<T>(f: impl FnOnce() -> T) -> T {
    unsafe {
        let _ = SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN);
    }
    let out = f();
    unsafe {
        let _ = SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_END);
    }
    out
}

/// Put the whole process (every thread) in background mode. Used by the short-lived
/// wua-scan child, whose search runs on a worker thread.
pub fn background_process() {
    unsafe {
        let _ = SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_BEGIN);
    }
}

fn ticks(t: FILETIME) -> u64 {
    (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime)
}

/// Whole-machine CPU use (0 to 100) over a short sample.
fn cpu_busy(sample: Duration) -> Option<f64> {
    let read = || {
        let (mut idle, mut kernel, mut user) = (FILETIME::default(), FILETIME::default(), FILETIME::default());
        unsafe { GetSystemTimes(Some(&mut idle), Some(&mut kernel), Some(&mut user)) }.ok()?;
        Some((ticks(idle), ticks(kernel) + ticks(user))) // kernel time includes idle time
    };
    let (i1, t1) = read()?;
    thread::sleep(sample);
    let (i2, t2) = read()?;
    let total = t2.saturating_sub(t1);
    (total > 0).then(|| 100.0 * (1.0 - (i2.saturating_sub(i1)) as f64 / total as f64))
}

/// On AC power (or a desktop with no battery) and the CPU mostly idle.
pub fn quiet() -> bool {
    let mut ps = SYSTEM_POWER_STATUS::default();
    let on_ac = unsafe { GetSystemPowerStatus(&mut ps) }.is_ok() && (ps.ACLineStatus == 1 || ps.BatteryFlag == 128);
    on_ac && cpu_busy(Duration::from_secs(5)).is_some_and(|b| b < 20.0)
}

/// (CPU milliseconds used by this process so far, peak working set in bytes).
pub fn self_usage() -> (u64, usize) {
    unsafe {
        let p = GetCurrentProcess();
        let (mut c, mut e, mut k, mut u) = (FILETIME::default(), FILETIME::default(), FILETIME::default(), FILETIME::default());
        let cpu = if GetProcessTimes(p, &mut c, &mut e, &mut k, &mut u).is_ok() { (ticks(k) + ticks(u)) / 10_000 } else { 0 };
        let mut m = PROCESS_MEMORY_COUNTERS { cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32, ..Default::default() };
        let peak = if K32GetProcessMemoryInfo(p, &mut m, m.cb).as_bool() { m.PeakWorkingSetSize } else { 0 };
        (cpu, peak)
    }
}
