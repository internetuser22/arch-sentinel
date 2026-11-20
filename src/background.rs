//! Background jobs: scheduled with systemd timers (user timers for the scans,
//! a system timer for freshclam, which has to run as root), each with its own
//! schedule, priority, CPU limit and power/notification options.

use crate::jobs::{Job, Report, Sev};
use crate::settings::{data_dir, home_dir, JobKind, Settings};
use crate::{clam, pkg, quarantine, rootkit};
use std::path::PathBuf;
use std::process::Command;

pub fn reports_dir() -> PathBuf {
    data_dir().join("reports")
}

pub fn report_path(k: JobKind) -> PathBuf {
    reports_dir().join(format!("{}.json", k.id()))
}

pub fn load_report(k: JobKind) -> Option<Report> {
    let t = std::fs::read_to_string(report_path(k)).ok()?;
    serde_json::from_str(&t).ok()
}

pub fn save_report(k: JobKind, r: &Report) {
    let _ = std::fs::create_dir_all(reports_dir());
    let _ = std::fs::write(report_path(k), serde_json::to_string_pretty(r).unwrap());
}

pub fn unit_name(k: JobKind) -> String {
    format!("arch-sentinel-{}", k.id())
}

fn user_unit_dir() -> PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from(home_dir()).join(".config"));
    base.join("systemd/user")
}

/// The service and timer text for one scan job (run as you, no administrator rights).
pub fn user_units(s: &Settings, k: JobKind) -> (String, String) {
    let bg = s.bg(k);
    let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "arch-sentinel".into());
    let mut service = format!("[Unit]\nDescription=Arch Sentinel: {}\n", k.title());
    if bg.only_on_ac {
        service.push_str("ConditionACPower=true\n");
    }
    service.push_str(&format!(
        "\n[Service]\nType=oneshot\nExecStart=\"{exe}\" --background {}\nNice=19\nIOSchedulingClass=idle\n",
        k.id()
    ));
    if bg.cpu_limit > 0 {
        // CPUQuota counts one core as 100%; the setting is a share of the whole computer.
        service.push_str(&format!("CPUQuota={}%\n", bg.cpu_limit as usize * crate::par::ncpu()));
    }
    let timer = format!(
        "[Unit]\nDescription=Arch Sentinel: {} ({})\n\n[Timer]\nOnCalendar={}\nRandomizedDelaySec={}min\nPersistent={}\n\n[Install]\nWantedBy=timers.target\n",
        k.title(),
        bg.schedule.label().to_lowercase(),
        bg.schedule.on_calendar(),
        bg.random_delay_min,
        if bg.catch_up { "true" } else { "false" }
    );
    (service, timer)
}

fn run(cmd: &mut Command) -> Result<String, String> {
    let out = cmd.output().map_err(|e| e.to_string())?;
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    if out.status.success() {
        Ok(text.trim().to_string())
    } else {
        Err(text.trim().to_string())
    }
}

/// Write (or remove) every scan job's user timer to match the settings.
pub fn apply_user_timers(s: &Settings) -> Result<String, String> {
    let dir = user_unit_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let mut done = vec![];
    for k in JobKind::ALL {
        if k == JobKind::Signatures {
            continue;
        }
        let name = unit_name(k);
        let bg = s.bg(k);
        if bg.enabled {
            let (service, timer) = user_units(s, k);
            std::fs::write(dir.join(format!("{name}.service")), service).map_err(|e| e.to_string())?;
            std::fs::write(dir.join(format!("{name}.timer")), timer).map_err(|e| e.to_string())?;
            done.push(format!("{}: {}", k.short(), bg.schedule.label().to_lowercase()));
        }
    }
    let _ = run(Command::new("systemctl").args(["--user", "daemon-reload"]));
    for k in JobKind::ALL {
        if k == JobKind::Signatures {
            continue;
        }
        let timer = format!("{}.timer", unit_name(k));
        if s.bg(k).enabled {
            run(Command::new("systemctl").args(["--user", "enable", "--now", &timer]))?;
            // Pick up a changed schedule on an already running timer.
            let _ = run(Command::new("systemctl").args(["--user", "restart", &timer]));
        } else {
            let _ = run(Command::new("systemctl").args(["--user", "disable", "--now", &timer]));
            let _ = std::fs::remove_file(dir.join(format!("{}.service", unit_name(k))));
            let _ = std::fs::remove_file(dir.join(&timer));
        }
    }
    let _ = run(Command::new("systemctl").args(["--user", "daemon-reload"]));
    Ok(if done.is_empty() { "No scan timers turned on.".into() } else { format!("Timers set: {}", done.join(", ")) })
}

#[derive(Clone, Debug, Default)]
pub struct TimerStatus {
    pub active: String,
    pub next: String,
    pub last: String,
}

pub fn timer_status(k: JobKind) -> TimerStatus {
    let mut c = Command::new("systemctl");
    if k != JobKind::Signatures {
        c.arg("--user");
    }
    let name = if k == JobKind::Signatures { clam::TIMER_NAME.to_string() } else { unit_name(k) };
    c.args(["show", &format!("{name}.timer"), "-p", "ActiveState", "-p", "NextElapseUSecRealtime", "-p", "LastTriggerUSec"]);
    let text = c.output().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    let mut st = TimerStatus::default();
    for l in text.lines() {
        if let Some((k, v)) = l.split_once('=') {
            match k {
                "ActiveState" => st.active = v.to_string(),
                "NextElapseUSecRealtime" => st.next = v.to_string(),
                "LastTriggerUSec" => st.last = v.to_string(),
                _ => {}
            }
        }
    }
    if st.last.is_empty() || st.last == "0" {
        st.last = "never".into();
    }
    if st.next.is_empty() {
        st.next = "—".into();
    }
    st
}

fn notify(title: &str, body: &str) {
    let _ = Command::new("notify-send").args(["-a", "Arch Sentinel", "-i", "security-high", title, body]).status();
}

fn set_priority(_s: &Settings, _k: JobKind) {
    // Every background scan runs at the lowest priority.
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, crate::par::NICE);
    }
}

/// Headless run for a timer: do the scan, save the report, notify if needed.
pub fn run_background(id: &str) -> i32 {
    let Some(k) = JobKind::from_id(id) else {
        eprintln!("unknown job {id}");
        return 2;
    };
    let s = Settings::load();
    set_priority(&s, k);
    let job = Job::default();
    match k {
        JobKind::Signatures => {
            eprintln!("Signature updates run from the system timer ({}.timer) as root.", clam::TIMER_NAME);
            return 2;
        }
        JobKind::Unowned => job.run_inline(|em| pkg::scan_unowned(&s, em)),
        JobKind::HomeCheck => job.run_inline(|em| pkg::scan_home(&s, em)),
        JobKind::Rootkit => job.run_inline(|em| rootkit::run_builtin(em, crate::par::threads(&s))),
        JobKind::Processes => job.run_inline(|em| crate::procs::scan_processes(&s, em)),
        JobKind::Integrity => job.run_inline(|em| pkg::scan_integrity(&s, false, em)),
        JobKind::Virus => {
            let mut first: Vec<String> = vec![];
            if s.virus_scope == 0 || s.virus_scope == 1 {
                for k2 in [JobKind::Unowned, JobKind::Integrity] {
                    if let Some(r) = load_report(k2) {
                        first.extend(clam::unverified_paths(&r.findings));
                    }
                }
                first.sort();
                first.dedup();
            }
            let mut targets = if matches!(s.virus_scope, 1 | 3) { vec![] } else { s.virus_targets.clone() };
            if s.scan_external || s.virus_scope == 3 {
                targets.extend(crate::drives::chosen(&s.external_skip).into_iter().map(|d| d.mount));
            }
            job.run_inline(|em| {
                clam::scan_parallel(&s, &first, &targets, false, em);
            });
            let found: Vec<_> = job.state.lock().unwrap().findings.clone();
            let mut final_findings = vec![];
            if !found.is_empty() && s.vt_check && !s.vt_api_key.is_empty() {
                let vt = Job::default();
                vt.run_inline(|em| clam::verify_findings(&s.vt_api_key, &found, em));
                final_findings = vt.state.lock().unwrap().findings.clone();
            } else {
                final_findings.extend(found.iter().cloned());
            }
            if s.quarantine {
                for f in final_findings.iter_mut() {
                    let confirmed = f.detail.contains("CONFIRMED") || (f.detail.starts_with("ClamAV match") && !s.vt_check);
                    if confirmed {
                        match quarantine::quarantine(&f.path, &f.kind) {
                            Ok(_) => f.detail.push_str(" · moved to quarantine"),
                            Err(e) => f.detail.push_str(&format!(" · couldn't quarantine: {e}")),
                        }
                    }
                }
            }
            let mut st = job.state.lock().unwrap();
            st.summary = format!("{} file(s) flagged by ClamAV.", final_findings.len());
            st.findings = final_findings;
        }
    }
    let r = job.report(k.id());
    save_report(k, &r);
    let serious = r.findings.iter().filter(|f| f.sev == Sev::High).count();
    if s.bg(k).notify && serious > 0 {
        notify(&format!("{}: {serious} serious finding(s)", k.short()), &r.summary);
    }
    println!("{}", r.summary);
    0
}
