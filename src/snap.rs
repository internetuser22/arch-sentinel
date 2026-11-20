//! Experimental: virus-scan btrfs snapshots (Timeshift, Snapper…).
//!
//! Snapshots live in a btrfs drive's top level, which normal programs don't
//! see. With administrator rights the top level is mounted READ-ONLY in a
//! private folder under /run, the snapshots you pick are scanned, and the mount
//! is removed again — even when the scan is stopped. Nothing inside a snapshot
//! is ever changed, quarantined or deleted.

use crate::jobs::{print_msg, Emitter, Msg};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    /// The btrfs device it's on.
    pub dev: String,
    pub id: u64,
    /// When it was taken ("2026-11-18 20:00:01").
    pub otime: String,
    /// Its path from the drive's top level.
    pub path: String,
}

impl Snapshot {
    pub fn tool(&self) -> &'static str {
        if self.path.starts_with("timeshift-btrfs/") {
            "Timeshift"
        } else if self.path.contains(".snapshots/") || self.path.starts_with("@snapshots/") {
            "Snapper"
        } else {
            "other"
        }
    }
    /// What part of the system it holds, from the subvolume name.
    pub fn holds(&self) -> &'static str {
        let last = self.path.rsplit('/').next().unwrap_or("");
        match last {
            "@" | "snapshot" => "system (/)",
            "@home" => "home folders",
            "@log" => "logs",
            "@cache" | "@pkg" => "caches",
            _ => "",
        }
    }
}

/// btrfs devices that are mounted now (one entry per drive).
pub fn btrfs_devices() -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_to_string("/proc/self/mounts")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() > 2 && f[2] == "btrfs" && f[0].starts_with("/dev/")).then(|| f[0].to_string())
        })
        .collect();
    v.sort();
    v.dedup();
    v
}

fn say(tag: &str, rest: &str) {
    use std::io::Write;
    let mut o = std::io::stdout().lock();
    let _ = writeln!(o, "@{tag}\t{rest}");
    let _ = o.flush();
}

/// Mount a drive's top level read-only in a fresh private folder.
fn mount_top(dev: &str) -> Result<std::path::PathBuf, String> {
    let dir = std::path::PathBuf::from(format!("/run/arch-sentinel-snap.{}.{}", std::process::id(), dev.replace('/', "_")));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let o = std::process::Command::new("mount")
        .args(["-o", "ro,subvolid=5", dev])
        .arg(&dir)
        .output()
        .map_err(|e| e.to_string())?;
    if !o.status.success() {
        let _ = std::fs::remove_dir(&dir);
        return Err(format!("couldn't mount {dev} read-only: {}", String::from_utf8_lossy(&o.stderr).trim()));
    }
    Ok(dir)
}

fn unmount(dir: &std::path::Path) {
    let _ = std::process::Command::new("umount").arg("-l").arg(dir).status();
    let _ = std::fs::remove_dir(dir);
}

/// `--helper snap list` (as root): every snapshot on every mounted btrfs drive.
pub fn list() {
    let devs = btrfs_devices();
    if devs.is_empty() {
        print_msg(&Msg::Done("No btrfs drives are mounted.".into()));
        return;
    }
    let mut n = 0;
    for dev in devs {
        print_msg(&Msg::Progress(format!("Looking at {dev}…")));
        let dir = match mount_top(&dev) {
            Ok(d) => d,
            Err(e) => {
                print_msg(&Msg::Log(e));
                continue;
            }
        };
        let o = std::process::Command::new("btrfs").args(["subvolume", "list", "-s"]).arg(&dir).output();
        unmount(&dir);
        let Ok(o) = o else { continue };
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            // ID 456 gen 789 cgen 700 top level 5 otime 2026-11-18 20:00:01 path timeshift-btrfs/snapshots/…/@
            let f: Vec<&str> = l.split_whitespace().collect();
            let id = f.get(1).and_then(|x| x.parse().ok()).unwrap_or(0);
            let otime = l.split(" otime ").nth(1).map(|r| r.split(" path ").next().unwrap_or("").to_string()).unwrap_or_default();
            let path = l.split(" path ").nth(1).unwrap_or("").to_string();
            if path.is_empty() {
                continue;
            }
            n += 1;
            let s = Snapshot { dev: dev.clone(), id, otime, path };
            say("N", &serde_json::to_string(&s).unwrap_or_default());
        }
    }
    print_msg(&Msg::Done(format!("Found {n} snapshot(s).")));
}

/// `--helper snap scan <mount> <path>…` (as root, top level already mounted
/// read-only by the wrapper script): scan those snapshots.
pub fn scan(settings: &crate::settings::Settings, mount: &str, paths: &[String]) {
    let mut s = settings.clone();
    s.cpu_cap = 0; // no user session here for a CPU cap
    let targets: Vec<String> = paths.iter().map(|p| format!("{}/{}", mount.trim_end_matches('/'), p.trim_start_matches('/'))).collect();
    let mut em = Emitter::printer();
    let found = crate::clam::scan_parallel(&s, &[], &targets, false, &mut em);
    if !found.is_empty() && s.vt_check && !s.vt_api_key.is_empty() {
        crate::clam::verify_findings(&s.vt_api_key, &found, &mut em);
    }
}

/// The administrator script for a scan: mount read-only, scan, and always unmount.
pub fn scan_script(exe: &str, settings_file: &str, dev: &str, paths: &[String]) -> String {
    let q = crate::clam::shell_quote;
    let list = paths.iter().map(|p| q(p)).collect::<Vec<_>>().join(" ");
    format!(
        "M=/run/arch-sentinel-snap.$$; mkdir -p \"$M\" || exit 3; \
         trap 'umount -l \"$M\" 2>/dev/null; rmdir \"$M\" 2>/dev/null' EXIT; trap 'exit 143' TERM INT; \
         mount -o ro,subvolid=5 {dev} \"$M\" || {{ echo 'Could not mount the snapshots read-only.' >&2; exit 3; }}; \
         {exe} --helper snap scan --settings {cfg} \"$M\" {list}",
        dev = q(dev),
        exe = q(exe),
        cfg = q(settings_file),
    )
}

/// Turn a path inside the temporary mount into "<snapshot path>/<file>".
pub fn readable_path(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("/run/arch-sentinel-snap.") {
        if let Some(i) = rest.find('/') {
            return rest[i + 1..].to_string();
        }
    }
    p.to_string()
}

/// The snapshot a found file lives in (longest matching path).
pub fn snapshot_of<'a>(snaps: &'a [Snapshot], readable: &str) -> Option<&'a Snapshot> {
    snaps.iter().filter(|s| readable.starts_with(&format!("{}/", s.path))).max_by_key(|s| s.path.len())
}
