//! Quarantine: lock flagged files away with a record of where they came from,
//! put them back, delete them, or try to clean them.

use crate::clam::{sha256_file, shell_quote};
use crate::settings::data_dir;
use serde::{Deserialize, Serialize};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub original_path: String,
    pub threat: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub sha256: String,
    pub quarantined_at: String,
    /// Moved with administrator rights (the file belonged to someone else).
    pub elevated: bool,
    #[serde(default)]
    pub note: String,
    /// Package that owns the original path, if any.
    #[serde(default)]
    pub package: Option<String>,
}

pub fn dir() -> PathBuf {
    data_dir().join("quarantine")
}

fn store_path(id: &str) -> PathBuf {
    dir().join(format!("{id}.quarantined"))
}
fn meta_path(id: &str) -> PathBuf {
    dir().join(format!("{id}.json"))
}

pub fn list() -> Vec<Entry> {
    let mut v: Vec<Entry> = std::fs::read_dir(dir())
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
                .filter_map(|e| std::fs::read_to_string(e.path()).ok())
                .filter_map(|t| serde_json::from_str(&t).ok())
                .collect()
        })
        .unwrap_or_default();
    v.sort_by(|a, b| b.quarantined_at.cmp(&a.quarantined_at));
    v
}

fn save(e: &Entry) -> std::io::Result<()> {
    std::fs::write(meta_path(&e.id), serde_json::to_string_pretty(e).unwrap())
}

fn pkexec_sh(script: &str) -> Result<(), String> {
    let out = crate::root::output({ let mut pk = Command::new("pkexec"); pk
        .args(["/bin/sh", "-c", script]); pk })
        .map_err(|e| format!("couldn't ask for administrator rights: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "administrator step failed ({}): {}",
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

pub fn owning_package(path: &str) -> Option<String> {
    let out = Command::new("pacman").args(["-Qoq", path]).output().ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        None
    }
}

/// Move a file into quarantine. The stored copy has no permissions at all.
pub fn quarantine(path: &str, threat: &str) -> Result<Entry, String> {
    std::fs::create_dir_all(dir()).map_err(|e| e.to_string())?;
    let _ = std::fs::set_permissions(dir(), std::fs::Permissions::from_mode(0o700));
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("{path}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{path} isn't a regular file"));
    }
    let sha = sha256_file(path).unwrap_or_default();
    let id = format!(
        "{}-{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0),
        &sha.get(..8).unwrap_or("x")
    );
    let dest = store_path(&id);
    let mut entry = Entry {
        id: id.clone(),
        original_path: path.to_string(),
        threat: threat.to_string(),
        mode: meta.permissions().mode() & 0o7777,
        uid: meta.uid(),
        gid: meta.gid(),
        size: meta.len(),
        sha256: sha,
        quarantined_at: crate::net::now_rfc3339(),
        elevated: false,
        note: String::new(),
        package: owning_package(path),
    };
    let mine = meta.uid() == unsafe { libc::getuid() };
    let moved = if mine {
        move_file(Path::new(path), &dest).is_ok()
    } else {
        false
    };
    if moved {
        let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o000));
    } else {
        entry.elevated = true;
        let uid = unsafe { libc::getuid() };
        pkexec_sh(&format!(
            "set -e; mv -f {src} {dst}; chown {uid} {dst}; chmod 000 {dst}",
            src = shell_quote(path),
            dst = shell_quote(&dest.to_string_lossy()),
        ))?;
    }
    save(&entry).map_err(|e| e.to_string())?;
    log_event("quarantined", &entry.original_path, &entry.threat, &entry.sha256);
    Ok(entry)
}

fn move_file(src: &Path, dst: &Path) -> std::io::Result<()> {
    match std::fs::rename(src, dst) {
        Ok(()) => Ok(()),
        Err(_) => {
            std::fs::copy(src, dst)?;
            std::fs::remove_file(src)
        }
    }
}

/// Put a quarantined file back where it came from, with its old permissions.
pub fn restore(e: &Entry) -> Result<String, String> {
    let src = store_path(&e.id);
    if Path::new(&e.original_path).exists() {
        return Err(format!("{} already exists again — move it away first", e.original_path));
    }
    if let Some(parent) = Path::new(&e.original_path).parent() {
        if !parent.exists() && !e.elevated {
            std::fs::create_dir_all(parent).map_err(|x| x.to_string())?;
        }
    }
    if e.elevated {
        pkexec_sh(&format!(
            "set -e; mkdir -p {dir}; mv -f {src} {dst}; chown {uid}:{gid} {dst}; chmod {mode:o} {dst}",
            dir = shell_quote(&Path::new(&e.original_path).parent().unwrap_or(Path::new("/")).to_string_lossy()),
            src = shell_quote(&src.to_string_lossy()),
            dst = shell_quote(&e.original_path),
            uid = e.uid,
            gid = e.gid,
            mode = e.mode,
        ))?;
    } else {
        let _ = std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o600));
        move_file(&src, Path::new(&e.original_path)).map_err(|x| x.to_string())?;
        let _ = std::fs::set_permissions(&e.original_path, std::fs::Permissions::from_mode(e.mode));
    }
    let _ = std::fs::remove_file(meta_path(&e.id));
    log_event("put back", &e.original_path, &e.threat, &e.sha256);
    Ok(format!("Put back {}", e.original_path))
}

pub fn delete(e: &Entry) -> Result<String, String> {
    let _ = std::fs::set_permissions(store_path(&e.id), std::fs::Permissions::from_mode(0o600));
    std::fs::remove_file(store_path(&e.id)).or_else(|x| if x.kind() == std::io::ErrorKind::NotFound { Ok(()) } else { Err(x.to_string()) })?;
    let _ = std::fs::remove_file(meta_path(&e.id));
    log_event("deleted for good", &e.original_path, &e.threat, &e.sha256);
    Ok(format!("Deleted {} for good", e.original_path))
}

fn scan_file(path: &Path) -> Result<Vec<(String, String)>, String> {
    let out = Command::new("/usr/bin/clamscan")
        .args(["-r", "--stdout", "--no-summary", "-i"])
        .arg(path)
        .output()
        .map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(text
        .lines()
        .filter_map(|l| l.strip_suffix(" FOUND"))
        .filter_map(|l| l.rsplit_once(": "))
        .map(|(p, n)| (p.to_string(), n.to_string()))
        .collect())
}

fn is_zip(path: &Path) -> bool {
    use std::io::Read;
    let mut b = [0u8; 4];
    std::fs::File::open(path).and_then(|mut f| f.read_exact(&mut b)).map(|_| &b == b"PK\x03\x04").unwrap_or(false)
}

/// Try to make a quarantined file safe again. Returns what happened.
pub fn clean(e: &Entry) -> Result<String, String> {
    let r = clean_inner(e);
    match &r {
        Ok(m) => log_event(&format!("clean: {m}"), &e.original_path, &e.threat, &e.sha256),
        Err(m) => log_event(&format!("clean failed: {m}"), &e.original_path, &e.threat, &e.sha256),
    }
    r
}

fn clean_inner(e: &Entry) -> Result<String, String> {
    let stored = store_path(&e.id);
    // 1. A package's file: reinstall the package to get the original back.
    if let Some(pkg) = &e.package {
        pkexec_sh(&format!("pacman -S --noconfirm {}", shell_quote(pkg)))?;
        let _ = std::fs::set_permissions(&stored, std::fs::Permissions::from_mode(0o600));
        let _ = std::fs::remove_file(&stored);
        let _ = std::fs::remove_file(meta_path(&e.id));
        return Ok(format!("Reinstalled package {pkg}: a clean original copy of {} is back.", e.original_path));
    }
    let work = std::env::temp_dir().join(format!("arch-sentinel-clean-{}", e.id));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|x| x.to_string())?;
    let _ = std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o700));
    let copy = work.join("file");
    if e.elevated {
        return Err("This file needed administrator rights; put it back or delete it instead.".into());
    }
    std::fs::set_permissions(&stored, std::fs::Permissions::from_mode(0o400)).map_err(|x| x.to_string())?;
    let r = std::fs::copy(&stored, &copy);
    let _ = std::fs::set_permissions(&stored, std::fs::Permissions::from_mode(0o000));
    r.map_err(|x| x.to_string())?;
    std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o600)).map_err(|x| x.to_string())?;

    let result = (|| {
        // 2. With today's signatures it may simply be clean (a false positive that was fixed).
        let hits = scan_file(&copy)?;
        if hits.is_empty() {
            let mut e2 = e.clone();
            e2.note = "Rescanned with current signatures: no longer detected. Safe to put back.".into();
            let _ = save(&e2);
            return Ok(e2.note);
        }
        // 3. A zip-style archive (zip, jar, docx, apk…): drop just the infected members.
        if is_zip(&copy) && Path::new("/usr/bin/unzip").exists() && Path::new("/usr/bin/zip").exists() {
            let ex = work.join("x");
            std::fs::create_dir_all(&ex).map_err(|x| x.to_string())?;
            let ok = Command::new("unzip").args(["-qq", "-o"]).arg(&copy).arg("-d").arg(&ex).status().map(|s| s.success() || s.code() == Some(1)).unwrap_or(false);
            if ok {
                let bad = scan_file(&ex)?;
                let prefix = format!("{}/", ex.display());
                let members: Vec<String> = bad.iter().filter_map(|(p, _)| p.strip_prefix(&prefix).map(|s| s.to_string())).collect();
                if !members.is_empty() {
                    let cleaned = work.join("cleaned.zip");
                    std::fs::copy(&copy, &cleaned).map_err(|x| x.to_string())?;
                    let st = Command::new("zip").arg("-q").arg("-d").arg(&cleaned).args(&members).status().map_err(|x| x.to_string())?;
                    if st.success() && scan_file(&cleaned)?.is_empty() {
                        let mut dest = e.original_path.clone();
                        if Path::new(&dest).exists() {
                            dest.push_str(".cleaned");
                        }
                        std::fs::copy(&cleaned, &dest).map_err(|x| x.to_string())?;
                        let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(e.mode & 0o666));
                        let mut e2 = e.clone();
                        e2.note = format!("Cleaned copy saved to {dest} (removed: {}). The original stays here.", members.join(", "));
                        let _ = save(&e2);
                        return Ok(e2.note);
                    }
                }
            }
        }
        Err(format!(
            "Couldn't clean it: still detected as {}. ClamAV can't remove infections from inside ordinary files — keep it here or delete it.",
            hits.first().map(|h| h.1.clone()).unwrap_or_default()
        ))
    })();
    let _ = std::fs::remove_dir_all(&work);
    result
}

// ---------- zero-fill and delete ----------

/// The filesystem a path lives on (btrfs, ext4…).
pub fn fs_type(path: &str) -> String {
    let dir = std::path::Path::new(path).parent().map(|p| p.display().to_string()).unwrap_or_else(|| "/".into());
    Command::new("findmnt")
        .args(["-no", "FSTYPE", "--target", &dir])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// What the warning should say about how thorough zero-filling is here.
pub fn fs_caveat(fs: &str) -> &'static str {
    match fs {
        "btrfs" | "zfs" | "bcachefs" => "This disk uses a copy-on-write filesystem: the zeros are written to new places, so the old bytes can survive on the disk (and in any snapshots) until they're reused. The file is still made unreadable and removed.",
        "ext4" | "ext3" | "ext2" | "xfs" => "On an SSD the drive may keep old copies internally, but the file is overwritten in place and removed.",
        "ntfs" | "ntfs3" | "fuseblk" | "exfat" | "vfat" | "msdos" => "This is a Windows filesystem. If Windows uses Fast Startup or is hibernated, writing here can corrupt the partition — shut Windows down fully first. Don't delete files from Windows' own folders: it can stop Windows from starting.",
        _ => "Zero-filling overwrites the file where it is, then removes it.",
    }
}

fn shred_cmd(path: &str) -> Vec<String> {
    vec!["/usr/bin/shred".into(), "--iterations=0".into(), "--zero".into(), "--remove=wipesync".into(), "--".into(), path.into()]
}

/// Overwrite a file with zeros, flush it to disk, then delete it. Uses
/// administrator rights only when the file isn't yours.
pub fn shred_file(path: &str) -> Result<String, String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("{path}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{path} isn't a regular file"));
    }
    let size = meta.len();
    let mine = meta.uid() == unsafe { libc::getuid() };
    let mut ok = false;
    let mut err = String::new();
    if mine {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        let c = shred_cmd(path);
        match Command::new(&c[0]).args(&c[1..]).output() {
            Ok(o) if o.status.success() => ok = true,
            Ok(o) => err = String::from_utf8_lossy(&o.stderr).trim().to_string(),
            Err(e) => err = e.to_string(),
        }
    }
    if !ok {
        let c = shred_cmd(path);
        let o = crate::root::output({ let mut pk = Command::new("pkexec"); pk.args(&c); pk }).map_err(|e| e.to_string())?;
        if !o.status.success() {
            return Err(if matches!(o.status.code(), Some(126) | Some(127)) {
                "Administrator rights were refused.".into()
            } else {
                format!("Couldn't zero-fill {path}: {} {err}", String::from_utf8_lossy(&o.stderr).trim())
            });
        }
    }
    Ok(format!("Zero-filled {} KB and deleted {path}.", size / 1024))
}

/// Zero-fill and delete a quarantined file and its record.
pub fn shred_entry(e: &Entry) -> Result<String, String> {
    let store = store_path(&e.id);
    let _ = std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o600));
    shred_file(&store.to_string_lossy())?;
    let _ = std::fs::remove_file(meta_path(&e.id));
    log_event("zero-filled and deleted", &e.original_path, &e.threat, &e.sha256);
    Ok(format!("Zero-filled and deleted the quarantined copy of {}.", e.original_path))
}

/// Where a quarantined file's locked copy is kept.
pub fn store_file(id: &str) -> String {
    store_path(id).display().to_string()
}

// ---------- history ----------

/// Every quarantine action, kept next to the quarantine for good (never trimmed by updates).
pub fn history_path() -> PathBuf {
    dir().join("history.log")
}

pub fn log_event(action: &str, path: &str, threat: &str, sha: &str) {
    use std::io::Write;
    let _ = std::fs::create_dir_all(dir());
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(history_path()) {
        let clean = |s: &str| s.replace(['\t', '\n'], " ");
        let _ = writeln!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}",
            crate::net::now_rfc3339(),
            env!("CARGO_PKG_VERSION"),
            clean(action),
            clean(path),
            clean(threat),
            sha
        );
    }
}

/// (time, app version, action, path, threat), newest first.
pub fn history(limit: usize) -> Vec<(String, String, String, String, String)> {
    let t = std::fs::read_to_string(history_path()).unwrap_or_default();
    let mut v: Vec<_> = t
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (f.len() >= 5).then(|| (f[0].to_string(), f[1].to_string(), f[2].to_string(), f[3].to_string(), f[4].to_string()))
        })
        .collect();
    v.reverse();
    v.truncate(limit);
    v
}
