//! Drives that aren't part of the running system: USB sticks, extra disks and
//! other partitions (anything mounted that doesn't hold /, /home, /boot...).

use serde_json::Value;

#[derive(Clone, Debug)]
pub struct Drive {
    pub mount: String,
    pub dev: String,
    pub label: String,
    pub size: String,
    pub fstype: String,
    /// USB / hot-pluggable / removable.
    pub removable: bool,
    /// A Windows filesystem (NTFS, exFAT, FAT).
    pub windows: bool,
    /// Holds a Windows installation (has Windows\System32).
    pub windows_system: bool,
    /// Mounted read-only.
    pub read_only: bool,
}

impl Drive {
    pub fn name(&self) -> String {
        let base = if !self.label.is_empty() {
            self.label.clone()
        } else {
            std::path::Path::new(&self.mount).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| self.mount.clone())
        };
        let base = if base.len() > 20 { format!("{}…", &base[..base.char_indices().nth(12).map(|c| c.0).unwrap_or(base.len())]) } else { base };
        format!(
            "{base} ({}{}{}{})",
            self.size,
            if self.removable { ", removable" } else { "" },
            if self.windows_system { ", Windows system" } else if self.windows { ", Windows filesystem" } else { "" },
            if self.read_only { ", read-only" } else { "" }
        )
    }

    /// Plain-language warnings for this drive.
    pub fn warnings(&self) -> Vec<&'static str> {
        let mut w = vec![];
        if self.windows_system {
            w.push(WARN_WINDOWS_SYSTEM);
            w.push(WARN_HIBERNATE);
        } else if self.windows {
            w.push(WARN_WINDOWS_FILES);
        }
        if self.read_only {
            w.push(WARN_READ_ONLY);
        }
        w
    }
}

const SYSTEM_MOUNTS: &[&str] = &["/", "/boot", "/boot/efi", "/efi", "/home", "/usr", "/var", "/opt", "/srv", "/root", "/nix"];

fn walk(n: &Value, parent_removable: bool, out: &mut Vec<Drive>) {
    let removable = parent_removable || n["rm"].as_bool().unwrap_or(false) || n["hotplug"].as_bool().unwrap_or(false) || n["tran"].as_str() == Some("usb");
    let mounts: Vec<String> = n["mountpoints"].as_array().map(|a| a.iter().filter_map(|m| m.as_str().map(|s| s.to_string())).collect()).unwrap_or_default();
    let system = mounts.iter().any(|m| SYSTEM_MOUNTS.contains(&m.as_str()) || m == "[SWAP]");
    let fstype = n["fstype"].as_str().unwrap_or("").to_string();
    if !system && fstype != "swap" {
        if let Some(m) = mounts.iter().filter(|m| m.starts_with('/')).min_by_key(|m| m.len()) {
            let windows = is_windows_fs(&fstype);
            let windows_system = ["Windows/System32", "WINDOWS/system32", "Windows/system32"].iter().any(|p| std::path::Path::new(m).join(p).is_dir());
            out.push(Drive {
                mount: m.clone(),
                dev: n["path"].as_str().unwrap_or("").to_string(),
                label: n["label"].as_str().unwrap_or("").to_string(),
                size: n["size"].as_str().unwrap_or("").to_string(),
                windows: windows || windows_system,
                windows_system,
                read_only: is_read_only(m),
                fstype,
                removable,
            });
        }
    }
    if let Some(children) = n["children"].as_array() {
        for c in children {
            walk(c, removable, out);
        }
    }
}

/// Mounted drives outside the running system.
pub fn external_drives() -> Vec<Drive> {
    let out = std::process::Command::new("lsblk")
        .args(["-J", "-o", "PATH,MOUNTPOINTS,RM,HOTPLUG,TRAN,LABEL,SIZE,FSTYPE"])
        .output();
    let Ok(out) = out else { return vec![] };
    let Ok(v) = serde_json::from_slice::<Value>(&out.stdout) else { return vec![] };
    let mut drives = vec![];
    if let Some(devs) = v["blockdevices"].as_array() {
        for d in devs {
            walk(d, false, &mut drives);
        }
    }
    drives.sort_by(|a, b| a.mount.cmp(&b.mount));
    drives.dedup_by(|a, b| a.mount == b.mount);
    drives
}

/// The drives a scan should include (all detected ones minus those switched off).
pub fn chosen(skip: &[String]) -> Vec<Drive> {
    external_drives().into_iter().filter(|d| !skip.contains(&d.mount)).collect()
}

pub const WARN_WINDOWS_SYSTEM: &str = "Windows system partition: don't quarantine, delete or zero-fill files inside Windows' own folders (Windows, Program Files, ProgramData) — it can stop Windows from starting. ClamAV finds Windows viruses that can't run on Linux; the safest cure is a scan with Windows Defender from inside Windows.";
pub const WARN_HIBERNATE: &str = "If Windows uses Fast Startup or was hibernated, it isn't really shut down: changing files on this partition from Linux can corrupt it. Scanning only reads, but turn Fast Startup off (or shut Windows down fully with Shift+Shut down) before quarantining or deleting anything here.";
pub const WARN_WINDOWS_FILES: &str = "Windows filesystem: Windows programs found here can't run on Linux, but they can infect any Windows PC this drive is used with.";
pub const WARN_READ_ONLY: &str = "Mounted read-only: it can be scanned, but found files can't be quarantined or deleted from here.";

pub fn is_windows_fs(fs: &str) -> bool {
    matches!(fs, "ntfs" | "ntfs3" | "ntfs-3g" | "fuseblk" | "exfat" | "vfat" | "msdos" | "BitLocker")
}

fn is_read_only(mount: &str) -> bool {
    std::fs::read_to_string("/proc/self/mounts")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() > 3).then(|| (f[1].replace("\\040", " "), f[3].to_string()))
        })
        .filter(|(m, _)| m == mount)
        .last()
        .map(|(_, o)| o.split(',').any(|x| x == "ro"))
        .unwrap_or(false)
}

/// A file inside Windows' own folders (on any drive, including Wine prefixes).
pub fn in_windows_system_folder(path: &str) -> bool {
    let p = path.to_lowercase();
    ["/windows/", "/program files/", "/program files (x86)/", "/programdata/"].iter().any(|d| p.contains(d))
}

/// Is this file on a Windows filesystem?
pub fn on_windows_fs(path: &str) -> bool {
    is_windows_fs(&crate::quarantine::fs_type(path))
}

/// Does this file start like a Windows program?
pub fn is_windows_program(path: &str) -> bool {
    use std::io::Read;
    let mut b = [0u8; 2];
    std::fs::File::open(path).and_then(|mut f| f.read_exact(&mut b)).map(|_| &b == b"MZ").unwrap_or(false)
}
