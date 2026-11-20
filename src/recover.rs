//! Experimental: recover deleted files with PhotoRec (from TestDisk) and hand
//! them to the virus scan. PhotoRec only reads the source drive; recovered
//! files must go to a different drive so nothing deleted gets overwritten.

use crate::jobs::{Emitter, Sev};
use serde_json::Value;
use std::path::Path;

pub const PHOTOREC: &str = "/usr/bin/photorec";

pub fn installed() -> bool {
    Path::new(PHOTOREC).exists()
}

#[derive(Clone, Debug)]
pub struct Partition {
    pub path: String,
    pub fstype: String,
    pub size: String,
    pub size_bytes: u64,
    pub label: String,
    pub mounts: Vec<String>,
}

fn human(b: u64) -> String {
    let units = ["B", "K", "M", "G", "T", "P"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i + 1 < units.len() {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{b}B") } else { format!("{v:.1}{}", units[i]) }
}

impl Partition {
    pub fn system(&self) -> bool {
        self.mounts.iter().any(|m| ["/", "/home", "/boot", "/var", "/usr"].contains(&m.as_str()))
    }
    pub fn describe(&self) -> String {
        format!(
            "{} — {} {}{}{}",
            self.path,
            self.size,
            if self.fstype.is_empty() { "?" } else { &self.fstype },
            if self.label.is_empty() { String::new() } else { format!(" \"{}\"", self.label) },
            if self.mounts.is_empty() { String::new() } else { format!(" at {}", self.mounts.join(", ")) }
        )
    }
    /// PhotoRec can tell free (deleted) space from used space on these.
    pub fn freespace_supported(&self) -> bool {
        matches!(self.fstype.as_str(), "ext2" | "ext3" | "ext4" | "vfat" | "exfat" | "ntfs" | "ntfs3" | "hfsplus")
    }
}

pub fn partitions() -> Vec<Partition> {
    let out = std::process::Command::new("lsblk").args(["-J", "-b", "-o", "PATH,TYPE,FSTYPE,SIZE,LABEL,MOUNTPOINTS"]).output();
    let Ok(out) = out else { return vec![] };
    let Ok(v) = serde_json::from_slice::<Value>(&out.stdout) else { return vec![] };
    let mut parts = vec![];
    fn walk(n: &Value, out: &mut Vec<Partition>) {
        let t = n["type"].as_str().unwrap_or("");
        let fstype = n["fstype"].as_str().unwrap_or("").to_string();
        if matches!(t, "part" | "crypt" | "lvm" | "md" | "raid0" | "raid1") && !fstype.is_empty() && fstype != "swap" && fstype != "crypto_LUKS" {
            let bytes = n["size"].as_u64().or_else(|| n["size"].as_str().and_then(|x| x.parse().ok())).unwrap_or(0);
            out.push(Partition {
                path: n["path"].as_str().unwrap_or("").to_string(),
                fstype,
                size: human(bytes),
                size_bytes: bytes,
                label: n["label"].as_str().unwrap_or("").to_string(),
                mounts: n["mountpoints"].as_array().map(|a| a.iter().filter_map(|m| m.as_str().map(|s| s.to_string())).collect()).unwrap_or_default(),
            });
        }
        if let Some(c) = n["children"].as_array() {
            for x in c {
                walk(x, out);
            }
        }
    }
    if let Some(d) = v["blockdevices"].as_array() {
        for x in d {
            walk(x, &mut parts);
        }
    }
    parts.sort_by(|a, b| a.path.cmp(&b.path));
    parts
}

/// The block device a folder lives on (btrfs subvolume suffixes removed).
pub fn device_of(dir: &str) -> String {
    let mut p = Path::new(dir).to_path_buf();
    while !p.exists() {
        if !p.pop() {
            break;
        }
    }
    std::process::Command::new("findmnt")
        .args(["-no", "SOURCE", "--target", &p.to_string_lossy()])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().split('[').next().unwrap_or("").to_string())
        .unwrap_or_default()
}

/// Free space at a folder, in bytes.
pub fn free_bytes(dir: &str) -> u64 {
    let mut p = Path::new(dir).to_path_buf();
    while !p.exists() {
        if !p.pop() {
            return 0;
        }
    }
    let c = std::ffi::CString::new(p.to_string_lossy().as_bytes()).unwrap_or_default();
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } == 0 {
        st.f_bavail as u64 * st.f_frsize as u64
    } else {
        0
    }
}

/// File kinds PhotoRec can look for (its name, what it is). All can carry malware.
pub const KINDS: [(&str, &str); 13] = [
    ("elf", "Linux programs and libraries"),
    ("exe", "Windows programs and DLLs"),
    ("zip", "zip archives, Office documents, Java .jar, Android .apk"),
    ("rar", "RAR archives"),
    ("7z", "7-Zip archives"),
    ("gz", "gzip archives"),
    ("bz2", "bzip2 archives"),
    ("xz", "xz archives"),
    ("cab", "Windows cabinet archives"),
    ("pdf", "PDF documents"),
    ("doc", "old Office documents (can hold macros)"),
    ("class", "Java classes"),
    ("swf", "Flash files"),
];

#[derive(Clone, Debug)]
pub struct Plan {
    pub source: Partition,
    pub dest: String,
    pub kinds: Vec<String>,
    /// Only look in deleted (free) space.
    pub only_free: bool,
    /// Every kind of file PhotoRec knows (photos, documents, everything), not only risky ones.
    pub all_kinds: bool,
    /// Keep files PhotoRec could only partly recover.
    pub keep_damaged: bool,
}

/// A warning when the destination may run out of room (empty when fine).
pub fn space_warning(plan: &Plan) -> Option<String> {
    let free = free_bytes(&plan.dest);
    if free == 0 {
        return None;
    }
    let need = if plan.all_kinds { plan.source.size_bytes } else { plan.source.size_bytes / 4 };
    if free < need {
        Some(format!(
            "Only {} free where the files go, and the drive being recovered is {}. {} — PhotoRec stops when the space runs out.",
            human(free),
            plan.source.size,
            if plan.all_kinds { "Recovering everything can need about as much room as the whole drive" } else { "There may not be enough room" }
        ))
    } else {
        None
    }
}

/// Problems that block a recovery (empty when it's safe to start).
pub fn check(plan: &Plan) -> Vec<String> {
    let mut e = vec![];
    if !installed() {
        e.push("PhotoRec (from the testdisk package) isn't installed.".into());
    }
    if plan.dest.trim().is_empty() || !plan.dest.starts_with('/') {
        e.push("Choose a folder (full path) to put recovered files in.".into());
        return e;
    }
    let dev = device_of(&plan.dest);
    if dev == plan.source.path {
        e.push(format!("The folder is on {}, the drive you're recovering from — saving there would overwrite the deleted files. Pick a folder on another drive.", plan.source.path));
    }
    if plan.kinds.is_empty() && !plan.all_kinds {
        e.push("Pick at least one kind of file to look for.".into());
    }
    e
}

/// The shell script run with administrator rights: PhotoRec, then hand the
/// recovered files to you.
pub fn script(plan: &Plan) -> String {
    let q = crate::clam::shell_quote;
    let mut opts = vec!["partition_none".to_string(), "options".into()];
    if plan.keep_damaged {
        opts.push("keep_corrupted_file".into());
    }
    if plan.source.fstype.starts_with("ext") {
        opts.push("mode_ext2".into());
    }
    opts.push("fileopt".into());
    opts.push("everything".into());
    if plan.all_kinds {
        opts.push("enable".into());
    } else {
        opts.push("disable".into());
        for k in &plan.kinds {
            opts.push(k.clone());
            opts.push("enable".into());
        }
    }
    opts.push(if plan.only_free && plan.source.freespace_supported() { "freespace".into() } else { "wholespace".into() });
    opts.push("search".into());
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    format!(
        "mkdir -p {dest} && cd {dest} && {pr} /log /d {dest}/recovered /cmd {src} {opts} > /dev/null 2>&1; code=$?; chown -R {uid}:{gid} {dest}; exit $code",
        dest = q(&plan.dest),
        pr = PHOTOREC,
        src = q(&plan.source.path),
        opts = opts.join(","),
    )
}

/// Run a recovery. Returns the folder recovered files went to, when any.
pub fn run(s: &crate::settings::Settings, plan: &Plan, em: &mut Emitter) -> Option<String> {
    let problems = check(plan);
    if !problems.is_empty() {
        em.done(problems.join(" "));
        return None;
    }
    let dest = plan.dest.clone();
    em.log(format!("Recovering from {} into {dest}", plan.source.describe()));
    if !plan.only_free || !plan.source.freespace_supported() {
        em.log("Looking through the whole partition (this also finds files that still exist).");
    }
    // Count recovered files every couple of seconds for the progress line.
    let state = em.state_handle();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watcher = {
        let dest = dest.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let n = walkdir::WalkDir::new(&dest).into_iter().flatten().filter(|e| e.file_type().is_file() && e.file_name() != "report.xml").count();
                state.lock().unwrap().progress = format!("PhotoRec is reading the drive… {n} file(s) recovered so far");
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
        })
    };
    let cmd = crate::par::command(s, true, "/bin/sh", &["-c".to_string(), script(plan)]);
    let code = crate::par::stream_command(cmd, em, &|_| vec![], &mut |_, _| {});
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = watcher.join();
    if code == 126 || code == 127 {
        em.done("Administrator rights were refused.");
        return None;
    }
    // What PhotoRec says it found.
    if let Ok(log) = std::fs::read_to_string(Path::new(&dest).join("photorec.log")) {
        for l in log.lines().filter(|l| l.contains(" recovered") || l.starts_with("Total:")) {
            em.log(format!("PhotoRec: {}", l.trim()));
        }
    }
    // PhotoRec reads empty disk areas as "files" made only of zero bytes; they hold nothing.
    let mut empty = 0usize;
    for e in walkdir::WalkDir::new(&dest).into_iter().flatten().filter(|e| e.file_type().is_file()) {
        if all_zero(e.path()) && std::fs::remove_file(e.path()).is_ok() {
            empty += 1;
        }
    }
    if empty > 0 {
        em.log(format!("Dropped {empty} empty fragment(s) that were only zero bytes."));
    }
    let files: Vec<(String, u64)> = walkdir::WalkDir::new(&dest)
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file() && e.file_name() != "report.xml" && e.file_name() != "photorec.log")
        .map(|e| (e.path().display().to_string(), e.metadata().map(|m| m.len()).unwrap_or(0)))
        .collect();
    // Count by kind for a readable summary.
    let mut by_kind: std::collections::BTreeMap<String, usize> = Default::default();
    for (p, _) in &files {
        let kind = Path::new(p).extension().map(|x| x.to_string_lossy().to_lowercase()).unwrap_or_else(|| "no extension".into());
        *by_kind.entry(kind).or_default() += 1;
    }
    let mut kinds: Vec<(String, usize)> = by_kind.into_iter().collect();
    kinds.sort_by(|a, b| b.1.cmp(&a.1));
    if !kinds.is_empty() {
        em.log(format!("By kind: {}", kinds.iter().take(15).map(|(k, n)| format!("{n} .{k}")).collect::<Vec<_>>().join(", ")));
    }
    for (p, len) in files.iter().take(5000) {
        let kind = Path::new(p).extension().map(|x| x.to_string_lossy().to_string()).unwrap_or_default();
        em.find(Sev::Info, &format!("Recovered .{kind}"), p.clone(), format!("{} KB", len / 1024));
    }
    em.done(format!("Recovered {} file(s) into {dest}{}.", files.len(), if code != 0 { format!(" (PhotoRec ended with code {code})") } else { String::new() }));
    if files.is_empty() { None } else { Some(dest) }
}

/// True when a file holds nothing but zero bytes (or is empty).
fn all_zero(p: &Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(p) else { return false };
    let mut buf = vec![0u8; 1 << 16];
    loop {
        match f.read(&mut buf) {
            Ok(0) => return true,
            Ok(n) => {
                if buf[..n].iter().any(|&b| b != 0) {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }
}
