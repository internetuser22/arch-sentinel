//! Package database checks: which files pacman owns, which files no package
//! owns, paccheck verification and the home folder check.

use crate::jobs::{Emitter, Msg, Sev};
use crate::settings::{glob_match, Settings};
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

pub const PACMAN_LOCAL: &str = "/var/lib/pacman/local";

pub struct OwnedDb {
    pub files: HashSet<String>,
    pub owner: HashMap<String, String>,
    pub packages: usize,
}

/// Read every installed package's `files` list straight from the pacman database.
pub fn load_owned(with_owner: bool) -> std::io::Result<OwnedDb> {
    let mut files = HashSet::with_capacity(400_000);
    let mut owner = HashMap::new();
    let mut packages = 0;
    for entry in std::fs::read_dir(PACMAN_LOCAL)? {
        let entry = entry?;
        let fpath = entry.path().join("files");
        let Ok(text) = std::fs::read_to_string(&fpath) else { continue };
        packages += 1;
        let pkgname = package_name(&entry.file_name().to_string_lossy());
        let mut in_files = false;
        for line in text.lines() {
            if line.starts_with('%') {
                in_files = line == "%FILES%";
                continue;
            }
            if !in_files || line.is_empty() {
                continue;
            }
            let p = format!("/{}", line.trim_end_matches('/'));
            if with_owner {
                owner.insert(p.clone(), pkgname.clone());
            }
            files.insert(p);
        }
    }
    Ok(OwnedDb { files, owner, packages })
}

/// "linux-firmware-20240101-1" -> "linux-firmware"
pub fn package_name(dir: &str) -> String {
    let parts: Vec<&str> = dir.rsplitn(3, '-').collect();
    if parts.len() == 3 {
        parts[2].to_string()
    } else {
        dir.to_string()
    }
}

pub fn package_count() -> usize {
    std::fs::read_dir(PACMAN_LOCAL).map(|d| d.count()).unwrap_or(0)
}

pub fn is_elf(path: &Path) -> bool {
    let mut buf = [0u8; 4];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut buf))
        .map(|_| buf == *b"\x7fELF")
        .unwrap_or(false)
}

fn is_script(path: &Path) -> bool {
    let mut buf = [0u8; 2];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut buf))
        .map(|_| buf == *b"#!")
        .unwrap_or(false)
}

fn ignored(s: &Settings, p: &str) -> bool {
    s.ignore_patterns.iter().any(|pat| glob_match(pat, p))
}

fn excluded(s: &Settings, p: &str) -> bool {
    s.excluded
        .iter()
        .any(|e| p == e || (p.starts_with(e.as_str()) && p.as_bytes().get(e.len()) == Some(&b'/')))
}

/// Walk the chosen system folders (with several threads) and report every
/// file no package owns.
pub fn scan_unowned(s: &Settings, em: &mut Emitter) {
    em.progress("Reading the package database…");
    let db = match load_owned(false) {
        Ok(d) => d,
        Err(e) => {
            em.done(format!("Couldn't read the package database: {e}"));
            return;
        }
    };
    let threads = crate::par::threads(s);
    em.log(format!("{} packages own {} paths. Scanning with {threads} thread(s).", db.packages, db.files.len()));
    enum Out {
        Found(Sev, String, String),
        Ignored,
    }
    let files = &db.files;
    let visit = |entry: &walkdir::DirEntry, tx: &std::sync::mpsc::Sender<crate::par::WalkOut<Out>>| -> bool {
        use crate::par::WalkOut::Item;
        let path = entry.path().to_string_lossy().to_string();
        if excluded(s, &path) {
            return true;
        }
        if files.contains(&path) {
            return false;
        }
        if ignored(s, &path) {
            let _ = tx.send(Item(Out::Ignored));
            return true;
        }
        let ft = entry.file_type();
        let meta = entry.metadata().ok();
        let mode = meta.as_ref().map(|m| m.permissions().mode()).unwrap_or(0);
        let (sev, detail) = if ft.is_dir() {
            let n = std::fs::read_dir(entry.path()).map(|d| d.count()).unwrap_or(0);
            (dir_sev(&path), format!("Folder no package owns ({n} items inside)"))
        } else if ft.is_symlink() {
            let t = std::fs::read_link(entry.path()).map(|t| t.display().to_string()).unwrap_or_default();
            (Sev::Low, format!("Link → {t}"))
        } else if mode & 0o6000 != 0 {
            (Sev::High, format!("Runs with raised rights (setuid/setgid), mode {:o}", mode & 0o7777))
        } else if is_elf(entry.path()) {
            (exec_sev(&path), "Program file (ELF) no package installed".to_string())
        } else if mode & 0o111 != 0 {
            (exec_sev(&path).max(Sev::Medium), "Executable file no package installed".to_string())
        } else {
            (Sev::Low, format!("{} bytes", meta.map(|m| m.len()).unwrap_or(0)))
        };
        let _ = tx.send(Item(Out::Found(sev, path, detail)));
        // Report an unowned folder once and skip its contents.
        ft.is_dir()
    };
    let mut checked = 0u64;
    let mut unowned = 0u64;
    let mut unreadable = 0u64;
    let mut skipped = 0u64;
    let cancel = em.cancel_flag();
    crate::par::par_walk(&s.system_roots, threads, cancel, &visit, &mut |out| match out {
        crate::par::WalkOut::Item(Out::Found(sev, path, detail)) => {
            unowned += 1;
            em.find(sev, "Unowned", path, detail);
        }
        crate::par::WalkOut::Item(Out::Ignored) => skipped += 1,
        crate::par::WalkOut::Unreadable(p) => {
            unreadable += 1;
            em.log(format!("Can't read {p} (run as administrator to look inside)"));
        }
        crate::par::WalkOut::Checked(n, p) => {
            checked += n;
            if !p.is_empty() {
                em.progress(format!("Checked {checked} files with {threads} thread(s)… {p}"));
            }
        }
    });
    em.done(format!(
        "Checked {checked} paths with {threads} thread(s): {unowned} not owned by any package, {skipped} ignored by your patterns, {unreadable} couldn't be read."
    ));
}

fn exec_sev(path: &str) -> Sev {
    if path.starts_with("/usr/local/") || path.starts_with("/opt/") {
        return Sev::Medium;
    }
    let hot = ["/usr/bin/", "/usr/lib/", "/etc/", "/boot/", "/usr/lib64/", "/usr/sbin/"];
    if hot.iter().any(|h| path.starts_with(h)) {
        Sev::High
    } else {
        Sev::Medium
    }
}

fn dir_sev(path: &str) -> Sev {
    if path.starts_with("/usr/bin") || path.starts_with("/usr/lib/systemd") || path.starts_with("/etc/systemd") {
        Sev::Medium
    } else {
        Sev::Low
    }
}

/// Parse one paccheck output line: `pkg: '/path' problem`.
pub fn parse_paccheck(line: &str) -> Vec<Msg> {
    let mut line = line.trim();
    if line.is_empty() {
        return vec![];
    }
    let mut warning = false;
    if let Some(rest) = line.strip_prefix("warning: ").or_else(|| line.strip_prefix("error: ")) {
        warning = true;
        line = rest;
    }
    let (pkg, rest) = match line.split_once(": ") {
        Some((p, r)) if !p.contains(' ') => (p.to_string(), r.to_string()),
        _ => return vec![Msg::Log(line.to_string())],
    };
    let (path, problem) = if let Some(start) = rest.find('\'') {
        if let Some(len) = rest[start + 1..].find('\'') {
            let p = rest[start + 1..start + 1 + len].to_string();
            let prob = rest[start + 2 + len..].trim().to_string();
            (p, prob)
        } else {
            (String::new(), rest.clone())
        }
    } else {
        (String::new(), rest.clone())
    };
    let low = problem.to_lowercase();
    if path.is_empty() && low.contains("all files match") {
        return vec![];
    }
    if path.is_empty() && low.contains("no mtree") {
        return vec![Msg::Log(line.to_string())];
    }
    let important = path.starts_with("/usr/bin")
        || path.starts_with("/usr/lib")
        || path.starts_with("/usr/sbin")
        || path.starts_with("/boot");
    let sev = if warning || low.contains("read error") {
        Sev::Info
    } else if low.contains("checksum mismatch") || low.contains("sha256") || low.contains("md5") {
        if important { Sev::High } else if path.starts_with("/etc") { Sev::Low } else { Sev::Medium }
    } else if low.contains("permission denied") || low.contains("could not read") || low.contains("unable to") {
        Sev::Info
    } else if low.contains("missing") {
        Sev::Medium
    } else if low.contains("uid") || low.contains("gid") || low.contains("owner") || low.contains("permission") || low.contains("mode") {
        if important { Sev::Medium } else { Sev::Low }
    } else if low.contains("modification time") || low.contains("mtime") || low.contains("size") {
        Sev::Low
    } else {
        Sev::Low
    };
    let shown = if path.is_empty() { format!("({pkg})") } else { path };
    vec![Msg::Find(crate::jobs::Finding {
        sev,
        kind: pkg,
        path: shown,
        detail: problem,
    })]
}

pub fn paccheck_args() -> Vec<String> {
    vec![
        "--files".into(),
        "--file-properties".into(),
        "--sha256sum".into(),
        "--require-mtree".into(),
    ]
}

/// Installed packages with a rough weight (how many files they own).
pub fn installed_packages() -> Vec<(String, u64)> {
    std::fs::read_dir(PACMAN_LOCAL)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.path().join("desc").exists())
                .map(|e| {
                    let w = std::fs::metadata(e.path().join("files")).map(|m| m.len()).unwrap_or(1);
                    (package_name(&e.file_name().to_string_lossy()), w)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The package name a paccheck line is about.
fn line_package(line: &str) -> Option<String> {
    let l = line.trim();
    let l = l.strip_prefix("warning: ").or_else(|| l.strip_prefix("error: ")).unwrap_or(l);
    let (p, _) = l.split_once(": ")?;
    if p.contains(' ') { None } else { Some(p.to_string()) }
}

/// Check every installed package with paccheck, several packages at a time.
pub fn scan_integrity(s: &Settings, admin: bool, em: &mut Emitter) {
    let pkgs = installed_packages();
    let total = pkgs.len().max(1);
    let threads = crate::par::threads(s).min(total);
    em.progress(format!("Checking {total} packages with {threads} thread(s)…"));
    let groups = crate::par::split_balanced(pkgs, threads);
    let cmds: Vec<Vec<String>> = groups
        .into_iter()
        .map(|g| {
            let mut c = vec!["/usr/bin/paccheck".to_string()];
            c.extend(paccheck_args());
            c.extend(g);
            c
        })
        .collect();
    let script = crate::par::parallel_script(&cmds);
    let cmd = crate::par::command(s, admin, "/bin/sh", &["-c".to_string(), script]);
    let mut seen = std::collections::HashSet::new();
    let code = crate::par::stream_command(cmd, em, &parse_paccheck, &mut |line, em| {
        if let Some(p) = line_package(line) {
            if seen.insert(p) && seen.len() % 10 == 0 {
                em.progress(format!("Checked {} of {total} packages ({}%) with {threads} thread(s)…", seen.len(), seen.len() * 100 / total));
            }
        }
    });
    let problems = em.findings().iter().filter(|f| f.sev != Sev::Info).count();
    em.done(match code {
        126 | 127 if admin => "Administrator rights were refused.".to_string(),
        _ if problems == 0 => format!("All {total} packages match what was installed."),
        _ => format!("Checked {total} packages with {threads} thread(s): {problems} file problem(s) — see the list."),
    });
}

/// Look at the home folder for things worth a second look: programs,
/// autostart entries, user services, scripts in caches and odd permissions.
pub fn scan_home(s: &Settings, em: &mut Emitter) {
    let home = s.home.clone();
    let mut checked = 0u64;
    let mut found = 0u64;
    em.progress(format!("Looking through {home}…"));

    // Places that start programs automatically.
    let autostart = [
        ".config/autostart",
        ".config/systemd/user",
        ".config/environment.d",
        ".local/share/systemd/user",
        ".config/plasma-workspace/env",
        ".config/plasma-workspace/shutdown",
    ];
    for a in autostart {
        let dir = Path::new(&home).join(a);
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let p = e.path();
                let exec = std::fs::read_to_string(&p)
                    .ok()
                    .and_then(|t| {
                        t.lines()
                            .find(|l| l.starts_with("Exec=") || l.starts_with("ExecStart="))
                            .map(|l| l.splitn(2, '=').nth(1).unwrap_or("").to_string())
                    })
                    .unwrap_or_default();
                em.find(Sev::Info, "Starts automatically", p.display().to_string(), if exec.is_empty() { "Autostart entry".to_string() } else { format!("Runs: {exec}") });
                found += 1;
            }
        }
    }
    for rc in [".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".xprofile", ".xinitrc"] {
        let p = Path::new(&home).join(rc);
        if let Ok(t) = std::fs::read_to_string(&p) {
            for (i, l) in t.lines().enumerate() {
                let ll = l.trim();
                if ll.starts_with('#') {
                    continue;
                }
                let bad = ll.contains("LD_PRELOAD")
                    || (ll.contains("curl ") && ll.contains("| sh"))
                    || (ll.contains("wget ") && ll.contains("| sh"))
                    || ll.contains("base64 -d")
                    || ll.contains("/dev/tcp/");
                if bad {
                    em.find(Sev::High, "Suspicious shell line", p.display().to_string(), format!("line {}: {}", i + 1, ll));
                    found += 1;
                }
            }
        }
    }
    let ssh = Path::new(&home).join(".ssh/authorized_keys");
    if let Ok(t) = std::fs::read_to_string(&ssh) {
        let n = t.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')).count();
        em.find(Sev::Info, "SSH access", ssh.display().to_string(), format!("{n} key(s) may log in as you"));
    }

    let uid = unsafe { libc::getuid() };
    let threads = crate::par::threads(s);
    let mut programs_per_dir: std::collections::BTreeMap<String, (u64, u64)> = Default::default();
    let mut config_per_dir: std::collections::BTreeMap<String, (u64, u64)> = Default::default();
    let mut foreign_per_dir: std::collections::BTreeMap<String, (u64, String)> = Default::default();
    let home_ref = &home;
    let group_of = |path: &str| -> String {
        let rel = path[home_ref.len()..].trim_start_matches('/');
        let parts: Vec<&str> = rel.split('/').collect();
        let n = if parts.first().map(|p| *p == ".local" || *p == ".var").unwrap_or(false) { 3 } else { 2 };
        let take = parts.len().saturating_sub(1).min(n).max(1);
        format!("{}/{}", home_ref, parts[..take].join("/"))
    };
    enum Out {
        Find(Sev, &'static str, String, String),
        Program(String, u64),
        Config(String, u64),
        Foreign(String, u32, String),
    }
    let visit = |entry: &walkdir::DirEntry, tx: &std::sync::mpsc::Sender<crate::par::WalkOut<Out>>| -> bool {
        use crate::par::WalkOut::Item;
        let path = entry.path().to_string_lossy().to_string();
        if s.virus_excluded.iter().any(|e| path.starts_with(e.as_str())) {
            return true;
        }
        if ignored(s, &path) || !entry.file_type().is_file() {
            return false;
        }
        let Ok(meta) = entry.metadata() else { return false };
        let mode = meta.permissions().mode();
        if meta.uid() != uid {
            let _ = tx.send(Item(Out::Foreign(group_of(&path), meta.uid(), path.clone())));
        }
        if mode & 0o6000 != 0 {
            let _ = tx.send(Item(Out::Find(Sev::High, "Raised rights", path, format!("setuid/setgid file in your home, mode {:o}", mode & 0o7777))));
            return false;
        }
        if mode & 0o111 == 0 {
            return false;
        }
        let elf = is_elf(entry.path());
        if mode & 0o002 != 0 && (elf || is_script(entry.path())) {
            let _ = tx.send(Item(Out::Find(Sev::Medium, "Anyone can change", path.clone(), "Program that every user on this computer can rewrite".into())));
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let in_cache = path.contains("/.cache/") || path.contains("/tmp/");
        let in_config = path.starts_with(&format!("{home_ref}/.config/"));
        if elf {
            if in_config && !in_cache && !name.starts_with('.') {
                let _ = tx.send(Item(Out::Config(group_of(&path), meta.len())));
            } else if in_cache || name.starts_with('.') {
                let why = if name.starts_with('.') { "hidden program file" } else { "program file inside a cache folder" };
                let _ = tx.send(Item(Out::Find(Sev::Medium, "Odd place for a program", path, format!("{why}, {} KB", meta.len() / 1024))));
            } else {
                let _ = tx.send(Item(Out::Program(group_of(&path), meta.len())));
            }
        } else if is_script(entry.path()) && in_cache {
            let _ = tx.send(Item(Out::Find(Sev::Low, "Script in cache", path, "Executable script inside a cache folder".into())));
        }
        false
    };
    let cancel = em.cancel_flag();
    crate::par::par_walk(&[home.clone()], threads, cancel, &visit, &mut |out| match out {
        crate::par::WalkOut::Item(Out::Find(sev, kind, path, detail)) => {
            found += 1;
            em.find(sev, kind, path, detail);
        }
        crate::par::WalkOut::Item(Out::Program(g, b)) => {
            let e = programs_per_dir.entry(g).or_insert((0, 0));
            e.0 += 1;
            e.1 += b;
        }
        crate::par::WalkOut::Item(Out::Config(g, b)) => {
            let e = config_per_dir.entry(g).or_insert((0, 0));
            e.0 += 1;
            e.1 += b;
        }
        crate::par::WalkOut::Item(Out::Foreign(g, uid, p)) => {
            let e = foreign_per_dir.entry(g).or_insert((0, String::new()));
            e.0 += 1;
            if e.1.is_empty() {
                e.1 = format!("user id {uid}, e.g. {p}");
            }
        }
        crate::par::WalkOut::Unreadable(_) => {}
        crate::par::WalkOut::Checked(n, p) => {
            checked += n;
            if !p.is_empty() {
                em.progress(format!("Checked {checked} files with {threads} thread(s)… {p}"));
            }
        }
    });
    for (dir, (n, bytes)) in &programs_per_dir {
        em.find(Sev::Info, "Programs in home", dir.clone(), format!("{n} program file(s), {} MB — not from packages (games, toolchains, apps you installed yourself)", bytes / 1_048_576));
    }
    for (dir, (n, bytes)) in &config_per_dir {
        em.find(Sev::Low, "Programs in settings folder", dir.clone(), format!("{n} program file(s), {} MB — usual for browsers and self-updating apps, unusual otherwise", bytes / 1_048_576));
    }
    for (dir, (n, example)) in &foreign_per_dir {
        found += 1;
        em.find(Sev::Medium, "Owned by someone else", dir.clone(), format!("{n} file(s) belong to another user ({example})"));
    }
    em.done(format!(
        "Checked {checked} items in your home folder with {threads} thread(s): {found} worth a look, programs found in {} folders.",
        programs_per_dir.len()
    ));
}

/// Setuid/setgid files in system folders that no package installed.
pub fn unowned_suid(db: &OwnedDb, threads: usize, em: &mut Emitter) -> usize {
    let files = &db.files;
    let visit = |e: &walkdir::DirEntry, tx: &std::sync::mpsc::Sender<crate::par::WalkOut<(String, u32)>>| -> bool {
        let p = e.path().to_string_lossy();
        if p.starts_with("/var/cache") || p.starts_with("/var/log") || p.starts_with("/var/lib/pacman") {
            return true;
        }
        if !e.file_type().is_file() {
            return false;
        }
        if let Ok(m) = e.metadata() {
            let mode = m.permissions().mode();
            if mode & 0o6000 != 0 && !files.contains(p.as_ref()) {
                let _ = tx.send(crate::par::WalkOut::Item((p.to_string(), mode)));
            }
        }
        false
    };
    let roots: Vec<String> = ["/usr", "/opt", "/etc", "/var", "/srv"].iter().map(|s| s.to_string()).collect();
    let mut n = 0;
    let cancel = em.cancel_flag();
    crate::par::par_walk(&roots, threads, cancel, &visit, &mut |out| {
        if let crate::par::WalkOut::Item((p, mode)) = out {
            n += 1;
            em.find(Sev::High, "Raised-rights file", p, format!("setuid/setgid ({:o}) and no package installed it", mode & 0o7777));
        }
    });
    n
}
