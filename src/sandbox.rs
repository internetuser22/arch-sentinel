//! Experimental throwaway sandbox (bubblewrap + strace): unpack a suspicious
//! archive, or run a suspicious program for a few seconds with no network,
//! no access to your files and a fake empty home, and record what it tried to
//! do — network connections and name lookups, programs it started, files it
//! read or wrote. Everything happens in a folder that's thrown away after.
//!
//! This is a sandbox, not a virtual machine: it stops ordinary programs, not
//! malware that attacks the kernel itself.

use crate::jobs::{Emitter, Sev};
use crate::settings::Settings;
use std::path::{Path, PathBuf};

pub fn available() -> bool {
    Path::new("/usr/bin/bwrap").exists() && Path::new("/usr/bin/strace").exists()
}

pub fn wine_path() -> Option<&'static str> {
    ["/usr/bin/wine", "/usr/local/bin/wine"].into_iter().find(|p| Path::new(p).exists())
}

/// Where throwaway sandboxes live.
pub fn base_dir() -> PathBuf {
    let base = std::env::var("XDG_CACHE_HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from(crate::settings::home_dir()).join(".cache"));
    base.join("arch-sentinel/sandboxes")
}

pub fn new_dir() -> std::io::Result<PathBuf> {
    let id = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
    let d = base_dir().join(format!("box-{id}"));
    std::fs::create_dir_all(d.join("work"))?;
    std::fs::create_dir_all(d.join("out"))?;
    Ok(d)
}

/// Throw a sandbox folder away (fixing any permissions the sample changed).
pub fn throw_away(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    if !dir.starts_with(base_dir()) {
        return Err("not a sandbox folder".into());
    }
    for e in walkdir::WalkDir::new(dir).into_iter().flatten() {
        let mode = if e.file_type().is_dir() { 0o700 } else { 0o600 };
        if !e.file_type().is_symlink() {
            let _ = std::fs::set_permissions(e.path(), std::fs::Permissions::from_mode(mode));
        }
    }
    std::fs::remove_dir_all(dir).map_err(|e| e.to_string())
}

/// Copy the sample into the sandbox (works for quarantined files too, which have no permissions).
fn copy_sample(sample: &str, work: &Path) -> Result<String, String> {
    use std::os::unix::fs::PermissionsExt;
    let src = Path::new(sample);
    let name = src.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "sample".into());
    let name: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || ".-_".contains(c) { c } else { '_' }).collect();
    let dst = work.join(&name);
    let old = std::fs::metadata(src).map(|m| m.permissions().mode()).ok();
    if old.map(|m| m & 0o400 == 0).unwrap_or(false) {
        let _ = std::fs::set_permissions(src, std::fs::Permissions::from_mode(0o400));
    }
    let r = std::fs::copy(src, &dst);
    if let Some(m) = old {
        let _ = std::fs::set_permissions(src, std::fs::Permissions::from_mode(m));
    }
    r.map_err(|e| format!("Couldn't copy the file into the sandbox: {e}"))?;
    let _ = std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o700));
    Ok(name)
}

/// The bubblewrap walls: read-only system, empty home and /tmp, no network,
/// no other processes, nothing of yours but the sandbox's own folder.
fn bwrap_args(dir: &Path) -> Vec<String> {
    let mut a: Vec<String> = [
        "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL", "--hostname", "sandbox",
        "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib", "/lib64", "--symlink", "usr/bin", "/sbin",
        "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/home", "--dir", "/home/user", "--dir", "/etc",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for f in ["/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/nsswitch.conf", "/etc/passwd", "/etc/group", "/etc/localtime", "/etc/ssl", "/etc/ca-certificates", "/etc/fonts"] {
        if Path::new(f).exists() {
            a.extend(["--ro-bind".to_string(), f.to_string(), f.to_string()]);
        }
    }
    a.extend([
        "--bind".to_string(), dir.join("work").display().to_string(), "/work".into(),
        "--bind".into(), dir.join("out").display().to_string(), "/out".into(),
        "--clearenv".into(), "--setenv".into(), "HOME".into(), "/home/user".into(),
        "--setenv".into(), "USER".into(), "user".into(),
        "--setenv".into(), "PATH".into(), "/usr/local/bin:/usr/bin".into(),
        "--setenv".into(), "TMPDIR".into(), "/tmp".into(),
        "--setenv".into(), "LANG".into(), "C.UTF-8".into(),
        "--chdir".into(), "/work".into(),
    ]);
    a
}

/// Limits for everything inside: memory, number of processes, CPU, time.
fn limited(secs: u64, inner: Vec<String>) -> std::process::Command {
    let mut parts: Vec<String> = vec![];
    if Path::new("/usr/bin/systemd-run").exists() {
        parts.extend(["/usr/bin/systemd-run", "--user", "--scope", "--quiet", "--collect", "-p", "MemoryMax=2G", "-p", "TasksMax=512", "-p", "CPUQuota=200%"].iter().map(|s| s.to_string()));
    }
    parts.extend(["/usr/bin/nice".into(), "-n".into(), "19".into()]);
    parts.extend(["/usr/bin/timeout".into(), "--kill-after=5".into(), format!("{secs}")]);
    parts.push("/usr/bin/bwrap".into());
    parts.extend(inner);
    let mut c = std::process::Command::new(&parts[0]);
    c.args(&parts[1..]);
    c
}

/// Unpack an archive inside the sandbox. Returns the folder holding what came out.
pub fn unpack(s: &Settings, sample: &str, dir: &Path, em: &mut Emitter) -> Option<PathBuf> {
    let name = match copy_sample(sample, &dir.join("work")) {
        Ok(n) => n,
        Err(e) => {
            em.done(e);
            return None;
        }
    };
    let _ = s;
    std::fs::create_dir_all(dir.join("work/unpacked")).ok()?;
    em.progress("Unpacking inside the sandbox…");
    let mut inner = bwrap_args(dir);
    inner.extend(["/usr/bin/bsdtar".into(), "-xf".into(), format!("/work/{name}"), "-C".into(), "/work/unpacked".into()]);
    let code = crate::par::stream_command(limited(600, inner), em, &|l| vec![crate::jobs::Msg::Log(l.to_string())], &mut |_, _| {});
    let out = dir.join("work/unpacked");
    let files: Vec<(String, u64)> = walkdir::WalkDir::new(&out)
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file())
        .map(|e| (e.path().display().to_string(), e.metadata().map(|m| m.len()).unwrap_or(0)))
        .collect();
    em.log(format!("bsdtar finished with code {code}; {} file(s) came out.", files.len()));
    for (p, len) in files.iter().take(3000) {
        em.find(Sev::Info, "Unpacked", p.clone(), format!("{} KB", len / 1024));
    }
    if files.is_empty() {
        em.done("Nothing came out — it may not be an archive bsdtar can open, or it's damaged or password-protected.");
        return None;
    }
    em.done(format!("Unpacked {} file(s) in the sandbox; they're being virus-scanned (see the Virus scan page).", files.len()));
    Some(out)
}

// ---------- watching a program ----------

/// Decode strace's -xx strings: "\x2f\x75..." → bytes.
fn decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 4);
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1] == b'x' {
            if let Ok(v) = u8::from_str_radix(std::str::from_utf8(&b[i + 2..i + 4]).unwrap_or(""), 16) {
                out.push(v);
                i += 4;
                continue;
            }
        }
        if b[i] == b'\\' && i + 1 < b.len() {
            out.push(match b[i + 1] {
                b'n' => b'\n',
                b't' => b'\t',
                x => x,
            });
            i += 2;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// Every "quoted" string in a line, decoded.
fn quoted(line: &str) -> Vec<String> {
    let mut v = vec![];
    let mut rest = line;
    while let Some(a) = rest.find('"') {
        let after = &rest[a + 1..];
        let mut end = None;
        let bytes = after.as_bytes();
        let mut j = 0;
        while j < bytes.len() {
            if bytes[j] == b'\\' {
                j += 2;
                continue;
            }
            if bytes[j] == b'"' {
                end = Some(j);
                break;
            }
            j += 1;
        }
        let Some(e) = end else { break };
        v.push(String::from_utf8_lossy(&decode(&after[..e])).to_string());
        rest = &after[e + 1..];
    }
    v
}

fn between<'a>(s: &'a str, a: &str, b: &str) -> Option<&'a str> {
    let i = s.find(a)? + a.len();
    let j = s[i..].find(b)? + i;
    Some(&s[i..j])
}

/// The name asked for in a DNS query packet.
fn dns_name(pkt: &[u8]) -> Option<String> {
    if pkt.len() < 17 {
        return None;
    }
    let mut i = 12;
    let mut labels = vec![];
    while i < pkt.len() {
        let n = pkt[i] as usize;
        if n == 0 {
            break;
        }
        if n > 63 || i + 1 + n > pkt.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&pkt[i + 1..i + 1 + n]).to_string());
        i += 1 + n;
    }
    if labels.is_empty() { None } else { Some(labels.join(".")) }
}

const SECRETS: &[(&str, &str)] = &[
    ("/.ssh/", "SSH keys"),
    ("/.gnupg/", "GPG keys"),
    ("/.mozilla/", "Firefox profile (passwords, cookies)"),
    ("/.librewolf/", "LibreWolf profile"),
    ("/.config/chromium", "Chromium profile"),
    ("/.config/google-chrome", "Chrome profile"),
    ("/.config/BraveSoftware", "Brave profile"),
    ("/.local/share/keyrings", "saved passwords (keyring)"),
    ("/.bitcoin", "crypto wallet"),
    ("/.electrum", "crypto wallet"),
    ("wallet.dat", "crypto wallet"),
    ("/etc/shadow", "the password hashes"),
    ("/.aws/", "cloud credentials"),
    ("/.kube/", "Kubernetes credentials"),
    ("/.docker/config.json", "Docker credentials"),
    ("/.netrc", "saved logins"),
];

const PERSIST: &[&str] = &[
    "/.bashrc", "/.bash_profile", "/.profile", "/.zshrc", "/.config/autostart", "/.config/systemd/user", "/.local/share/systemd/user",
    "/etc/cron", "/var/spool/cron", "/etc/systemd", "/etc/ld.so.preload", "/etc/rc.local", "/.xprofile", "/.xinitrc",
];

/// Turn the trace into findings.
fn analyse(trace: &str, sample_name: &str, em: &mut Emitter) -> (usize, usize) {
    use std::collections::BTreeSet;
    let mut nets = BTreeSet::new();
    let mut lookups = BTreeSet::new();
    let mut programs = BTreeSet::new();
    let mut secrets = BTreeSet::new();
    let mut persist = BTreeSet::new();
    let mut deleted = BTreeSet::new();
    let mut unix = BTreeSet::new();
    for line in trace.lines() {
        let l = line.trim_start_matches(|c: char| c.is_ascii_digit() || c == ' ');
        if l.starts_with("connect(") {
            if l.contains("AF_INET6") {
                let port = between(l, "sin6_port=htons(", ")").unwrap_or("?");
                let addr = quoted(l).into_iter().last().unwrap_or_default();
                if port != "53" && addr != "::1" {
                    nets.insert(format!("[{addr}]:{port}"));
                }
            } else if l.contains("AF_INET") {
                let port = between(l, "sin_port=htons(", ")").unwrap_or("?");
                let addr = quoted(l).into_iter().last().unwrap_or_default();
                if port != "53" && !addr.starts_with("127.") {
                    nets.insert(format!("{addr}:{port}"));
                }
            } else if l.contains("AF_UNIX") {
                if let Some(p) = quoted(l).into_iter().next() {
                    if !p.contains("systemd/resolve") && !p.contains("nscd") {
                        unix.insert(p);
                    }
                }
            }
        } else if l.starts_with("sendto(") || l.starts_with("sendmsg(") {
            if let Some(buf) = quoted(l).into_iter().next() {
                // Re-decode from the raw line to keep binary bytes intact.
                let raw = between(l, "\"", "\"").map(decode).unwrap_or_else(|| buf.into_bytes());
                if let Some(n) = dns_name(&raw) {
                    lookups.insert(n);
                }
            }
        } else if l.starts_with("execve(") {
            let q = quoted(l);
            if q.len() > 1 {
                let cmd: Vec<String> = q[1..].iter().take(8).cloned().collect();
                let first = q[0].rsplit('/').next().unwrap_or("").to_string();
                if first != sample_name && first != "strace" {
                    programs.insert(cmd.join(" ").chars().take(160).collect::<String>());
                }
            }
        } else if l.starts_with("openat(") {
            let q = quoted(l);
            let Some(path) = q.first().cloned() else { continue };
            let writes = l.contains("O_WRONLY") || l.contains("O_RDWR") || l.contains("O_CREAT");
            for (pat, what) in SECRETS {
                if path.contains(pat) {
                    secrets.insert(format!("{path} ({what})"));
                }
            }
            if writes && PERSIST.iter().any(|p| path.contains(p)) {
                persist.insert(path.clone());
            }
        } else if l.starts_with("unlink(") || l.starts_with("unlinkat(") {
            if let Some(p) = quoted(l).into_iter().next() {
                if p.contains(sample_name) {
                    deleted.insert(p);
                }
            }
        }
    }
    let mut high = 0;
    let mut med = 0;
    for n in &nets {
        high += 1;
        em.find(Sev::High, "Network connection", n.clone(), "Tried to connect here (blocked: the sandbox has no network)");
    }
    for n in &lookups {
        med += 1;
        em.find(Sev::Medium, "Name lookup", n.clone(), "Tried to look up this internet name (blocked)");
    }
    for s in &secrets {
        high += 1;
        em.find(Sev::High, "Read secrets", s.clone(), "Tried to open this (the sandbox's home is empty, so nothing was there)");
    }
    for p in &persist {
        high += 1;
        em.find(Sev::High, "Start-up change", p.clone(), "Tried to change a file that makes things start automatically");
    }
    for p in &programs {
        let low = p.to_lowercase();
        let risky = ["curl", "wget", " nc ", "ncat", "bash -c", "sh -c", "python", "perl", "chmod +x", "base64", "crontab", "systemctl"].iter().any(|r| low.contains(r));
        if risky {
            med += 1;
        }
        em.find(if risky { Sev::Medium } else { Sev::Info }, "Started a program", p.clone(), if risky { "Started a downloader, shell or script runner" } else { "Started another program" });
    }
    for d in &deleted {
        med += 1;
        em.find(Sev::Medium, "Deleted itself", d.clone(), "Tried to delete its own file (common for droppers)");
    }
    for u in &unix {
        em.find(Sev::Info, "Local socket", u.clone(), "Tried to talk to a local service (not available in the sandbox)");
    }
    (high, med)
}

/// Run a program inside the sandbox for `secs` seconds and record what it tries.
pub fn run_watch(_s: &Settings, sample: &str, dir: &Path, secs: u64, use_wine: bool, em: &mut Emitter) -> Vec<(String, u64)> {
    let name = match copy_sample(sample, &dir.join("work")) {
        Ok(n) => n,
        Err(e) => {
            em.done(e);
            return vec![];
        }
    };
    let path = dir.join("work").join(&name);
    let mut head = [0u8; 4];
    {
        use std::io::Read;
        let _ = std::fs::File::open(&path).and_then(|mut f| f.read_exact(&mut head));
    }
    let mut inner = bwrap_args(dir);
    inner.extend(["/usr/bin/strace".to_string(), "-f".into(), "-qq".into(), "-s".into(), "300".into(), "-xx".into(), "-o".into(), "/out/trace.log".into(), "-e".into(), "trace=connect,sendto,sendmsg,execve,openat,unlink,unlinkat,rename,renameat2".into()]);
    if &head[..2] == b"MZ" {
        match (use_wine, wine_path()) {
            (true, Some(w)) => {
                inner.extend(["/usr/bin/env".into(), "WINEPREFIX=/work/.wine".into(), "WINEDEBUG=-all".into(), "WINEDLLOVERRIDES=winemenubuilder.exe=d".into(), w.to_string(), format!("/work/{name}")]);
                em.log("Windows program: running it with Wine inside the sandbox (no screen, so windows won't show).");
            }
            _ => {
                em.done("This is a Windows program. Turn on \"Use Wine for Windows programs\" (Wine is needed) to run it in the sandbox.");
                return vec![];
            }
        }
    } else if &head == b"\x7fELF" || &head[..2] == b"#!" {
        inner.push(format!("/work/{name}"));
    } else {
        em.done("This isn't a program the sandbox can run (Linux program, script, or Windows program with Wine). Try Unpack instead if it's an archive.");
        return vec![];
    }
    em.progress(format!("Running it in the sandbox for {secs} seconds, with no network…"));
    let started = std::time::Instant::now();
    let code = crate::par::stream_command(limited(secs, inner), em, &|l| vec![crate::jobs::Msg::Log(format!("output: {l}"))], &mut |_, _| {});
    let took = started.elapsed().as_secs();
    em.log(if code == 124 || code == 137 { format!("Stopped after {took}s (time limit).") } else { format!("It exited by itself after {took}s (code {code}).") });
    let trace = std::fs::read_to_string(dir.join("out/trace.log")).unwrap_or_default();
    let (high, med) = analyse(&trace, &name, em);
    // Files it made in the sandbox.
    let work = dir.join("work");
    let dropped: Vec<(String, u64)> = walkdir::WalkDir::new(&work)
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path() != path && !e.path().starts_with(work.join(".wine")))
        .map(|e| (e.path().display().to_string(), e.metadata().map(|m| m.len()).unwrap_or(0)))
        .collect();
    for (p, len) in &dropped {
        em.find(Sev::Medium, "Dropped a file", p.clone(), format!("{} KB written inside the sandbox", len / 1024));
    }
    em.done(format!(
        "Ran for {took}s: {high} serious and {med} suspicious action(s), {} file(s) dropped.{}",
        dropped.len(),
        if high + med == 0 { " Nothing obviously bad — but a quiet run doesn't prove it's safe (some malware waits or checks for sandboxes)." } else { "" }
    ));
    dropped
}

