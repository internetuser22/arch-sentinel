//! Built-in rootkit checks (in the spirit of rkhunter), plus running
//! rkhunter and unhide when they're installed.

use crate::jobs::{Emitter, Sev};
use crate::pkg;
use std::collections::HashSet;
use std::path::Path;

const CORE_PACKAGES: &[&str] = &[
    "coreutils", "procps-ng", "util-linux", "shadow", "openssh", "iproute2", "findutils",
    "systemd", "sudo", "pam", "bash", "grep", "glibc", "psmisc", "net-tools", "kmod", "inetutils",
];

const KNOWN_ROOTKIT_PATHS: &[(&str, &str)] = &[
    ("/reptile", "Reptile"),
    ("/lib/udev/reptile", "Reptile"),
    ("/usr/lib/udev/reptile", "Reptile"),
    ("/XxJynx", "Jynx"),
    ("/etc/rc.d/rsha", "RSHA"),
    ("/usr/sbin/xntps", "Suckit / xntps"),
    ("/dev/.lib", "generic"),
    ("/usr/bin/.sshd", "hidden sshd"),
    ("/usr/lib/.sshd", "hidden sshd"),
    ("/dev/.hdlc", "generic"),
    ("/usr/share/.aPa", "Ambient"),
    ("/usr/lib/libsh", "SHV4/SHV5"),
    ("/lib/libsh.so", "SHV4/SHV5"),
    ("/usr/include/hosts.h", "Ramen / t0rn"),
    ("/usr/src/.puta", "t0rn"),
    ("/etc/ld.so.hash", "generic"),
    ("/usr/lib/libkeyutils.so.1.9", "Ebury"),
    ("/lib64/libkeyutils.so.1.9", "Ebury"),
    ("/usr/lib/libns2.so", "Ebury"),
    ("/var/run/.tmp", "generic"),
    ("/usr/bin/bsd-port", "Suckit"),
];

pub fn run_builtin(em: &mut Emitter, threads: usize) {
    let mut checks = 0;
    let mut problems = 0usize;

    // 1. Preload hijacking.
    checks += 1;
    em.progress("Checking for forced library preloading…");
    match std::fs::read_to_string("/etc/ld.so.preload") {
        Ok(t) if !t.trim().is_empty() => {
            problems += 1;
            em.find(Sev::High, "Preload", "/etc/ld.so.preload", format!("Forces libraries into every program: {}", t.trim().replace('\n', ", ")));
        }
        Ok(_) => em.log("/etc/ld.so.preload exists but is empty."),
        Err(_) => em.log("OK: no /etc/ld.so.preload."),
    }
    if let Ok(v) = std::env::var("LD_PRELOAD") {
        problems += 1;
        em.find(Sev::Medium, "Preload", "LD_PRELOAD", format!("Set in this session: {v}"));
    }

    em.wait_if_paused();
    // 2. Hidden processes.
    checks += 1;
    em.progress("Looking for hidden processes…");
    problems += hidden_processes(em, threads);

    // 3. Hidden kernel modules.
    checks += 1;
    em.progress("Comparing loaded kernel modules…");
    problems += hidden_modules(em);

    // 4. Kernel taint.
    checks += 1;
    if let Ok(t) = std::fs::read_to_string("/proc/sys/kernel/tainted") {
        let v: u64 = t.trim().parse().unwrap_or(0);
        if v != 0 {
            let mut why = vec![];
            if v & (1 << 0) != 0 { why.push("proprietary module"); }
            if v & (1 << 1) != 0 { why.push("module force-loaded"); }
            if v & (1 << 12) != 0 { why.push("out-of-tree module"); }
            if v & (1 << 13) != 0 { why.push("unsigned module"); }
            if v & (1 << 7) != 0 { why.push("kernel died before"); }
            let sev = if v & ((1 << 1) | (1 << 13)) != 0 { Sev::Medium } else { Sev::Info };
            em.find(sev, "Kernel", "/proc/sys/kernel/tainted", format!("Kernel taint {v}: {}", why.join(", ")));
        } else {
            em.log("OK: kernel isn't tainted.");
        }
    }

    em.wait_if_paused();
    // 5. Known rootkit files.
    checks += 1;
    em.progress("Looking for known rootkit files…");
    for (p, name) in KNOWN_ROOTKIT_PATHS {
        if Path::new(p).symlink_metadata().is_ok() {
            problems += 1;
            em.find(Sev::High, "Known rootkit file", *p, format!("Name used by {name}"));
        }
    }

    // 6. Regular files hiding in /dev.
    checks += 1;
    em.progress("Looking for files hiding in /dev…");
    for e in walkdir::WalkDir::new("/dev").follow_links(false).into_iter().filter_entry(|e| {
        let p = e.path().to_string_lossy();
        !(p.starts_with("/dev/shm") || p.starts_with("/dev/mqueue") || p.starts_with("/dev/hugepages") || p.starts_with("/dev/.lxd"))
    }).flatten()
    {
        if e.file_type().is_file() {
            let p = e.path().display().to_string();
            problems += 1;
            em.find(Sev::Medium, "File in /dev", p, "Ordinary file where only devices belong");
        }
    }

    // 7. Processes running from odd places or deleted programs.
    checks += 1;
    em.progress("Checking where running programs came from…");
    problems += process_origins(em);

    // 8. Network cards listening to all traffic.
    checks += 1;
    if let Ok(rd) = std::fs::read_dir("/sys/class/net") {
        for e in rd.flatten() {
            let flags = std::fs::read_to_string(e.path().join("flags")).unwrap_or_default();
            let v = u64::from_str_radix(flags.trim().trim_start_matches("0x"), 16).unwrap_or(0);
            if v & 0x100 != 0 {
                problems += 1;
                em.find(Sev::Medium, "Network", e.file_name().to_string_lossy().to_string(), "Network card is in promiscuous mode (sniffing all traffic)");
            }
        }
    }

    em.wait_if_paused();
    // 9. Raised-rights files that no package installed.
    checks += 1;
    em.progress("Reading the package database…");
    if let Ok(db) = pkg::load_owned(false) {
        em.progress("Looking for setuid files no package installed…");
        problems += pkg::unowned_suid(&db, threads, em);
    }

    // 10. Account database.
    checks += 1;
    problems += accounts(em);

    em.wait_if_paused();
    // 11. Core system tools against package checksums.
    checks += 1;
    em.progress("Verifying core system tools with paccheck…");
    let installed: Vec<&str> = CORE_PACKAGES
        .iter()
        .copied()
        .filter(|p| std::process::Command::new("pacman").args(["-Q", p]).output().map(|o| o.status.success()).unwrap_or(false))
        .collect();
    {
        let names: Vec<String> = installed.iter().map(|s| s.to_string()).collect();
        let text = crate::par::paccheck_many(&names, &["--sha256sum", "--file-properties", "--quiet"], threads);
        for l in text.lines() {
            for m in pkg::parse_paccheck(l) {
                if let crate::jobs::Msg::Find(mut f) = m {
                    if f.detail.to_lowercase().contains("checksum") && f.path.contains("/bin/") {
                        f.sev = Sev::High;
                        f.detail = format!("Core tool changed: {}", f.detail);
                    }
                    if f.sev != Sev::Info && f.sev != Sev::Low {
                        problems += 1;
                    }
                    em.emit(crate::jobs::Msg::Find(f));
                }
            }
        }
        em.log(format!("Verified {} core packages.", installed.len()));
    }

    let elevated = unsafe { libc::geteuid() } == 0;
    em.done(format!(
        "{checks} checks done, {problems} need a look.{}",
        if elevated { "" } else { " Run as administrator to see every process and file." }
    ));
}

fn proc_pids() -> HashSet<i32> {
    std::fs::read_dir("/proc")
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| e.file_name().to_string_lossy().parse::<i32>().ok())
                .collect()
        })
        .unwrap_or_default()
}

fn hidden_processes(em: &mut Emitter, threads: usize) -> usize {
    let pid_max: i32 = std::fs::read_to_string("/proc/sys/kernel/pid_max")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(32768)
        .min(4_194_304);
    let listed = proc_pids();
    em.progress(format!("Looking for hidden processes among {pid_max} ids with {threads} thread(s)…"));
    let cancel = em.cancel_flag();
    let chunk = (pid_max as usize / threads.max(1)).max(1) as i32;
    let suspects: Vec<i32> = std::thread::scope(|scope| {
        let mut hs = vec![];
        let mut start = 1;
        while start <= pid_max {
            let end = (start + chunk - 1).min(pid_max);
            let listed = &listed;
            let cancel = cancel.clone();
            hs.push(scope.spawn(move || {
                crate::par::lowest_priority_thread();
                let mut out = vec![];
                for pid in start..=end {
                    if pid % 65536 == 0 {
                        cancel.wait_if_paused();
                        if cancel.cancelled() {
                            break;
                        }
                    }
                    if listed.contains(&pid) {
                        continue;
                    }
                    let r = unsafe { libc::kill(pid, 0) };
                    if r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) {
                        out.push(pid);
                    }
                }
                out
            }));
            start = end + 1;
        }
        hs.into_iter().flat_map(|h| h.join().unwrap_or_default()).collect()
    });
    if em.cancelled() {
        return 0;
    }
    let now = proc_pids();
    let mut n = 0;
    for pid in suspects {
        if now.contains(&pid) {
            continue; // started while we were looking
        }
        // Threads answer kill() but aren't listed; their status names another Tgid.
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
        let tgid = status
            .lines()
            .find(|l| l.starts_with("Tgid:"))
            .and_then(|l| l[5..].trim().parse::<i32>().ok());
        match tgid {
            Some(t) if t != pid => continue,
            Some(_) => {
                let name = status.lines().next().unwrap_or("").replace("Name:\t", "");
                n += 1;
                em.find(Sev::High, "Hidden process", format!("pid {pid}"), format!("Running but missing from the process list ({name})"));
            }
            None => {
                // Gone already, or truly invisible.
                if unsafe { libc::kill(pid, 0) } == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) {
                    n += 1;
                    em.find(Sev::High, "Hidden process", format!("pid {pid}"), "Answers signals but /proc shows nothing for it");
                }
            }
        }
    }
    if n == 0 {
        em.log(format!("OK: no hidden processes among {pid_max} process ids."));
    }
    n
}

fn hidden_modules(em: &mut Emitter) -> usize {
    let listed: HashSet<String> = std::fs::read_to_string("/proc/modules")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_whitespace().next().map(|s| s.to_string()))
        .collect();
    let mut n = 0;
    if let Ok(rd) = std::fs::read_dir("/sys/module") {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            // Loadable modules have an initstate file; built-ins don't.
            let Ok(state) = std::fs::read_to_string(e.path().join("initstate")) else { continue };
            if state.trim() == "live" && !listed.contains(&name) {
                n += 1;
                em.find(Sev::High, "Hidden kernel module", name, "Loaded in /sys/module but hidden from /proc/modules");
            }
        }
    }
    if n == 0 {
        em.log(format!("OK: {} loaded kernel modules, none hidden.", listed.len()));
    }
    n
}

fn process_origins(em: &mut Emitter) -> usize {
    let mut n = 0;
    let mut unreadable = 0;
    for pid in proc_pids() {
        let exe = match std::fs::read_link(format!("/proc/{pid}/exe")) {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => {
                unreadable += 1;
                continue;
            }
        };
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default().trim().to_string();
        let tmp = ["/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/"];
        if tmp.iter().any(|t| exe.starts_with(t)) {
            n += 1;
            em.find(Sev::High, "Program from temp folder", format!("pid {pid} {comm}"), format!("Runs {exe}"));
        } else if exe.ends_with(" (deleted)") {
            let real = exe.trim_end_matches(" (deleted)");
            let updated = Path::new(real).exists();
            let (sev, why) = if updated {
                (Sev::Low, "program file was replaced (probably an update — restart it)")
            } else {
                (Sev::Medium, "program file was deleted while it runs")
            };
            n += 1;
            em.find(sev, "Deleted program running", format!("pid {pid} {comm}"), format!("{real}: {why}"));
        } else if exe.starts_with("memfd:") || exe.contains("/memfd:") {
            n += 1;
            em.find(Sev::High, "Program in memory only", format!("pid {pid} {comm}"), format!("Runs from {exe}"));
        }
    }
    if unreadable > 0 {
        em.log(format!("{unreadable} processes belong to other users (run as administrator to check them)."));
    }
    n
}

fn accounts(em: &mut Emitter) -> usize {
    let mut n = 0;
    for l in std::fs::read_to_string("/etc/passwd").unwrap_or_default().lines() {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() < 7 {
            continue;
        }
        if f[2] == "0" && f[0] != "root" {
            n += 1;
            em.find(Sev::High, "Account", format!("user {}", f[0]), "Has administrator id 0 besides root");
        }
        if f[1].is_empty() {
            n += 1;
            em.find(Sev::High, "Account", format!("user {}", f[0]), "No password field at all in /etc/passwd");
        }
    }
    if let Ok(t) = std::fs::read_to_string("/etc/shadow") {
        for l in t.lines() {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() > 1 && f[1].is_empty() {
                n += 1;
                em.find(Sev::High, "Account", format!("user {}", f[0]), "Can log in with an empty password");
            }
        }
    }
    n
}

pub fn external_tools() -> Vec<(&'static str, bool)> {
    ["rkhunter", "unhide"]
        .iter()
        .map(|t| (*t, Path::new(&format!("/usr/bin/{t}")).exists()))
        .collect()
}

/// Parse rkhunter/unhide lines into findings.
pub fn parse_external(line: &str) -> Vec<crate::jobs::Msg> {
    use crate::jobs::{Finding, Msg};
    let l = line.trim();
    if l.is_empty() {
        return vec![];
    }
    let low = l.to_lowercase();
    if low.contains("[ warning ]") || low.contains("warning:") || low.contains("infected") && !low.contains("not infected") || low.contains("found hidden") {
        return vec![Msg::Find(Finding { sev: Sev::Medium, kind: "External tool".into(), path: l.split(" [").next().unwrap_or(l).trim().into(), detail: l.into() })];
    }
    vec![Msg::Log(l.into())]
}
