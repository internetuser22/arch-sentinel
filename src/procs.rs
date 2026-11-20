//! Optional check of every running process: where its program and loaded
//! libraries came from, whether they still match their package, and an
//! optional ClamAV scan of those files.

use crate::jobs::{Emitter, Sev};
use crate::pkg;
use crate::settings::Settings;
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Default)]
struct Use {
    pids: Vec<(i32, String)>,
    is_program: bool,
}

fn who(u: &Use) -> String {
    let mut names: Vec<String> = u.pids.iter().map(|(p, n)| format!("{n} ({p})")).collect();
    names.dedup();
    let more = names.len().saturating_sub(3);
    names.truncate(3);
    if more > 0 {
        format!("{} +{more} more", names.join(", "))
    } else {
        names.join(", ")
    }
}

pub fn scan_processes(s: &Settings, em: &mut Emitter) {
    em.progress("Reading the package database…");
    let db = match pkg::load_owned(true) {
        Ok(d) => d,
        Err(e) => {
            em.done(format!("Couldn't read the package database: {e}"));
            return;
        }
    };
    em.progress("Listing running programs and their libraries…");
    let mut files: BTreeMap<String, Use> = BTreeMap::new();
    let mut procs = 0;
    let mut hidden = 0;
    let me = unsafe { libc::getuid() };
    let root = unsafe { libc::geteuid() } == 0;
    for e in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
        let comm = std::fs::read_to_string(e.path().join("comm")).unwrap_or_default().trim().to_string();
        let Ok(exe) = std::fs::read_link(e.path().join("exe")) else {
            // Kernel threads have no program; other users' processes need administrator rights.
            let status = std::fs::read_to_string(e.path().join("status")).unwrap_or_default();
            let kthread = status.lines().any(|l| l.starts_with("VmSize:")) == false;
            if !kthread {
                hidden += 1;
            }
            continue;
        };
        procs += 1;
        let exe = exe.to_string_lossy().to_string();
        let deleted = exe.ends_with(" (deleted)");
        let exe_clean = exe.trim_end_matches(" (deleted)").to_string();
        if exe.starts_with("/tmp/") || exe.starts_with("/dev/shm/") || exe.starts_with("/var/tmp/") || exe.contains("memfd:") {
            em.find(Sev::High, "Runs from temp/memory", format!("pid {pid} {comm}"), format!("Program: {exe}"));
        } else if deleted {
            let replaced = std::path::Path::new(&exe_clean).exists();
            em.find(
                if replaced { Sev::Low } else { Sev::Medium },
                "Program file gone",
                format!("pid {pid} {comm}"),
                if replaced { format!("{exe_clean} was updated while running — restart it to use the new version") } else { format!("{exe_clean} was deleted while it runs") },
            );
        }
        let u = files.entry(exe_clean).or_default();
        u.is_program = true;
        u.pids.push((pid, comm.clone()));
        // Shared libraries mapped into the process.
        if let Ok(maps) = std::fs::read_to_string(e.path().join("maps")) {
            let mut seen = BTreeSet::new();
            for l in maps.lines() {
                let Some(path) = l.split_whitespace().nth(5) else { continue };
                let base = path.rsplit('/').next().unwrap_or(path);
                let is_lib = base.ends_with(".so")
                    || base.split(".so.").nth(1).map(|r| r.starts_with(|c: char| c.is_ascii_digit())).unwrap_or(false);
                if !path.starts_with('/') || !is_lib {
                    continue;
                }
                if !seen.insert(path.to_string()) {
                    continue;
                }
                if l.ends_with("(deleted)") {
                    let p = path.to_string();
                    if !std::path::Path::new(&p).exists() || !db.files.contains(&p) {
                        em.find(Sev::Low, "Old library in use", format!("pid {pid} {comm}"), format!("{p} was replaced on disk — restart the program"));
                    }
                    continue;
                }
                files.entry(path.to_string()).or_default().pids.push((pid, comm.clone()));
            }
        }
        if procs % 50 == 0 {
            em.progress(format!("Read {procs} processes…"));
            em.wait_if_paused();
        }
        if em.cancelled() {
            return;
        }
    }
    em.log(format!("{procs} processes use {} distinct program and library files.", files.len()));

    // Which packages do these files come from?
    let mut by_pkg: HashMap<String, Vec<String>> = HashMap::new();
    let mut unpackaged: Vec<String> = vec![];
    for (path, u) in &files {
        match db.owner.get(path) {
            Some(p) => by_pkg.entry(p.clone()).or_default().push(path.clone()),
            None => {
                unpackaged.push(path.clone());
                let flatpak = path.starts_with("/var/lib/flatpak") || path.contains("/.local/share/flatpak/");
                let sev = if flatpak {
                    Sev::Info
                } else if u.is_program {
                    if path.starts_with(&s.home) { Sev::Low } else { Sev::Medium }
                } else {
                    Sev::Low
                };
                let what = if u.is_program { "Program" } else { "Library" };
                let why = if flatpak { "comes from a Flatpak, not pacman".to_string() } else { "no package installed it".to_string() };
                em.find(sev, &format!("{what} not from a package"), path.clone(), format!("{why} · used by {}", who(u)));
            }
        }
    }

    // Verify the packaged ones with paccheck in one go.
    if !by_pkg.is_empty() && !em.cancelled() {
        em.progress(format!("Verifying {} packages that running programs come from…", by_pkg.len()));
        let mut pkgs: Vec<&String> = by_pkg.keys().collect();
        pkgs.sort();
        let names: Vec<String> = pkgs.iter().map(|s| s.to_string()).collect();
        {
            let text = crate::par::paccheck_many(&names, &["--sha256sum", "--quiet"], crate::par::threads(s));
            let mut changed = 0;
            for l in text.lines() {
                if !l.contains("checksum") && !l.contains("size") {
                    continue;
                }
                let Some(start) = l.find('\'') else { continue };
                let Some(len) = l[start + 1..].find('\'') else { continue };
                let path = &l[start + 1..start + 1 + len];
                if let Some(u) = files.get(path) {
                    changed += 1;
                    em.find(Sev::High, "Running file was changed", path.to_string(), format!("{} · used by {}", l.trim(), who(u)));
                }
            }
            em.log(format!("{} packages checked, {changed} running files differ from their package.", pkgs.len()));
        }
    }

    // Optional ClamAV scan of the files themselves.
    let targets: Vec<String> = match s.process_clam_scope {
        0 => vec![],
        1 => unpackaged.clone(),
        _ => files.keys().cloned().collect(),
    };
    let mut infected = 0;
    if !targets.is_empty() && !em.cancelled() && std::path::Path::new("/usr/bin/clamscan").exists() {
        em.progress(format!("ClamAV is scanning {} running program files (loading signatures takes a moment)…", targets.len()));
        let weighted: Vec<(String, u64)> = targets.iter().map(|t| (t.clone(), std::fs::metadata(t).map(|m| m.len()).unwrap_or(1))).collect();
        let before = em.findings().len();
        let (_, found) = crate::clam::scan_files_parallel(s, vec![], weighted, false, em);
        let found: Vec<crate::jobs::Finding> = found.into_iter().skip(0).collect();
        infected = em.findings().len().saturating_sub(before).min(found.len());
        if !found.is_empty() && s.vt_check && !s.vt_api_key.is_empty() {
            crate::clam::verify_findings(&s.vt_api_key, &found, em);
        }
    }
    if s.paranoid && !em.cancelled() {
        let progs: Vec<String> = unpackaged.iter().filter(|p| files.get(*p).map(|u| u.is_program).unwrap_or(false)).cloned().collect();
        let serious = crate::paranoid::inspect_files(progs, crate::par::threads(s), em);
        if !serious.is_empty() && s.vt_check && !s.vt_api_key.is_empty() {
            crate::clam::verify_findings(&s.vt_api_key, &serious, em);
        }
    }
    let note = if !root && hidden > 0 { format!(" {hidden} processes belong to other users — run as administrator to include them.") } else { String::new() };
    let _ = me;
    em.done(format!(
        "Checked {procs} running processes and {} files: {} not from a package{}.{note}",
        files.len(),
        unpackaged.len(),
        if targets.is_empty() { String::new() } else { format!(", ClamAV flagged {infected}") }
    ));
}
