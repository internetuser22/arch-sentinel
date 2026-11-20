//! ClamAV scanning, signature updates with freshclam on a timer (never as a
//! daemon), and VirusTotal second opinions for anything ClamAV flags.

use crate::jobs::{Emitter, Finding, Msg, Sev};
use crate::settings::Settings;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::process::Command;

/// One clamscan output line -> messages.
pub fn parse_clamscan(line: &str) -> Vec<Msg> {
    let l = line.trim_end();
    if let Some(rest) = l.strip_suffix(" FOUND") {
        if let Some((path, name)) = rest.rsplit_once(": ") {
            if name.contains("Limits.Exceeded") {
                return vec![Msg::Find(Finding {
                    sev: Sev::Low,
                    kind: name.to_string(),
                    path: path.to_string(),
                    detail: "Not fully scanned: ClamAV stopped at a size or depth limit".to_string(),
                })];
            }
            let (sev, what) = if name.starts_with("PUA.") {
                (Sev::Medium, "possibly unwanted program")
            } else if name.starts_with("Heuristics.") {
                (Sev::Medium, "heuristic guess")
            } else {
                (Sev::High, "virus signature")
            };
            let win = if crate::drives::is_windows_program(path) {
                " · Windows program: can't run on Linux by itself, but can through Wine or on a Windows PC"
            } else {
                ""
            };
            return vec![Msg::Find(Finding {
                sev,
                kind: name.to_string(),
                path: path.to_string(),
                detail: format!("ClamAV match ({what}) — not yet checked on VirusTotal{win}"),
            })];
        }
    }
    if l.ends_with(": OK") || l.ends_with(": Empty file") || l.ends_with(": Symbolic link") || l.ends_with(": Excluded") {
        let p = l.rsplit_once(": ").map(|x| x.0).unwrap_or(l);
        return vec![Msg::Progress(format!("Scanning… {p}"))];
    }
    if l.contains(" moved to ") {
        return vec![Msg::Log(format!("Quarantined: {l}"))];
    }
    if l.contains("ERROR") || l.contains("WARNING") {
        return vec![Msg::Log(l.to_string())];
    }
    if l.is_empty() {
        return vec![];
    }
    vec![Msg::Log(l.to_string())]
}

/// "ClamAV 1.5.4/28181/Thu Nov 12 00:27:14 2026" -> (engine, db version, db date)
pub fn version() -> Option<(String, String, String)> {
    let out = Command::new("/usr/bin/clamscan").arg("--version").output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let mut parts = s.splitn(3, '/');
    let engine = parts.next()?.trim_start_matches("ClamAV ").to_string();
    let db = parts.next().unwrap_or("?").to_string();
    let date = parts.next().unwrap_or("?").to_string();
    Some((engine, db, date))
}

pub fn sha256_file(path: &str) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

#[derive(Clone, Debug)]
pub enum VtVerdict {
    Report(crate::vt::VtReport),
    Unknown,
    Error(String),
}

impl VtVerdict {
    pub fn describe(&self) -> (Sev, String) {
        match self {
            VtVerdict::Report(r) => {
                let (_, sev, headline, _) = crate::vt::assess(r);
                (sev, headline)
            }
            VtVerdict::Unknown => (Sev::Medium, "VirusTotal has never seen this file (no second opinion)".to_string()),
            VtVerdict::Error(e) => (Sev::High, format!("VirusTotal lookup failed: {e}")),
        }
    }
}

/// Look up a file's SHA-256 on VirusTotal (only the fingerprint is sent, never the file).
pub fn virustotal_lookup(api_key: &str, sha256: &str) -> VtVerdict {
    match crate::vt::fetch(api_key, sha256) {
        Ok(Some(r)) => VtVerdict::Report(r),
        Ok(None) => VtVerdict::Unknown,
        Err(e) => VtVerdict::Error(e),
    }
}

/// Check each finding on VirusTotal, pacing requests for the free tier (4 a minute).
pub fn verify_findings(api_key: &str, findings: &[Finding], em: &mut Emitter) {
    let items: Vec<(Finding, Option<String>)> = findings.iter().map(|f| (f.clone(), None)).collect();
    verify_list(api_key, &items, em);
    em.done(format!("Checked {} file(s) on VirusTotal.", findings.len()));
}

/// The fingerprint written into a finding's detail ("… sha256 <hex>"), if any.
pub fn sha_in(detail: &str) -> Option<String> {
    detail.split("sha256 ").nth(1).map(|x| x.trim().trim_end_matches('…').to_string()).filter(|x| x.len() == 64 && x.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Did this finding's VirusTotal check fail (and so is worth trying again)?
pub fn vt_failed(f: &Finding) -> bool {
    f.detail.contains("VirusTotal lookup failed") || f.detail.starts_with("Couldn't read file to fingerprint it")
}

/// Look up files on VirusTotal one by one. A file's fingerprint can be given (for
/// files no longer where they were); otherwise it's worked out from the file. When
/// VirusTotal's free-tier limit is hit, wait a minute and try again (up to 3 times).
pub fn verify_list(api_key: &str, items: &[(Finding, Option<String>)], em: &mut Emitter) {
    let wait = |secs: u64, why: &str, em: &mut Emitter| -> bool {
        for s in (1..=secs).rev() {
            em.progress(format!("{why} {s}s…"));
            std::thread::sleep(std::time::Duration::from_secs(1));
            em.wait_if_paused();
            if em.cancelled() {
                return false;
            }
        }
        true
    };
    for (i, (f, sha)) in items.iter().enumerate() {
        em.wait_if_paused();
        if em.cancelled() {
            break;
        }
        if i > 0 && !wait(15, "Waiting for VirusTotal's rate limit:", em) {
            return;
        }
        em.progress(format!("Asking VirusTotal about {} ({} of {})", f.path, i + 1, items.len()));
        let hash = match sha.clone().map(Ok).unwrap_or_else(|| sha256_file(&f.path)) {
            Ok(h) => h,
            Err(e) => {
                em.find(Sev::Medium, &f.kind, &f.path, format!("Couldn't read file to fingerprint it: {e}"));
                continue;
            }
        };
        let mut verdict = virustotal_lookup(api_key, &hash);
        let mut tries = 0;
        while matches!(&verdict, VtVerdict::Error(e) if e.contains("rate limit")) && tries < 3 {
            tries += 1;
            if !wait(60, &format!("VirusTotal's limit was reached; trying again ({tries} of 3) in"), em) {
                return;
            }
            verdict = virustotal_lookup(api_key, &hash);
        }
        let (sev, text) = verdict.describe();
        em.log(format!("{} sha256 {hash}: {text}", f.path));
        em.find(sev, &f.kind, &f.path, format!("{text} · sha256 {hash}"));
    }
}

// ---------- freshclam on a timer ----------

pub const TIMER_NAME: &str = "arch-sentinel-freshclam";

pub fn freshclam_units(s: &Settings) -> (String, String) {
    let bg = &s.bg_signatures;
    let mut service = String::from(
        "[Unit]\nDescription=Arch Sentinel: update ClamAV virus signatures\nWants=network-online.target\nAfter=network-online.target\n",
    );
    if bg.only_on_ac {
        service.push_str("ConditionACPower=true\n");
    }
    service.push_str("\n[Service]\nType=oneshot\nExecStart=/usr/bin/freshclam --stdout --no-warnings\n");
    service.push_str("Nice=19\nIOSchedulingClass=idle\n");
    if bg.cpu_limit > 0 {
        service.push_str(&format!("CPUQuota={}%\n", bg.cpu_limit as usize * crate::par::ncpu()));
    }
    let timer = format!(
        "[Unit]\nDescription=Arch Sentinel: run freshclam {}\n\n[Timer]\nOnCalendar={}\nRandomizedDelaySec={}min\nPersistent={}\nOnBootSec=5min\n\n[Install]\nWantedBy=timers.target\n",
        bg.schedule.label().to_lowercase(),
        bg.schedule.on_calendar(),
        bg.random_delay_min,
        if bg.catch_up { "true" } else { "false" },
    );
    (service, timer)
}

pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Shell script (run once through pkexec) that installs the freshclam timer,
/// and optionally turns off the freshclam daemon.
pub fn install_timer_script(s: &Settings, enable: bool) -> std::io::Result<String> {
    let (service, timer) = freshclam_units(s);
    let dir = std::env::temp_dir().join(format!("arch-sentinel-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let sp = dir.join(format!("{TIMER_NAME}.service"));
    let tp = dir.join(format!("{TIMER_NAME}.timer"));
    std::fs::write(&sp, service)?;
    std::fs::write(&tp, timer)?;
    let mut sh = String::from("set -e\n");
    if enable {
        sh.push_str(&format!(
            "install -m 0644 {} /etc/systemd/system/{TIMER_NAME}.service\ninstall -m 0644 {} /etc/systemd/system/{TIMER_NAME}.timer\nsystemctl daemon-reload\nsystemctl enable --now {TIMER_NAME}.timer\n",
            shell_quote(&sp.to_string_lossy()),
            shell_quote(&tp.to_string_lossy())
        ));
        if s.stop_freshclam_daemon {
            sh.push_str("systemctl disable --now clamav-freshclam.service 2>/dev/null || true\nsystemctl disable --now clamav-freshclam-once.timer 2>/dev/null || true\n");
        }
    } else {
        sh.push_str(&format!(
            "systemctl disable --now {TIMER_NAME}.timer 2>/dev/null || true\nrm -f /etc/systemd/system/{TIMER_NAME}.service /etc/systemd/system/{TIMER_NAME}.timer\nsystemctl daemon-reload\n"
        ));
    }
    sh.push_str("echo 'Done.'\n");
    Ok(sh)
}

/// The files under the scan folders (skipping excluded folders and files
/// bigger than the limit), found with several threads. Folders we can't read
/// are returned as folders so an administrator scan still covers them.
pub fn collect_files(s: &Settings, targets: &[String], em: &mut Emitter) -> Vec<(String, u64)> {
    let threads = crate::par::threads(s);
    let max = s.max_file_mb as u64 * 1_048_576;
    let visit = |e: &walkdir::DirEntry, tx: &std::sync::mpsc::Sender<crate::par::WalkOut<(String, u64)>>| -> bool {
        let p = e.path().to_string_lossy();
        if s.virus_excluded.iter().any(|x| p.starts_with(x.as_str())) {
            return true;
        }
        if e.file_type().is_file() {
            let len = e.metadata().map(|m| m.len()).unwrap_or(0);
            if len > 0 && (len <= max || s.clam.alert_exceeds_max) {
                let _ = tx.send(crate::par::WalkOut::Item((p.to_string(), len)));
            }
        }
        false
    };
    let mut files = vec![];
    // Files given directly (not folders) are scanned as they are.
    let mut roots = vec![];
    for t in targets {
        if std::path::Path::new(t).is_dir() {
            roots.push(t.clone());
        } else {
            files.push((t.clone(), std::fs::metadata(t).map(|m| m.len()).unwrap_or(1)));
        }
    }
    let cancel = em.cancel_flag();
    crate::par::par_walk(&roots, threads, cancel, &visit, &mut |out| match out {
        crate::par::WalkOut::Item(f) => {
            files.push(f);
            if files.len() % 5000 == 0 {
                em.progress(format!("Listing files to scan… {}", files.len()));
            }
        }
        crate::par::WalkOut::Unreadable(p) => {
            if !p.is_empty() {
                files.push((p, 1_000_000));
            }
        }
        crate::par::WalkOut::Checked(..) => {}
    });
    files
}

/// Scan files with several ClamAV processes side by side. Each process loads
/// the signatures itself (about 1 GiB of memory), so the number of processes
/// is also limited by free memory.
pub fn scan_files_parallel(s: &Settings, first: Vec<(String, u64)>, files: Vec<(String, u64)>, admin: bool, em: &mut Emitter) -> (i32, Vec<Finding>) {
    let first_set: std::collections::HashSet<String> = first.iter().map(|f| f.0.clone()).collect();
    let files: Vec<(String, u64)> = files.into_iter().filter(|f| !first_set.contains(&f.0)).collect();
    let first_total = first.len();
    let total = first_total + files.len();
    if total == 0 {
        return (0, vec![]);
    }
    let by_mem = ((crate::par::mem_available_gib() - 0.5) / 1.1).floor().max(1.0) as usize;
    let mut threads = crate::par::threads(s).min(by_mem);
    if total < 500 {
        threads = 1;
    }
    if threads < crate::par::threads(s) {
        em.log(format!("Using {threads} ClamAV process(es): each needs about 1 GiB of memory."));
    }
    // Every process gets its share of the priority files at the top of its
    // list, so all of them are scanned before anything else.
    let mut groups: Vec<Vec<String>> = vec![vec![]; threads.max(1)];
    for (i, g) in crate::par::split_balanced(first, threads).into_iter().enumerate() {
        groups[i].extend(g);
    }
    let mut rest = crate::par::split_balanced(files, threads);
    rest.sort_by_key(|g| g.len());
    // Give the most remaining work to the processes with the fewest priority files.
    let mut order: Vec<usize> = (0..groups.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(groups[i].len()));
    for (g, i) in rest.into_iter().zip(order) {
        groups[i].extend(g);
    }
    let groups: Vec<Vec<String>> = groups.into_iter().filter(|g| !g.is_empty()).collect();
    let dir = std::env::temp_dir().join(format!("arch-sentinel-scan-{}-{}", std::process::id(), total));
    let _ = std::fs::create_dir_all(&dir);
    let mut cmds = vec![];
    for (i, g) in groups.iter().enumerate() {
        let list = dir.join(format!("list-{i}.txt"));
        if std::fs::write(&list, g.join("\n")).is_err() {
            continue;
        }
        cmds.push(vec![
            "/usr/bin/clamscan".to_string(),
            "-r".into(),
            "--stdout".into(),
            "--no-summary".into(),
        ]);
        let c = cmds.last_mut().unwrap();
        c.extend(s.clam.flags(s.max_file_mb));
        c.push(format!("--file-list={}", list.display()));
    }
    let n = cmds.len();
    em.progress(format!("Loading virus signatures in {n} ClamAV process(es)…"));
    let script = crate::par::parallel_script(&cmds);
    let cmd = crate::par::command(s, admin, "/bin/sh", &["-c".to_string(), script]);
    let mut done = 0usize;
    let mut first_done = 0usize;
    let code = crate::par::stream_command(cmd, em, &parse_clamscan, &mut |line, em| {
        if line.ends_with(": OK") || line.ends_with(" FOUND") || line.ends_with(": Empty file") || line.ends_with(": Excluded") {
            done += 1;
            if first_total > 0 && first_done < first_total {
                if let Some((p, _)) = line.rsplit_once(": ") {
                    if first_set.contains(p) {
                        first_done += 1;
                    }
                }
            }
            if done % 200 == 0 || done == total || (first_done > 0 && first_done == first_total && done % 20 == 0) {
                let phase = if first_total > 0 && first_done < first_total {
                    format!("system files first: {first_done} of {first_total}")
                } else if first_total > 0 {
                    format!("system files done ({first_total}), now the rest")
                } else {
                    String::new()
                };
                em.progress(format!(
                    "Scanned {done} of {total} files ({}%) with {n} ClamAV process(es){}…",
                    done * 100 / total,
                    if phase.is_empty() { String::new() } else { format!(" — {phase}") }
                ));
            }
        }
    });
    if first_total > 0 {
        em.log(format!("Scanned {first_total} unverified system files first."));
    }
    let _ = std::fs::remove_dir_all(&dir);
    let found: Vec<Finding> = em.findings().into_iter().filter(|f| f.detail.starts_with("ClamAV match")).collect();
    (code, found)
}

/// The whole virus scan: list files, scan them in parallel, report. Files under
/// `first` are scanned before anything under `targets`.
pub fn scan_parallel(s: &Settings, first: &[String], targets: &[String], admin: bool, em: &mut Emitter) -> Vec<Finding> {
    em.progress("Listing files to scan…");
    let first_files = if first.is_empty() { vec![] } else { collect_files(s, first, em) };
    let files = if targets.is_empty() { vec![] } else { collect_files(s, targets, em) };
    if em.cancelled() {
        em.done("Stopped.");
        return vec![];
    }
    let total = first_files.len() + files.len();
    let n_first = first_files.len();
    let paths: Vec<String> = if s.paranoid { first_files.iter().chain(files.iter()).map(|f| f.0.clone()).collect() } else { vec![] };
    let (code, mut found) = scan_files_parallel(s, first_files, files, admin, em);
    let mut paranoid_note = String::new();
    if s.paranoid && !em.cancelled() {
        let serious = crate::paranoid::inspect_files(paths, crate::par::threads(s), em);
        let odd = em.findings().iter().filter(|f| f.kind == "Paranoid check").count();
        paranoid_note = format!(" Paranoid check: {odd} program file(s) look odd.");
        found.extend(serious);
    }
    let what = if n_first > 0 && total > n_first {
        format!("{total} files ({n_first} unverified system files first)")
    } else if n_first > 0 {
        format!("{n_first} unverified system files")
    } else {
        format!("{total} files")
    };
    em.done(match code {
        _ if em.cancelled() => "Stopped.".to_string(),
        126 | 127 if admin => "Administrator rights were refused.".to_string(),
        _ if total == 0 => "Nothing to scan: run the Unowned files and Package files checks first, or pick another option under What to scan.".to_string(),
        _ if found.iter().all(|f| f.kind == "Paranoid check") => format!("No viruses found in {what}.{paranoid_note}"),
        _ => format!("{} of {what} flagged by ClamAV.{paranoid_note}", found.iter().filter(|f| f.kind != "Paranoid check").count()),
    });
    found
}

/// Paths flagged by the unowned-files or package-files checks that still
/// exist: worth a virus scan of their own.
pub fn unverified_paths(findings: &[Finding]) -> Vec<String> {
    let mut v: Vec<String> = findings
        .iter()
        // Read errors and missing files have nothing to scan.
        .filter(|f| f.path.starts_with('/') && f.sev != Sev::Info && !f.detail.contains("missing"))
        .filter(|f| {
            let p = std::path::Path::new(&f.path);
            let Ok(m) = std::fs::symlink_metadata(p) else { return false };
            if m.file_type().is_symlink() {
                return false;
            }
            if f.kind == "Unowned" {
                // A folder no package owns: everything inside is unowned too.
                m.is_file() || m.is_dir()
            } else {
                // A package file that failed the check: just that file, never
                // the whole folder (a folder's permission note isn't a file to scan).
                m.is_file()
            }
        })
        .map(|f| f.path.clone())
        .collect();
    v.sort();
    v.dedup();
    v
}

// ---------- right-click scans: ask before skipping big files ----------

/// ClamAV can't scan single files of 2 GiB or more.
pub const CLAM_MAX_MB: u32 = 2047;

#[derive(Clone, Debug, PartialEq)]
pub enum AskKind {
    /// Files bigger than the size limit were found before scanning.
    TooBig,
    /// Files where ClamAV stopped at a limit while scanning.
    HitLimit,
}

#[derive(Clone, Debug)]
pub struct SizeAsk {
    pub kind: AskKind,
    /// (path, bytes)
    pub files: Vec<(String, u64)>,
    /// Suggested temporary limit in MB.
    pub suggested_mb: u32,
    /// Files too big for ClamAV at any limit.
    pub too_big_for_clamav: Vec<(String, u64)>,
}

#[derive(Default)]
pub struct AskState {
    pub question: Option<SizeAsk>,
    /// Some(Some(mb)): go ahead with this limit; Some(None): skip them.
    pub answer: Option<Option<u32>>,
    /// Also look up the files ClamAV can't scan on VirusTotal.
    pub vt_for_huge: bool,
}

pub type AskSlot = std::sync::Arc<std::sync::Mutex<AskState>>;

fn mb(b: u64) -> u32 {
    ((b + 1_048_575) / 1_048_576) as u32
}

/// Ask the person in the window and wait for the answer (None when stopped).
fn ask(em: &mut Emitter, slot: &AskSlot, q: SizeAsk, title: &str) -> Option<(Option<u32>, bool)> {
    {
        let mut st = slot.lock().unwrap();
        st.question = Some(q);
        st.answer = None;
        st.vt_for_huge = true;
    }
    em.progress("Waiting for your answer…");
    em.repaint_now();
    let _ = std::process::Command::new("notify-send")
        .args(["-a", "Arch Sentinel", "-i", "security-medium", title, "Open Arch Sentinel to choose what to do."])
        .spawn();
    loop {
        if em.cancelled() {
            slot.lock().unwrap().question = None;
            return None;
        }
        {
            let mut st = slot.lock().unwrap();
            if let Some(a) = st.answer.take() {
                st.question = None;
                return Some((a, st.vt_for_huge));
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// A scan of files and folders picked in the file manager. Files over the size
/// limit aren't skipped silently: the person is asked whether to raise the limit
/// for this scan, and files ClamAV stopped short on can be rescanned with
/// higher limits.
pub fn scan_custom(s: &Settings, targets: &[String], admin: bool, em: &mut Emitter, slot: &AskSlot) -> Vec<Finding> {
    em.progress("Listing files to scan…");
    let mut s2 = s.clone();
    s2.clam.alert_exceeds_max = true; // report anything ClamAV couldn't finish
    let all = collect_files(&s2, targets, em);
    if em.cancelled() {
        em.done("Stopped.");
        return vec![];
    }
    let limit = s.max_file_mb as u64 * 1_048_576;
    let clam_max = CLAM_MAX_MB as u64 * 1_048_576;
    let (mut files, big): (Vec<_>, Vec<_>) = all.into_iter().partition(|f| f.1 <= limit);
    let (big_ok, huge): (Vec<_>, Vec<_>) = big.into_iter().partition(|f| f.1 <= clam_max);
    if !big_ok.is_empty() || !huge.is_empty() {
        let largest = big_ok.iter().map(|f| f.1).max().unwrap_or(0);
        let q = SizeAsk {
            kind: AskKind::TooBig,
            files: big_ok.clone(),
            suggested_mb: (mb(largest) + mb(largest) / 10 + 1).clamp(s.max_file_mb, CLAM_MAX_MB),
            too_big_for_clamav: huge.clone(),
        };
        let n = big_ok.len() + huge.len();
        match ask(em, slot, q, &format!("{n} file(s) are over the {} MB scan limit", s.max_file_mb)) {
            None => {
                em.done("Stopped.");
                return vec![];
            }
            Some((answer, vt_huge)) => {
                if let Some(l) = answer {
                    s2.max_file_mb = l.min(CLAM_MAX_MB);
                    s2.clam.max_scan_mb = s2.clam.max_scan_mb.max(s2.max_file_mb);
                    let lim = s2.max_file_mb as u64 * 1_048_576;
                    let mut skipped = 0;
                    for f in big_ok {
                        if f.1 <= lim {
                            files.push(f);
                        } else {
                            skipped += 1;
                            em.find(Sev::Low, "Skipped (too big)", f.0.clone(), format!("{} MB is over the {l} MB you chose", mb(f.1)));
                        }
                    }
                    em.log(format!("Size limit raised to {} MB for this scan only ({skipped} still too big).", s2.max_file_mb));
                } else {
                    for f in &big_ok {
                        em.find(Sev::Low, "Skipped (too big)", f.0.clone(), format!("{} MB is over the {} MB limit — not scanned", mb(f.1), s.max_file_mb));
                    }
                }
                for f in &huge {
                    em.find(Sev::Low, "Too big for ClamAV", f.0.clone(), format!("{} MB: ClamAV can't scan files of 2 GiB or more", mb(f.1)));
                }
                if vt_huge && !huge.is_empty() && s.vt_check && !s.vt_api_key.is_empty() {
                    let fake: Vec<Finding> = huge
                        .iter()
                        .map(|f| Finding { sev: Sev::Low, kind: "Too big for ClamAV".into(), path: f.0.clone(), detail: String::new() })
                        .collect();
                    em.log("Looking up the files too big for ClamAV on VirusTotal by fingerprint…");
                    verify_findings(&s.vt_api_key, &fake, em);
                }
            }
        }
    }
    let total = files.len();
    let paths: Vec<String> = if s.paranoid { files.iter().chain(huge.iter()).map(|f| f.0.clone()).collect() } else { vec![] };
    let (code, _) = scan_files_parallel(&s2, vec![], files, admin, em);
    if em.cancelled() {
        em.done("Stopped.");
        return vec![];
    }

    // Anything ClamAV stopped short on: offer a rescan with higher limits.
    let hits: Vec<(String, u64)> = em
        .findings()
        .into_iter()
        .filter(|f| f.kind.contains("Limits.Exceeded"))
        .map(|f| {
            let len = std::fs::metadata(&f.path).map(|m| m.len()).unwrap_or(0);
            (f.path, len)
        })
        .collect();
    if !hits.is_empty() {
        let q = SizeAsk {
            kind: AskKind::HitLimit,
            files: hits.clone(),
            suggested_mb: (s2.clam.max_scan_mb * 4).clamp(400, 4000),
            too_big_for_clamav: vec![],
        };
        if let Some((Some(l), _)) = ask(em, slot, q, &format!("{} file(s) weren't fully scanned", hits.len())) {
            let mut s3 = s2.clone();
            s3.clam.max_scan_mb = l.max(s3.clam.max_scan_mb);
            s3.max_file_mb = s3.max_file_mb.max(l.min(CLAM_MAX_MB));
            s3.clam.max_files = s3.clam.max_files.max(100_000);
            s3.clam.max_recursion = s3.clam.max_recursion.max(64);
            let paths: std::collections::HashSet<String> = hits.iter().map(|h| h.0.clone()).collect();
            em.remove_findings(|f| paths.contains(&f.path) && f.kind.contains("Limits.Exceeded"));
            em.log(format!("Rescanning {} file(s) with limits raised to {} MB, {} files and {} levels (this scan only).", hits.len(), s3.clam.max_scan_mb, s3.clam.max_files, s3.clam.max_recursion));
            scan_files_parallel(&s3, vec![], hits, admin, em);
        }
    }
    let mut found: Vec<Finding> = em.findings().into_iter().filter(|f| f.detail.starts_with("ClamAV match")).collect();
    let n_clam = found.len();
    if s.paranoid && !em.cancelled() {
        found.extend(crate::paranoid::inspect_files(paths, crate::par::threads(s), em));
    }
    let odd = em.findings().iter().filter(|f| f.kind == "Paranoid check").count();
    let partial = em.findings().iter().filter(|f| f.kind.contains("Limits.Exceeded") || f.kind.starts_with("Skipped") || f.kind == "Too big for ClamAV").count();
    em.done(match code {
        _ if em.cancelled() => "Stopped.".to_string(),
        126 | 127 if admin => "Administrator rights were refused.".to_string(),
        _ => format!(
            "{} in {total} file(s){}.{}",
            if n_clam == 0 { "No viruses found".to_string() } else { format!("{n_clam} flagged by ClamAV") },
            if partial > 0 { format!(", {partial} not (fully) scanned — see the list") } else { String::new() },
            if s.paranoid { format!(" Paranoid check: {odd} program file(s) look odd.") } else { String::new() }
        ),
    });
    found
}
