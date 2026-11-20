//! Multithreaded scanning: a parallel folder walker, parallel external
//! commands, and the CPU controls (thread count, CPU cap, lowest priority).
//!
//! Every scan thread and scan program runs at the lowest priority (nice 19,
//! idle disk access), so scans only take CPU time nothing else wants.

use crate::jobs::{Emitter, Msg};
use crate::settings::Settings;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc;
use std::sync::Mutex;

pub const NICE: i32 = 19;

pub fn ncpu() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

/// How many threads a scan may use, from the settings (0 = automatic: half the cores).
pub fn threads(s: &Settings) -> usize {
    let n = ncpu();
    let t = if s.scan_threads == 0 { (n / 2).max(1) } else { s.scan_threads as usize };
    t.clamp(1, n.max(1))
}

/// Free memory in GiB (each ClamAV process needs about 1 GiB for its signatures).
pub fn mem_available_gib() -> f64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|t| {
            t.lines()
                .find(|l| l.starts_with("MemAvailable:"))
                .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse::<f64>().ok()))
        })
        .map(|kb| kb / 1_048_576.0)
        .unwrap_or(4.0)
}

/// Put the calling thread at the lowest CPU and disk priority.
pub fn lowest_priority_thread() {
    unsafe {
        let tid = libc::syscall(libc::SYS_gettid) as libc::id_t;
        libc::setpriority(libc::PRIO_PROCESS, tid, NICE);
        // ioprio_set(IOPRIO_WHO_PROCESS, tid, IOPRIO_CLASS_IDLE << 13)
        libc::syscall(libc::SYS_ioprio_set, 1, tid as libc::c_long, (3i64 << 13) as libc::c_long);
    }
}

/// The words placed before a scan program: an optional CPU cap (a systemd
/// scope), administrator rights, then lowest priority.
pub fn prefix(s: &Settings, admin: bool) -> Vec<String> {
    let mut p = vec![];
    if s.cpu_cap > 0 && s.cpu_cap < 100 && std::path::Path::new("/usr/bin/systemd-run").exists() {
        // CPUQuota counts one core as 100%.
        let quota = (s.cpu_cap as usize * ncpu()).max(1);
        p.extend([
            "/usr/bin/systemd-run".to_string(),
            "--user".into(),
            "--scope".into(),
            "--quiet".into(),
            "--collect".into(),
            "-p".into(),
            format!("CPUQuota={quota}%"),
        ]);
    }
    if admin {
        p.push("/usr/bin/pkexec".into());
    }
    p.extend(["/usr/bin/nice".into(), "-n".into(), NICE.to_string(), "/usr/bin/ionice".into(), "-c".into(), "3".into()]);
    p
}

pub fn command(s: &Settings, admin: bool, program: &str, args: &[String]) -> Command {
    let mut parts = prefix(s, admin);
    parts.push(program.to_string());
    parts.extend(args.iter().cloned());
    let mut c = Command::new(&parts[0]);
    c.args(&parts[1..]);
    c
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// One shell line that runs several commands side by side, each with
/// line-buffered output so their lines don't get mixed up.
pub fn parallel_script(cmds: &[Vec<String>]) -> String {
    let mut sh = String::new();
    for c in cmds {
        sh.push_str("/usr/bin/stdbuf -oL -eL ");
        sh.push_str(&c.iter().map(|a| sh_quote(a)).collect::<Vec<_>>().join(" "));
        sh.push_str(" &\n");
    }
    sh.push_str("wait\n");
    sh
}

/// Split items into `n` groups of similar total weight.
pub fn split_balanced<T>(mut items: Vec<(T, u64)>, n: usize) -> Vec<Vec<T>> {
    let n = n.max(1);
    items.sort_by(|a, b| b.1.cmp(&a.1));
    let mut groups: Vec<(u64, Vec<T>)> = (0..n).map(|_| (0, vec![])).collect();
    for (it, w) in items {
        let g = groups.iter_mut().min_by_key(|g| g.0).unwrap();
        g.0 += w.max(1);
        g.1.push(it);
    }
    groups.into_iter().map(|g| g.1).filter(|g| !g.is_empty()).collect()
}

/// Run a command (in its own process group), turning each output line into
/// messages. `on_line` sees every line too. Stops the group when cancelled.
pub fn stream_command(cmd: Command, em: &mut Emitter, parse: &dyn Fn(&str) -> Vec<Msg>, on_line: &mut dyn FnMut(&str, &mut Emitter)) -> i32 {
    em.log(format!("$ {}", crate::jobs::describe(&cmd)));
    // Administrator commands go through the session (one password prompt).
    let child = match crate::root::spawn(cmd) {
        Ok(c) => c,
        Err(e) => {
            em.log(format!("Could not start: {e}"));
            return -1;
        }
    };
    let mut killed = false;
    let mut frozen = false;
    let mut code = -1;
    loop {
        match child.rx.recv_timeout(std::time::Duration::from_millis(300)) {
            Ok(crate::root::Ev::Out(line)) | Ok(crate::root::Ev::Err(line)) => {
                if line.starts_with('@') {
                    if let Some(m) = crate::jobs::decode(&line) {
                        em.emit(m);
                        continue;
                    }
                }
                on_line(&line, em);
                for m in parse(&line) {
                    em.emit(m);
                }
            }
            Ok(crate::root::Ev::Exit(c)) => {
                code = c;
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        if em.paused() != frozen && !em.cancelled() {
            frozen = em.paused();
            if !child.sig.send(if frozen { libc::SIGSTOP } else { libc::SIGCONT }) && frozen {
                em.log("This part couldn't be paused; it keeps going.");
            }
        }
        if em.cancelled() && !killed {
            killed = true;
            child.sig.send(libc::SIGCONT);
            child.sig.send(libc::SIGTERM);
        }
    }
    if killed {
        em.log("Stopped.");
    }
    code
}

/// What the parallel walker hands back to the scanning thread.
pub enum WalkOut<O> {
    Item(O),
    Unreadable(String),
    Checked(u64, String),
}

/// Walk folders with several threads. `visit` runs for every entry on a
/// worker thread (at the lowest priority) and returns true to skip a folder's
/// contents. `on_out` runs on the calling thread for everything workers send.
pub fn par_walk<O: Send>(
    roots: &[String],
    threads: usize,
    cancel: crate::jobs::Ctl,
    visit: &(dyn Fn(&walkdir::DirEntry, &mpsc::Sender<WalkOut<O>>) -> bool + Sync),
    on_out: &mut dyn FnMut(WalkOut<O>),
) {
    let (tx, rx) = mpsc::channel::<WalkOut<O>>();
    // Split the work: the roots' own entries are checked here, and every
    // sub-folder two levels down becomes a separate piece of work.
    let mut starts: Vec<PathBuf> = vec![];
    let mut top = 0u64;
    for root in roots {
        let mut it = walkdir::WalkDir::new(root).follow_links(false).max_depth(2).into_iter();
        while let Some(e) = it.next() {
            let e = match e {
                Ok(e) => e,
                Err(err) => {
                    let _ = tx.send(WalkOut::Unreadable(err.path().map(|p| p.display().to_string()).unwrap_or_default()));
                    continue;
                }
            };
            if e.depth() == 0 {
                continue;
            }
            cancel.wait_if_paused();
            top += 1;
            let skip = visit(&e, &tx);
            if e.file_type().is_dir() {
                if skip {
                    it.skip_current_dir();
                } else if e.depth() == 2 {
                    starts.push(e.path().to_path_buf());
                }
            }
        }
    }
    let _ = tx.send(WalkOut::Checked(top, String::new()));
    // Workers walk below each start folder (its own entry was already visited).
    let queue = Mutex::new(starts);
    std::thread::scope(|scope| {
        for _ in 0..threads.max(1) {
            let tx = tx.clone();
            let queue = &queue;
            let cancel = cancel.clone();
            scope.spawn(move || {
                lowest_priority_thread();
                let mut count = 0u64;
                loop {
                    cancel.wait_if_paused();
                    if cancel.cancelled() {
                        break;
                    }
                    let Some(dir) = queue.lock().unwrap().pop() else { break };
                    let mut it = walkdir::WalkDir::new(&dir).follow_links(false).same_file_system(true).min_depth(1).into_iter();
                    while let Some(e) = it.next() {
                        if count % 256 == 0 {
                            cancel.wait_if_paused();
                        }
                        if cancel.cancelled() {
                            break;
                        }
                        let e = match e {
                            Ok(e) => e,
                            Err(err) => {
                                let _ = tx.send(WalkOut::Unreadable(err.path().map(|p| p.display().to_string()).unwrap_or_default()));
                                continue;
                            }
                        };
                        count += 1;
                        if count % 2000 == 0 {
                            let _ = tx.send(WalkOut::Checked(2000, e.path().display().to_string()));
                        }
                        if visit(&e, &tx) && e.file_type().is_dir() {
                            it.skip_current_dir();
                        }
                    }
                }
                let _ = tx.send(WalkOut::Checked(count % 2000, String::new()));
            });
        }
        drop(tx);
        for out in rx {
            on_out(out);
        }
    });
}

/// Run paccheck on many packages, split over several processes at the lowest
/// priority, and return everything they printed.
pub fn paccheck_many(pkgs: &[String], args: &[&str], threads: usize) -> String {
    let weighted: Vec<(String, u64)> = pkgs.iter().map(|p| (p.clone(), 1)).collect();
    let groups = split_balanced(weighted, threads);
    let handles: Vec<_> = groups
        .into_iter()
        .map(|g| {
            let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
            std::thread::spawn(move || {
                Command::new("/usr/bin/nice")
                    .args(["-n", &NICE.to_string(), "/usr/bin/ionice", "-c", "3", "/usr/bin/paccheck"])
                    .args(&args)
                    .args(&g)
                    .output()
                    .map(|o| format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
                    .unwrap_or_default()
            })
        })
        .collect();
    handles.into_iter().filter_map(|h| h.join().ok()).collect::<Vec<_>>().join("\n")
}
