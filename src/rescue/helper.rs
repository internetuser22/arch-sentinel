//! The part of the File Rescue engine that runs as a separate process (with
//! administrator rights when it reads a real disk). It talks to the window in
//! lines: the usual @P/@L/@F/@D messages plus
//!   @V <json Volume>        a volume (partition) on the disk
//!   @R <json Found>         a deleted file found
//!   @H <index> <sha256>     fingerprint of a file the virus scan flagged
//!   @Z <index>              zero-filled
//!   @S <index> <why>        left alone by the wipe, and why
//!   @M <partitions>         refused: these partitions are mounted

use super::disk::Disk;
use super::model::{Found, Volume};
use crate::jobs::{print_msg, Emitter, Msg};
use std::path::{Path, PathBuf};

fn say(tag: &str, rest: &str) {
    use std::io::Write;
    let mut o = std::io::stdout().lock();
    let _ = writeln!(o, "@{tag}\t{}", rest.replace('\n', " "));
    let _ = o.flush();
}

fn progress(s: impl Into<String>) {
    print_msg(&Msg::Progress(s.into()));
}
fn log(s: impl Into<String>) {
    print_msg(&Msg::Log(s.into()));
}
fn done(s: impl Into<String>) {
    print_msg(&Msg::Done(s.into()));
}

fn open(path: &str) -> Option<Disk> {
    match Disk::open(path) {
        Ok(d) => Some(d),
        Err(e) => {
            done(super::scan::open_error(path, &e));
            None
        }
    }
}

/// Find deleted files: by name on FAT/exFAT/NTFS, by content (deep), and on previous partitions.
pub fn find(path: &str, undelete: bool, deep: bool, previous: bool) {
    let Some(disk) = open(path) else { return };
    let layout = super::parts::read_layout(&disk);
    for v in &layout.volumes {
        say("V", &serde_json::to_string(v).unwrap_or_default());
    }
    log(format!("{path}: {} bytes, {} partition table, {} volume(s).", disk.size, layout.scheme, layout.volumes.len()));
    let (tx, rx) = std::sync::mpsc::channel();
    let req = super::scan::Request {
        path: path.to_string(),
        area: Volume { label: "Whole disk".into(), start: 0, len: disk.size, fs: super::model::FsKind::Unknown, kind: String::new(), lost: false, boot: 0 },
        volumes: layout.volumes.clone(),
        undelete,
        deep,
        cats: super::model::CATEGORIES.iter().copied().collect(),
        previous,
    };
    drop(disk);
    super::scan::run(req, tx, Default::default(), std::sync::Arc::new(|| {}));
    let mut n = 0usize;
    let mut phase = String::new();
    for m in rx {
        match m {
            super::scan::Msg::Phase(p) => {
                phase = p.clone();
                progress(p);
            }
            super::scan::Msg::Progress(d, t) if t > 0 => progress(format!("{phase} {}%  ({n} found)", d * 100 / t)),
            super::scan::Msg::Found(f) => {
                n += 1;
                say("R", &serde_json::to_string(&f).unwrap_or_default());
            }
            super::scan::Msg::LostVolume(v) => say("V", &serde_json::to_string(&v).unwrap_or_default()),
            super::scan::Msg::Log(s) => log(s),
            super::scan::Msg::Done { cancelled, secs } => {
                done(format!("Found {n} deleted file(s) in {secs:.0}s{}.", if cancelled { " (stopped)" } else { "" }));
                break;
            }
            _ => {}
        }
    }
}

fn read_items(file: &str) -> Vec<(usize, Found)> {
    std::fs::read_to_string(file).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

/// Virus-scan deleted files where they are: each is read from the disk into memory
/// (/dev/shm), scanned with ClamAV (and the Paranoid check when it's on), then dropped.
/// Nothing is written to the disk being examined.
pub fn scan(path: &str, items_file: &str, settings_file: &str, shm: &str) {
    let mut s: crate::settings::Settings = std::fs::read_to_string(settings_file).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
    // A CPU cap needs your own session's systemd, which an administrator helper doesn't have.
    s.cpu_cap = 0;
    let Some(disk) = open(path) else { return };
    let items = read_items(items_file);
    let total = items.len();
    let shm = PathBuf::from(shm);
    if std::fs::create_dir_all(&shm).is_err() {
        done("Couldn't make a scratch folder in memory (/dev/shm).");
        return;
    }
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&shm, std::fs::Permissions::from_mode(0o700));
    }
    let max_file = (s.max_file_mb as u64 * 1_048_576).max(1 << 20);
    // Keep each batch to a quarter of the free memory (at most 2 GiB).
    let budget = ((crate::par::mem_available_gib() * 1_073_741_824.0 / 4.0) as u64).clamp(64 << 20, 2 << 30);
    let mut em = Emitter::printer();
    let readers = if rotational(path) { crate::par::threads(&s).min(2) } else { crate::par::threads(&s) };
    log(format!("Reading with {readers} thread(s) ({}).", if rotational(path) { "spinning disk" } else { "SSD or image file" }));
    let mut i = 0;
    let mut flagged_total = 0usize;
    let mut skipped = 0usize;
    while i < total {
        // Pick this batch's files (up to the memory budget)…
        let mut picked: Vec<&(usize, Found)> = vec![];
        let mut used = 0u64;
        while i < total && (used < budget || picked.is_empty()) {
            let it = &items[i];
            i += 1;
            if it.1.size > max_file {
                skipped += 1;
                say("S", &format!("{}\tbigger than the {} MB scan limit — not scanned", it.0, s.max_file_mb));
                continue;
            }
            used += it.1.size;
            picked.push(it);
        }
        // …and read them off the disk with several threads (reading only; each
        // thread has its own read-only handle). Spinning disks get two threads,
        // since more would just make the heads jump back and forth.
        progress(format!("Reading {} deleted file(s) into memory with {readers} thread(s)…", picked.len()));
        let queue = std::sync::Mutex::new(picked);
        let batch = std::sync::Mutex::new(Vec::<(String, u64)>::new());
        std::thread::scope(|sc| {
            for _ in 0..readers {
                sc.spawn(|| {
                    crate::par::lowest_priority_thread();
                    let Ok(d) = Disk::open(path) else { return };
                    loop {
                        let Some((idx, f)) = queue.lock().unwrap().pop() else { break };
                        let bytes = super::scan::read_found(&d, f, f.size as usize);
                        let ext = if f.ext.is_empty() { "bin".to_string() } else { f.ext.clone() };
                        let p = shm.join(format!("{idx}.{ext}"));
                        if std::fs::write(&p, &bytes).is_ok() {
                            batch.lock().unwrap().push((p.display().to_string(), bytes.len() as u64));
                        }
                    }
                });
            }
        });
        let batch = batch.into_inner().unwrap();
        progress(format!("Scanning files {}–{} of {total} in memory…", i - batch.len().min(i) + 1, i));
        let before = em.findings().len();
        let (_, found) = crate::clam::scan_files_parallel(&s, vec![], batch.clone(), false, &mut em);
        if s.paranoid {
            crate::paranoid::inspect_files(batch.iter().map(|b| b.0.clone()).collect(), crate::par::threads(&s), &mut em);
        }
        // Fingerprints of what was flagged, for a VirusTotal lookup later.
        for f in em.findings().iter().skip(before) {
            if let Some(name) = Path::new(&f.path).file_name().map(|n| n.to_string_lossy().to_string()) {
                if let (Some(idx), Ok(h)) = (name.split('.').next(), crate::clam::sha256_file(&f.path)) {
                    say("H", &format!("{idx}\t{h}"));
                }
            }
        }
        flagged_total += found.len();
        for (p, _) in &batch {
            let _ = std::fs::remove_file(p);
        }
    }
    let _ = std::fs::remove_dir_all(&shm);
    done(format!(
        "Scanned {} deleted file(s) in place: ClamAV flagged {flagged_total}{}.",
        total - skipped,
        if skipped > 0 { format!(", {skipped} too big to scan") } else { String::new() }
    ));
}

/// Zero-fill deleted files in place, only where the file system marks every piece as free.
pub fn wipe(path: &str, items_file: &str, volumes_file: &str) {
    let mounted = super::wipe::mounted_parts(path);
    if !mounted.is_empty() {
        say("M", &mounted.join(" "));
        done(format!("Not wiped: {} is mounted (in use). Unmount it first, so nothing writes to the free space while it's being wiped.", mounted.join(", ")));
        return;
    }
    let Some(disk) = open(path) else { return };
    let items = read_items(items_file);
    let volumes: Vec<Volume> = std::fs::read_to_string(volumes_file).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
    progress("Checking which space is free…");
    let plan = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| super::wipe::plan(&disk, &volumes, &items))) {
        Ok(p) => p,
        Err(_) => {
            done("Couldn't work out which space is free on this disk, so nothing was wiped.");
            return;
        }
    };
    drop(disk);
    for (idx, why) in &plan.skipped {
        say("S", &format!("{idx}\t{why}"));
    }
    let total = plan.bytes.max(1);
    let mut base = 0u64;
    let mut wiped = 0usize;
    for (idx, ranges) in &plan.safe {
        let mut last = std::time::Instant::now();
        let r = super::wipe::zero_ranges(path, ranges, &mut |d| {
            if last.elapsed().as_millis() > 200 {
                last = std::time::Instant::now();
                progress(format!("Zero-filling… {}%", (base + d) * 100 / total));
            }
        });
        match r {
            Ok(()) => {
                wiped += 1;
                say("Z", &idx.to_string());
            }
            Err(e) => {
                done(format!("Writing to the disk failed: {e}"));
                return;
            }
        }
        base += ranges.iter().map(|r| r.1).sum::<u64>();
    }
    done(format!("Zero-filled {wiped} file(s) ({} MB); {} left alone (see why on each).", plan.bytes / 1_048_576, plan.skipped.len()));
}

/// Copy deleted files out with their original names and folders.
pub fn recover(path: &str, items_file: &str, out: &str) {
    let items: Vec<Found> = read_items(items_file).into_iter().map(|(_, f)| f).collect();
    let (tx, rx) = std::sync::mpsc::channel();
    super::scan::recover(path.to_string(), items, PathBuf::from(out), true, tx, std::sync::Arc::new(|| {}));
    for m in rx {
        match m {
            super::scan::Msg::Recovered { done: d, total, .. } => progress(format!("Recovering {d} of {total}…")),
            super::scan::Msg::Log(s) => log(s),
            super::scan::Msg::RecoverDone { ok, failed, folder } => {
                done(format!("Recovered {ok} file(s) into {}{}.", folder.display(), if failed > 0 { format!(", {failed} failed") } else { String::new() }));
                break;
            }
            _ => {}
        }
    }
}

/// The command-line entry: `--helper rescue <action> ...`.
pub fn main(args: &[String]) -> i32 {
    let a = |i: usize| args.get(i).cloned().unwrap_or_default();
    match a(0).as_str() {
        "find" => find(&a(1), a(2) == "1", a(3) == "1", a(4) == "1"),
        "scan" => scan(&a(1), &a(2), &a(3), &a(4)),
        "wipe" => wipe(&a(1), &a(2), &a(3)),
        "recover" => recover(&a(1), &a(2), &a(3)),
        "sample" => match super::sample::make_sample(Path::new(&a(1))) {
            Ok(()) => done(format!("Practice disk image written to {}.", a(1))),
            Err(e) => done(format!("Couldn't write the practice image: {e}")),
        },
        other => {
            eprintln!("unknown rescue action {other}");
            return 2;
        }
    }
    0
}

/// Is this a spinning hard disk? (Partitions ask their whole disk; image files count as no.)
fn rotational(path: &str) -> bool {
    let Some(name) = std::fs::canonicalize(path).ok().and_then(|p| p.strip_prefix("/dev").ok().map(|n| n.display().to_string())) else {
        return false;
    };
    let name = name.trim_start_matches('/');
    let direct = format!("/sys/class/block/{name}/queue/rotational");
    let parent = std::fs::canonicalize(format!("/sys/class/block/{name}")).ok().and_then(|p| p.parent().map(|p| p.join("queue/rotational")));
    let v = std::fs::read_to_string(&direct).ok().or_else(|| parent.and_then(|p| std::fs::read_to_string(p).ok()));
    v.map(|x| x.trim() == "1").unwrap_or(false)
}
