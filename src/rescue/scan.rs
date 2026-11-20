//! Runs a search in the background and reports what it finds.

use crate::rescue::carve::{carve, CarveJob};
use crate::rescue::disk::Disk;
use crate::rescue::fat::{undelete_exfat, undelete_fat, Sink};
use crate::rescue::model::{safe_name, Category, Found, FsKind, Volume};
use crate::rescue::ntfs::undelete_ntfs;
use crate::rescue::partfind;
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::Instant;

pub enum Msg {
    Phase(String),
    Progress(u64, u64),
    Found(Found),
    Log(String),
    LostVolume(Volume),
    Done { cancelled: bool, secs: f32 },
    Recovered { done: usize, total: usize, failed: usize, last: String },
    RecoverDone { ok: usize, failed: usize, folder: PathBuf },
    WipePlan { plan: crate::rescue::wipe::Plan, mounted: Vec<String>, error: Option<String> },
    Wiping { done: u64, total: u64 },
    WipeDone { wiped: Vec<usize>, error: Option<String> },
}

#[derive(Clone)]
pub struct Request {
    pub path: String,
    /// The area to search (a partition or the whole disk).
    pub area: Volume,
    /// All volumes known on the disk.
    pub volumes: Vec<Volume>,
    pub undelete: bool,
    pub deep: bool,
    pub cats: HashSet<Category>,
    /// Also look for, and on, partitions that were deleted or replaced.
    pub previous: bool,
}

pub type Notify = Arc<dyn Fn() + Send + Sync>;

fn undelete_volume(disk: &Disk, v: &Volume, sink: &mut Sink) {
    match v.fs {
        FsKind::Fat => undelete_fat(disk, v, sink),
        FsKind::ExFat => undelete_exfat(disk, v, sink),
        FsKind::Ntfs => undelete_ntfs(disk, v, sink),
        _ => {}
    }
}

pub fn run(req: Request, tx: Sender<Msg>, cancel: Arc<AtomicBool>, notify: Notify) {
    std::thread::spawn(move || {
        let t0 = Instant::now();
        let send = |m: Msg| {
            let _ = tx.send(m);
            notify();
        };
        let disk = match Disk::open(&req.path) {
            Ok(d) => d,
            Err(e) => {
                send(Msg::Log(open_error(&req.path, &e)));
                send(Msg::Done { cancelled: false, secs: 0.0 });
                return;
            }
        };
        let cancelled = || cancel.load(Ordering::Relaxed);
        let area_end = (req.area.start + req.area.len).min(disk.size);
        let in_area = |v: &Volume| v.start >= req.area.start && v.start < area_end;
        let whole_disk = req.area.start == 0 && area_end >= disk.size;

        // Read one volume's records and send what they hold; returns the files' starts.
        let read_names = |v: &Volume, everything: bool| -> Vec<u64> {
            let mut found = Vec::new();
            {
                let mut e = |f: Found| found.push(f);
                let mut l = |s: String| send(Msg::Log(s));
                let mut sink = Sink { emit: &mut e, log: &mut l, cancelled: &cancelled, include_existing: everything };
                undelete_volume(&disk, v, &mut sink);
            }
            let n = found.len();
            let mut starts = Vec::new();
            for f in found {
                if let Some(&(o, _)) = f.extents.iter().find(|e| e.0 != u64::MAX) {
                    starts.push(o);
                }
                let _ = tx.send(Msg::Found(f));
            }
            notify();
            if v.fs.can_undelete() {
                let what = if everything { "file(s)" } else { "deleted file(s)" };
                send(Msg::Log(format!("{}: {n} {what} found by name ({}).", v.label, v.fs.label())));
            }
            starts
        };

        // Previous partitions already known (from an earlier search) or found now.
        let mut previous: Vec<Volume> = req.volumes.iter().filter(|v| v.lost).cloned().collect();
        let current: Vec<Volume> = req.volumes.iter().filter(|v| !v.lost).cloned().collect();
        let is_new = |v: &Volume, previous: &[Volume]| {
            !current.iter().any(|c| c.start == v.start) && !previous.iter().any(|p| p.start == v.start) && previous.len() < 64
        };
        let searching_previous = req.previous && previous.iter().all(|v| !in_area(v)) || req.previous && whole_disk;

        // 1. Look for previous partitions first, unless the deep search will read the whole disk anyway.
        let fold_into_deep = req.deep && whole_disk;
        if searching_previous && !fold_into_deep && !cancelled() {
            send(Msg::Phase("Looking for previous partitions…".into()));
            let mut last = Instant::now();
            let mut prog = |d: u64, t: u64| {
                if last.elapsed().as_millis() > 100 {
                    last = Instant::now();
                    send(Msg::Progress(d, t));
                }
            };
            let mut newly = Vec::new();
            partfind::hunt(&disk, &cancelled, &mut prog, &mut |v| {
                if is_new(&v, &previous) {
                    send(Msg::LostVolume(v.clone()));
                    send(Msg::Log(format!("Found a {} ({}).", v.label, crate::rescue::disk::human_size(v.len))));
                    previous.push(v.clone());
                    newly.push(v);
                }
            });
            send(Msg::Progress(disk.size, disk.size));
            if newly.is_empty() {
                send(Msg::Log("No previous partitions were found.".into()));
            }
        }

        let mut known_starts: HashSet<u64> = HashSet::new();
        // 2. Names from the file systems in the area, and from previous partitions.
        if req.undelete {
            let mut todo: Vec<(Volume, bool)> = current.iter().filter(|v| in_area(v) && v.fs.can_undelete()).map(|v| (v.clone(), false)).collect();
            if req.previous {
                // On a previous partition every file is lost, deleted or not.
                for v in previous.iter().filter(|v| v.fs.can_undelete() && (whole_disk || in_area(v))) {
                    todo.push((v.clone(), true));
                }
            }
            for (v, everything) in todo {
                if cancelled() {
                    break;
                }
                send(Msg::Phase(format!("Reading names on {} ({})…", v.label, v.fs.label())));
                known_starts.extend(read_names(&v, everything));
            }
        }

        // 3. Deep content search over the whole area.
        if req.deep && !cancelled() {
            send(Msg::Phase(format!("Deep search of {} by file content…", req.area.label)));
            let job = CarveJob {
                disk: &disk,
                start: req.area.start,
                end: area_end,
                volume: req.area.label.clone(),
                cats: &req.cats,
                known: &known_starts,
                find_partitions: fold_into_deep && req.previous,
            };
            let total = job.end - job.start;
            let mut count = 0usize;
            let mut last_progress = Instant::now();
            let mut newly = 0usize;
            {
                let tx3 = tx.clone();
                let n3 = notify.clone();
                let mut e = |f: Found| {
                    let _ = tx3.send(Msg::Found(f));
                    count += 1;
                    if count % 16 == 0 {
                        n3();
                    }
                };
                let mut l = |s: String| send(Msg::Log(s));
                let mut sink = Sink { emit: &mut e, log: &mut l, cancelled: &cancelled, include_existing: false };
                let mut prog = |done: u64| {
                    if last_progress.elapsed().as_millis() > 100 {
                        last_progress = Instant::now();
                        send(Msg::Progress(done, total));
                    }
                };
                let mut lost = |v: Volume| -> Vec<u64> {
                    if !is_new(&v, &previous) {
                        return Vec::new();
                    }
                    newly += 1;
                    send(Msg::LostVolume(v.clone()));
                    send(Msg::Log(format!("Found a {} ({}).", v.label, crate::rescue::disk::human_size(v.len))));
                    previous.push(v.clone());
                    if req.undelete && v.fs.can_undelete() {
                        read_names(&v, true)
                    } else {
                        Vec::new()
                    }
                };
                carve(&job, &mut sink, &mut prog, &mut lost);
            }
            send(Msg::Progress(total, total));
            send(Msg::Log(format!("Deep search: {count} file(s) found by content.")));
            if job.find_partitions && newly == 0 {
                send(Msg::Log("No previous partitions were found.".into()));
            }
        }
        send(Msg::Done { cancelled: cancelled(), secs: t0.elapsed().as_secs_f32() });
    });
}

pub fn open_error(path: &str, e: &std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        format!(
            "Couldn't open {path}: permission denied. Reading a whole disk needs administrator rights (on Linux start it with sudo, on Windows \"Run as administrator\"), or use a disk image file instead."
        )
    } else {
        format!("Couldn't open {path}: {e}")
    }
}

/// Read a found file's bytes (at most `max`).
pub fn read_found(disk: &Disk, f: &Found, max: usize) -> Vec<u8> {
    if let Some(d) = &f.inline_data {
        return d[..d.len().min(max)].to_vec();
    }
    let mut out = Vec::new();
    for &(off, len) in &f.extents {
        if out.len() >= max {
            break;
        }
        let take = (len as usize).min(max - out.len());
        if off == u64::MAX {
            out.extend(std::iter::repeat(0).take(take));
        } else {
            out.extend(disk.read_vec(off, take));
        }
    }
    out
}

fn unique_path(p: PathBuf) -> PathBuf {
    if !p.exists() {
        return p;
    }
    let stem = p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    let ext = p.extension().map(|s| format!(".{}", s.to_string_lossy())).unwrap_or_default();
    let dir = p.parent().map(Path::to_path_buf).unwrap_or_default();
    for i in 2..100_000 {
        let c = dir.join(format!("{stem} ({i}){ext}"));
        if !c.exists() {
            return c;
        }
    }
    p
}

/// Where a recovered file goes: <output>/<type>/<original folders>/<name>.
pub fn target_path(out: &Path, f: &Found, keep_folders: bool) -> PathBuf {
    let mut p = out.join(f.category().label());
    if keep_folders && !f.folder.is_empty() {
        for part in f.folder.split('/').filter(|s| !s.is_empty()) {
            p = p.join(safe_name(part));
        }
    }
    p.join(safe_name(&f.name))
}

fn write_one(disk: &Disk, f: &Found, path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::File::create(path)?;
    if let Some(d) = &f.inline_data {
        file.write_all(d)?;
        return Ok(());
    }
    let mut left = f.size;
    let mut buf = vec![0u8; 1 << 20];
    for &(off, len) in &f.extents {
        let mut done = 0u64;
        let len = len.min(left);
        while done < len {
            let n = ((len - done) as usize).min(buf.len());
            if off == u64::MAX {
                buf[..n].fill(0);
            } else {
                let got = disk.read_at(&mut buf[..n], off + done)?;
                buf[got..n].fill(0);
            }
            file.write_all(&buf[..n])?;
            done += n as u64;
        }
        left -= len;
    }
    Ok(())
}

pub fn recover(path: String, items: Vec<Found>, out: PathBuf, keep_folders: bool, tx: Sender<Msg>, notify: Notify) {
    std::thread::spawn(move || {
        let send = |m: Msg| {
            let _ = tx.send(m);
            notify();
        };
        let disk = match Disk::open(&path) {
            Ok(d) => d,
            Err(e) => {
                send(Msg::Log(open_error(&path, &e)));
                send(Msg::RecoverDone { ok: 0, failed: items.len(), folder: out });
                return;
            }
        };
        let total = items.len();
        let mut ok = 0;
        let mut failed = 0;
        for (i, f) in items.iter().enumerate() {
            let p = unique_path(target_path(&out, f, keep_folders));
            match write_one(&disk, f, &p) {
                Ok(()) => {
                    ok += 1;
                    crate::rescue::elevate::give_back(&p, &out);
                }
                Err(e) => {
                    failed += 1;
                    send(Msg::Log(format!("Couldn't save {}: {e}", f.name)));
                }
            }
            if i % 8 == 0 || i + 1 == total {
                send(Msg::Recovered { done: i + 1, total, failed, last: f.name.clone() });
            }
        }
        crate::rescue::elevate::give_back_folder(&out);
        send(Msg::RecoverDone { ok, failed, folder: out });
    });
}

/// Check which chosen files can be zero-filled (reads the file systems' allocation maps).
pub fn plan_wipe(path: String, volumes: Vec<Volume>, items: Vec<(usize, Found)>, tx: Sender<Msg>, notify: Notify) {
    std::thread::spawn(move || {
        let empty = || crate::rescue::wipe::Plan { safe: Vec::new(), skipped: Vec::new(), bytes: 0 };
        let msg = match Disk::open(&path) {
            Ok(d) => {
                // Never leave the window waiting: a damaged file system that trips the
                // checker becomes a message instead.
                let planned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| crate::rescue::wipe::plan(&d, &volumes, &items)));
                match planned {
                    Ok(plan) => Msg::WipePlan { plan, mounted: crate::rescue::wipe::mounted_parts(&path), error: None },
                    Err(_) => Msg::WipePlan {
                        plan: empty(),
                        mounted: Vec::new(),
                        error: Some("Couldn't work out which space is free on this disk, so nothing will be wiped.".into()),
                    },
                }
            }
            Err(e) => Msg::WipePlan {
                plan: empty(),
                mounted: Vec::new(),
                error: Some(open_error(&path, &e)),
            },
        };
        let _ = tx.send(msg);
        notify();
    });
}

/// Wipe the planned files one after another: with zeros, or ("burn") with a copy of
/// another found file's content, repeated to fill the space.
pub fn run_wipe(path: String, safe: Vec<(usize, Vec<(u64, u64)>, Option<Found>)>, tx: Sender<Msg>, notify: Notify) {
    std::thread::spawn(move || {
        let total: u64 = safe.iter().flat_map(|s| s.1.iter()).map(|r| r.1).sum();
        let mut base = 0u64;
        let mut wiped = Vec::new();
        let mut error = None;
        let mut last = Instant::now();
        // Read every copy before writing anything: a copy may come from a file that's
        // also being wiped.
        let disk = Disk::open(&path).ok();
        let patterns: Vec<Vec<u8>> = safe
            .iter()
            .map(|(_, _, donor)| match (&disk, donor) {
                (Some(d), Some(f)) => read_found(d, f, (f.size as usize).min(64 << 20)),
                _ => Vec::new(),
            })
            .collect();
        drop(disk);
        for ((idx, ranges, _), pattern) in safe.iter().zip(patterns.iter()) {
            let mut prog = |d: u64| {
                if last.elapsed().as_millis() > 100 {
                    last = Instant::now();
                    let _ = tx.send(Msg::Wiping { done: base + d, total });
                    notify();
                }
            };
            match crate::rescue::wipe::fill_ranges(&path, ranges, pattern, &mut prog) {
                Ok(()) => wiped.push(*idx),
                Err(e) => {
                    error = Some(if e.kind() == std::io::ErrorKind::PermissionDenied {
                        "The disk couldn't be written: permission denied. Unlock disks (administrator rights) and try again.".to_string()
                    } else {
                        format!("Writing to the disk failed: {e}")
                    });
                    break;
                }
            }
            base += ranges.iter().map(|r| r.1).sum::<u64>();
        }
        let _ = tx.send(Msg::WipeDone { wiped, error });
        notify();
    });
}
