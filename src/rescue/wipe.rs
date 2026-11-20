//! Zero-filling recoverable files so nobody can bring them back.
//!
//! Safety first: a file's bytes are only overwritten when every piece of it lies in
//! space that the current file system marks as free (or outside every partition).
//! Anything that can't be confirmed free is skipped, so files still in use are never
//! touched. This is the only part of the app that writes to the disk.

use crate::rescue::disk::Disk;
use crate::rescue::model::{Found, FsKind, Volume};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io;

/// Which clusters of a volume are in use now.
pub struct AllocMap {
    pub vol_start: u64,
    pub vol_end: u64,
    /// Where cluster 0 of the map starts on the disk; anything before it is file-system metadata.
    pub base: u64,
    pub cluster: u64,
    pub clusters: u64,
    pub used: Vec<u8>,
}

impl AllocMap {
    fn is_free(&self, off: u64, len: u64) -> bool {
        if len == 0 {
            return true;
        }
        if off < self.base || off < self.vol_start || off + len > self.vol_end {
            return false;
        }
        let first = (off - self.base) / self.cluster;
        let last = (off + len - 1 - self.base) / self.cluster;
        if last >= self.clusters {
            return false;
        }
        (first..=last).all(|c| self.used.get((c / 8) as usize).map(|b| b & (1 << (c % 8)) == 0).unwrap_or(false))
    }
}

const RESERVED: u64 = 1 << 20; // partition tables live in the first and last megabyte

pub struct Plan {
    /// Found-list indices that can be wiped, with the byte ranges to zero.
    pub safe: Vec<(usize, Vec<(u64, u64)>)>,
    /// Found-list indices left alone, with why.
    pub skipped: Vec<(usize, String)>,
    pub bytes: u64,
}

fn alloc_for(disk: &Disk, v: &Volume) -> Option<AllocMap> {
    match v.fs {
        FsKind::Fat => crate::rescue::fat::fat_alloc(disk, v),
        FsKind::ExFat => crate::rescue::fat::exfat_alloc(disk, v),
        FsKind::Ntfs => crate::rescue::ntfs::ntfs_alloc(disk, v),
        _ => None,
    }
}

/// Work out which of the chosen files can be zero-filled safely.
pub fn plan(disk: &Disk, volumes: &[Volume], items: &[(usize, Found)]) -> Plan {
    let current: Vec<&Volume> = volumes.iter().filter(|v| !v.lost).collect();
    let mut maps: HashMap<u64, Option<AllocMap>> = HashMap::new();
    let mut out = Plan { safe: Vec::new(), skipped: Vec::new(), bytes: 0 };
    'items: for (idx, f) in items {
        if f.inline_data.is_some() {
            out.skipped.push((*idx, "It's stored inside the NTFS file table, which is left alone".into()));
            continue;
        }
        if f.note.starts_with("Zero-filled") {
            out.skipped.push((*idx, "Already zero-filled".into()));
            continue;
        }
        let mut ranges = Vec::new();
        let mut left = f.size;
        for &(off, len) in &f.extents {
            let len = len.min(left);
            left -= len;
            if off == u64::MAX || len == 0 {
                continue;
            }
            match current.iter().find(|v| off >= v.start && off < v.start + v.len) {
                Some(v) => {
                    let map = maps.entry(v.start).or_insert_with(|| alloc_for(disk, v));
                    match map {
                        Some(m) if m.is_free(off, len) => {}
                        Some(_) => {
                            out.skipped.push((*idx, format!("Part of its space is in use on {}", v.label)));
                            continue 'items;
                        }
                        None => {
                            out.skipped.push((*idx, format!("Can't check which space is free on {} ({})", v.label, v.fs.label())));
                            continue 'items;
                        }
                    }
                }
                None => {
                    // Outside every partition: free, except where partition tables live
                    // or where it would run into a partition.
                    let end = off + len;
                    if off < RESERVED || end > disk.size.saturating_sub(RESERVED) || current.iter().any(|v| off < v.start + v.len && end > v.start) {
                        out.skipped.push((*idx, "It overlaps a partition table or a partition".into()));
                        continue 'items;
                    }
                }
            }
            ranges.push((off, len));
        }
        if ranges.is_empty() {
            out.skipped.push((*idx, "Nothing of it is left on the disk".into()));
            continue;
        }
        out.bytes += ranges.iter().map(|r| r.1).sum::<u64>();
        out.safe.push((*idx, ranges));
    }
    out
}

/// Refuse to write to a disk the system is using (Linux).
pub fn mounted_parts(path: &str) -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        let real = std::fs::canonicalize(path).map(|p| p.display().to_string()).unwrap_or(path.to_string());
        if !real.starts_with("/dev/") {
            return Vec::new();
        }
        std::fs::read_to_string("/proc/mounts")
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.split_whitespace().next())
            .filter(|d| d.starts_with(&real))
            .map(String::from)
            .collect()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Vec::new()
    }
}

#[cfg(unix)]
fn write_at(f: &std::fs::File, buf: &[u8], off: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    f.write_all_at(buf, off)
}

#[cfg(windows)]
fn write_at(f: &std::fs::File, mut buf: &[u8], mut off: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        let n = f.seek_write(buf, off)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "nothing written"));
        }
        buf = &buf[n..];
        off += n as u64;
    }
    Ok(())
}

/// Overwrite byte ranges with zeros.
pub fn zero_ranges(path: &str, ranges: &[(u64, u64)], progress: &mut dyn FnMut(u64)) -> io::Result<()> {
    fill_ranges(path, ranges, &[], progress)
}

/// Overwrite byte ranges with `pattern` repeated from the file's first byte (zeros when
/// the pattern is empty). Whole sectors are read, changed where needed and written
/// back, so bytes next to a range stay as they were.
pub fn fill_ranges(path: &str, ranges: &[(u64, u64)], pattern: &[u8], progress: &mut dyn FnMut(u64)) -> io::Result<()> {
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    let reader = Disk::open(path)?;
    let mut done = 0u64;
    let mut buf = vec![0u8; 1 << 20];
    for &(off, len) in ranges {
        let end = off + len;
        let mut pos = off & !511;
        while pos < end {
            let chunk_end = ((pos + buf.len() as u64).min((end + 511) & !511)).min(reader.size.max(end));
            let n = (chunk_end - pos) as usize;
            let got = reader.read_at(&mut buf[..n], pos)?;
            let n = got.min(n);
            if n == 0 {
                break;
            }
            let z0 = off.max(pos) - pos;
            let z1 = end.min(pos + n as u64) - pos;
            if pattern.is_empty() {
                buf[z0 as usize..z1 as usize].fill(0);
            } else {
                // `done` counts the file's bytes written so far: keep the copy in step.
                for (k, b) in buf[z0 as usize..z1 as usize].iter_mut().enumerate() {
                    *b = pattern[((done + k as u64) % pattern.len() as u64) as usize];
                }
            }
            write_at(&file, &buf[..n], pos)?;
            done += z1 - z0;
            pos += n as u64;
            progress(done);
        }
    }
    file.sync_all()?;
    Ok(())
}
