//! Read-only access to a disk, partition or disk image.

use std::fs::File;
use std::io::{self, Seek, SeekFrom};

pub struct Disk {
    file: File,
    pub size: u64,
    pub path: String,
}

impl Disk {
    pub fn open(path: &str) -> io::Result<Disk> {
        let file = File::open(path)?;
        let mut size = file.metadata().map(|m| m.len()).unwrap_or(0);
        if size == 0 {
            // Block devices report 0 as their length; seeking to the end works on Unix.
            if let Ok(end) = (&file).seek(SeekFrom::End(0)) {
                size = end;
            }
        }
        let disk = Disk { file, size, path: path.to_string() };
        let mut disk = disk;
        if disk.size == 0 {
            disk.size = disk.probe_size();
        }
        Ok(disk)
    }

    /// Find the size of a device that won't tell us, by trying to read further and further.
    fn probe_size(&self) -> u64 {
        let mut buf = [0u8; 512];
        let mut lo: u64 = 0;
        let mut hi: u64 = 1 << 20;
        while self.raw_read(&mut buf, hi * 512).map(|n| n == 512).unwrap_or(false) {
            lo = hi;
            hi *= 2;
            if hi > (1u64 << 40) {
                break;
            }
        }
        while hi - lo > 1 {
            let mid = (lo + hi) / 2;
            if self.raw_read(&mut buf, mid * 512).map(|n| n == 512).unwrap_or(false) {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        if lo == 0 && self.raw_read(&mut buf, 0).map(|n| n == 0).unwrap_or(true) {
            0
        } else {
            (lo + 1) * 512
        }
    }

    #[cfg(unix)]
    fn raw_read(&self, buf: &mut [u8], off: u64) -> io::Result<usize> {
        use std::os::unix::fs::FileExt;
        let mut done = 0;
        while done < buf.len() {
            match self.file.read_at(&mut buf[done..], off + done as u64) {
                Ok(0) => break,
                Ok(n) => done += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    if done > 0 {
                        break;
                    }
                    return Err(e);
                }
            }
        }
        Ok(done)
    }

    #[cfg(windows)]
    fn raw_read(&self, buf: &mut [u8], off: u64) -> io::Result<usize> {
        use std::os::windows::fs::FileExt;
        let mut done = 0;
        while done < buf.len() {
            match self.file.seek_read(&mut buf[done..], off + done as u64) {
                Ok(0) => break,
                Ok(n) => done += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    if done > 0 {
                        break;
                    }
                    return Err(e);
                }
            }
        }
        Ok(done)
    }

    /// Read at any offset. Raw devices need sector-aligned reads, so unaligned
    /// requests go through an aligned buffer. Returns how many bytes were read.
    pub fn read_at(&self, buf: &mut [u8], off: u64) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if off % 512 == 0 && buf.len() % 512 == 0 {
            return self.raw_read(buf, off);
        }
        let start = off & !511;
        let end = (off + buf.len() as u64 + 511) & !511;
        let mut tmp = vec![0u8; (end - start) as usize];
        let n = self.raw_read(&mut tmp, start)?;
        let skip = (off - start) as usize;
        if n <= skip {
            return Ok(0);
        }
        let avail = (n - skip).min(buf.len());
        buf[..avail].copy_from_slice(&tmp[skip..skip + avail]);
        Ok(avail)
    }

    /// Read exactly `len` bytes (zero-filled past the end of the disk).
    pub fn read_vec(&self, off: u64, len: usize) -> Vec<u8> {
        let mut v = vec![0u8; len];
        let _ = self.read_at(&mut v, off);
        v
    }
}

/// A cached reader for parsing structures at arbitrary offsets.
pub struct Cursor<'a> {
    disk: &'a Disk,
    limit: u64,
    win_start: u64,
    win: Vec<u8>,
}

const WIN: usize = 1 << 20;

impl<'a> Cursor<'a> {
    pub fn new(disk: &'a Disk, limit: u64) -> Self {
        Cursor { disk, limit: limit.min(disk.size), win_start: u64::MAX, win: Vec::new() }
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }

    /// Bytes at [off, off+len), or None past the limit. `len` must be <= 64 KiB.
    pub fn get(&mut self, off: u64, len: usize) -> Option<&[u8]> {
        if off.checked_add(len as u64)? > self.limit {
            return None;
        }
        if self.win_start == u64::MAX
            || off < self.win_start
            || off + len as u64 > self.win_start + self.win.len() as u64
        {
            let start = off & !511;
            let want = (WIN as u64).min(self.limit - start).max(len as u64 + (off - start));
            let want = ((want + 511) & !511) as usize;
            self.win.resize(want, 0);
            let n = self.disk.read_at(&mut self.win, start).unwrap_or(0);
            self.win.truncate(n);
            self.win_start = start;
            if off + len as u64 > self.win_start + self.win.len() as u64 {
                return None;
            }
        }
        let s = (off - self.win_start) as usize;
        Some(&self.win[s..s + len])
    }

    pub fn u8(&mut self, off: u64) -> Option<u8> {
        self.get(off, 1).map(|b| b[0])
    }
    pub fn u16le(&mut self, off: u64) -> Option<u16> {
        self.get(off, 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }
    pub fn u32le(&mut self, off: u64) -> Option<u32> {
        self.get(off, 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub fn u32be(&mut self, off: u64) -> Option<u32> {
        self.get(off, 4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub fn u64le(&mut self, off: u64) -> Option<u64> {
        self.get(off, 8).map(le64)
    }
    pub fn u64be(&mut self, off: u64) -> Option<u64> {
        self.get(off, 8).map(|b| u64::from_be_bytes(b[..8].try_into().unwrap()))
    }
}

pub fn le16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
pub fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
pub fn le64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b[..8].try_into().unwrap())
}

/// A disk the computer knows about, for the "where to look" list.
#[derive(Clone)]
pub struct DeviceInfo {
    pub path: String,
    pub label: String,
    pub size: u64,
}

pub fn list_devices() -> Vec<DeviceInfo> {
    let mut out = Vec::new();
    #[cfg(target_os = "linux")]
    {
        if let Ok(rd) = std::fs::read_dir("/sys/block") {
            let mut names: Vec<String> = rd.flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect();
            names.sort();
            for name in names {
                if name.starts_with("loop") && !has_backing(&name)
                    || name.starts_with("ram")
                    || name.starts_with("zram")
                    || name.starts_with("dm-")
                    || name.starts_with("sr")
                {
                    continue;
                }
                let size = read_sys_num(&format!("/sys/block/{name}/size")) * 512;
                if size == 0 {
                    continue;
                }
                let model = std::fs::read_to_string(format!("/sys/block/{name}/device/model"))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                let removable = read_sys_num(&format!("/sys/block/{name}/removable")) == 1;
                let mut label = if model.is_empty() { "Disk".to_string() } else { model };
                if removable {
                    label.push_str(" (removable)");
                }
                out.push(DeviceInfo { path: format!("/dev/{name}"), label, size });
                // Its partitions
                if let Ok(rd) = std::fs::read_dir(format!("/sys/block/{name}")) {
                    let mut parts: Vec<String> = rd
                        .flatten()
                        .map(|e| e.file_name().to_string_lossy().to_string())
                        .filter(|p| p.starts_with(&name) && p != &name)
                        .collect();
                    parts.sort();
                    for p in parts {
                        let psize = read_sys_num(&format!("/sys/block/{name}/{p}/size")) * 512;
                        if psize > 0 {
                            out.push(DeviceInfo { path: format!("/dev/{p}"), label: "  partition".into(), size: psize });
                        }
                    }
                }
            }
        }
    }
    #[cfg(windows)]
    {
        for i in 0..16 {
            let p = format!(r"\\.\PhysicalDrive{i}");
            if let Ok(d) = Disk::open(&p) {
                out.push(DeviceInfo { path: p, label: format!("Disk {i}"), size: d.size });
            }
        }
        for c in b'A'..=b'Z' {
            let root = format!("{}:\\", c as char);
            if std::path::Path::new(&root).exists() {
                let p = format!(r"\\.\{}:", c as char);
                out.push(DeviceInfo { path: p, label: format!("Drive {}:", c as char), size: 0 });
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        for i in 0..16 {
            let p = format!("/dev/disk{i}");
            if std::path::Path::new(&p).exists() {
                out.push(DeviceInfo { path: format!("/dev/rdisk{i}"), label: format!("Disk {i}"), size: 0 });
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn read_sys_num(p: &str) -> u64 {
    std::fs::read_to_string(p).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
}

#[cfg(target_os = "linux")]
fn has_backing(name: &str) -> bool {
    std::fs::read_to_string(format!("/sys/block/{name}/loop/backing_file")).is_ok()
}

pub fn human_size(n: u64) -> String {
    const U: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if v >= 100.0 {
        format!("{:.0} {}", v, U[i])
    } else if v >= 10.0 {
        format!("{:.1} {}", v, U[i])
    } else {
        format!("{:.2} {}", v, U[i])
    }
}
