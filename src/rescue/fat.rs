//! Name-preserving undelete for FAT12/16/32 (with long file names) and exFAT.

use crate::rescue::disk::{le16, le32, le64, Disk};
use crate::rescue::model::{content_matches, ext_of, Chance, Found, Method, Volume};
use std::collections::HashSet;

pub struct Sink<'a> {
    pub emit: &'a mut dyn FnMut(Found),
    pub log: &'a mut dyn FnMut(String),
    pub cancelled: &'a dyn Fn() -> bool,
    /// List every file, not only deleted ones (for a partition that was itself lost).
    pub include_existing: bool,
}

const MAX_FAT_BYTES: u64 = 512 << 20;
const MAX_DIR_BYTES: usize = 32 << 20;

// ---------------------------------------------------------------- FAT12/16/32

struct Fat<'a> {
    disk: &'a Disk,
    fat_type: u8,
    cluster: u64,
    data_start: u64,
    max_cluster: u32,
    fat: Vec<u8>,
    root_fixed: Option<(u64, u64)>,
    root_cluster: u32,
    fs_name: String,
    vol_label: String,
}

impl<'a> Fat<'a> {
    fn open(disk: &'a Disk, vol: &Volume) -> Option<Fat<'a>> {
        let b = disk.read_vec(vol.boot, 512);
        let bps = le16(&b[11..13]) as u64;
        let spc = b[13] as u64;
        let reserved = le16(&b[14..16]) as u64;
        let nfats = b[16] as u64;
        let root_entries = le16(&b[17..19]) as u64;
        let t16 = le16(&b[19..21]) as u64;
        let total = if t16 != 0 { t16 } else { le32(&b[32..36]) as u64 };
        let f16 = le16(&b[22..24]) as u64;
        let fat_sectors = if f16 != 0 { f16 } else { le32(&b[36..40]) as u64 };
        if bps == 0 || spc == 0 || fat_sectors == 0 || total == 0 {
            return None;
        }
        let root_sectors = (root_entries * 32 + bps - 1) / bps;
        let first_data = reserved + nfats * fat_sectors + root_sectors;
        if first_data >= total {
            return None;
        }
        let clusters = (total - first_data) / spc;
        let fat_type = if clusters < 4085 {
            12
        } else if clusters < 65525 {
            16
        } else {
            32
        };
        let fat_bytes = (fat_sectors * bps).min(MAX_FAT_BYTES);
        let fat = disk.read_vec(vol.start + reserved * bps, fat_bytes as usize);
        let root_fixed = if fat_type != 32 {
            Some((vol.start + (reserved + nfats * fat_sectors) * bps, root_sectors * bps))
        } else {
            None
        };
        Some(Fat {
            disk,
            fat_type,
            cluster: spc * bps,
            data_start: vol.start + first_data * bps,
            max_cluster: (clusters + 1) as u32,
            fat,
            root_fixed,
            root_cluster: le32(&b[44..48]),
            fs_name: format!("FAT{fat_type}"),
            vol_label: vol.label.clone(),
        })
    }

    fn entry(&self, n: u32) -> u32 {
        let n = n as usize;
        match self.fat_type {
            12 => {
                let off = n + n / 2;
                if off + 1 >= self.fat.len() {
                    return 0;
                }
                let v = le16(&self.fat[off..off + 2]) as u32;
                if n & 1 == 1 {
                    v >> 4
                } else {
                    v & 0xFFF
                }
            }
            16 => {
                let off = n * 2;
                if off + 2 > self.fat.len() {
                    return 0;
                }
                le16(&self.fat[off..off + 2]) as u32
            }
            _ => {
                let off = n * 4;
                if off + 4 > self.fat.len() {
                    return 0;
                }
                le32(&self.fat[off..off + 4]) & 0x0FFF_FFFF
            }
        }
    }

    fn is_end(&self, v: u32) -> bool {
        match self.fat_type {
            12 => v >= 0xFF8,
            16 => v >= 0xFFF8,
            _ => v >= 0x0FFF_FFF8,
        }
    }

    fn valid(&self, c: u32) -> bool {
        c >= 2 && c <= self.max_cluster
    }

    fn cluster_off(&self, c: u32) -> u64 {
        self.data_start + (c as u64 - 2) * self.cluster
    }

    fn chain(&self, start: u32, max: usize) -> Vec<u32> {
        let mut out = Vec::new();
        let mut c = start;
        let mut seen = HashSet::new();
        while self.valid(c) && out.len() < max && seen.insert(c) {
            out.push(c);
            let next = self.entry(c);
            if self.is_end(next) || next < 2 {
                break;
            }
            c = next;
        }
        out
    }

    fn read_clusters(&self, cl: &[u32]) -> Vec<u8> {
        let mut v = Vec::with_capacity(cl.len() * self.cluster as usize);
        for &c in cl {
            v.extend(self.disk.read_vec(self.cluster_off(c), self.cluster as usize));
            if v.len() > MAX_DIR_BYTES {
                break;
            }
        }
        v
    }

    /// A deleted folder's cluster chain is gone; read its clusters one after another
    /// while they still look like a folder.
    fn read_deleted_dir(&self, start: u32) -> Option<Vec<u8>> {
        if !self.valid(start) {
            return None;
        }
        let first = self.disk.read_vec(self.cluster_off(start), self.cluster as usize);
        // A folder starts with its "." entry.
        if &first[0..11] != b".          " || first[11] & 0x10 == 0 {
            return None;
        }
        let mut v = first;
        let mut c = start + 1;
        while self.valid(c) && v.len() < 64 * self.cluster as usize {
            if v.chunks(32).any(|e| e[0] == 0) || self.entry(c) != 0 {
                break;
            }
            let next = self.disk.read_vec(self.cluster_off(c), self.cluster as usize);
            if !looks_like_dir(&next) {
                break;
            }
            v.extend(next);
            c += 1;
        }
        Some(v)
    }

    fn walk(&self, dir: &[u8], path: &str, parent_deleted: bool, depth: usize, seen: &mut HashSet<u32>, sink: &mut Sink) {
        if depth > 40 || (sink.cancelled)() {
            return;
        }
        for e in parse_fat_dir(dir) {
            if e.is_dir {
                if !e.deleted && !parent_deleted {
                    // Live folder: follow it to find deleted files inside.
                    if !self.valid(e.start) || !seen.insert(e.start) {
                        continue;
                    }
                    let bytes = self.read_clusters(&self.chain(e.start, 1 << 16));
                    self.walk(&bytes, &format!("{path}/{}", e.name), false, depth + 1, seen, sink);
                } else {
                    if !self.valid(e.start) || !seen.insert(e.start) {
                        continue;
                    }
                    match self.read_deleted_dir(e.start) {
                        Some(bytes) => self.walk(&bytes, &format!("{path}/{}", e.name), true, depth + 1, seen, sink),
                        None => (sink.log)(format!(
                            "Deleted folder \"{path}/{}\" has been overwritten; its files may still turn up in the content search.",
                            e.name
                        )),
                    }
                }
                continue;
            }
            if !(e.deleted || parent_deleted || sink.include_existing) {
                continue;
            }
            let found = self.make_found(&e, path, parent_deleted);
            (sink.emit)(found);
        }
    }

    fn make_found(&self, e: &FatEntry, path: &str, parent_deleted: bool) -> Found {
        let size = e.size as u64;
        let need = ((size + self.cluster - 1) / self.cluster) as u32;
        let mut extents = Vec::new();
        let mut chance;
        let mut note = String::new();
        if size == 0 {
            chance = Chance::Good;
            note = "Empty file".into();
        } else if !self.valid(e.start) || !self.valid(e.start.saturating_add(need - 1)) {
            chance = Chance::Poor;
            note = "Its location was wiped".into();
        } else {
            let chain = if !e.deleted { self.chain(e.start, need as usize + 1) } else { Vec::new() };
            let clusters: Vec<u32> = if chain.len() == need as usize { chain } else { (e.start..e.start + need).collect() };
            let reused = clusters.iter().filter(|&&c| self.entry(c) != 0).count();
            chance = if !e.deleted && reused == clusters.len() {
                Chance::Good
            } else if reused == 0 {
                Chance::Good
            } else if reused < clusters.len() {
                note = "Some of its space is now used by other files".into();
                Chance::Fair
            } else {
                note = "Its space is now used by other files".into();
                Chance::Poor
            };
            let mut left = size;
            for &c in &clusters {
                let len = left.min(self.cluster);
                push_extent(&mut extents, self.cluster_off(c), len);
                left -= len;
            }
        }
        let ext = ext_of(&e.name);
        if let Some(&(off, _)) = extents.first() {
            let head = self.disk.read_vec(off, 64);
            if content_matches(&ext, &head) == Some(false) {
                chance = Chance::Poor;
                if note.is_empty() {
                    note = "Its content no longer looks like this kind of file".into();
                }
            }
        }
        if parent_deleted && note.is_empty() {
            note = "Its folder was deleted too".into();
        }
        if !e.deleted && !parent_deleted && note.is_empty() {
            note = "Not deleted, but its partition was lost".into();
        }
        Found {
            name: e.name.clone(),
            folder: if path.is_empty() { "/".into() } else { path.to_string() },
            ext,
            size,
            method: Method::Undelete,
            fs: self.fs_name.clone(),
            volume: self.vol_label.clone(),
            extents,
            inline_data: None,
            chance,
            note,
        }
    }
}

pub fn push_extent(ext: &mut Vec<(u64, u64)>, off: u64, len: u64) {
    if len == 0 {
        return;
    }
    if let Some(last) = ext.last_mut() {
        if last.0 + last.1 == off {
            last.1 += len;
            return;
        }
    }
    ext.push((off, len));
}

fn looks_like_dir(b: &[u8]) -> bool {
    let mut good = 0;
    for e in b.chunks(32) {
        if e[0] == 0 {
            break;
        }
        let attr = e[11];
        if attr == 0x0F || (attr & 0xC0 == 0 && (e[0] == 0xE5 || e[0] >= 0x20)) {
            good += 1;
        } else {
            return false;
        }
    }
    good > 0 || b[0] == 0
}

struct FatEntry {
    name: String,
    is_dir: bool,
    deleted: bool,
    start: u32,
    size: u32,
}

fn lfn_checksum(sn: &[u8; 11]) -> u8 {
    let mut sum: u8 = 0;
    for &b in sn {
        sum = ((sum & 1) << 7).wrapping_add(sum >> 1).wrapping_add(b);
    }
    sum
}

fn short_name(sn: &[u8; 11], case: u8) -> String {
    let base: String = sn[0..8].iter().map(|&b| b as char).collect::<String>().trim_end().to_string();
    let ext: String = sn[8..11].iter().map(|&b| b as char).collect::<String>().trim_end().to_string();
    let base = if case & 0x08 != 0 { base.to_lowercase() } else { base };
    let ext = if case & 0x10 != 0 { ext.to_lowercase() } else { ext };
    if ext.is_empty() {
        base
    } else {
        format!("{base}.{ext}")
    }
}

fn parse_fat_dir(dir: &[u8]) -> Vec<FatEntry> {
    let mut out = Vec::new();
    // Long-name pieces collected so far: (checksum, 13 characters).
    let mut lfn: Vec<(u8, [u16; 13])> = Vec::new();
    for e in dir.chunks_exact(32) {
        if e[0] == 0 {
            break;
        }
        let attr = e[11];
        if attr & 0x3F == 0x0F {
            let mut ch = [0u16; 13];
            let idx = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
            for (k, &i) in idx.iter().enumerate() {
                ch[k] = le16(&e[i..i + 2]);
            }
            if e[0] != 0xE5 && e[0] & 0x40 != 0 {
                lfn.clear();
            }
            if let Some(last) = lfn.last() {
                if last.0 != e[13] {
                    lfn.clear();
                }
            }
            lfn.push((e[13], ch));
            continue;
        }
        let deleted = e[0] == 0xE5;
        let mut sn: [u8; 11] = e[0..11].try_into().unwrap();
        if sn[0] == 0x05 {
            sn[0] = 0xE5;
        }
        let pieces = std::mem::take(&mut lfn);
        if attr & 0x08 != 0 {
            continue; // volume label
        }
        if &sn == b".          " || &sn == b"..         " {
            continue;
        }
        let mut long: Option<String> = None;
        if !pieces.is_empty() {
            let ck = pieces[0].0;
            let mut chars: Vec<u16> = Vec::new();
            for (_, p) in pieces.iter().rev() {
                chars.extend_from_slice(p);
            }
            let end = chars.iter().position(|&c| c == 0 || c == 0xFFFF).unwrap_or(chars.len());
            let name = String::from_utf16_lossy(&chars[..end]);
            if deleted {
                // The first letter of the short name was overwritten; find the one
                // that makes the long-name checksum match.
                let mut tries: Vec<u8> = Vec::new();
                if let Some(c) = name.chars().next() {
                    if c.is_ascii() {
                        tries.push(c.to_ascii_uppercase() as u8);
                    }
                }
                tries.extend(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_~!#$%&'()-@^`{}".iter());
                for t in tries {
                    let mut s2 = sn;
                    s2[0] = t;
                    if lfn_checksum(&s2) == ck {
                        sn = s2;
                        long = Some(name.clone());
                        break;
                    }
                }
            } else if lfn_checksum(&sn) == ck {
                long = Some(name);
            }
        }
        if deleted && long.is_none() {
            sn[0] = b'_';
        }
        let name = long.unwrap_or_else(|| short_name(&sn, e[12]));
        if name.is_empty() || name.chars().any(|c| c == '\0') {
            continue;
        }
        let hi = le16(&e[20..22]) as u32;
        let lo = le16(&e[26..28]) as u32;
        out.push(FatEntry {
            name,
            is_dir: attr & 0x10 != 0,
            deleted,
            start: (hi << 16) | lo,
            size: le32(&e[28..32]),
        });
    }
    out
}

pub fn undelete_fat(disk: &Disk, vol: &Volume, sink: &mut Sink) {
    let Some(fat) = Fat::open(disk, vol) else {
        (sink.log)(format!("{}: the FAT file system header couldn't be read.", vol.label));
        return;
    };
    let root = match fat.root_fixed {
        Some((off, len)) => disk.read_vec(off, len as usize),
        None => fat.read_clusters(&fat.chain(fat.root_cluster, 1 << 16)),
    };
    let mut seen = HashSet::new();
    seen.insert(fat.root_cluster);
    fat.walk(&root, "", false, 0, &mut seen, sink);
}

// ---------------------------------------------------------------- exFAT

struct ExFat<'a> {
    disk: &'a Disk,
    cluster: u64,
    heap: u64,
    count: u32,
    fat: Vec<u8>,
    bitmap: Vec<u8>,
    vol_label: String,
}

struct ExEntry {
    name: String,
    is_dir: bool,
    deleted: bool,
    no_chain: bool,
    first: u32,
    len: u64,
}

impl<'a> ExFat<'a> {
    fn valid(&self, c: u32) -> bool {
        c >= 2 && c < self.count + 2
    }
    fn off(&self, c: u32) -> u64 {
        self.heap + (c as u64 - 2) * self.cluster
    }
    fn entry(&self, c: u32) -> u32 {
        let o = c as usize * 4;
        if o + 4 > self.fat.len() {
            0
        } else {
            le32(&self.fat[o..o + 4])
        }
    }
    fn used(&self, c: u32) -> bool {
        let i = (c - 2) as usize;
        self.bitmap.get(i / 8).map(|b| b & (1 << (i % 8)) != 0).unwrap_or(false)
    }
    fn chain(&self, start: u32, max: usize) -> Vec<u32> {
        let mut out = Vec::new();
        let mut c = start;
        let mut seen = HashSet::new();
        while self.valid(c) && out.len() < max && seen.insert(c) {
            out.push(c);
            let n = self.entry(c);
            if n >= 0xFFFF_FFF7 || n < 2 {
                break;
            }
            c = n;
        }
        out
    }
    fn clusters_for(&self, first: u32, len: u64, no_chain: bool, trust_fat: bool) -> Vec<u32> {
        let need = ((len + self.cluster - 1) / self.cluster).max(1) as usize;
        if !no_chain && trust_fat {
            let ch = self.chain(first, need + 1);
            if ch.len() == need {
                return ch;
            }
        }
        (first..first.saturating_add(need as u32)).filter(|&c| self.valid(c)).collect()
    }
    fn read(&self, cl: &[u32], len: u64) -> Vec<u8> {
        let mut v = Vec::new();
        for &c in cl {
            v.extend(self.disk.read_vec(self.off(c), self.cluster as usize));
            if v.len() > MAX_DIR_BYTES {
                break;
            }
        }
        v.truncate(len as usize);
        v
    }

    fn parse_dir(&self, dir: &[u8]) -> Vec<ExEntry> {
        let mut out = Vec::new();
        let n = dir.len() / 32;
        let e = |i: usize| &dir[i * 32..i * 32 + 32];
        let mut i = 0;
        while i < n {
            let t = e(i)[0];
            if t == 0 {
                break;
            }
            if t & 0x7F != 0x05 {
                i += 1;
                continue;
            }
            let in_use = t & 0x80 != 0;
            let sc = e(i)[1] as usize;
            let attr = le16(&e(i)[4..6]);
            if sc < 2 || i + sc >= n {
                i += 1;
                continue;
            }
            let s = e(i + 1);
            if s[0] & 0x7F != 0x40 || (s[0] & 0x80 != 0) != in_use {
                i += 1;
                continue;
            }
            let name_len = s[3] as usize;
            let mut chars: Vec<u16> = Vec::new();
            let mut ok = true;
            for k in 2..=sc {
                let f = e(i + k);
                if f[0] & 0x7F != 0x41 || (f[0] & 0x80 != 0) != in_use {
                    ok = false;
                    break;
                }
                for j in 0..15 {
                    chars.push(le16(&f[2 + j * 2..4 + j * 2]));
                }
            }
            if !ok {
                i += 1;
                continue;
            }
            chars.truncate(name_len);
            out.push(ExEntry {
                name: String::from_utf16_lossy(&chars),
                is_dir: attr & 0x10 != 0,
                deleted: !in_use,
                no_chain: s[1] & 0x02 != 0,
                first: le32(&s[20..24]),
                len: le64(&s[24..32]),
            });
            i += 1 + sc;
        }
        out
    }

    fn walk(&self, dir: &[u8], path: &str, parent_deleted: bool, depth: usize, seen: &mut HashSet<u32>, sink: &mut Sink) {
        if depth > 40 || (sink.cancelled)() {
            return;
        }
        for e in self.parse_dir(dir) {
            let gone = e.deleted || parent_deleted;
            if e.is_dir {
                if !self.valid(e.first) || !seen.insert(e.first) {
                    continue;
                }
                let cl = self.clusters_for(e.first, e.len, e.no_chain, !gone);
                let bytes = self.read(&cl, e.len);
                self.walk(&bytes, &format!("{path}/{}", e.name), gone, depth + 1, seen, sink);
                continue;
            }
            if !gone && !sink.include_existing {
                continue;
            }
            let ext = ext_of(&e.name);
            let mut extents = Vec::new();
            let mut chance = Chance::Good;
            let mut note = String::new();
            if e.len == 0 {
                note = "Empty file".into();
            } else if !self.valid(e.first) {
                chance = Chance::Poor;
                note = "Its location was wiped".into();
            } else {
                let cl = self.clusters_for(e.first, e.len, e.no_chain, !e.deleted);
                let reused = cl.iter().filter(|&&c| self.used(c)).count();
                if reused > 0 && e.deleted {
                    chance = if reused < cl.len() { Chance::Fair } else { Chance::Poor };
                    note = "Its space is now used by other files".into();
                } else if !e.no_chain && e.deleted {
                    chance = Chance::Fair;
                    note = "It may have been stored in pieces".into();
                }
                let mut left = e.len;
                for &c in &cl {
                    let l = left.min(self.cluster);
                    push_extent(&mut extents, self.off(c), l);
                    left -= l;
                }
                let head = self.disk.read_vec(self.off(e.first), 64);
                if content_matches(&ext, &head) == Some(false) {
                    chance = Chance::Poor;
                    note = "Its content no longer looks like this kind of file".into();
                }
            }
            if parent_deleted && note.is_empty() {
                note = "Its folder was deleted too".into();
            }
            if !gone && note.is_empty() {
                note = "Not deleted, but its partition was lost".into();
            }
            (sink.emit)(Found {
                name: e.name.clone(),
                folder: if path.is_empty() { "/".into() } else { path.to_string() },
                ext,
                size: e.len,
                method: Method::Undelete,
                fs: "exFAT".into(),
                volume: self.vol_label.clone(),
                extents,
                inline_data: None,
                chance,
                note,
            });
        }
    }
}

fn open_exfat<'a>(disk: &'a Disk, vol: &Volume) -> Option<(ExFat<'a>, Vec<u8>, u32)> {
    let b = disk.read_vec(vol.boot, 512);
    let bps_shift = b[108] as u32;
    let spc_shift = b[109] as u32;
    if !(9..=12).contains(&bps_shift) || spc_shift > 25 {
        return None;
    }
    let bps = 1u64 << bps_shift;
    let fat_off = le32(&b[80..84]) as u64 * bps;
    let fat_len = (le32(&b[84..88]) as u64 * bps).min(MAX_FAT_BYTES);
    let mut ex = ExFat {
        disk,
        cluster: bps << spc_shift,
        heap: vol.start + le32(&b[88..92]) as u64 * bps,
        count: le32(&b[92..96]),
        fat: disk.read_vec(vol.start + fat_off, fat_len as usize),
        bitmap: Vec::new(),
        vol_label: vol.label.clone(),
    };
    let root_first = le32(&b[96..100]);
    let root_cl = ex.chain(root_first, 1 << 16);
    let root = ex.read(&root_cl, u64::MAX);
    // The allocation bitmap tells which clusters are in use now.
    for e in root.chunks_exact(32) {
        if e[0] == 0 {
            break;
        }
        if e[0] == 0x81 {
            let first = le32(&e[20..24]);
            let len = le64(&e[24..32]).min(MAX_FAT_BYTES);
            let cl = ex.clusters_for(first, len, false, true);
            ex.bitmap = ex.read(&cl, len);
            break;
        }
    }
    Some((ex, root, root_first))
}

pub fn undelete_exfat(disk: &Disk, vol: &Volume, sink: &mut Sink) {
    let Some((ex, root, root_first)) = open_exfat(disk, vol) else {
        (sink.log)(format!("{}: the exFAT header couldn't be read.", vol.label));
        return;
    };
    let mut seen = HashSet::new();
    seen.insert(root_first);
    ex.walk(&root, "", false, 0, &mut seen, sink);
}

/// Which clusters a FAT volume uses now.
pub fn fat_alloc(disk: &Disk, vol: &Volume) -> Option<crate::rescue::wipe::AllocMap> {
    let f = Fat::open(disk, vol)?;
    let n = (f.max_cluster - 1) as usize;
    let mut used = vec![0u8; (n + 7) / 8];
    for i in 0..n {
        if f.entry(i as u32 + 2) != 0 {
            used[i / 8] |= 1 << (i % 8);
        }
    }
    Some(crate::rescue::wipe::AllocMap { vol_start: vol.start, vol_end: vol.start + vol.len, base: f.data_start, cluster: f.cluster, clusters: n as u64, used })
}

/// Which clusters an exFAT volume uses now.
pub fn exfat_alloc(disk: &Disk, vol: &Volume) -> Option<crate::rescue::wipe::AllocMap> {
    let (ex, _, _) = open_exfat(disk, vol)?;
    if ex.bitmap.is_empty() {
        return None;
    }
    Some(crate::rescue::wipe::AllocMap { vol_start: vol.start, vol_end: vol.start + vol.len, base: ex.heap, cluster: ex.cluster, clusters: ex.count as u64, used: ex.bitmap })
}
