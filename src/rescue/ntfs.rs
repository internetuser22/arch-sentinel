//! Name-preserving undelete for NTFS: reads every record of the Master File Table
//! and lists the ones marked "not in use" with their names, folders and data runs.

use crate::rescue::disk::{le16, le32, le64, Disk};
use crate::rescue::fat::{push_extent, Sink};
use crate::rescue::model::{content_matches, ext_of, Chance, Found, Method, Volume};
use std::collections::HashMap;

struct Rec {
    in_use: bool,
    is_dir: bool,
    base: u64,
    name: Option<(String, u64)>,
    fn_size: u64,
    data: Option<DataAttr>,
    has_attr_list: bool,
}

enum DataAttr {
    Resident(Vec<u8>),
    Runs { runs: Vec<(Option<u64>, u64)>, size: u64 },
}

fn fixup(rec: &mut [u8]) -> bool {
    if rec.len() < 48 || &rec[0..4] != b"FILE" {
        return false;
    }
    let usa_off = le16(&rec[4..6]) as usize;
    let usa_cnt = le16(&rec[6..8]) as usize;
    if usa_cnt < 2 || usa_off + usa_cnt * 2 > rec.len() {
        return false;
    }
    let stride = rec.len() / (usa_cnt - 1);
    if stride < 256 {
        return false;
    }
    let usn = [rec[usa_off], rec[usa_off + 1]];
    for i in 1..usa_cnt {
        let end = i * stride - 2;
        if end + 2 > rec.len() {
            break;
        }
        if rec[end] != usn[0] || rec[end + 1] != usn[1] {
            return false;
        }
        rec[end] = rec[usa_off + i * 2];
        rec[end + 1] = rec[usa_off + i * 2 + 1];
    }
    true
}

/// Decode a data-run list into (cluster or None for a hole, cluster count).
fn decode_runs(b: &[u8]) -> Vec<(Option<u64>, u64)> {
    let mut out = Vec::new();
    let mut i = 0;
    let mut lcn: i64 = 0;
    while i < b.len() && out.len() < 100_000 {
        let h = b[i];
        if h == 0 {
            break;
        }
        let ls = (h & 0x0F) as usize;
        let os = (h >> 4) as usize;
        i += 1;
        if ls == 0 || ls > 8 || os > 8 || i + ls + os > b.len() {
            break;
        }
        let mut len: u64 = 0;
        for k in 0..ls {
            len |= (b[i + k] as u64) << (8 * k);
        }
        i += ls;
        if os == 0 {
            out.push((None, len));
        } else {
            let mut off: i64 = 0;
            for k in 0..os {
                off |= (b[i + k] as i64) << (8 * k);
            }
            if b[i + os - 1] & 0x80 != 0 && os < 8 {
                off -= 1i64 << (8 * os);
            }
            lcn += off;
            if lcn < 0 {
                break;
            }
            out.push((Some(lcn as u64), len));
        }
        i += os;
    }
    out
}

fn parse_record(rec: &[u8]) -> Rec {
    let flags = le16(&rec[22..24]);
    let mut r = Rec {
        in_use: flags & 1 != 0,
        is_dir: flags & 2 != 0,
        base: le64(&rec[32..40]) & 0x0000_FFFF_FFFF_FFFF,
        name: None,
        fn_size: 0,
        data: None,
        has_attr_list: false,
    };
    let mut best_ns = 99u8;
    let mut off = le16(&rec[20..22]) as usize;
    while off + 16 <= rec.len() {
        let t = le32(&rec[off..off + 4]);
        if t == 0xFFFF_FFFF {
            break;
        }
        let len = le32(&rec[off + 4..off + 8]) as usize;
        if len < 16 || off + len > rec.len() {
            break;
        }
        let a = &rec[off..off + len];
        let nonres = a[8] != 0;
        let name_len = a[9];
        match t {
            0x20 => r.has_attr_list = true,
            0x30 if !nonres && a.len() >= 24 => {
                let vl = le32(&a[16..20]) as usize;
                let vo = le16(&a[20..22]) as usize;
                if vo + vl <= a.len() && vl >= 66 {
                    let v = &a[vo..vo + vl];
                    let parent = le64(&v[0..8]) & 0x0000_FFFF_FFFF_FFFF;
                    let nlen = v[64] as usize;
                    let ns = v[65];
                    if 66 + nlen * 2 <= v.len() {
                        let chars: Vec<u16> = v[66..66 + nlen * 2].chunks(2).map(le16).collect();
                        // Prefer the long (Win32/POSIX) name over the short DOS one.
                        let rank = match ns {
                            1 | 3 => 0,
                            0 => 1,
                            _ => 2,
                        };
                        if rank < best_ns {
                            best_ns = rank;
                            r.name = Some((String::from_utf16_lossy(&chars), parent));
                            r.fn_size = le64(&v[48..56]);
                        }
                    }
                }
            }
            0x80 if name_len == 0 => {
                if !nonres && a.len() >= 24 {
                    let vl = le32(&a[16..20]) as usize;
                    let vo = le16(&a[20..22]) as usize;
                    if vo + vl <= a.len() {
                        r.data = Some(DataAttr::Resident(a[vo..vo + vl].to_vec()));
                    }
                } else if nonres && a.len() >= 64 {
                    let start_vcn = le64(&a[16..24]);
                    let ro = le16(&a[32..34]) as usize;
                    let size = le64(&a[48..56]);
                    if start_vcn == 0 && ro < a.len() {
                        r.data = Some(DataAttr::Runs { runs: decode_runs(&a[ro..]), size });
                    }
                }
            }
            _ => {}
        }
        off += len;
    }
    r
}

pub fn undelete_ntfs(disk: &Disk, vol: &Volume, sink: &mut Sink) {
    let b = disk.read_vec(vol.boot, 512);
    let bps = le16(&b[11..13]) as u64;
    let spc_raw = b[13];
    let spc = if spc_raw > 0x80 { 1u64 << (256 - spc_raw as u32) } else { spc_raw as u64 };
    let cluster = bps * spc;
    let mft_lcn = le64(&b[48..56]);
    let cpr = b[64] as i8;
    let rec_size = if cpr < 0 { 1u64 << (-cpr as u32) } else { cpr as u64 * cluster };
    if cluster == 0 || !(256..=65536).contains(&rec_size) {
        (sink.log)(format!("{}: the NTFS header couldn't be read.", vol.label));
        return;
    }
    let abs = |lcn: u64| vol.start + lcn * cluster;
    let include = sink.include_existing;

    // Record 0 describes where the whole table lives.
    let mut r0 = disk.read_vec(abs(mft_lcn), rec_size as usize);
    if !fixup(&mut r0) {
        // Try the mirror copy.
        let mirr = le64(&b[56..64]);
        r0 = disk.read_vec(abs(mirr), rec_size as usize);
        if !fixup(&mut r0) {
            (sink.log)(format!("{}: the NTFS file table is damaged.", vol.label));
            return;
        }
    }
    let p0 = parse_record(&r0);
    let Some(DataAttr::Runs { runs, size: mft_size }) = p0.data else {
        (sink.log)(format!("{}: the NTFS file table couldn't be located.", vol.label));
        return;
    };
    // Count every record the table has room for: deleted ones can sit past its used size.
    let room: u64 = runs.iter().map(|r| r.1 * cluster).sum::<u64>().max(mft_size);
    let total = (room / rec_size).min(50_000_000);

    // Current cluster usage, to judge whether a file's space was reused.
    let bitmap = read_bitmap(disk, vol, abs(mft_lcn), rec_size, &runs, cluster);

    let mut recs: HashMap<u64, Rec> = HashMap::new();
    let mut dir_names: HashMap<u64, (String, u64, bool)> = HashMap::new();
    let mut idx: u64 = 0;
    let chunk_recs = (4u64 << 20) / rec_size;
    'runs: for (lcn, len) in &runs {
        let Some(lcn) = lcn else {
            idx += len * cluster / rec_size;
            continue;
        };
        let run_bytes = len * cluster;
        let mut done = 0u64;
        while done < run_bytes {
            if (sink.cancelled)() || idx >= total {
                break 'runs;
            }
            let n = chunk_recs.min((run_bytes - done) / rec_size).max(1);
            let buf = disk.read_vec(abs(*lcn) + done, (n * rec_size) as usize);
            for k in 0..n as usize {
                if idx >= total {
                    break;
                }
                let mut rec = buf[k * rec_size as usize..(k + 1) * rec_size as usize].to_vec();
                if fixup(&mut rec) {
                    let p = parse_record(&rec);
                    if p.base == 0 {
                        if p.is_dir {
                            if let Some((n, parent)) = &p.name {
                                dir_names.insert(idx, (n.clone(), *parent, !p.in_use));
                            }
                        } else if (!p.in_use || include) && p.name.is_some() {
                            recs.insert(idx, p);
                        }
                    }
                }
                idx += 1;
            }
            done += n * rec_size;
        }
    }

    let path_of = |mut parent: u64| -> (String, bool) {
        let mut parts = Vec::new();
        let mut deleted = false;
        for _ in 0..64 {
            if parent == 5 {
                break;
            }
            match dir_names.get(&parent) {
                Some((n, p, del)) => {
                    parts.push(n.clone());
                    deleted |= *del;
                    if *p == parent {
                        break;
                    }
                    parent = *p;
                }
                None => {
                    parts.push(format!("(lost folder {parent})"));
                    break;
                }
            }
        }
        parts.reverse();
        (format!("/{}", parts.join("/")), deleted)
    };

    let mut keys: Vec<u64> = recs.keys().copied().collect();
    keys.sort();
    for k in keys {
        let r = &recs[&k];
        let (name, parent) = r.name.clone().unwrap();
        if (name.starts_with('$') && parent == 5) || parent == 11 {
            continue;
        }
        let (folder, folder_deleted) = path_of(parent);
        let ext = ext_of(&name);
        let mut extents = Vec::new();
        let mut inline = None;
        let mut size = r.fn_size;
        let mut chance = Chance::Good;
        let mut note = String::new();
        match &r.data {
            Some(DataAttr::Resident(d)) => {
                size = d.len() as u64;
                inline = Some(d.clone());
                note = "Small file kept inside the file table".into();
            }
            Some(DataAttr::Runs { runs, size: s }) => {
                size = *s;
                let mut left = size;
                let mut reused = 0u64;
                let mut total_cl = 0u64;
                for (lcn, len) in runs {
                    let bytes = (len * cluster).min(left);
                    if let Some(l) = lcn {
                        push_extent(&mut extents, abs(*l), bytes);
                        let used_cl = (bytes + cluster - 1) / cluster;
                        for c in *l..*l + used_cl.min(1 << 20) {
                            total_cl += 1;
                            if bit(&bitmap, c) {
                                reused += 1;
                            }
                        }
                    } else {
                        // A hole: stored as zeros.
                        extents.push((u64::MAX, bytes));
                    }
                    left -= bytes;
                    if left == 0 {
                        break;
                    }
                }
                if reused > 0 && !r.in_use {
                    chance = if reused < total_cl { Chance::Fair } else { Chance::Poor };
                    note = "Some of its space is now used by other files".into();
                }
            }
            None => {
                chance = Chance::Poor;
                note = if r.has_attr_list {
                    "Stored in many pieces; the list of pieces is gone".into()
                } else {
                    "Its location was wiped".into()
                };
            }
        }
        if let Some(d) = &inline {
            if content_matches(&ext, d) == Some(false) {
                chance = Chance::Fair;
            }
        } else if let Some(&(off, _)) = extents.iter().find(|e| e.0 != u64::MAX) {
            let head = disk.read_vec(off, 64);
            if content_matches(&ext, &head) == Some(false) {
                chance = Chance::Poor;
                note = "Its content no longer looks like this kind of file".into();
            }
        }
        if folder_deleted && note.is_empty() {
            note = "Its folder was deleted too".into();
        }
        if r.in_use && note.is_empty() {
            note = "Not deleted, but its partition was lost".into();
        }
        (sink.emit)(Found {
            name,
            folder,
            ext,
            size,
            method: Method::Undelete,
            fs: "NTFS".into(),
            volume: vol.label.clone(),
            extents,
            inline_data: inline,
            chance,
            note,
        });
    }
}

fn bit(map: &[u8], c: u64) -> bool {
    map.get((c / 8) as usize).map(|b| b & (1 << (c % 8)) != 0).unwrap_or(false)
}

/// Read $Bitmap (record 6) to know which clusters are in use now.
fn read_bitmap(disk: &Disk, vol: &Volume, mft_abs: u64, rec_size: u64, mft_runs: &[(Option<u64>, u64)], cluster: u64) -> Vec<u8> {
    // Record 6 is almost always in the first run of the table.
    let first_run_bytes = mft_runs.first().map(|r| r.1 * cluster).unwrap_or(0);
    if first_run_bytes < 7 * rec_size {
        return Vec::new();
    }
    let mut rec = disk.read_vec(mft_abs + 6 * rec_size, rec_size as usize);
    if !fixup(&mut rec) {
        return Vec::new();
    }
    let p = parse_record(&rec);
    match p.data {
        Some(DataAttr::Resident(d)) => d,
        Some(DataAttr::Runs { runs, size }) => {
            let size = size.min(256 << 20);
            let mut out = Vec::with_capacity(size as usize);
            for (lcn, len) in runs {
                if out.len() as u64 >= size {
                    break;
                }
                let want = (len * cluster).min(size - out.len() as u64) as usize;
                match lcn {
                    Some(l) => out.extend(disk.read_vec(vol.start + l * cluster, want)),
                    None => out.extend(std::iter::repeat(0).take(want)),
                }
            }
            out
        }
        None => Vec::new(),
    }
}

/// Which clusters an NTFS volume uses now (from $Bitmap).
pub fn ntfs_alloc(disk: &Disk, vol: &Volume) -> Option<crate::rescue::wipe::AllocMap> {
    let b = disk.read_vec(vol.boot, 512);
    let bps = le16(&b[11..13]) as u64;
    let spc_raw = b[13];
    let spc = if spc_raw > 0x80 { 1u64 << (256 - spc_raw as u32) } else { spc_raw as u64 };
    let cluster = bps * spc;
    let mft_lcn = le64(&b[48..56]);
    let cpr = b[64] as i8;
    let rec_size = if cpr < 0 { 1u64 << (-cpr as u32) } else { cpr as u64 * cluster };
    if cluster == 0 || !(256..=65536).contains(&rec_size) {
        return None;
    }
    let mft_abs = vol.start + mft_lcn * cluster;
    let mut r0 = disk.read_vec(mft_abs, rec_size as usize);
    if !fixup(&mut r0) {
        return None;
    }
    let Some(DataAttr::Runs { runs, .. }) = parse_record(&r0).data else { return None };
    let used = read_bitmap(disk, vol, mft_abs, rec_size, &runs, cluster);
    if used.is_empty() {
        return None;
    }
    let clusters = (le64(&b[40..48]) * bps / cluster).min(used.len() as u64 * 8);
    // Cluster 0 holds the boot sector, so the whole volume is covered by the map.
    Some(crate::rescue::wipe::AllocMap { vol_start: vol.start, vol_end: vol.start + vol.len, base: vol.start, cluster, clusters, used })
}
