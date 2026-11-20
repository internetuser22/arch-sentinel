//! Finding previous partitions: ones that were deleted, or replaced by
//! re-partitioning or reformatting, but whose file systems are still on the disk.
//! Each candidate boot sector (or its backup copy) is checked against the
//! structures it points to before it's believed.

use crate::rescue::disk::{human_size, le16, le32, le64, Disk};
use crate::rescue::model::{FsKind, Volume};
use crate::rescue::parts::{boot_volume_len, classify_boot};

fn volume(start: u64, len: u64, fs: FsKind, boot: u64, disk: &Disk) -> Option<Volume> {
    if start >= disk.size {
        return None;
    }
    let len = if len == 0 { disk.size - start } else { len.min(disk.size - start) };
    let from_backup = boot != start;
    Some(Volume {
        label: format!("Previous {} partition at {}", fs.label(), human_size(start)),
        start,
        len,
        fs,
        kind: if from_backup {
            "previous partition, rebuilt from its backup boot sector".into()
        } else {
            "previous partition, found by searching the disk".into()
        },
        lost: true,
        boot,
    })
}

fn ntfs_ok(disk: &Disk, start: u64, b: &[u8]) -> bool {
    let bps = le16(&b[11..13]) as u64;
    let spc = if b[13] > 0x80 { 1u64 << (256 - b[13] as u32) } else { b[13] as u64 };
    let mft = le64(&b[48..56]);
    let Some(off) = mft.checked_mul(bps * spc).and_then(|o| o.checked_add(start)) else { return false };
    off + 4 <= disk.size && &disk.read_vec(off, 4)[..] == b"FILE"
}

fn fat_ok(disk: &Disk, start: u64, b: &[u8]) -> bool {
    let bps = le16(&b[11..13]) as u64;
    let reserved = le16(&b[14..16]) as u64;
    let v = disk.read_vec(start + reserved * bps, 3);
    v[0] == b[21] && v[0] >= 0xF0 && v[1] == 0xFF && v[2] == 0xFF
}

fn exfat_ok(disk: &Disk, start: u64, b: &[u8]) -> bool {
    let bps = 1u64 << b[108];
    let fat = le32(&b[80..84]) as u64 * bps;
    disk.read_vec(start + fat, 4) == [0xF8, 0xFF, 0xFF, 0xFF]
}

/// Is there the start (or a backup copy) of a file system in this sector at `off`?
pub fn check(disk: &Disk, off: u64, sec: &[u8]) -> Option<Volume> {
    if sec.len() < 512 {
        return None;
    }
    if let Some(fs) = classify_boot(sec) {
        let len = boot_volume_len(sec, fs);
        match fs {
            FsKind::Ntfs => {
                // The backup copy sits in the last sector of the partition.
                let bps = le16(&sec[11..13]) as u64;
                let total = le64(&sec[40..48]);
                if let Some(s) = total.checked_mul(bps).and_then(|t| off.checked_sub(t)) {
                    if s != off && ntfs_ok(disk, s, sec) {
                        return volume(s, len, fs, off, disk);
                    }
                }
                if ntfs_ok(disk, off, sec) {
                    return volume(off, len, fs, off, disk);
                }
            }
            FsKind::Fat => {
                if fat_ok(disk, off, sec) {
                    return volume(off, len, fs, off, disk);
                }
                // FAT32 keeps a backup copy a few sectors in.
                let backup = le16(&sec[50..52]) as u64;
                if &sec[82..87] == b"FAT32" && (1..32).contains(&backup) {
                    let bps = le16(&sec[11..13]) as u64;
                    if let Some(s) = off.checked_sub(backup * bps) {
                        if fat_ok(disk, s, sec) {
                            return volume(s, len, fs, off, disk);
                        }
                    }
                }
            }
            FsKind::ExFat => {
                if exfat_ok(disk, off, sec) {
                    return volume(off, len, fs, off, disk);
                }
                // exFAT keeps a backup boot region 12 sectors in.
                let bps = 1u64 << sec[108];
                if let Some(s) = off.checked_sub(12 * bps) {
                    if exfat_ok(disk, s, sec) {
                        return volume(s, len, fs, off, disk);
                    }
                }
            }
            _ => {}
        }
        return None;
    }
    // ext2/3/4: the main superblock is 1024 bytes into the partition.
    if le16(&sec[56..58]) == 0xEF53 && le16(&sec[90..92]) == 0 {
        let log = le32(&sec[24..28]);
        let blocks = le32(&sec[4..8]) as u64;
        let per_group = le32(&sec[40..44]);
        let rev = le32(&sec[76..80]);
        if log <= 6 && blocks > 0 && per_group > 0 && rev <= 1 {
            let start = off.checked_sub(1024)?;
            return volume(start, blocks * (1024u64 << log), FsKind::Ext, start, disk);
        }
    }
    None
}

/// Read the whole disk looking for previous partitions.
pub fn hunt(disk: &Disk, cancelled: &dyn Fn() -> bool, progress: &mut dyn FnMut(u64, u64), found: &mut dyn FnMut(Volume)) {
    const CHUNK: usize = 4 << 20;
    let mut buf = vec![0u8; CHUNK];
    let mut pos = 0u64;
    while pos < disk.size {
        if cancelled() {
            return;
        }
        let want = (CHUNK as u64).min(disk.size - pos) as usize;
        let n = disk.read_at(&mut buf[..want], pos).unwrap_or(0);
        if n < 512 {
            break;
        }
        let mut s = 0;
        while s + 512 <= n {
            let sec = &buf[s..s + 512];
            // Cheap pre-check: boot sectors end in 55 AA; ext superblocks have EF53 at 56.
            if (sec[510] == 0x55 && sec[511] == 0xAA) || (sec[56] == 0x53 && sec[57] == 0xEF) {
                if let Some(v) = check(disk, pos + s as u64, sec) {
                    found(v);
                }
            }
            s += 512;
        }
        pos += n as u64;
        progress(pos, disk.size);
    }
}
