//! Partition tables (MBR, extended, GPT) and file system detection.

use crate::rescue::disk::{le16, le32, le64, Disk};
use crate::rescue::model::{FsKind, Volume};

pub struct Layout {
    pub scheme: String,
    pub volumes: Vec<Volume>,
}

pub fn read_layout(disk: &Disk) -> Layout {
    let mbr = disk.read_vec(0, 512);
    let mut volumes = Vec::new();
    let mut scheme = "none".to_string();

    let has_sig = mbr[510] == 0x55 && mbr[511] == 0xAA;
    let boot_fs = detect_fs(disk, 0);
    let looks_like_boot_sector = boot_fs != FsKind::Unknown;

    if has_sig && !looks_like_boot_sector {
        let entries: Vec<&[u8]> = (0..4).map(|i| &mbr[446 + i * 16..446 + i * 16 + 16]).collect();
        let gpt = entries.iter().any(|e| e[4] == 0xEE);
        if gpt {
            scheme = "GPT".into();
            read_gpt(disk, &mut volumes);
        } else if entries.iter().any(|e| e[4] != 0) {
            scheme = "MBR".into();
            let mut n = 1;
            for e in &entries {
                let t = e[4];
                let start = le32(&e[8..12]) as u64 * 512;
                let len = le32(&e[12..16]) as u64 * 512;
                if t == 0 || len == 0 {
                    continue;
                }
                if matches!(t, 0x05 | 0x0F | 0x85) {
                    read_extended(disk, start, &mut volumes, &mut n);
                    continue;
                }
                push_volume(disk, &mut volumes, format!("Partition {n}"), start, len, mbr_type_name(t));
                n += 1;
            }
        }
    }

    if volumes.is_empty() {
        // No partition table: treat the whole thing as one volume.
        let fs = boot_fs;
        volumes.push(Volume {
            label: "Whole disk".into(),
            start: 0,
            len: disk.size,
            fs,
            kind: if fs == FsKind::Unknown { "no partition table".into() } else { "file system".into() },
            lost: false,
            boot: 0,
        });
    }
    Layout { scheme, volumes }
}

fn push_volume(disk: &Disk, out: &mut Vec<Volume>, label: String, start: u64, len: u64, kind: String) {
    if start >= disk.size {
        return;
    }
    let len = len.min(disk.size - start);
    let fs = detect_fs(disk, start);
    out.push(Volume { label, start, len, fs, kind, lost: false, boot: start });
}

fn read_extended(disk: &Disk, ext_start: u64, out: &mut Vec<Volume>, n: &mut usize) {
    let mut ebr = ext_start;
    for _ in 0..128 {
        let s = disk.read_vec(ebr, 512);
        if s[510] != 0x55 || s[511] != 0xAA {
            break;
        }
        let e1 = &s[446..462];
        let e2 = &s[462..478];
        if e1[4] != 0 {
            let start = ebr + le32(&e1[8..12]) as u64 * 512;
            let len = le32(&e1[12..16]) as u64 * 512;
            push_volume(disk, out, format!("Partition {n} (logical)"), start, len, mbr_type_name(e1[4]));
            *n += 1;
        }
        if e2[4] == 0 {
            break;
        }
        let next = ext_start + le32(&e2[8..12]) as u64 * 512;
        if next <= ebr {
            break;
        }
        ebr = next;
    }
}

fn read_gpt(disk: &Disk, out: &mut Vec<Volume>) {
    // Try 512-byte and 4096-byte sectors.
    for lba_size in [512u64, 4096] {
        let h = disk.read_vec(lba_size, 512);
        if &h[0..8] != b"EFI PART" {
            continue;
        }
        let entries_lba = le64(&h[72..80]);
        let count = le32(&h[80..84]).min(1024) as u64;
        let esize = le32(&h[84..88]).max(128) as u64;
        let table = disk.read_vec(entries_lba * lba_size, (count * esize) as usize);
        let mut n = 1;
        for i in 0..count as usize {
            let e = &table[i * esize as usize..(i + 1) * esize as usize];
            if e[0..16].iter().all(|&b| b == 0) {
                continue;
            }
            let first = le64(&e[32..40]);
            let last = le64(&e[40..48]);
            if last < first {
                continue;
            }
            let name_u16: Vec<u16> = e[56..128].chunks(2).map(le16).take_while(|&c| c != 0).collect();
            let name = String::from_utf16_lossy(&name_u16);
            let guid = guid_string(&e[0..16]);
            let mut kind = gpt_type_name(&guid).to_string();
            if !name.is_empty() {
                kind = format!("{kind} \"{name}\"");
            }
            push_volume(disk, out, format!("Partition {n}"), first * lba_size, (last - first + 1) * lba_size, kind);
            n += 1;
        }
        return;
    }
}

fn guid_string(b: &[u8]) -> String {
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        le32(&b[0..4]),
        le16(&b[4..6]),
        le16(&b[6..8]),
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}

fn gpt_type_name(g: &str) -> &'static str {
    match g {
        "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7" => "Basic data",
        "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" => "EFI system",
        "E3C9E316-0B5C-4DB8-817D-F92DF00215AE" => "Microsoft reserved",
        "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC" => "Windows recovery",
        "0FC63DAF-8483-4772-8E79-3D69D8477DE4" => "Linux file system",
        "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F" => "Linux swap",
        "E6D6D379-F507-44C2-A23C-238F2A3DF928" => "Linux LVM",
        "48465300-0000-11AA-AA11-00306543ECAC" => "Apple HFS+",
        "7C3457EF-0000-11AA-AA11-00306543ECAC" => "Apple APFS",
        _ => "Partition",
    }
}

fn mbr_type_name(t: u8) -> String {
    match t {
        0x01 => "FAT12",
        0x04 | 0x06 | 0x0E => "FAT16",
        0x0B | 0x0C => "FAT32",
        0x07 => "NTFS / exFAT",
        0x27 => "Windows recovery",
        0x82 => "Linux swap",
        0x83 => "Linux",
        0x8E => "Linux LVM",
        0xAF => "Apple HFS",
        0xEF => "EFI system",
        _ => return format!("type {t:02X}"),
    }
    .to_string()
}

/// What file system starts at this offset?
pub fn detect_fs(disk: &Disk, start: u64) -> FsKind {
    let b = disk.read_vec(start, 2048);
    classify_boot(&b).unwrap_or_else(|| {
        if le16(&b[1024 + 56..1024 + 58]) == 0xEF53 {
            FsKind::Ext
        } else if &b[1024..1026] == b"H+" || &b[1024..1026] == b"HX" {
            FsKind::HfsPlus
        } else if &b[32..36] == b"NXSB" {
            FsKind::Apfs
        } else {
            FsKind::Unknown
        }
    })
}

/// Recognise a FAT/exFAT/NTFS boot sector (first 512 bytes).
pub fn classify_boot(b: &[u8]) -> Option<FsKind> {
    if b.len() < 512 || b[510] != 0x55 || b[511] != 0xAA {
        return None;
    }
    if &b[3..11] == b"NTFS    " {
        let bps = le16(&b[11..13]);
        if matches!(bps, 512 | 1024 | 2048 | 4096) && b[13] != 0 {
            return Some(FsKind::Ntfs);
        }
        return None;
    }
    if &b[3..11] == b"EXFAT   " {
        if (9..=12).contains(&b[108]) {
            return Some(FsKind::ExFat);
        }
        return None;
    }
    let bps = le16(&b[11..13]);
    let spc = b[13];
    let reserved = le16(&b[14..16]);
    let nfats = b[16];
    let fat_label = &b[54..59] == b"FAT12" || &b[54..59] == b"FAT16" || &b[82..87] == b"FAT32";
    if matches!(bps, 512 | 1024 | 2048 | 4096)
        && spc != 0
        && spc.is_power_of_two()
        && reserved != 0
        && (nfats == 1 || nfats == 2)
        && (b[0] == 0xEB || b[0] == 0xE9)
        && fat_label
    {
        return Some(FsKind::Fat);
    }
    None
}

/// The size in bytes a boot sector says its volume has.
pub fn boot_volume_len(b: &[u8], fs: FsKind) -> u64 {
    match fs {
        FsKind::Ntfs => le64(&b[40..48]).saturating_add(1) * le16(&b[11..13]) as u64,
        FsKind::ExFat => le64(&b[72..80]) << b[108],
        FsKind::Fat => {
            let t16 = le16(&b[19..21]) as u64;
            let total = if t16 != 0 { t16 } else { le32(&b[32..36]) as u64 };
            total * le16(&b[11..13]) as u64
        }
        _ => 0,
    }
}
