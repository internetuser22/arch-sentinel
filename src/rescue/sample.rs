//! Builds a small practice disk image: an MBR with a FAT16 and an exFAT partition
//! holding deleted files (with long names), plus loose files in unpartitioned space.

use image::{DynamicImage, ImageFormat, Rgb, RgbImage};
use std::io::Cursor as IoCursor;

const SECTOR: u64 = 512;
const DISK_SECTORS: u64 = 32768; // 16 MB
const P1_START: u64 = 2048;
const P1_LEN: u64 = 16384;
const P2_START: u64 = 18432;
const P2_LEN: u64 = 8192;
const LOOSE_START: u64 = 26624;

fn put(img: &mut [u8], off: u64, data: &[u8]) {
    let o = off as usize;
    img[o..o + data.len()].copy_from_slice(data);
}
fn put16(img: &mut [u8], off: u64, v: u16) {
    put(img, off, &v.to_le_bytes());
}
fn put32(img: &mut [u8], off: u64, v: u32) {
    put(img, off, &v.to_le_bytes());
}
fn put64(img: &mut [u8], off: u64, v: u64) {
    put(img, off, &v.to_le_bytes());
}

fn picture(w: u32, h: u32, kind: u32) -> RgbImage {
    RgbImage::from_fn(w, h, |x, y| {
        let fx = x as f32 / w as f32;
        let fy = y as f32 / h as f32;
        match kind {
            0 => {
                // Sunset over the sea
                let sun = ((fx - 0.5).powi(2) + (fy - 0.55).powi(2)).sqrt();
                if fy > 0.62 {
                    let wave = ((fx * 40.0 + fy * 90.0).sin() * 0.5 + 0.5) * 30.0;
                    Rgb([(30.0 + wave) as u8, (60.0 + wave) as u8, (120.0 + wave) as u8])
                } else if sun < 0.12 {
                    Rgb([255, 220, 120])
                } else {
                    Rgb([(250.0 - fy * 80.0) as u8, (120.0 + fy * 60.0) as u8, (90.0 + fy * 100.0) as u8])
                }
            }
            1 => {
                // Mountains and a lake
                let ridge = 0.45 + 0.15 * (fx * 9.0).sin() * (fx * 3.0).cos();
                if fy > 0.7 {
                    Rgb([40, (110.0 + fy * 40.0) as u8, 150])
                } else if fy > ridge {
                    Rgb([(70.0 + fy * 30.0) as u8, (90.0 + fy * 50.0) as u8, 80])
                } else {
                    Rgb([(140.0 + fy * 80.0) as u8, (190.0 + fy * 40.0) as u8, 240])
                }
            }
            2 => {
                // Party balloons
                let mut c = Rgb([250, 240, 225]);
                for (i, (cx, cy)) in [(0.25, 0.35), (0.5, 0.25), (0.75, 0.4)].iter().enumerate() {
                    if ((fx - cx).powi(2) + (fy - cy).powi(2) * 0.6).sqrt() < 0.12 {
                        c = [Rgb([230, 70, 90]), Rgb([70, 150, 230]), Rgb([250, 190, 50])][i];
                    }
                }
                c
            }
            3 => {
                // Abstract logo draft
                let r = ((fx - 0.5).powi(2) + (fy - 0.5).powi(2)).sqrt();
                if r < 0.3 && r > 0.2 {
                    Rgb([90, 120, 230])
                } else if (fx - fy).abs() < 0.05 {
                    Rgb([240, 120, 60])
                } else {
                    Rgb([245, 245, 250])
                }
            }
            _ => {
                // Garden
                let flower = ((fx * 12.0).sin() * (fy * 10.0).sin()).abs() > 0.9;
                if flower {
                    Rgb([240, 100, 160])
                } else {
                    Rgb([(60.0 + fy * 40.0) as u8, (140.0 + fx * 50.0) as u8, 70])
                }
            }
        }
    })
}

fn encode(img: RgbImage, fmt: ImageFormat) -> Vec<u8> {
    let mut out = IoCursor::new(Vec::new());
    let dynimg = DynamicImage::ImageRgb8(img);
    let dynimg = if fmt == ImageFormat::Gif { DynamicImage::ImageRgba8(dynimg.to_rgba8()) } else { dynimg };
    dynimg.write_to(&mut out, fmt).expect("encode picture");
    out.into_inner()
}

fn pdf(text: &str) -> Vec<u8> {
    let stream = format!("BT /F1 18 Tf 72 720 Td ({text}) Tj ET");
    let objs = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>".to_string(),
        format!("<< /Length {} >>\nstream\n{stream}\nendstream", stream.len()),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
    ];
    let mut out = b"%PDF-1.4\n".to_vec();
    let mut offs = Vec::new();
    for (i, o) in objs.iter().enumerate() {
        offs.push(out.len());
        out.extend(format!("{} 0 obj\n{o}\nendobj\n", i + 1).bytes());
    }
    let xref = out.len();
    out.extend(format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).bytes());
    for o in offs {
        out.extend(format!("{o:010} 00000 n \n").bytes());
    }
    out.extend(format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n", objs.len() + 1).bytes());
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

fn zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cd = Vec::new();
    for (name, data) in files {
        let off = out.len() as u32;
        let crc = crc32(data);
        let mut h = Vec::new();
        h.extend(b"PK\x03\x04");
        h.extend(20u16.to_le_bytes());
        h.extend([0u8; 4]);
        h.extend([0u8; 4]);
        h.extend(crc.to_le_bytes());
        h.extend((data.len() as u32).to_le_bytes());
        h.extend((data.len() as u32).to_le_bytes());
        h.extend((name.len() as u16).to_le_bytes());
        h.extend(0u16.to_le_bytes());
        h.extend(name.bytes());
        out.extend(&h);
        out.extend(*data);
        cd.extend(b"PK\x01\x02");
        cd.extend(20u16.to_le_bytes());
        cd.extend(20u16.to_le_bytes());
        cd.extend([0u8; 8]);
        cd.extend(crc.to_le_bytes());
        cd.extend((data.len() as u32).to_le_bytes());
        cd.extend((data.len() as u32).to_le_bytes());
        cd.extend((name.len() as u16).to_le_bytes());
        cd.extend([0u8; 12]);
        cd.extend(off.to_le_bytes());
        cd.extend(name.bytes());
    }
    let cd_off = out.len() as u32;
    out.extend(&cd);
    out.extend(b"PK\x05\x06");
    out.extend([0u8; 4]);
    out.extend((files.len() as u16).to_le_bytes());
    out.extend((files.len() as u16).to_le_bytes());
    out.extend((cd.len() as u32).to_le_bytes());
    out.extend(cd_off.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out
}

fn wav(seconds: f32, freq: f32) -> Vec<u8> {
    let rate = 8000u32;
    let n = (rate as f32 * seconds) as u32;
    let mut out = Vec::new();
    out.extend(b"RIFF");
    out.extend((36 + n).to_le_bytes());
    out.extend(b"WAVEfmt ");
    out.extend(16u32.to_le_bytes());
    out.extend(1u16.to_le_bytes());
    out.extend(1u16.to_le_bytes());
    out.extend(rate.to_le_bytes());
    out.extend(rate.to_le_bytes());
    out.extend(1u16.to_le_bytes());
    out.extend(8u16.to_le_bytes());
    out.extend(b"data");
    out.extend(n.to_le_bytes());
    for i in 0..n {
        let t = i as f32 / rate as f32;
        out.push((128.0 + 90.0 * (t * freq * std::f32::consts::TAU).sin()) as u8);
    }
    out
}

fn mp4(bytes: usize) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(20u32.to_be_bytes());
    out.extend(b"ftypisom");
    out.extend(0x200u32.to_be_bytes());
    out.extend(b"isom");
    out.extend(((bytes + 8) as u32).to_be_bytes());
    out.extend(b"mdat");
    let mut x: u32 = 12345;
    for _ in 0..bytes {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
        out.push((x >> 16) as u8);
    }
    out.extend(8u32.to_be_bytes());
    out.extend(b"moov");
    out
}

// ----------------------------------------------------------------- FAT16

struct Fat16<'a> {
    img: &'a mut Vec<u8>,
    base: u64,
    next: u32,
    fat: Vec<u16>,
}

const F_SPC: u64 = 2;
const F_FATSZ: u64 = 32;
const F_ROOT_SECTORS: u64 = 32;
const F_FIRST_DATA: u64 = 1 + 2 * F_FATSZ + F_ROOT_SECTORS;
const F_CLUSTER: u64 = F_SPC * SECTOR;

fn lfn_checksum(sn: &[u8; 11]) -> u8 {
    let mut s: u8 = 0;
    for &b in sn {
        s = ((s & 1) << 7).wrapping_add(s >> 1).wrapping_add(b);
    }
    s
}

fn fat_entries(long: Option<&str>, short: &[u8; 11], attr: u8, case: u8, start: u32, size: u32, deleted: bool) -> Vec<[u8; 32]> {
    let mut out = Vec::new();
    if let Some(name) = long {
        let mut chars: Vec<u16> = name.encode_utf16().collect();
        if chars.len() % 13 != 0 {
            chars.push(0);
            while chars.len() % 13 != 0 {
                chars.push(0xFFFF);
            }
        }
        let n = chars.len() / 13;
        let ck = lfn_checksum(short);
        for i in (0..n).rev() {
            let mut e = [0u8; 32];
            e[0] = (i as u8 + 1) | if i == n - 1 { 0x40 } else { 0 };
            e[11] = 0x0F;
            e[13] = ck;
            let idx = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
            for (k, &p) in idx.iter().enumerate() {
                e[p..p + 2].copy_from_slice(&chars[i * 13 + k].to_le_bytes());
            }
            out.push(e);
        }
    }
    let mut e = [0u8; 32];
    e[0..11].copy_from_slice(short);
    e[11] = attr;
    e[12] = case;
    e[14..16].copy_from_slice(&0x6000u16.to_le_bytes()); // time
    e[16..18].copy_from_slice(&0x5A71u16.to_le_bytes()); // date
    e[22..24].copy_from_slice(&0x6000u16.to_le_bytes());
    e[24..26].copy_from_slice(&0x5A71u16.to_le_bytes());
    e[26..28].copy_from_slice(&(start as u16).to_le_bytes());
    e[28..32].copy_from_slice(&size.to_le_bytes());
    out.push(e);
    if deleted {
        for e in &mut out {
            e[0] = 0xE5;
        }
    }
    out
}

impl<'a> Fat16<'a> {
    fn coff(&self, c: u32) -> u64 {
        self.base + (F_FIRST_DATA + (c as u64 - 2) * F_SPC) * SECTOR
    }
    fn alloc(&mut self, data: &[u8], in_use: bool) -> u32 {
        let n = ((data.len() as u64 + F_CLUSTER - 1) / F_CLUSTER).max(1) as u32;
        let start = self.next;
        self.next += n;
        let off = self.coff(start);
        put(self.img, off, data);
        if in_use {
            for c in start..start + n {
                self.fat[c as usize] = if c + 1 == start + n { 0xFFFF } else { (c + 1) as u16 };
            }
        }
        start
    }
    fn write_dir(&mut self, off: u64, entries: &[[u8; 32]]) {
        for (i, e) in entries.iter().enumerate() {
            put(self.img, off + i as u64 * 32, e);
        }
    }
    fn dot_entries(&self, me: u32, parent: u32) -> Vec<[u8; 32]> {
        let mut v = fat_entries(None, b".          ", 0x10, 0, me, 0, false);
        v.extend(fat_entries(None, b"..         ", 0x10, 0, parent, 0, false));
        v
    }
}

fn build_fat16(img: &mut Vec<u8>) {
    let base = P1_START * SECTOR;
    // Boot sector
    let mut b = [0u8; 512];
    b[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    b[3..11].copy_from_slice(b"MSDOS5.0");
    b[11..13].copy_from_slice(&512u16.to_le_bytes());
    b[13] = F_SPC as u8;
    b[14..16].copy_from_slice(&1u16.to_le_bytes());
    b[16] = 2;
    b[17..19].copy_from_slice(&512u16.to_le_bytes());
    b[19..21].copy_from_slice(&(P1_LEN as u16).to_le_bytes());
    b[21] = 0xF8;
    b[22..24].copy_from_slice(&(F_FATSZ as u16).to_le_bytes());
    b[24..26].copy_from_slice(&63u16.to_le_bytes());
    b[26..28].copy_from_slice(&255u16.to_le_bytes());
    b[28..32].copy_from_slice(&(P1_START as u32).to_le_bytes());
    b[36] = 0x80;
    b[38] = 0x29;
    b[39..43].copy_from_slice(&0x1234_ABCDu32.to_le_bytes());
    b[43..54].copy_from_slice(b"USB STICK  ");
    b[54..62].copy_from_slice(b"FAT16   ");
    b[510] = 0x55;
    b[511] = 0xAA;
    put(img, base, &b);

    let mut f = Fat16 { img, base, next: 2, fat: vec![0u16; (F_FATSZ * SECTOR / 2) as usize] };
    f.fat[0] = 0xFFF8;
    f.fat[1] = 0xFFFF;

    let holiday = f.alloc(&[0u8; 1024], true);
    let old = f.alloc(&[0u8; 1024], false); // deleted folder: chain cleared

    let beach = encode(picture(480, 320, 0), ImageFormat::Jpeg);
    let lake = encode(picture(360, 240, 1), ImageFormat::Png);
    let logo = encode(picture(200, 200, 3), ImageFormat::Gif);
    let song = wav(1.5, 440.0);
    let budget = pdf("Household budget 2026 - draft");
    let notes = b"Call the plumber on Tuesday.\nBuy batteries.\nBack up the laptop!\n".to_vec();
    let packing = b"Packing list: sunscreen, hat, camera, charger.\n".to_vec();
    let invite = b"You're invited to the summer party! Saturday at 6pm.\n".to_vec();

    let c_beach = f.alloc(&beach, false);
    let c_lake = f.alloc(&lake, false);
    let c_packing = f.alloc(&packing, true);
    let c_logo = f.alloc(&logo, false);
    let c_song = f.alloc(&song, false);
    let c_budget = f.alloc(&budget, false);
    let c_notes = f.alloc(&notes, false);
    // A deleted invitation whose space was later reused by readme.txt.
    let c_invite = f.alloc(&invite, false);
    let readme = b"This stick holds the family's holiday files.\n".to_vec();
    let off = f.coff(c_invite);
    put(f.img, off, &[0u8; 1024]);
    put(f.img, off, &readme);
    f.fat[c_invite as usize] = 0xFFFF;

    // Root folder
    let mut root = Vec::new();
    let mut label = [0u8; 32];
    label[0..11].copy_from_slice(b"USB STICK  ");
    label[11] = 0x08;
    root.push(label);
    root.extend(fat_entries(Some("Holiday photos"), b"HOLIDA~1   ", 0x10, 0, holiday, 0, false));
    root.extend(fat_entries(Some("Old projects"), b"OLDPRO~1   ", 0x10, 0, old, 0, true));
    root.extend(fat_entries(Some("Budget 2026.pdf"), b"BUDGET~1PDF", 0x20, 0, c_budget, budget.len() as u32, true));
    root.extend(fat_entries(None, b"NOTES   TXT", 0x20, 0, c_notes, notes.len() as u32, true));
    root.extend(fat_entries(Some("Party invitation.txt"), b"PARTYI~1TXT", 0x20, 0, c_invite, invite.len() as u32, true));
    root.extend(fat_entries(None, b"README  TXT", 0x20, 0x18, c_invite, readme.len() as u32, false));
    let root_off = base + (1 + 2 * F_FATSZ) * SECTOR;
    f.write_dir(root_off, &root);

    let mut hd = f.dot_entries(holiday, 0);
    hd.extend(fat_entries(Some("Beach sunset.jpg"), b"BEACHS~1JPG", 0x20, 0, c_beach, beach.len() as u32, true));
    hd.extend(fat_entries(Some("Mountain lake.png"), b"MOUNTA~1PNG", 0x20, 0, c_lake, lake.len() as u32, true));
    hd.extend(fat_entries(Some("Packing list.txt"), b"PACKIN~1TXT", 0x20, 0, c_packing, packing.len() as u32, false));
    let o = f.coff(holiday);
    f.write_dir(o, &hd);

    let mut od = f.dot_entries(old, 0);
    od.extend(fat_entries(Some("Logo draft.gif"), b"LOGODR~1GIF", 0x20, 0, c_logo, logo.len() as u32, true));
    od.extend(fat_entries(Some("Song idea.wav"), b"SONGID~1WAV", 0x20, 0, c_song, song.len() as u32, true));
    let o = f.coff(old);
    f.write_dir(o, &od);

    // Both copies of the FAT
    let fat_bytes: Vec<u8> = f.fat.iter().flat_map(|v| v.to_le_bytes()).collect();
    put(f.img, base + SECTOR, &fat_bytes);
    put(f.img, base + (1 + F_FATSZ) * SECTOR, &fat_bytes);
}

// ----------------------------------------------------------------- exFAT

const X_SPC_SHIFT: u8 = 3;
const X_CLUSTER: u64 = SECTOR << X_SPC_SHIFT;
const X_FAT_OFF: u32 = 24;
const X_FAT_LEN: u32 = 8;
const X_HEAP: u32 = 32;
const X_COUNT: u32 = ((P2_LEN - X_HEAP as u64) >> X_SPC_SHIFT) as u32;

fn ex_file(name: &str, dir: bool, first: u32, len: u64, deleted: bool) -> Vec<[u8; 32]> {
    let chars: Vec<u16> = name.encode_utf16().collect();
    let nn = (chars.len() + 14) / 15;
    let mut v = Vec::new();
    let mut f = [0u8; 32];
    f[0] = 0x85;
    f[1] = (1 + nn) as u8;
    f[4..6].copy_from_slice(&(if dir { 0x10u16 } else { 0x20 }).to_le_bytes());
    v.push(f);
    let mut s = [0u8; 32];
    s[0] = 0xC0;
    s[1] = 0x03;
    s[3] = chars.len() as u8;
    s[8..16].copy_from_slice(&len.to_le_bytes());
    s[20..24].copy_from_slice(&first.to_le_bytes());
    s[24..32].copy_from_slice(&len.to_le_bytes());
    v.push(s);
    for k in 0..nn {
        let mut n = [0u8; 32];
        n[0] = 0xC1;
        for j in 0..15 {
            if let Some(c) = chars.get(k * 15 + j) {
                n[2 + j * 2..4 + j * 2].copy_from_slice(&c.to_le_bytes());
            }
        }
        v.push(n);
    }
    if deleted {
        for e in &mut v {
            e[0] &= 0x7F;
        }
    }
    v
}

fn build_exfat(img: &mut Vec<u8>) {
    let base = P2_START * SECTOR;
    let mut b = [0u8; 512];
    b[0..3].copy_from_slice(&[0xEB, 0x76, 0x90]);
    b[3..11].copy_from_slice(b"EXFAT   ");
    b[64..72].copy_from_slice(&P2_START.to_le_bytes());
    b[72..80].copy_from_slice(&P2_LEN.to_le_bytes());
    b[80..84].copy_from_slice(&X_FAT_OFF.to_le_bytes());
    b[84..88].copy_from_slice(&X_FAT_LEN.to_le_bytes());
    b[88..92].copy_from_slice(&X_HEAP.to_le_bytes());
    b[92..96].copy_from_slice(&X_COUNT.to_le_bytes());
    b[96..100].copy_from_slice(&4u32.to_le_bytes());
    b[100..104].copy_from_slice(&0x5EED_CAFEu32.to_le_bytes());
    b[104..106].copy_from_slice(&0x0100u16.to_le_bytes());
    b[108] = 9;
    b[109] = X_SPC_SHIFT;
    b[110] = 1;
    b[111] = 0x80;
    b[510] = 0x55;
    b[511] = 0xAA;
    put(img, base, &b);

    let coff = |c: u32| base + X_HEAP as u64 * SECTOR + (c as u64 - 2) * X_CLUSTER;
    let mut next = 6u32;
    let mut place = |img: &mut Vec<u8>, data: &[u8]| -> u32 {
        let start = next;
        next += ((data.len() as u64 + X_CLUSTER - 1) / X_CLUSTER).max(1) as u32;
        put(img, coff(start), data);
        start
    };
    let party = encode(picture(400, 300, 2), ImageFormat::Png);
    let garden = encode(picture(420, 280, 4), ImageFormat::Jpeg);
    let clip = mp4(60_000);
    let list = b"Milk, eggs, bread, apples, coffee.\n".to_vec();
    let c_party = place(img, &party);
    let c_garden = place(img, &garden);
    let c_clip = place(img, &clip);
    let c_list = place(img, &list);

    // FAT: system clusters 2-5 are single-cluster chains.
    let mut fat = vec![0u32; (X_FAT_LEN as u64 * SECTOR / 4) as usize];
    fat[0] = 0xFFFF_FFF8;
    fat[1] = 0xFFFF_FFFF;
    for c in 2..=5 {
        fat[c] = 0xFFFF_FFFF;
    }
    let fb: Vec<u8> = fat.iter().flat_map(|v| v.to_le_bytes()).collect();
    put(img, base + X_FAT_OFF as u64 * SECTOR, &fb);

    // Allocation bitmap: only the system clusters, the Camera folder and the list are in use.
    let mut bm = vec![0u8; ((X_COUNT + 7) / 8) as usize];
    let mut mark = |c: u32| bm[((c - 2) / 8) as usize] |= 1 << ((c - 2) % 8);
    for c in 2..=5 {
        mark(c);
    }
    mark(c_list);
    put(img, coff(2), &bm);
    put(img, coff(3), &[0x00, 0x00, 0x01, 0x00, 0x02, 0x00]);

    let mut root: Vec<[u8; 32]> = Vec::new();
    let mut lab = [0u8; 32];
    lab[0] = 0x83;
    let name: Vec<u16> = "PHONE CARD".encode_utf16().collect();
    lab[1] = name.len() as u8;
    for (i, c) in name.iter().enumerate() {
        lab[2 + i * 2..4 + i * 2].copy_from_slice(&c.to_le_bytes());
    }
    root.push(lab);
    let mut bme = [0u8; 32];
    bme[0] = 0x81;
    bme[20..24].copy_from_slice(&2u32.to_le_bytes());
    bme[24..32].copy_from_slice(&(bm.len() as u64).to_le_bytes());
    root.push(bme);
    let mut up = [0u8; 32];
    up[0] = 0x82;
    up[20..24].copy_from_slice(&3u32.to_le_bytes());
    up[24..32].copy_from_slice(&6u64.to_le_bytes());
    root.push(up);
    root.extend(ex_file("Camera", true, 5, X_CLUSTER, false));
    root.extend(ex_file("Shopping list.txt", false, c_list, list.len() as u64, false));
    for (i, e) in root.iter().enumerate() {
        put(img, coff(4) + i as u64 * 32, e);
    }
    let mut cam: Vec<[u8; 32]> = Vec::new();
    cam.extend(ex_file("Party balloons.png", false, c_party, party.len() as u64, true));
    cam.extend(ex_file("Garden in spring.jpg", false, c_garden, garden.len() as u64, true));
    cam.extend(ex_file("Birthday clip.mp4", false, c_clip, clip.len() as u64, true));
    for (i, e) in cam.iter().enumerate() {
        put(img, coff(5) + i as u64 * 32, e);
    }
}

// ----------------------------------------------------------------- previous partition

/// An old FAT12 partition whose entry was removed from the partition table
/// (as after re-partitioning): its files are intact but nothing points to them.
const OLD_START: u64 = 28672;
const OLD_LEN: u64 = 4096;

fn set12(fat: &mut [u8], n: usize, v: u16) {
    let off = n + n / 2;
    if n & 1 == 1 {
        fat[off] = (fat[off] & 0x0F) | ((v << 4) as u8);
        fat[off + 1] = (v >> 4) as u8;
    } else {
        fat[off] = v as u8;
        fat[off + 1] = (fat[off + 1] & 0xF0) | ((v >> 8) as u8 & 0x0F);
    }
}

fn build_previous(img: &mut Vec<u8>) {
    let base = OLD_START * SECTOR;
    let (spc, fatsz, root_secs) = (2u64, 6u64, 32u64);
    let first_data = 1 + 2 * fatsz + root_secs;
    let cl = spc * SECTOR;
    let mut b = [0u8; 512];
    b[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    b[3..11].copy_from_slice(b"MSWIN4.1");
    b[11..13].copy_from_slice(&512u16.to_le_bytes());
    b[13] = spc as u8;
    b[14..16].copy_from_slice(&1u16.to_le_bytes());
    b[16] = 2;
    b[17..19].copy_from_slice(&512u16.to_le_bytes());
    b[19..21].copy_from_slice(&(OLD_LEN as u16).to_le_bytes());
    b[21] = 0xF8;
    b[22..24].copy_from_slice(&(fatsz as u16).to_le_bytes());
    b[28..32].copy_from_slice(&(OLD_START as u32).to_le_bytes());
    b[38] = 0x29;
    b[43..54].copy_from_slice(b"OLD CARD   ");
    b[54..62].copy_from_slice(b"FAT12   ");
    b[510] = 0x55;
    b[511] = 0xAA;
    put(img, base, &b);

    let mut fat = vec![0u8; (fatsz * SECTOR) as usize];
    fat[0] = 0xF8;
    fat[1] = 0xFF;
    fat[2] = 0xFF;
    let mut next = 2u32;
    let coff = |c: u32| base + (first_data + (c as u64 - 2) * spc) * SECTOR;
    let mut alloc = |img: &mut Vec<u8>, fat: &mut Vec<u8>, data: &[u8], in_use: bool| -> u32 {
        let n = ((data.len() as u64 + cl - 1) / cl).max(1) as u32;
        let start = next;
        next += n;
        put(img, coff(start), data);
        if in_use {
            for c in start..start + n {
                set12(fat, c as usize, if c + 1 == start + n { 0xFFF } else { (c + 1) as u16 });
            }
        }
        start
    };
    let letters = alloc(img, &mut fat, &[0u8; 1024], true);
    let speech = b"Wedding speech\n\nThank you all for coming today. When I first met...\n".to_vec();
    let car = encode(picture(440, 300, 1), ImageFormat::Jpeg);
    let grandma = b"Dear Grandma,\nThe garden is blooming and the kids say hello.\nLove, Alex\n".to_vec();
    let book = b"Address book\nSam - 12 Oak Lane\nJo - 4 River Road\n".to_vec();
    let c_speech = alloc(img, &mut fat, &speech, true);
    let c_car = alloc(img, &mut fat, &car, true);
    let c_grandma = alloc(img, &mut fat, &grandma, true);
    let c_book = alloc(img, &mut fat, &book, false);

    let mut root: Vec<[u8; 32]> = Vec::new();
    let mut label = [0u8; 32];
    label[0..11].copy_from_slice(b"OLD CARD   ");
    label[11] = 0x08;
    root.push(label);
    root.extend(fat_entries(Some("Letters"), b"LETTERS    ", 0x10, 0, letters, 0, false));
    root.extend(fat_entries(Some("Wedding speech.txt"), b"WEDDIN~1TXT", 0x20, 0, c_speech, speech.len() as u32, false));
    root.extend(fat_entries(Some("First car.jpg"), b"FIRSTC~1JPG", 0x20, 0, c_car, car.len() as u32, false));
    root.extend(fat_entries(Some("Old address book.txt"), b"OLDADD~1TXT", 0x20, 0, c_book, book.len() as u32, true));
    for (i, e) in root.iter().enumerate() {
        put(img, base + (1 + 2 * fatsz) * SECTOR + i as u64 * 32, e);
    }
    let mut ld = fat_entries(None, b".          ", 0x10, 0, letters, 0, false);
    ld.extend(fat_entries(None, b"..         ", 0x10, 0, 0, 0, false));
    ld.extend(fat_entries(Some("To Grandma.txt"), b"TOGRAN~1TXT", 0x20, 0, c_grandma, grandma.len() as u32, false));
    for (i, e) in ld.iter().enumerate() {
        put(img, coff(letters) + i as u64 * 32, e);
    }
    put(img, base + SECTOR, &fat);
    put(img, base + (1 + fatsz) * SECTOR, &fat);
}

fn build_mbr(img: &mut [u8]) {
    let mut m = [0u8; 512];
    m[440..444].copy_from_slice(&0x2026_1119u32.to_le_bytes());
    let parts = [(0x06u8, P1_START, P1_LEN), (0x07u8, P2_START, P2_LEN)];
    for (i, (t, s, l)) in parts.iter().enumerate() {
        let e = 446 + i * 16;
        m[e + 4] = *t;
        m[e + 8..e + 12].copy_from_slice(&(*s as u32).to_le_bytes());
        m[e + 12..e + 16].copy_from_slice(&(*l as u32).to_le_bytes());
    }
    m[510] = 0x55;
    m[511] = 0xAA;
    put(img, 0, &m);
}

/// Loose files left in space outside any partition: only a content search finds them.
fn build_loose(img: &mut [u8]) {
    let files: Vec<Vec<u8>> = vec![
        encode(picture(500, 340, 1), ImageFormat::Jpeg),
        encode(picture(240, 240, 2), ImageFormat::Gif),
        zip(&[("letter.txt", b"Dear Sam, thanks for the lovely weekend!".as_slice()), ("recipe.txt", b"Pancakes: flour, milk, eggs.".as_slice())]),
        wav(1.0, 660.0),
        pdf("Old invoice #1042"),
        encode(picture(300, 200, 0), ImageFormat::Png),
    ];
    let mut off = LOOSE_START * SECTOR;
    for f in files {
        put(img, off, &f);
        off += ((f.len() as u64 + SECTOR - 1) / SECTOR + 8) * SECTOR;
    }
}

pub fn make_sample(path: &std::path::Path) -> std::io::Result<()> {
    let mut img = vec![0u8; (DISK_SECTORS * SECTOR) as usize];
    build_mbr(&mut img);
    build_fat16(&mut img);
    build_exfat(&mut img);
    let _ = put16;
    let _ = put32;
    let _ = put64;
    build_loose(&mut img);
    build_previous(&mut img);
    std::fs::write(path, img)
}
