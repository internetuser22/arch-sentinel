//! Deep content search: recognises files by what they contain, sector by sector,
//! and works out where each one ends. Used when the file system's records are gone.

use crate::rescue::disk::{Cursor, Disk};
use crate::rescue::fat::Sink;
use crate::rescue::model::{category_of, Category, Chance, Found, FsKind, Method};
use crate::rescue::model::Volume;
use std::collections::HashSet;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Jpeg,
    Png,
    Gif,
    Bmp,
    Pdf,
    Zip,
    Rar,
    SevenZ,
    Riff,
    Isobmff,
    Mkv,
    Ogg,
    Flac,
    Mp3,
    Sqlite,
    Exe,
    Ole,
    Tiff,
    Gzip,
}

fn identify(h: &[u8]) -> Option<Kind> {
    if h.len() < 32 {
        return None;
    }
    let s = |sig: &[u8]| &h[..sig.len()] == sig;
    Some(match h[0] {
        0xFF if h[1] == 0xD8 && h[2] == 0xFF && matches!(h[3], 0xE0..=0xEF | 0xDB | 0xC4 | 0xC0 | 0xFE) => Kind::Jpeg,
        0x89 if s(b"\x89PNG\r\n\x1a\n") => Kind::Png,
        b'G' if s(b"GIF87a") || s(b"GIF89a") => Kind::Gif,
        b'B' if s(b"BM") && h[6..10] == [0, 0, 0, 0] && matches!(h[14], 12 | 40 | 56 | 108 | 124) && h[15..18] == [0, 0, 0] => Kind::Bmp,
        b'%' if s(b"%PDF-") => Kind::Pdf,
        b'P' if s(b"PK\x03\x04") => Kind::Zip,
        b'R' if s(b"Rar!\x1a\x07") => Kind::Rar,
        b'R' if s(b"RIFF") && (&h[8..12] == b"WAVE" || &h[8..12] == b"AVI " || &h[8..12] == b"WEBP") => Kind::Riff,
        b'7' if s(b"7z\xBC\xAF\x27\x1C") => Kind::SevenZ,
        0x1A if s(&[0x1A, 0x45, 0xDF, 0xA3]) => Kind::Mkv,
        b'O' if s(b"OggS\0\x02") => Kind::Ogg,
        b'f' if s(b"fLaC\0") => Kind::Flac,
        b'I' if s(b"ID3") && h[3] <= 4 && h[5] & 0x0F == 0 && h[6..10].iter().all(|&b| b < 0x80) => Kind::Mp3,
        b'S' if s(b"SQLite format 3\0") => Kind::Sqlite,
        b'M' if s(b"MZ") && u32::from_le_bytes([h[60], h[61], h[62], h[63]]) < 4096 => Kind::Exe,
        0xD0 if s(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) => Kind::Ole,
        b'I' if s(b"II*\0") => Kind::Tiff,
        b'M' if s(b"MM\0*") => Kind::Tiff,
        0x1F if h[1] == 0x8B && h[2] == 8 && h[3] & 0xE0 == 0 => Kind::Gzip,
        _ => {
            if &h[4..8] == b"ftyp" && h[8..12].iter().all(|b| b.is_ascii_alphanumeric() || *b == b' ') {
                Kind::Isobmff
            } else {
                return None;
            }
        }
    })
}

/// Which categories each kind can produce (so unticked categories are skipped early).
fn kind_category(k: Kind) -> Category {
    match k {
        Kind::Jpeg | Kind::Png | Kind::Gif | Kind::Bmp | Kind::Tiff => Category::Pictures,
        Kind::Pdf | Kind::Ole => Category::Documents,
        Kind::Zip => Category::Archives,
        Kind::Rar | Kind::SevenZ | Kind::Gzip => Category::Archives,
        Kind::Riff | Kind::Isobmff | Kind::Mkv => Category::Videos,
        Kind::Ogg | Kind::Flac | Kind::Mp3 => Category::Music,
        Kind::Sqlite => Category::Databases,
        Kind::Exe => Category::Programs,
    }
}

const MB: u64 = 1 << 20;

fn avail(c: &Cursor, p: u64, n: u64) -> u64 {
    c.limit().saturating_sub(p).min(n)
}

fn is_zero(b: &[u8]) -> bool {
    b.iter().all(|&x| x == 0)
}

/// For formats that don't say how long they are: run until a blank sector or the
/// start of another recognised file.
fn until_gap(c: &mut Cursor, off: u64, max: u64) -> u64 {
    let mut p = off + 512;
    let end = (off + max).min(c.limit());
    while p + 512 <= end {
        let stop = match c.get(p, 512) {
            Some(s) => is_zero(s) || identify(&s[..64]).is_some(),
            None => true,
        };
        if stop {
            break;
        }
        p += 512;
    }
    p.min(end) - off
}

/// Find every occurrence of `pat` sector by sector, handing each to `f`, which returns
/// Some(length) to accept it. `stop` ends the search at a sector boundary.
fn find_footer(
    c: &mut Cursor,
    off: u64,
    pat: &[u8],
    max: u64,
    mut stop: impl FnMut(&[u8], u64) -> bool,
    mut f: impl FnMut(&mut Cursor, u64) -> Option<u64>,
) -> Option<u64> {
    let end = (off + max).min(c.limit());
    let ov = pat.len() as u64 - 1;
    let mut p = off;
    let mut hits = Vec::new();
    while p < end {
        let n = avail(c, p, 512).min(end - p);
        if n == 0 {
            break;
        }
        let from = if p >= off + ov { p - ov } else { off };
        let span = (p + n - from) as usize;
        {
            let Some(b) = c.get(from, span) else { break };
            if p > off && p % 512 == 0 && stop(&b[(p - from) as usize..], p) {
                return None;
            }
            hits.clear();
            if b.len() >= pat.len() {
                for i in 0..=b.len() - pat.len() {
                    if &b[i..i + pat.len()] == pat {
                        hits.push(from + i as u64);
                    }
                }
            }
        }
        for &h in &hits {
            if let Some(l) = f(c, h) {
                return Some(l);
            }
        }
        p += n;
    }
    None
}

fn jpeg(c: &mut Cursor, off: u64) -> Option<u64> {
    let max = off + 64 * MB;
    let mut p = off + 2;
    let mut saw_sos = false;
    loop {
        if p >= max {
            return None;
        }
        if c.u8(p)? != 0xFF {
            return None;
        }
        let mut m = c.u8(p + 1)?;
        while m == 0xFF {
            p += 1;
            m = c.u8(p + 1)?;
        }
        if m == 0xD9 {
            return if saw_sos { Some(p + 2 - off) } else { None };
        }
        if m == 0x01 || (0xD0..=0xD7).contains(&m) {
            p += 2;
            continue;
        }
        let b = c.get(p + 2, 2)?;
        let len = u16::from_be_bytes([b[0], b[1]]) as u64;
        if len < 2 {
            return None;
        }
        p += 2 + len;
        if m == 0xDA {
            saw_sos = true;
            // Entropy-coded data: look for the next real marker.
            'scan: loop {
                if p >= max {
                    return None;
                }
                let n = avail(c, p, 65536);
                if n < 2 {
                    return Some(p + n - off);
                }
                let b = c.get(p, n as usize)?;
                for i in 0..b.len() - 1 {
                    if b[i] == 0xFF {
                        let x = b[i + 1];
                        if x == 0 || (0xD0..=0xD7).contains(&x) || x == 0xFF {
                            continue;
                        }
                        p += i as u64;
                        break 'scan;
                    }
                }
                p += n - 1;
            }
        }
    }
}

fn png(c: &mut Cursor, off: u64) -> Option<u64> {
    let mut p = off + 8;
    for _ in 0..100_000 {
        let len = c.u32be(p)? as u64;
        let t = c.get(p + 4, 4)?;
        if !t.iter().all(|b| b.is_ascii_alphabetic()) || len > 256 * MB {
            return None;
        }
        let iend = t == b"IEND";
        p += 12 + len;
        if iend {
            return Some(p - off);
        }
    }
    None
}

fn gif(c: &mut Cursor, off: u64) -> Option<u64> {
    let flags = c.u8(off + 10)?;
    let mut p = off + 13;
    if flags & 0x80 != 0 {
        p += 3 << ((flags & 7) + 1);
    }
    let skip_blocks = |c: &mut Cursor, mut p: u64| -> Option<u64> {
        for _ in 0..10_000_000 {
            let n = c.u8(p)? as u64;
            p += 1;
            if n == 0 {
                return Some(p);
            }
            p += n;
        }
        None
    };
    for _ in 0..1_000_000 {
        match c.u8(p)? {
            0x3B => return Some(p + 1 - off),
            0x21 => p = skip_blocks(c, p + 2)?,
            0x2C => {
                let f = c.u8(p + 9)?;
                p += 10;
                if f & 0x80 != 0 {
                    p += 3 << ((f & 7) + 1);
                }
                p = skip_blocks(c, p + 1)?;
            }
            _ => return None,
        }
        if p - off > 128 * MB {
            return None;
        }
    }
    None
}

fn bmp(c: &mut Cursor, off: u64) -> Option<u64> {
    let size = c.u32le(off + 2)? as u64;
    let data = c.u32le(off + 10)? as u64;
    if size < 26 || data >= size || size > 512 * MB {
        return None;
    }
    Some(size)
}

fn pdf(c: &mut Cursor, off: u64) -> Option<u64> {
    let mut last: Option<u64> = None;
    let eof_hits = std::cell::Cell::new(0u32);
    let r = find_footer(
        c,
        off,
        b"%%EOF",
        512 * MB,
        |sec, _| {
            let header = sec.len() >= 64 && identify(&sec[..64]).is_some();
            let blank = sec.len() >= 512 && is_zero(&sec[..512]);
            // Stop at a blank sector or another file once the end mark was seen.
            (header || blank) && eof_hits.get() > 0 || (header && sec.starts_with(b"%PDF"))
        },
        |c, h| {
            let mut e = h + 5;
            while let Some(b) = c.u8(e) {
                if b == b'\r' || b == b'\n' {
                    e += 1;
                    if e - h > 7 {
                        break;
                    }
                } else {
                    break;
                }
            }
            last = Some(e - off);
            eof_hits.set(eof_hits.get() + 1);
            None
        },
    );
    r.or(last)
}

fn zip(c: &mut Cursor, off: u64) -> Option<u64> {
    find_footer(c, off, b"PK\x05\x06", 1024 * MB, |_, _| false, |c, h| {
        let cd_size = c.u32le(h + 12)? as u64;
        let cd_off = c.u32le(h + 16)? as u64;
        let comment = c.u16le(h + 20)? as u64;
        if off + cd_off + cd_size == h || cd_off == 0xFFFF_FFFF {
            Some(h + 22 + comment - off)
        } else {
            None
        }
    })
}

fn zip_kind(c: &mut Cursor, off: u64, len: u64) -> &'static str {
    // Look at the central directory (the end of the file) and the first entry name.
    let mut hay = Vec::new();
    if let Some(b) = c.get(off, avail(c, off, 4096).min(len) as usize) {
        hay.extend_from_slice(b);
    }
    let tail = len.min(65536);
    if let Some(b) = c.get(off + len - tail, tail as usize) {
        hay.extend_from_slice(b);
    }
    let has = |p: &[u8]| hay.windows(p.len()).any(|w| w == p);
    if has(b"application/vnd.oasis.opendocument.text") {
        "odt"
    } else if has(b"application/vnd.oasis.opendocument.spreadsheet") {
        "ods"
    } else if has(b"application/vnd.oasis.opendocument.presentation") {
        "odp"
    } else if has(b"application/epub+zip") {
        "epub"
    } else if has(b"word/") {
        "docx"
    } else if has(b"xl/") {
        "xlsx"
    } else if has(b"ppt/") {
        "pptx"
    } else if has(b"AndroidManifest.xml") {
        "apk"
    } else if has(b"META-INF/MANIFEST.MF") {
        "jar"
    } else {
        "zip"
    }
}

fn riff(c: &mut Cursor, off: u64) -> Option<(u64, &'static str)> {
    let size = c.u32le(off + 4)? as u64 + 8;
    if size < 16 {
        return None;
    }
    let ext = match c.get(off + 8, 4)? {
        b"WAVE" => "wav",
        b"AVI " => "avi",
        _ => "webp",
    };
    Some((size, ext))
}

fn isobmff(c: &mut Cursor, off: u64) -> Option<(u64, &'static str)> {
    let brand = c.get(off + 8, 4)?.to_vec();
    let ext = match &brand[..] {
        b"qt  " => "mov",
        b"M4A " | b"M4B " => "m4a",
        b"M4V " => "m4v",
        b"heic" | b"heix" | b"mif1" | b"msf1" | b"hevc" => "heic",
        b"avif" => "avif",
        b if b.starts_with(b"3g") => "3gp",
        _ => "mp4",
    };
    let mut p = off;
    let mut media = false;
    for _ in 0..100_000 {
        let Some(mut size) = c.u32be(p).map(|v| v as u64) else { break };
        let Some(t) = c.get(p + 4, 4).map(|t| t.to_vec()) else { break };
        if !t.iter().all(|&b| (0x20..0x7F).contains(&b) || b == 0xA9) {
            break;
        }
        if size == 1 {
            size = c.u64be(p + 8)?;
        } else if size == 0 {
            size = until_gap(c, p, 4096 * MB);
        }
        if size < 8 {
            break;
        }
        if matches!(&t[..], b"moov" | b"mdat" | b"meta") {
            media = true;
        }
        p += size;
        if p - off > 16384 * MB {
            return None;
        }
    }
    if !media || p == off {
        return None;
    }
    Some((p.min(c.limit()) - off, ext))
}

fn vint(c: &mut Cursor, p: u64) -> Option<(u64, u64)> {
    let b = c.u8(p)?;
    if b == 0 {
        return None;
    }
    let n = b.leading_zeros() as u64 + 1;
    let mut v = (b as u64) & ((1u64 << (8 - n)) - 1);
    let mut all_ones = v == (1u64 << (8 - n)) - 1;
    for i in 1..n {
        let x = c.u8(p + i)?;
        all_ones &= x == 0xFF;
        v = (v << 8) | x as u64;
    }
    Some((n, if all_ones { u64::MAX } else { v }))
}

fn mkv(c: &mut Cursor, off: u64) -> Option<(u64, &'static str)> {
    let (n, hsize) = vint(c, off + 4)?;
    if hsize > 4096 {
        return None;
    }
    let hdr_end = off + 4 + n + hsize;
    let hdr = c.get(off, (hdr_end - off) as usize)?.to_vec();
    let ext = if hdr.windows(4).any(|w| w == b"webm") { "webm" } else { "mkv" };
    if c.get(hdr_end, 4)? != &[0x18u8, 0x53, 0x80, 0x67][..] {
        return None;
    }
    let (m, seg) = vint(c, hdr_end + 4)?;
    let total = if seg == u64::MAX { until_gap(c, off, 4096 * MB) } else { hdr_end + 4 + m + seg - off };
    Some((total, ext))
}

fn ogg(c: &mut Cursor, off: u64) -> Option<(u64, &'static str)> {
    let first = c.get(off + 28, 8)?.to_vec();
    let ext = if first.starts_with(b"OpusHead") { "opus" } else { "ogg" };
    let mut p = off;
    for _ in 0..10_000_000 {
        if c.get(p, 4)? != &b"OggS"[..] {
            return if p > off { Some((p - off, ext)) } else { None };
        }
        let ht = c.u8(p + 5)?;
        let nseg = c.u8(p + 26)? as u64;
        let segs = c.get(p + 27, nseg as usize)?;
        let body: u64 = segs.iter().map(|&b| b as u64).sum();
        p += 27 + nseg + body;
        if ht & 4 != 0 {
            return Some((p - off, ext));
        }
        if p - off > 2048 * MB {
            return None;
        }
    }
    None
}

fn mp3(c: &mut Cursor, off: u64) -> Option<u64> {
    let s = c.get(off + 6, 4)?;
    let tag = ((s[0] as u64) << 21) | ((s[1] as u64) << 14) | ((s[2] as u64) << 7) | s[3] as u64;
    let footer = if c.u8(off + 5)? & 0x10 != 0 { 10 } else { 0 };
    let mut p = off + 10 + tag + footer;
    const BR1: [u64; 15] = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320];
    const BR2: [u64; 15] = [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160];
    let mut frames = 0;
    // Some taggers pad with zeros after the tag.
    for _ in 0..4096 {
        if c.u8(p)? == 0 {
            p += 1;
        } else {
            break;
        }
    }
    loop {
        let Some(h) = c.get(p, 4).map(|h| [h[0], h[1], h[2], h[3]]) else { break };
        if h[0] != 0xFF || h[1] & 0xE0 != 0xE0 {
            break;
        }
        let ver = (h[1] >> 3) & 3; // 3 = MPEG1, 2 = MPEG2, 0 = MPEG2.5
        let layer = (h[1] >> 1) & 3; // 1 = layer III
        let bri = (h[2] >> 4) as usize;
        let sri = ((h[2] >> 2) & 3) as usize;
        let pad = ((h[2] >> 1) & 1) as u64;
        if ver == 1 || layer != 1 || bri == 0 || bri == 15 || sri == 3 {
            break;
        }
        let sr = match ver {
            3 => [44100, 48000, 32000][sri],
            2 => [22050, 24000, 16000][sri],
            _ => [11025, 12000, 8000][sri],
        };
        let len = if ver == 3 { 144_000 * BR1[bri] / sr + pad } else { 72_000 * BR2[bri] / sr + pad };
        if len < 4 {
            break;
        }
        p += len;
        frames += 1;
        if p - off > 1024 * MB {
            break;
        }
    }
    if frames < 3 {
        return None;
    }
    if c.get(p, 3) == Some(b"TAG") {
        p += 128;
    }
    Some(p - off)
}

fn sqlite(c: &mut Cursor, off: u64) -> Option<u64> {
    let ps = c.get(off + 16, 2)?;
    let ps = match u16::from_be_bytes([ps[0], ps[1]]) {
        1 => 65536,
        v if v >= 512 && v.is_power_of_two() => v as u64,
        _ => return None,
    };
    let pages = c.u32be(off + 28)? as u64;
    if pages == 0 {
        return Some(until_gap(c, off, 1024 * MB));
    }
    Some(pages * ps)
}

fn seven_z(c: &mut Cursor, off: u64) -> Option<u64> {
    let o = c.u64le(off + 12)?;
    let s = c.u64le(off + 20)?;
    let t = 32u64.checked_add(o)?.checked_add(s)?;
    if t > 64 * 1024 * MB || s == 0 {
        return None;
    }
    Some(t)
}

fn exe(c: &mut Cursor, off: u64) -> Option<(u64, &'static str)> {
    let lf = c.u32le(off + 60)? as u64;
    let pe = off + lf;
    if c.get(pe, 4)? != b"PE\0\0" {
        return None;
    }
    let nsec = c.u16le(pe + 6)? as u64;
    let opt = c.u16le(pe + 20)? as u64;
    let chars = c.u16le(pe + 22)?;
    if nsec == 0 || nsec > 96 {
        return None;
    }
    let mut end = 0u64;
    let st = pe + 24 + opt;
    for i in 0..nsec {
        let s = st + i * 40;
        let raw = c.u32le(s + 16)? as u64;
        let ptr = c.u32le(s + 20)? as u64;
        if raw > 0 {
            end = end.max(ptr + raw);
        }
    }
    let magic = c.u16le(pe + 24)?;
    let dd = match magic {
        0x10B => pe + 24 + 96,
        0x20B => pe + 24 + 112,
        _ => 0,
    };
    if dd != 0 && opt >= (dd - pe - 24) + 40 {
        let cert_off = c.u32le(dd + 4 * 8)? as u64;
        let cert_len = c.u32le(dd + 4 * 8 + 4)? as u64;
        if cert_off > 0 && cert_len > 0 && cert_len < 64 * MB {
            end = end.max(cert_off + cert_len);
        }
    }
    if end == 0 || end > 4096 * MB {
        return None;
    }
    Some((end, if chars & 0x2000 != 0 { "dll" } else { "exe" }))
}

fn ole(c: &mut Cursor, off: u64) -> Option<(u64, &'static str)> {
    let shift = c.u16le(off + 30)?;
    if shift != 9 && shift != 12 {
        return None;
    }
    let ss = 1u64 << shift;
    let nfat = c.u32le(off + 44)? as u64;
    let dir_start = c.u32le(off + 48)?;
    let mut fat_secs: Vec<u32> = Vec::new();
    for i in 0..109u64.min(nfat) {
        fat_secs.push(c.u32le(off + 76 + i * 4)?);
    }
    let mut difat = c.u32le(off + 68)?;
    let mut guard = 0;
    while fat_secs.len() < nfat as usize && difat < 0xFFFF_FFFA && guard < 10_000 {
        let base = off + (difat as u64 + 1) * ss;
        let per = ss / 4 - 1;
        for i in 0..per {
            if fat_secs.len() >= nfat as usize {
                break;
            }
            fat_secs.push(c.u32le(base + i * 4)?);
        }
        difat = c.u32le(base + per * 4)?;
        guard += 1;
    }
    let mut fat: Vec<u32> = Vec::new();
    for &fs in &fat_secs {
        if fs >= 0xFFFF_FFFA {
            continue;
        }
        let base = off + (fs as u64 + 1) * ss;
        let b = c.get(base, ss as usize)?;
        fat.extend(b.chunks(4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]])));
    }
    let last = fat.iter().rposition(|&v| v != 0xFFFF_FFFF)? as u64;
    let size = (last + 2) * ss;
    // Name the kind from its directory entries.
    let mut names = Vec::new();
    let mut s = dir_start;
    for _ in 0..8 {
        if s >= 0xFFFF_FFFA {
            break;
        }
        if let Some(b) = c.get(off + (s as u64 + 1) * ss, ss as usize) {
            names.extend_from_slice(b);
        }
        s = *fat.get(s as usize).unwrap_or(&0xFFFF_FFFE);
    }
    let has = |t: &str| {
        let u: Vec<u8> = t.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        names.windows(u.len()).any(|w| w == &u[..])
    };
    let ext = if has("WordDocument") {
        "doc"
    } else if has("Workbook") || has("Book") {
        "xls"
    } else if has("PowerPoint Document") {
        "ppt"
    } else if has("__substg1.0_") {
        "msg"
    } else {
        "ole"
    };
    Some((size, ext))
}

fn tiff(c: &mut Cursor, off: u64) -> Option<(u64, &'static str)> {
    let be = c.get(off, 2)? == b"MM";
    let r16 = |c: &mut Cursor, p: u64| -> Option<u64> {
        let b = c.get(p, 2)?;
        Some(if be { u16::from_be_bytes([b[0], b[1]]) } else { u16::from_le_bytes([b[0], b[1]]) } as u64)
    };
    let r32 = |c: &mut Cursor, p: u64| -> Option<u64> {
        let b = c.get(p, 4)?;
        let a = [b[0], b[1], b[2], b[3]];
        Some(if be { u32::from_be_bytes(a) } else { u32::from_le_bytes(a) } as u64)
    };
    let ext = if c.get(off + 8, 2) == Some(b"CR") { "cr2" } else { "tif" };
    const TS: [u64; 14] = [0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8, 4];
    let mut end = 8u64;
    let mut queue = vec![r32(c, off + 4)?];
    let mut seen = HashSet::new();
    while let Some(ifd) = queue.pop() {
        if ifd < 8 || ifd > 2048 * MB || !seen.insert(ifd) || seen.len() > 64 {
            continue;
        }
        let p = off + ifd;
        let n = r16(c, p)?;
        if n == 0 || n > 1000 {
            continue;
        }
        end = end.max(ifd + 2 + n * 12 + 4);
        let mut strips: [(Vec<u64>, Vec<u64>); 3] = Default::default();
        for i in 0..n {
            let e = p + 2 + i * 12;
            let tag = r16(c, e)?;
            let typ = r16(c, e + 2)?;
            let cnt = r32(c, e + 4)?;
            let tsz = *TS.get(typ as usize).unwrap_or(&1);
            let bytes = cnt.saturating_mul(tsz);
            let vpos = if bytes > 4 { off + r32(c, e + 8)? } else { e + 8 };
            if bytes > 4 {
                end = end.max(vpos - off + bytes);
            }
            let read_vals = |c: &mut Cursor| -> Vec<u64> {
                let mut v = Vec::new();
                for k in 0..cnt.min(100_000) {
                    let x = if tsz == 2 { r16(c, vpos + k * 2) } else { r32(c, vpos + k * 4) };
                    match x {
                        Some(x) => v.push(x),
                        None => break,
                    }
                }
                v
            };
            match tag {
                0x111 => strips[0].0 = read_vals(c),
                0x117 => strips[0].1 = read_vals(c),
                0x144 => strips[1].0 = read_vals(c),
                0x145 => strips[1].1 = read_vals(c),
                0x201 => strips[2].0 = read_vals(c),
                0x202 => strips[2].1 = read_vals(c),
                0x14A | 0x8769 => {
                    for v in read_vals(c) {
                        queue.push(v);
                    }
                }
                _ => {}
            }
        }
        for (o, l) in &strips {
            for (a, b) in o.iter().zip(l.iter()) {
                end = end.max(a + b);
            }
        }
        let next = r32(c, p + 2 + n * 12)?;
        if next != 0 {
            queue.push(next);
        }
    }
    if end > 2048 * MB {
        return None;
    }
    Some((end, ext))
}

fn measure(c: &mut Cursor, off: u64, k: Kind) -> Option<(u64, String)> {
    let (len, ext): (u64, &str) = match k {
        Kind::Jpeg => (jpeg(c, off)?, "jpg"),
        Kind::Png => (png(c, off)?, "png"),
        Kind::Gif => (gif(c, off)?, "gif"),
        Kind::Bmp => (bmp(c, off)?, "bmp"),
        Kind::Pdf => (pdf(c, off)?, "pdf"),
        Kind::Zip => {
            let l = zip(c, off)?;
            (l, zip_kind(c, off, l))
        }
        Kind::Rar => (until_gap(c, off, 1024 * MB), "rar"),
        Kind::Gzip => (until_gap(c, off, 1024 * MB), "gz"),
        Kind::SevenZ => (seven_z(c, off)?, "7z"),
        Kind::Riff => riff(c, off)?,
        Kind::Isobmff => isobmff(c, off)?,
        Kind::Mkv => mkv(c, off)?,
        Kind::Ogg => ogg(c, off)?,
        Kind::Flac => (until_gap(c, off, 1024 * MB), "flac"),
        Kind::Mp3 => (mp3(c, off)?, "mp3"),
        Kind::Sqlite => (sqlite(c, off)?, "sqlite"),
        Kind::Exe => exe(c, off)?,
        Kind::Ole => ole(c, off)?,
        Kind::Tiff => tiff(c, off)?,
    };
    if len < 16 {
        return None;
    }
    Some((len, ext.to_string()))
}

pub struct CarveJob<'a> {
    pub disk: &'a Disk,
    pub start: u64,
    pub end: u64,
    pub volume: String,
    pub cats: &'a HashSet<Category>,
    /// Starts of files already found by name, so they aren't listed twice.
    pub known: &'a HashSet<u64>,
    /// Also report previous partitions met along the way.
    pub find_partitions: bool,
}

/// `lost` gets each previous partition met along the way and returns the starts of
/// the files it recovered from it, so they aren't listed a second time.
pub fn carve(job: &CarveJob, sink: &mut Sink, progress: &mut dyn FnMut(u64), lost: &mut dyn FnMut(Volume) -> Vec<u64>) {
    let mut known = job.known.clone();
    let disk = job.disk;
    let chunk: u64 = 4 * MB;
    let mut pos = (job.start + 511) & !511;
    let mut cur = Cursor::new(disk, job.end);
    let mut buf = vec![0u8; chunk as usize];
    let mut counter = 0u64;
    while pos < job.end {
        if (sink.cancelled)() {
            return;
        }
        let want = chunk.min(job.end - pos) as usize;
        let n = disk.read_at(&mut buf[..want], pos).unwrap_or(0);
        if n < 64 {
            break;
        }
        let mut next = pos + n as u64;
        let mut s = 0usize;
        while s + 64 <= n {
            let off = pos + s as u64;
            let sec = &buf[s..(s + 512).min(n)];
            if job.find_partitions
                && sec.len() >= 512
                && ((sec[510] == 0x55 && sec[511] == 0xAA) || (sec[56] == 0x53 && sec[57] == 0xEF))
            {
                if let Some(v) = crate::rescue::partfind::check(disk, off, sec) {
                    known.extend(lost(v));
                }
            }
            if let Some(k) = identify(&sec[..64]) {
                if job.cats.contains(&kind_category(k)) || k == Kind::Zip || k == Kind::Riff || k == Kind::Isobmff {
                    if let Some((len, ext)) = measure(&mut cur, off, k) {
                        let len = len.min(job.end - off);
                        if job.cats.contains(&category_of(&ext)) && !known.contains(&off) {
                            counter += 1;
                            (sink.emit)(Found {
                                name: format!("f{:08}.{ext}", off / 512),
                                folder: String::new(),
                                ext: ext.clone(),
                                size: len,
                                method: Method::Carved,
                                fs: "content".into(),
                                volume: job.volume.clone(),
                                extents: vec![(off, len)],
                                inline_data: None,
                                chance: if len >= 1024 { Chance::Good } else { Chance::Fair },
                                note: "Name lost; found by its content".into(),
                            });
                        }
                        let skip_to = (off + len + 511) & !511;
                        if skip_to > off {
                            if skip_to >= pos + n as u64 {
                                next = skip_to;
                                break;
                            }
                            s = (skip_to - pos) as usize;
                            continue;
                        }
                    }
                }
            }
            s += 512;
        }
        let _ = counter;
        pos = next;
        progress(pos.min(job.end) - job.start);
    }
}
