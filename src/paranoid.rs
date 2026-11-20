//! "Paranoid" check: a quick structural look inside program files (Linux ELF
//! and Windows PE) at the places file-infecting viruses, packers and backdoors
//! usually show themselves. These are heuristics, not proof: each sign adds to
//! a score, and only files that add up are reported.

use crate::jobs::{Emitter, Finding, Sev};
use goblin::Object;
use std::io::Read;

/// Bigger files are only partly checked (headers and the first part).
const MAX_BYTES: u64 = 64 * 1_048_576;
/// Score at which a file is reported, and at which it counts as serious.
const REPORT_AT: u32 = 3;
const SERIOUS_AT: u32 = 6;

pub struct Verdict {
    pub score: u32,
    pub reasons: Vec<String>,
}

impl Verdict {
    fn add(&mut self, points: u32, why: impl Into<String>) {
        self.score += points;
        self.reasons.push(why.into());
    }
}

/// Is this a program file worth a look (ELF or Windows PE)?
pub fn is_binary(path: &str) -> bool {
    let mut b = [0u8; 4];
    std::fs::File::open(path).and_then(|mut f| f.read_exact(&mut b)).map(|_| &b == b"\x7fELF" || &b[..2] == b"MZ").unwrap_or(false)
}

fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    counts.iter().filter(|&&c| c > 0).map(|&c| {
        let p = c as f64 / n;
        -p * p.log2()
    }).sum()
}

/// Text that turns up in miners, backdoors and droppers (weight, text, meaning).
const STRINGS: &[(u32, &str, &str)] = &[
    (3, "stratum+tcp", "crypto-miner pool address"),
    (3, "xmrig", "crypto-miner (XMRig)"),
    (3, "/etc/ld.so.preload", "writes the system-wide preload file (rootkit trick)"),
    (3, "kinsing", "known Linux malware name"),
    (1, "/dev/tcp/", "shell reverse connection"),
    (2, "/bin/sh -i", "interactive remote shell"),
    (2, "chattr +i", "locks files against deletion"),
    (2, "iptables -F", "wipes firewall rules"),
    (2, "rm -rf /var/log", "deletes system logs"),
    (2, "busybox wget", "downloads with busybox (IoT botnets)"),
    (1, "LD_PRELOAD", "library preloading"),
    (1, "authorized_keys", "touches SSH login keys"),
    (1, "crontab", "schedules itself"),
    (1, "HISTFILE", "fiddles with shell history"),
    (1, "/tmp/.", "hidden file in a temp folder"),
    (1, "masscan", "mass port scanning"),
];

/// Names that must stand alone (not inside a longer word).
const WHOLE_WORDS: &[&str] = &["xmrig", "kinsing", "masscan"];

fn string_signs(data: &[u8], v: &mut Verdict, is_loader: bool) {
    let mut points = 0;
    let lower: Vec<u8> = data.iter().map(|b| b.to_ascii_lowercase()).collect();
    for (w, s, why) in STRINGS {
        // The system's program loader reads the preload file; that's its job.
        if is_loader && *s == "/etc/ld.so.preload" {
            continue;
        }
        let needle = s.to_ascii_lowercase();
        let n = needle.len();
        let whole = WHOLE_WORDS.contains(s);
        let found = lower.windows(n).enumerate().any(|(i, win)| {
            win == needle.as_bytes()
                && (!whole
                    || ((i == 0 || !lower[i - 1].is_ascii_alphanumeric()) && (i + n >= lower.len() || !lower[i + n].is_ascii_alphanumeric())))
        });
        if found {
            points += w;
            v.reasons.push(format!("contains \"{s}\" ({why})"));
        }
    }
    let has = |s: &str| lower.windows(s.len()).any(|w| w == s.as_bytes());
    if (has("curl ") || has("wget ")) && (has("| sh") || has("|sh") || has("| bash") || has("|bash")) {
        points += 2;
        v.reasons.push("downloads and runs a script (curl/wget | sh)".into());
    }
    v.score += points.min(6);
}

fn check_elf(data: &[u8], file_len: u64, elf: &goblin::elf::Elf, v: &mut Verdict) {
    use goblin::elf::program_header::{PF_W, PF_X, PT_LOAD};
    let entry = elf.entry;
    let exec_like = elf.header.e_type == goblin::elf::header::ET_EXEC || (elf.header.e_type == goblin::elf::header::ET_DYN && elf.interpreter.is_some());
    let loads: Vec<_> = elf.program_headers.iter().filter(|p| p.p_type == PT_LOAD).collect();

    // Memory that is both writable and runnable: self-modifying or injected code.
    for p in &loads {
        if p.p_flags & PF_W != 0 && p.p_flags & PF_X != 0 {
            v.add(3, "has memory that is both writable and runnable");
            break;
        }
    }

    if exec_like && entry != 0 {
        let names: Vec<(String, u64, u64)> = elf
            .section_headers
            .iter()
            .filter(|s| s.sh_addr != 0 && s.sh_size != 0)
            .map(|s| (elf.shdr_strtab.get_at(s.sh_name).unwrap_or("?").to_string(), s.sh_addr, s.sh_addr + s.sh_size))
            .collect();
        if elf.section_headers.is_empty() {
            v.add(2, "section table removed (common in packed malware)");
        } else {
            match names.iter().find(|(_, a, b)| entry >= *a && entry < *b) {
                None => v.add(3, "starts running outside every section (classic file-infector trick)"),
                Some((n, _, _)) if n != ".text" && n != ".init" && !n.starts_with(".text") => v.add(2, format!("starts running in section {n} instead of .text")),
                _ => {}
            }
        }
        // Entry in the last loaded segment that's writable: appended virus body.
        if let Some(last) = loads.last() {
            if entry >= last.p_vaddr && entry < last.p_vaddr + last.p_memsz && last.p_flags & PF_W != 0 {
                v.add(3, "starts running in the last, writable part of the file (appended code)");
            }
        }
        // The code segment's content: very high entropy = encrypted or packed.
        if let Some(code) = loads.iter().find(|p| p.p_flags & PF_X != 0) {
            let a = code.p_offset as usize;
            let b = (code.p_offset + code.p_filesz).min(data.len() as u64) as usize;
            if b > a + 4096 {
                let e = entropy(&data[a..b]);
                if e > 7.3 {
                    v.add(2, format!("code looks encrypted or compressed (entropy {e:.2} of 8)"));
                }
            }
        }
    }

    // Packers.
    let head = &data[..data.len().min(8192)];
    if head.windows(4).any(|w| w == b"UPX!") || elf.section_headers.iter().any(|s| elf.shdr_strtab.get_at(s.sh_name).map(|n| n.starts_with("UPX")).unwrap_or(false)) {
        v.add(3, "packed with UPX (hides its real code from scanners)");
    }

    // Data glued on after the end of the program.
    let end_sections = elf.section_headers.iter().map(|s| if s.sh_type == goblin::elf::section_header::SHT_NOBITS { 0 } else { s.sh_offset + s.sh_size }).max().unwrap_or(0);
    let end_segments = elf.program_headers.iter().map(|p| p.p_offset + p.p_filesz).max().unwrap_or(0);
    let end_table = elf.header.e_shoff + elf.header.e_shnum as u64 * elf.header.e_shentsize as u64;
    let end = end_sections.max(end_segments).max(end_table);
    if file_len > end + 65536 {
        let extra = file_len - end;
        let a = end as usize;
        let tail_e = if a < data.len() { entropy(&data[a..data.len().min(a + 1_048_576)]) } else { 0.0 };
        if tail_e > 7.5 {
            v.add(2, format!("{} KB of encrypted-looking data appended after the program", extra / 1024));
        } else {
            v.add(1, format!("{} KB of extra data appended after the program", extra / 1024));
        }
    }

    // Loader and library search paths.
    if let Some(interp) = elf.interpreter {
        let normal = interp.starts_with("/lib64/ld-linux") || interp.starts_with("/lib/ld-") || interp.starts_with("/usr/lib/ld-") || interp.starts_with("/lib/ld64") || interp.starts_with("/usr/lib64/ld-") || interp.starts_with("/nix/store/");
        if !normal {
            v.add(3, format!("uses an unusual program loader: {interp}"));
        }
    }
    for p in elf.rpaths.iter().chain(elf.runpaths.iter()) {
        if p.contains("/tmp") || p.contains("/dev/shm") || p.split(':').any(|x| x == "." || x.is_empty()) {
            v.add(2, format!("looks for libraries in an unsafe place: {p}"));
        }
    }
    for lib in &elf.libraries {
        if lib.starts_with('/') && (lib.starts_with("/tmp") || lib.starts_with("/dev/shm") || lib.contains("/.")) {
            v.add(3, format!("loads a library from a suspicious path: {lib}"));
        }
    }

    // What it asks the system for.
    let imports: Vec<&str> = elf.dynsyms.iter().filter(|s| s.is_import()).filter_map(|s| elf.dynstrtab.get_at(s.st_name)).collect();
    let has = |n: &str| imports.iter().any(|i| *i == n);
    if has("ptrace") && (has("process_vm_writev") || has("mprotect")) {
        v.add(2, "can attach to and modify other programs (ptrace)");
    }
    if (has("socket") || has("connect")) && (has("execve") || has("execl") || has("system") || has("popen")) && has("dup2") {
        v.add(1, "connects to the network and hands its input/output to a command (reverse-shell pattern, also normal for shells)");
    }
    // Statically linked and stripped: can't tell what it uses.
    if elf.interpreter.is_none() && elf.header.e_type == goblin::elf::header::ET_EXEC && elf.syms.is_empty() {
        v.add(1, "statically linked and stripped (nothing to tell what it does)");
    }
}

fn check_pe(data: &[u8], file_len: u64, pe: &goblin::pe::PE, v: &mut Verdict) {
    const EXEC: u32 = 0x2000_0000;
    const WRITE: u32 = 0x8000_0000;
    let entry = pe.entry as u32;
    let secs = &pe.sections;
    for s in secs {
        if s.characteristics & EXEC != 0 && s.characteristics & WRITE != 0 {
            v.add(2, format!("section {} is both writable and runnable", s.name().unwrap_or("?")));
            break;
        }
    }
    if secs.iter().any(|s| s.name().map(|n| n.starts_with("UPX")).unwrap_or(false)) {
        v.add(3, "packed with UPX (hides its real code from scanners)");
    }
    if entry != 0 {
        let idx = secs.iter().position(|s| entry >= s.virtual_address && entry < s.virtual_address + s.virtual_size.max(s.size_of_raw_data));
        match idx {
            None => v.add(3, "starts running outside every section (classic file-infector trick)"),
            Some(i) => {
                let s = &secs[i];
                if s.characteristics & EXEC == 0 {
                    v.add(3, format!("starts running in a section not marked as code ({})", s.name().unwrap_or("?")));
                }
                if i + 1 == secs.len() && secs.len() > 1 {
                    v.add(2, "starts running in the last section (appended virus body)");
                }
                let a = s.pointer_to_raw_data as usize;
                let b = (a + s.size_of_raw_data as usize).min(data.len());
                if b > a + 4096 {
                    let e = entropy(&data[a..b]);
                    if e > 7.3 {
                        v.add(2, format!("code looks encrypted or compressed (entropy {e:.2} of 8)"));
                    }
                }
            }
        }
    }
    let end = secs.iter().map(|s| s.pointer_to_raw_data as u64 + s.size_of_raw_data as u64).max().unwrap_or(0);
    if file_len > end + 65536 {
        v.add(1, format!("{} KB of extra data appended after the program (installers do this too)", (file_len - end) / 1024));
    }
    let names: Vec<String> = pe.imports.iter().map(|i| i.name.to_string()).collect();
    let has = |n: &str| names.iter().any(|i| i == n);
    if has("WriteProcessMemory") && (has("CreateRemoteThread") || has("NtCreateThreadEx")) {
        v.add(3, "can inject code into other programs (WriteProcessMemory + CreateRemoteThread)");
    }
    if has("URLDownloadToFileA") || has("URLDownloadToFileW") {
        v.add(2, "downloads files from the internet by itself");
    }
    if has("SetWindowsHookExA") || has("SetWindowsHookExW") {
        if has("GetAsyncKeyState") || has("GetKeyState") {
            v.add(2, "watches the keyboard (keylogger pattern)");
        }
    }
    if pe.imports.is_empty() && !pe.is_lib {
        v.add(1, "imports nothing (it finds what it needs at run time — common in packed malware)");
    }
}

/// Look inside one program file. None when it isn't one or can't be read.
pub fn inspect(path: &str) -> Option<Verdict> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || !is_binary(path) {
        return None;
    }
    let len = meta.len();
    let mut data = Vec::with_capacity(len.min(MAX_BYTES) as usize);
    std::fs::File::open(path).ok()?.take(MAX_BYTES).read_to_end(&mut data).ok()?;
    let mut v = Verdict { score: 0, reasons: vec![] };
    // Windows' own system folders hold signed Microsoft files; scoring them is all noise.
    {
        let p = path.to_lowercase();
        if p.contains("/windows/system32/") || p.contains("/windows/syswow64/") || p.contains("/windows/winsxs/") || p.contains("/windows/servicing/") {
            return None;
        }
    }
    // Flatpak checks its own files against their checksums.
    if path.contains("/flatpak/repo/objects/") || path.contains("/flatpak/runtime/") || path.contains("/flatpak/app/") {
        return None;
    }
    // Wine's own builtin Windows DLLs are generated stubs, not real Windows programs.
    if data.len() > 0x60 && (data[0x40..0x60].windows(16).any(|w| w == b"Wine builtin DLL") || data[0x40..0x60].windows(20).any(|w| w == b"Wine placeholder DLL")) {
        return None;
    }
    let name = std::path::Path::new(path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let is_loader = name.starts_with("ld-linux") || name.starts_with("ld-musl") || name == "ld.so" || name.starts_with("ld64.so");
    if len > MAX_BYTES {
        v.reasons.push(format!("only the first {} MB were checked", MAX_BYTES / 1_048_576));
    }
    match Object::parse(&data) {
        Ok(Object::Elf(elf)) => check_elf(&data, len, &elf, &mut v),
        Ok(Object::PE(pe)) => check_pe(&data, len, &pe, &mut v),
        Ok(_) => return None,
        Err(e) => {
            if len <= MAX_BYTES {
                v.add(2, format!("damaged or deliberately malformed headers ({e})"));
            }
        }
    }
    string_signs(&data, &mut v, is_loader);
    Some(v)
}

/// Check many files with several low-priority threads; report the suspicious
/// ones. Returns the serious findings (worth a VirusTotal second opinion).
pub fn inspect_files(paths: Vec<String>, threads: usize, em: &mut Emitter) -> Vec<Finding> {
    let bins: Vec<String> = paths.into_iter().filter(|p| is_binary(p)).collect();
    let total = bins.len();
    if total == 0 {
        return vec![];
    }
    em.progress(format!("Paranoid check: looking inside {total} program files…"));
    let ctl = em.cancel_flag();
    let queue = std::sync::Mutex::new(bins);
    let (tx, rx) = std::sync::mpsc::channel::<(String, Option<Verdict>)>();
    let mut serious = vec![];
    let mut flagged = 0;
    std::thread::scope(|scope| {
        for _ in 0..threads.max(1) {
            let tx = tx.clone();
            let queue = &queue;
            let ctl = ctl.clone();
            scope.spawn(move || {
                crate::par::lowest_priority_thread();
                loop {
                    ctl.wait_if_paused();
                    if ctl.cancelled() {
                        break;
                    }
                    let Some(p) = queue.lock().unwrap().pop() else { break };
                    let v = inspect(&p);
                    let _ = tx.send((p, v));
                }
            });
        }
        drop(tx);
        let mut done = 0;
        for (path, v) in rx {
            done += 1;
            if done % 50 == 0 || done == total {
                em.progress(format!("Paranoid check: {done} of {total} program files…"));
            }
            let Some(v) = v else { continue };
            if v.score < REPORT_AT {
                continue;
            }
            flagged += 1;
            let sev = if v.score >= SERIOUS_AT { Sev::High } else { Sev::Medium };
            let f = Finding {
                sev,
                kind: "Paranoid check".into(),
                path,
                detail: format!("Paranoid: suspicion score {} — {}", v.score, v.reasons.join("; ")),
            };
            em.emit(crate::jobs::Msg::Find(f.clone()));
            if sev == Sev::High {
                serious.push(f);
            }
        }
    });
    em.log(format!("Paranoid check: {total} program files inspected, {flagged} look odd ({} seriously).", serious.len()));
    serious
}
