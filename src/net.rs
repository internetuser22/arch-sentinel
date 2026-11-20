//! Live connections per program (from /proc/net) and the installed
//! OpenSnitch service's rules (/etc/opensnitchd/rules/*.json).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug)]
pub struct Conn {
    pub proto: &'static str,
    pub local: String,
    pub remote: String,
    pub remote_ip: String,
    pub remote_port: u16,
    pub state: &'static str,
    pub uid: u32,
    pub pid: Option<i32>,
    pub program: String,
}

fn tcp_state(code: &str) -> &'static str {
    match code {
        "01" => "Connected",
        "02" => "Connecting",
        "03" => "Opening",
        "04" => "Closing",
        "05" => "Closing",
        "06" => "Waiting",
        "07" => "Closed",
        "08" => "Closing",
        "09" => "Closing",
        "0A" => "Listening",
        "0B" => "Closing",
        _ => "?",
    }
}

fn parse_addr(s: &str, v6: bool) -> (String, u16) {
    let (a, p) = s.split_once(':').unwrap_or((s, "0"));
    let port = u16::from_str_radix(p, 16).unwrap_or(0);
    let ip = if !v6 {
        let n = u32::from_str_radix(a, 16).unwrap_or(0);
        Ipv4Addr::from(u32::from_be(n)).to_string()
    } else {
        let mut b = [0u8; 16];
        for i in 0..4 {
            let w = u32::from_str_radix(&a.get(i * 8..i * 8 + 8).unwrap_or("0"), 16).unwrap_or(0);
            b[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        let ip6 = Ipv6Addr::from(b);
        match ip6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => ip6.to_string(),
        }
    };
    (ip, port)
}

/// socket inode -> (pid, program)
fn socket_owners() -> HashMap<u64, (i32, String)> {
    let mut map = HashMap::new();
    let Ok(rd) = std::fs::read_dir("/proc") else { return map };
    for e in rd.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
        let Ok(fds) = std::fs::read_dir(e.path().join("fd")) else { continue };
        let mut prog: Option<String> = None;
        for fd in fds.flatten() {
            let Ok(t) = std::fs::read_link(fd.path()) else { continue };
            let t = t.to_string_lossy();
            if let Some(ino) = t.strip_prefix("socket:[").and_then(|x| x.strip_suffix(']')) {
                if let Ok(ino) = ino.parse::<u64>() {
                    let p = prog
                        .get_or_insert_with(|| {
                            std::fs::read_link(e.path().join("exe"))
                                .map(|p| p.to_string_lossy().trim_end_matches(" (deleted)").to_string())
                                .unwrap_or_else(|_| std::fs::read_to_string(e.path().join("comm")).unwrap_or_default().trim().to_string())
                        })
                        .clone();
                    map.insert(ino, (pid, p));
                }
            }
        }
    }
    map
}

pub fn connections() -> Vec<Conn> {
    let owners = socket_owners();
    let mut out = vec![];
    for (file, proto, v6) in [
        ("/proc/net/tcp", "TCP", false),
        ("/proc/net/tcp6", "TCP6", true),
        ("/proc/net/udp", "UDP", false),
        ("/proc/net/udp6", "UDP6", true),
    ] {
        let Ok(t) = std::fs::read_to_string(file) else { continue };
        for l in t.lines().skip(1) {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 10 {
                continue;
            }
            let (lip, lport) = parse_addr(f[1], v6);
            let (rip, rport) = parse_addr(f[2], v6);
            let state = if proto.starts_with("UDP") {
                if rport == 0 { "Open" } else { "Connected" }
            } else {
                tcp_state(f[3])
            };
            if state == "Closed" {
                continue;
            }
            let uid: u32 = f[7].parse().unwrap_or(0);
            let ino: u64 = f[9].parse().unwrap_or(0);
            let (pid, program) = match owners.get(&ino) {
                Some((p, n)) => (Some(*p), n.clone()),
                None => (None, if ino == 0 { "(kernel)".into() } else { format!("(user {uid} — needs administrator to see)") }),
            };
            let fmt = |ip: &str, port: u16| if ip.contains(':') { format!("[{ip}]:{port}") } else { format!("{ip}:{port}") };
            out.push(Conn {
                proto,
                local: fmt(&lip, lport),
                remote: if rport == 0 { "—".into() } else { fmt(&rip, rport) },
                remote_ip: rip,
                remote_port: rport,
                state,
                uid,
                pid,
                program,
            });
        }
    }
    out.sort_by(|a, b| a.program.cmp(&b.program).then(a.remote.cmp(&b.remote)));
    out
}

// ---------- OpenSnitch rules ----------

pub const RULES_DIR: &str = "/etc/opensnitchd/rules";

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Operator {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub operand: String,
    #[serde(default)]
    pub sensitive: bool,
    #[serde(default)]
    pub data: String,
    #[serde(default)]
    pub list: Option<Vec<Operator>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Rule {
    #[serde(default)]
    pub created: String,
    #[serde(default)]
    pub updated: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub precedence: bool,
    #[serde(default)]
    pub nolog: bool,
    pub action: String,
    #[serde(default)]
    pub duration: String,
    pub operator: Operator,
}

impl Rule {
    pub fn summary(&self) -> String {
        describe_op(&self.operator)
    }
}

pub fn operand_label(op: &str) -> &str {
    match op {
        "process.path" => "program",
        "process.command" => "command line",
        "dest.host" => "host name",
        "dest.ip" => "address",
        "dest.port" => "port",
        "dest.network" => "network",
        "user.id" => "user id",
        "protocol" => "protocol",
        "process.id" => "process id",
        o => o,
    }
}

fn describe_op(op: &Operator) -> String {
    if op.kind == "list" {
        op.list
            .as_ref()
            .map(|l| l.iter().map(describe_op).collect::<Vec<_>>().join(" and "))
            .unwrap_or_default()
    } else {
        let verb = match op.kind.as_str() {
            "regexp" => "matches",
            "network" => "in",
            "lists" => "listed in",
            _ => "is",
        };
        format!("{} {verb} {}", operand_label(&op.operand), op.data)
    }
}

/// Parse the concatenated output of the privileged rule dump.
pub fn parse_rule_dump(text: &str) -> (Vec<(String, Rule)>, Vec<String>) {
    let mut rules = vec![];
    let mut errors = vec![];
    for chunk in text.split("\n===ASRULE ").skip(0) {
        let chunk = chunk.trim_start_matches("===ASRULE ");
        let Some((file, body)) = chunk.split_once('\n') else { continue };
        let file = file.trim().to_string();
        if file.is_empty() || !file.ends_with(".json") {
            continue;
        }
        match serde_json::from_str::<Rule>(body.trim()) {
            Ok(r) => rules.push((file, r)),
            Err(e) => errors.push(format!("{file}: {e}")),
        }
    }
    rules.sort_by(|a, b| a.1.name.cmp(&b.1.name));
    (rules, errors)
}

pub fn dump_rules_script() -> String {
    format!(
        "for f in {RULES_DIR}/*.json; do [ -e \"$f\" ] || continue; printf '\\n===ASRULE %s\\n' \"$(basename \"$f\")\"; cat \"$f\"; done"
    )
}

pub fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, (rem % 3600) / 60, rem % 60)
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn new_rule(name: &str, action: &str, operand: &str, data: &str) -> Rule {
    let now = now_rfc3339();
    let kind = if operand == "dest.network" { "network" } else { "simple" };
    Rule {
        created: now.clone(),
        updated: now,
        name: name.to_string(),
        description: "Made with Arch Sentinel".into(),
        enabled: true,
        precedence: action != "allow",
        nolog: false,
        action: action.to_string(),
        duration: "always".into(),
        operator: Operator {
            kind: kind.into(),
            operand: operand.into(),
            sensitive: false,
            data: data.into(),
            list: Some(vec![]),
        },
    }
}

pub fn rule_file_name(name: &str) -> String {
    let clean: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c.to_ascii_lowercase() } else { '-' })
        .collect();
    format!("{}.json", clean.trim_matches('-'))
}

/// Script (for pkexec) that writes a rule file into the rules folder.
pub fn write_rule_script(file: &str, rule: &Rule) -> std::io::Result<String> {
    let tmp = std::env::temp_dir().join(format!("arch-sentinel-rule-{}-{}", std::process::id(), file));
    std::fs::write(&tmp, serde_json::to_string_pretty(rule).unwrap())?;
    Ok(format!(
        "install -m 0600 {} {}/{}",
        crate::clam::shell_quote(&tmp.to_string_lossy()),
        RULES_DIR,
        crate::clam::shell_quote(file)
    ))
}

pub fn delete_rule_script(file: &str) -> String {
    format!("rm -f {}/{}", RULES_DIR, crate::clam::shell_quote(file))
}

pub fn service_state(unit: &str) -> String {
    std::process::Command::new("systemctl")
        .args(["is-active", unit])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}

pub fn service_enabled(unit: &str) -> String {
    std::process::Command::new("systemctl")
        .args(["is-enabled", unit])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}

/// OpenSnitch's default action and whether unknown connections are intercepted.
pub fn opensnitch_config() -> Option<(String, bool)> {
    let t = std::fs::read_to_string("/etc/opensnitchd/default-config.json").ok()?;
    let v: serde_json::Value = serde_json::from_str(&t).ok()?;
    Some((
        v["DefaultAction"].as_str().unwrap_or("?").to_string(),
        v["InterceptUnknown"].as_bool().unwrap_or(false),
    ))
}

// ---------- verifying the programs behind connections ----------

#[derive(Clone, Debug, PartialEq)]
pub enum Trust {
    /// From a package and its files match the package's checksums.
    Verified,
    /// Not installed by any package.
    NotPackaged,
    /// From a package, but the file differs from what the package installed.
    Changed,
    /// The program file is gone or was replaced while running.
    Replaced,
    /// Running from a temporary folder or memory.
    Suspicious,
    /// We couldn't see which program owns the connection.
    Unknown,
}

impl Trust {
    pub fn label(&self) -> &'static str {
        match self {
            Trust::Verified => "Verified",
            Trust::NotPackaged => "Not from a package",
            Trust::Changed => "CHANGED",
            Trust::Replaced => "Replaced on disk",
            Trust::Suspicious => "Suspicious place",
            Trust::Unknown => "Unknown",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Verification {
    pub trust: Trust,
    pub package: Option<String>,
    pub note: String,
}

/// Ports that ordinary desktop software rarely uses but malware and remote shells often do.
pub fn port_warning(port: u16) -> Option<&'static str> {
    match port {
        4444 | 4445 => Some("port often used by remote-control shells"),
        1337 | 31337 | 12345 | 54321 => Some("port often used by backdoors"),
        6666 | 6667 | 6697 => Some("IRC port (old botnets used it to take orders)"),
        3333 | 5555 | 7777 | 14444 | 45700 => Some("port often used by crypto-miners"),
        9001 | 9030 | 9050 | 9150 => Some("Tor port"),
        23 => Some("Telnet (unencrypted remote login)"),
        _ => None,
    }
}

/// Check one program path against the package database and paccheck.
pub fn verify_program(path: &str, owner: &HashMap<String, String>) -> Verification {
    if path.starts_with('(') {
        return Verification { trust: Trust::Unknown, package: None, note: "run as administrator to see the program".into() };
    }
    if path.starts_with("/tmp/") || path.starts_with("/dev/shm/") || path.starts_with("/var/tmp/") || path.contains("memfd:") {
        return Verification { trust: Trust::Suspicious, package: None, note: format!("runs from {path}") };
    }
    if !std::path::Path::new(path).exists() {
        return Verification { trust: Trust::Replaced, package: owner.get(path).cloned(), note: "program file no longer on disk (updated or deleted) — restart it".into() };
    }
    let Some(pkg) = owner.get(path).cloned() else {
        return Verification { trust: Trust::NotPackaged, package: None, note: "no package installed this program".into() };
    };
    let out = std::process::Command::new("/usr/bin/paccheck")
        .args(["--sha256sum", "--file-properties", "--quiet", &pkg])
        .output();
    match out {
        Ok(o) => {
            let text = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
            let quoted = format!("'{path}'");
            if let Some(line) = text.lines().find(|l| l.contains(&quoted) && (l.contains("checksum") || l.contains("size"))) {
                Verification { trust: Trust::Changed, package: Some(pkg), note: line.to_string() }
            } else {
                let other = text.lines().filter(|l| l.contains("checksum")).count();
                let note = if other > 0 { format!("program matches; {other} other file(s) in {pkg} differ") } else { format!("matches package {pkg}") };
                Verification { trust: Trust::Verified, package: Some(pkg), note }
            }
        }
        Err(e) => Verification { trust: Trust::Unknown, package: Some(pkg), note: format!("paccheck failed: {e}") },
    }
}

/// Which loaded OpenSnitch rule would apply to a connection (simple rules only).
pub fn matching_rule<'a>(rules: &'a [(String, Rule)], c: &Conn) -> Option<&'a Rule> {
    let op_matches = |op: &Operator| -> bool {
        let d = op.data.as_str();
        match (op.kind.as_str(), op.operand.as_str()) {
            ("simple", "process.path") => c.program == d,
            ("simple", "dest.ip") => c.remote_ip == d,
            ("simple", "dest.port") => c.remote_port.to_string() == d,
            ("simple", "user.id") => c.uid.to_string() == d,
            ("regexp", "process.path") => c.program.contains(d.trim_matches(|x| x == '^' || x == '$')),
            _ => false,
        }
    };
    let mut best: Option<&Rule> = None;
    for (_, r) in rules.iter().filter(|(_, r)| r.enabled) {
        let m = if r.operator.kind == "list" {
            r.operator.list.as_ref().map(|l| !l.is_empty() && l.iter().all(|o| op_matches(o))).unwrap_or(false)
        } else {
            op_matches(&r.operator)
        };
        if m && (best.is_none() || r.precedence || r.action != "allow") {
            best = Some(r);
        }
    }
    best
}

// ---------- firewall mode (default deny + ask) ----------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FwMode {
    /// Deny by default and ask with OpenSnitch's pop-up; no answer means deny.
    Ask,
    /// Deny anything without a rule, no pop-ups.
    Deny,
    /// Allow anything without a rule (OpenSnitch's own default).
    Allow,
}

impl FwMode {
    pub fn label(self) -> &'static str {
        match self {
            FwMode::Ask => "Ask me, deny if I don't answer (recommended)",
            FwMode::Deny => "Deny silently",
            FwMode::Allow => "Allow (OpenSnitch's original default)",
        }
    }
}

fn ui_conf_path() -> std::path::PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(crate::settings::home_dir()).join(".config"));
    base.join("opensnitch/settings.conf")
}

/// (pop-ups on, pop-up timeout in seconds) from the OpenSnitch pop-up's settings.
pub fn ui_prompt_settings() -> (bool, u32) {
    let t = std::fs::read_to_string(ui_conf_path()).unwrap_or_default();
    let mut popups = true;
    let mut timeout = 30;
    let mut in_global = false;
    for l in t.lines() {
        let l = l.trim();
        if l.starts_with('[') {
            in_global = l == "[global]";
            continue;
        }
        if !in_global {
            continue;
        }
        if let Some(v) = l.strip_prefix("disable_popups=") {
            popups = v.trim() != "true";
        }
        if let Some(v) = l.strip_prefix("default_timeout=") {
            timeout = v.trim().parse().unwrap_or(30);
        }
    }
    (popups, timeout)
}

/// Set keys in the [global] section of the pop-up's settings (an ini file).
fn set_ui_conf(keys: &[(&str, String)]) -> std::io::Result<()> {
    let p = ui_conf_path();
    let text = std::fs::read_to_string(&p).unwrap_or_default();
    let mut out: Vec<String> = vec![];
    let mut in_global = false;
    let mut done: Vec<bool> = vec![false; keys.len()];
    let mut saw_global = false;
    for l in text.lines() {
        let t = l.trim();
        if t.starts_with('[') {
            if in_global {
                for (i, (k, v)) in keys.iter().enumerate() {
                    if !done[i] {
                        out.push(format!("{k}={v}"));
                        done[i] = true;
                    }
                }
            }
            in_global = t == "[global]";
            saw_global |= in_global;
            out.push(l.to_string());
            continue;
        }
        if in_global {
            if let Some(i) = keys.iter().position(|(k, _)| t.starts_with(&format!("{k}="))) {
                out.push(format!("{}={}", keys[i].0, keys[i].1));
                done[i] = true;
                continue;
            }
        }
        out.push(l.to_string());
    }
    if !saw_global {
        out.push("[global]".into());
    }
    if in_global || !saw_global {
        for (i, (k, v)) in keys.iter().enumerate() {
            if !done[i] {
                out.push(format!("{k}={v}"));
            }
        }
    }
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    std::fs::write(&p, out.join("\n") + "\n")
}

/// Process ids of running OpenSnitch pop-up apps.
pub fn ui_pids() -> Vec<i32> {
    std::fs::read_dir("/proc")
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| {
                    let pid = e.file_name().to_string_lossy().parse::<i32>().ok()?;
                    let cmd = std::fs::read(e.path().join("cmdline")).ok()?;
                    let cmd = String::from_utf8_lossy(&cmd).replace('\0', " ");
                    if cmd.contains("opensnitch-ui") && !cmd.contains("arch-sentinel") { Some(pid) } else { None }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn restart_ui() {
    for pid in ui_pids() {
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }
    std::thread::sleep(std::time::Duration::from_millis(1500));
    use std::os::unix::process::CommandExt;
    let _ = std::process::Command::new("/usr/bin/opensnitch-ui")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .process_group(0)
        .spawn();
}

fn ensure_ui_autostart() -> std::io::Result<()> {
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(crate::settings::home_dir()).join(".config"));
    let dst = base.join("autostart/opensnitch_ui.desktop");
    if !dst.exists() {
        std::fs::create_dir_all(base.join("autostart"))?;
        std::fs::copy("/usr/share/applications/opensnitch_ui.desktop", &dst)?;
    }
    Ok(())
}

/// Switch OpenSnitch's behaviour for connections no rule covers.
pub fn apply_firewall_mode(mode: FwMode, timeout: u32) -> Result<String, String> {
    // 1. The pop-up app (runs as you): pop-ups on/off, deny when unanswered, timeout.
    set_ui_conf(&[
        ("disable_popups", if mode == FwMode::Ask { "false".into() } else { "true".into() }),
        ("default_action", "0".into()),
        ("default_timeout", timeout.to_string()),
    ])
    .map_err(|e| format!("Couldn't change the pop-up settings: {e}"))?;
    // 2. The daemon (needs the administrator): what happens without a rule or an answer.
    let cfg = "/etc/opensnitchd/default-config.json";
    let text = std::fs::read_to_string(cfg).map_err(|e| format!("Couldn't read {cfg}: {e}"))?;
    let mut v: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("{cfg} isn't valid JSON: {e}"))?;
    v["DefaultAction"] = serde_json::Value::String(if mode == FwMode::Allow { "allow".into() } else { "deny".into() });
    let tmp = std::env::temp_dir().join(format!("arch-sentinel-osd-{}.json", std::process::id()));
    std::fs::write(&tmp, serde_json::to_string_pretty(&v).unwrap()).map_err(|e| e.to_string())?;
    let script = format!(
        "set -e; cp -a {cfg} {cfg}.bak-arch-sentinel; install -m 0644 {} {cfg}; systemctl restart opensnitchd.service",
        crate::clam::shell_quote(&tmp.to_string_lossy())
    );
    let o = crate::root::output({ let mut pk = std::process::Command::new("pkexec"); pk.args(["/bin/sh", "-c", &script]); pk }).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&tmp);
    if !o.status.success() {
        return Err(if matches!(o.status.code(), Some(126) | Some(127)) {
            "Administrator rights were refused.".into()
        } else {
            format!("Couldn't change OpenSnitch: {}", String::from_utf8_lossy(&o.stderr).trim())
        });
    }
    // 3. Make sure the pop-up app runs (and starts at login) so it can ask.
    if mode == FwMode::Ask {
        let _ = ensure_ui_autostart();
    }
    restart_ui();
    Ok(match mode {
        FwMode::Ask => format!("OpenSnitch now denies by default and asks you about new connections ({timeout}s to answer, then deny)."),
        FwMode::Deny => "OpenSnitch now silently denies anything without a rule.".into(),
        FwMode::Allow => "OpenSnitch allows anything without a rule again.".into(),
    })
}

/// Allow rules for what must keep working under default-deny.
pub fn essential_rules() -> Vec<(String, Rule)> {
    let mut v = vec![];
    for (name, path) in [
        ("allow-pacman", "/usr/bin/pacman"),
        ("allow-freshclam", "/usr/bin/freshclam"),
        ("allow-networkmanager", "/usr/bin/NetworkManager"),
        ("allow-systemd-resolved", "/usr/lib/systemd/systemd-resolved"),
        ("allow-systemd-timesyncd", "/usr/lib/systemd/systemd-timesyncd"),
    ] {
        if std::path::Path::new(path).exists() {
            let r = new_rule(name, "allow", "process.path", path);
            v.push((rule_file_name(name), r));
        }
    }
    // VirusTotal lookups: curl, but only to VirusTotal.
    let mut vt = new_rule("allow-curl-virustotal", "allow", "process.path", "/usr/bin/curl");
    vt.operator = Operator {
        kind: "list".into(),
        operand: "list".into(),
        sensitive: false,
        data: String::new(),
        list: Some(vec![
            Operator { kind: "simple".into(), operand: "process.path".into(), sensitive: false, data: "/usr/bin/curl".into(), list: None },
            Operator { kind: "simple".into(), operand: "dest.host".into(), sensitive: false, data: "www.virustotal.com".into(), list: None },
        ]),
    };
    vt.precedence = true;
    v.push((rule_file_name("allow-curl-virustotal"), vt));
    v
}

/// A unix time as YYYY-MM-DD (UTC).
pub fn date_from_unix(ts: i64) -> String {
    let (y, m, d) = civil_from_days(ts.div_euclid(86400));
    format!("{y:04}-{m:02}-{d:02}")
}
