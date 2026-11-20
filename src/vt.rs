//! VirusTotal reports: fetched by fingerprint (SHA-256 only, never the file),
//! kept on disk so reopening one doesn't use up the free lookup allowance,
//! and read out in plain language.

use crate::jobs::Sev;
use serde_json::Value;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[derive(Clone, Debug, Default)]
pub struct Engine {
    pub name: String,
    pub category: String,
    pub result: String,
    pub major: bool,
    pub generic: bool,
    /// Engines that share one scanning engine count once.
    pub group: String,
}

/// Vendors that license another vendor's engine: their votes aren't independent.
fn engine_group(name: &str) -> String {
    let n = name.to_lowercase();
    let g = match n.as_str() {
        "avg" | "avast" | "avast-mobile" => "avast",
        "f-secure" | "avira" => "avira",
        "trellix" | "trellixens" | "trellix (hx)" | "trellix (fireeye)" | "mcafee" | "mcafeed" | "mcafee-gw-edition" | "fireeye" => "mcafee",
        "gdata" | "emsisoft" | "escan" | "max" | "arcabit" | "alyac" | "vipre" | "bitdefender" | "bitdefendertheta" | "microworld-escan" => "bitdefender",
        "kaspersky" | "zonealarm" => "kaspersky",
        "symantec" | "norton" => "symantec",
        _ => return n,
    };
    g.to_string()
}

#[derive(Clone, Debug, Default)]
pub struct VtReport {
    pub sha256: String,
    pub malicious: u64,
    pub suspicious: u64,
    pub harmless: u64,
    pub undetected: u64,
    pub unsupported: u64,
    pub label: String,
    pub categories: Vec<(String, u64)>,
    /// Family names that several independent engines agree on.
    pub families: Vec<(String, u64)>,
    /// VirusTotal's own suggested names.
    pub vt_names: Vec<(String, u64)>,
    pub flagged: Vec<Engine>,
    pub reputation: i64,
    pub votes_harmless: u64,
    pub votes_malicious: u64,
    pub type_desc: String,
    pub names: Vec<String>,
    pub size: u64,
    pub first_seen: i64,
    pub last_analysis: i64,
    pub times_submitted: u64,
    pub tags: Vec<String>,
    pub signer: String,
    pub sig_verified: String,
    pub product: String,
    pub yara: Vec<String>,
    pub sandboxes: Vec<(String, String, String)>,
    /// When we fetched it (unix seconds).
    pub fetched: i64,
}

impl VtReport {
    pub fn total(&self) -> u64 {
        self.malicious + self.suspicious + self.harmless + self.undetected
    }
    pub fn url(&self) -> String {
        format!("https://www.virustotal.com/gui/file/{}", self.sha256)
    }
}

/// Engines from large, long-established vendors: their opinion weighs more.
const MAJOR: &[&str] = &[
    "Microsoft", "Kaspersky", "ESET-NOD32", "BitDefender", "Sophos", "Avast", "AVG", "Symantec", "TrendMicro", "McAfee",
    "CrowdStrike", "SentinelOne", "Malwarebytes", "Fortinet", "DrWeb", "Emsisoft", "F-Secure", "GData", "Panda", "ClamAV", "Google", "Avira",
];

/// Words in detection names that mean "this looks odd" rather than "this is a known virus".
const GENERIC: &[&str] = &[
    "generic", "heur", "suspicious", "malicious", "unsafe", "confidence", "static", "riskware", "pua", "possible", "behaveslike",
    "score", "agen", "artemis", "cloud", "reputation", "lowfi", "susgen", "deepscan", "ml.", ".ml", "ai.", "!ml", "ai_score",
    "attribute", "highconfidence", "variant", "packed", "packer", "obfus", "wacatac", "kryptik", "presenoker", "unwanted",
];

/// Words that are categories, not family names.
const NOT_FAMILY: &[&str] = &[
    "win32", "win64", "w32", "w64", "trojan", "generic", "variant", "malware", "virus", "worm", "backdoor", "linux", "elf", "pe32",
    "file", "heur", "unsafe", "riskware", "application", "adware", "tool", "hacktool", "dropper", "downloader", "agent", "msil",
    "script", "html", "msword", "office", "android", "infector", "suspicious", "malicious", "trojandownloader", "trojandropper",
    "trojanspy", "gen", "high", "confidence", "score", "detected", "program", "unwanted", "static", "behaveslike", "lowfi",
];

/// A detection name is generic when, after removing category words, nothing
/// specific (a family name) is left - e.g. "Win32:Malware-gen", "TR/W32.Malware",
/// "Artemis!D83E626416BA" - or it uses a known "looks odd" word.
fn is_generic(result: &str) -> bool {
    let r = result.to_lowercase();
    if GENERIC.iter().any(|g| r.contains(g)) {
        return true;
    }
    family_tokens(&r).is_empty()
}

fn family_tokens(r: &str) -> Vec<String> {
    r.split(|c: char| !c.is_ascii_alphanumeric())
        .map(|w| w.to_lowercase())
        .filter(|w| w.len() >= 4)
        .filter(|w| !w.chars().all(|c| c.is_ascii_hexdigit()))
        .filter(|w| !NOT_FAMILY.contains(&w.as_str()) && !["malware", "susgen", "artemis", "gen"].contains(&w.as_str()))
        .filter(|w| !GENERIC.iter().any(|g| w.contains(g.trim_matches(|c| c == '.' || c == '!'))))
        .collect()
}

pub fn parse(sha256: &str, v: &Value) -> VtReport {
    let a = &v["data"]["attributes"];
    let st = &a["last_analysis_stats"];
    let g = |k: &str| st[k].as_u64().unwrap_or(0);
    let pairs = |key: &str| -> Vec<(String, u64)> {
        a["popular_threat_classification"][key]
            .as_array()
            .map(|arr| arr.iter().map(|x| (x["value"].as_str().unwrap_or("").to_string(), x["count"].as_u64().unwrap_or(0))).collect())
            .unwrap_or_default()
    };
    let mut flagged: Vec<Engine> = a["last_analysis_results"]
        .as_object()
        .map(|o| {
            o.values()
                .filter(|e| matches!(e["category"].as_str(), Some("malicious") | Some("suspicious")))
                .map(|e| {
                    let name = e["engine_name"].as_str().unwrap_or("?").to_string();
                    let result = e["result"].as_str().unwrap_or("").to_string();
                    Engine {
                        major: MAJOR.iter().any(|m| m.eq_ignore_ascii_case(&name)),
                        generic: is_generic(&result),
                        group: engine_group(&name),
                        category: e["category"].as_str().unwrap_or("").to_string(),
                        name,
                        result,
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    flagged.sort_by(|x, y| y.major.cmp(&x.major).then(x.generic.cmp(&y.generic)).then(x.name.cmp(&y.name)));
    // Family names: words shared by several engines' detection names.
    let mut fam: std::collections::HashMap<String, std::collections::HashSet<String>> = Default::default();
    for e in flagged.iter().filter(|e| !e.generic) {
        for w in family_tokens(&e.result) {
            fam.entry(w).or_default().insert(e.group.clone());
        }
    }
    let fam: std::collections::HashMap<String, u64> = fam.into_iter().map(|(k, v)| (k, v.len() as u64)).collect();
    let mut families: Vec<(String, u64)> = fam.into_iter().filter(|f| f.1 >= 2).collect();
    families.sort_by(|x, y| y.1.cmp(&x.1));
    families.truncate(5);
    let strs = |key: &str| -> Vec<String> { a[key].as_array().map(|x| x.iter().filter_map(|s| s.as_str().map(|s| s.to_string())).collect()).unwrap_or_default() };
    let sig = &a["signature_info"];
    VtReport {
        sha256: sha256.to_string(),
        malicious: g("malicious"),
        suspicious: g("suspicious"),
        harmless: g("harmless"),
        undetected: g("undetected"),
        unsupported: g("type-unsupported"),
        label: a["popular_threat_classification"]["suggested_threat_label"].as_str().unwrap_or("").to_string(),
        categories: pairs("popular_threat_category"),
        families,
        vt_names: pairs("popular_threat_name"),
        flagged,
        reputation: a["reputation"].as_i64().unwrap_or(0),
        votes_harmless: a["total_votes"]["harmless"].as_u64().unwrap_or(0),
        votes_malicious: a["total_votes"]["malicious"].as_u64().unwrap_or(0),
        type_desc: a["type_description"].as_str().unwrap_or("").to_string(),
        names: strs("names").into_iter().take(8).collect(),
        size: a["size"].as_u64().unwrap_or(0),
        first_seen: a["first_submission_date"].as_i64().unwrap_or(0),
        last_analysis: a["last_analysis_date"].as_i64().unwrap_or(0),
        times_submitted: a["times_submitted"].as_u64().unwrap_or(0),
        tags: strs("tags"),
        signer: sig["signers"].as_str().unwrap_or("").to_string(),
        sig_verified: sig["verified"].as_str().unwrap_or("").to_string(),
        product: sig["product"].as_str().or(sig["description"].as_str()).unwrap_or("").to_string(),
        yara: a["crowdsourced_yara_results"]
            .as_array()
            .map(|x| x.iter().filter_map(|y| y["rule_name"].as_str().map(|s| s.to_string())).take(8).collect())
            .unwrap_or_default(),
        sandboxes: a["sandbox_verdicts"]
            .as_object()
            .map(|o| {
                o.values()
                    .map(|s| {
                        (
                            s["sandbox_name"].as_str().unwrap_or("?").to_string(),
                            s["category"].as_str().unwrap_or("?").to_string(),
                            s["malware_names"].as_array().map(|n| n.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default(),
        fetched: 0,
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Level {
    Malicious,
    Suspicious,
    Unclear,
    Clean,
}

impl Level {
    pub fn word(self) -> &'static str {
        match self {
            Level::Malicious => "Malicious",
            Level::Suspicious => "Suspicious",
            Level::Unclear => "Probably a false alarm",
            Level::Clean => "Clean",
        }
    }
}

pub fn ymd(ts: i64) -> String {
    if ts <= 0 {
        return "?".into();
    }
    crate::net::date_from_unix(ts)
}

/// The verdict, how serious it is, a one-line headline, and the reasons in plain words.
/// ClamAV's own vote isn't counted as a second opinion (it's usually what flagged the
/// file in the first place), and vendors sharing one engine count once.
pub fn assess(r: &VtReport) -> (Level, Sev, String, Vec<String>) {
    use std::collections::BTreeSet;
    let total = r.total().max(1);
    let flagged = r.malicious + r.suspicious;
    let others: Vec<&Engine> = r.flagged.iter().filter(|e| !e.name.eq_ignore_ascii_case("ClamAV")).collect();
    let clam = r.flagged.iter().find(|e| e.name.eq_ignore_ascii_case("ClamAV"));
    let groups: BTreeSet<&str> = others.iter().map(|e| e.group.as_str()).collect();
    let specific: Vec<&Engine> = others.iter().copied().filter(|e| !e.generic).collect();
    let specific_groups: BTreeSet<&str> = specific.iter().map(|e| e.group.as_str()).collect();
    let major_specific: Vec<&Engine> = specific.iter().copied().filter(|e| e.major).collect();
    let top_family = r.families.first().cloned();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let age_days = if r.first_seen > 0 { (now - r.first_seen) / 86400 } else { 0 };
    let signed_ok = r.sig_verified.eq_ignore_ascii_case("signed") && !r.signer.is_empty();
    let bad_sandboxes: Vec<&(String, String, String)> = r.sandboxes.iter().filter(|s| s.1 == "malicious" || s.1 == "suspicious").collect();
    let mut why = vec![];

    why.push(format!(
        "{flagged} of {total} antivirus engines flag it; {} found nothing{}.",
        r.undetected + r.harmless,
        if r.unsupported > 0 { format!(" and {} couldn't read this kind of file", r.unsupported) } else { String::new() }
    ));
    if let Some(c) = clam {
        why.push(format!("ClamAV is one of them ({}) - that's the scanner that flagged it here, so it isn't a second opinion.", c.result));
    }
    let shared = others.len().saturating_sub(groups.len());
    if shared > 0 {
        why.push(format!(
            "{} of the other engines use another vendor's scanning engine (e.g. AVG = Avast, F-Secure = Avira), so they count once: {} independent opinion(s).",
            shared,
            groups.len()
        ));
    }
    if !others.is_empty() {
        if specific.is_empty() {
            why.push(format!(
                "Every other engine gives only a generic guess ({}), not a known virus name - typical of false alarms on unusual, packed or rare files.",
                others.iter().take(3).map(|e| e.result.as_str()).collect::<Vec<_>>().join(", ")
            ));
        } else if let Some((f, n)) = top_family.as_ref().filter(|f| f.1 >= 2) {
            why.push(format!("{n} independent engines name the same family, \"{f}\" - engines agreeing on a specific name is a strong sign it's real."));
        } else {
            why.push(format!(
                "{} other engine(s) give a specific name, but no two independent engines agree: {}.",
                specific.len(),
                specific.iter().take(3).map(|e| format!("{} says {}", e.name, e.result)).collect::<Vec<_>>().join("; ")
            ));
        }
        if !major_specific.is_empty() {
            why.push(format!("Big vendors naming a specific threat: {}.", major_specific.iter().take(5).map(|e| e.name.as_str()).collect::<Vec<_>>().join(", ")));
        } else {
            why.push("None of the big vendors (Microsoft, Kaspersky, ESET, BitDefender, Sophos...) name a specific threat.".into());
        }
    }
    if r.first_seen > 0 {
        why.push(format!(
            "First seen by VirusTotal on {} ({} days ago), submitted {} time(s){}.",
            ymd(r.first_seen),
            age_days,
            r.times_submitted,
            if r.times_submitted > 50 && specific_groups.len() <= 1 { " - a widely shared file with few real detections, which makes a false alarm more likely" } else { "" }
        ));
    }
    if signed_ok {
        why.push(format!(
            "Digitally signed by {} and the signature checks out{}.",
            r.signer.split(';').next().unwrap_or(&r.signer),
            if r.product.is_empty() { String::new() } else { format!(" ({})", r.product) }
        ));
    } else if !r.signer.is_empty() {
        why.push(format!("Carries a signature from {}, but it isn't valid ({}).", r.signer.split(';').next().unwrap_or(&r.signer), r.sig_verified));
    }
    if r.votes_harmless + r.votes_malicious > 0 {
        why.push(format!("VirusTotal users voted {} harmless / {} malicious.", r.votes_harmless, r.votes_malicious));
    }
    if !bad_sandboxes.is_empty() {
        why.push(format!("{} automated sandbox(es) watched it run and called it {}.", bad_sandboxes.len(), bad_sandboxes[0].1));
    }
    if !r.yara.is_empty() {
        why.push(format!("Matches community detection rules: {}.", r.yara.iter().take(3).cloned().collect::<Vec<_>>().join(", ")));
    }

    let agree = top_family.as_ref().map(|f| f.1).unwrap_or(0);
    let level = if flagged == 0 {
        Level::Clean
    } else if groups.len() >= 12 || (specific_groups.len() >= 3 && agree >= 2) || (major_specific.len() >= 2 && specific_groups.len() >= 3) || bad_sandboxes.len() >= 2 {
        Level::Malicious
    } else if specific_groups.len() >= 2 || !major_specific.is_empty() || groups.len() >= 6 || !bad_sandboxes.is_empty() {
        Level::Suspicious
    } else {
        Level::Unclear
    };
    let fam = top_family.filter(|f| f.1 >= 2).map(|f| format!(", family \"{}\"", f.0)).unwrap_or_default();
    let (sev, headline) = match level {
        Level::Malicious => (Sev::High, format!("VirusTotal: CONFIRMED malicious - {} independent engines{fam}", groups.len())),
        Level::Suspicious => (Sev::Medium, format!("VirusTotal: suspicious - {flagged} of {total} engines ({} independent){fam}; read the report", groups.len())),
        Level::Unclear => (
            Sev::Low,
            format!(
                "VirusTotal: probably a false alarm - {flagged} of {total} engines, {}",
                if specific.is_empty() { "the others only generic guesses" } else { "no two independent engines agree" }
            ),
        ),
        Level::Clean => (Sev::Low, format!("VirusTotal: clean - 0 of {total} engines flag it (likely a false positive)")),
    };
    (level, sev, headline, why)
}

// ---------- fetching and caching ----------

fn cache_dir() -> PathBuf {
    crate::settings::data_dir().join("virustotal")
}

pub fn cached(sha256: &str) -> Option<VtReport> {
    let p = cache_dir().join(format!("{sha256}.json"));
    let text = std::fs::read_to_string(&p).ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    let mut r = parse(sha256, &v);
    r.fetched = std::fs::metadata(&p).ok().and_then(|m| m.modified().ok()).and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs() as i64).unwrap_or(0);
    Some(r)
}

/// Fetch a report. Ok(None): VirusTotal has never seen this file.
pub fn fetch(api_key: &str, sha256: &str) -> Result<Option<VtReport>, String> {
    if api_key.trim().is_empty() {
        return Err("no VirusTotal key set (Settings → VirusTotal)".into());
    }
    let url = format!("https://www.virustotal.com/api/v3/files/{sha256}");
    // The key goes in on stdin as a header so it never shows in the process list.
    let mut child = Command::new("curl")
        .args(["-sS", "--max-time", "30", "-w", "\n%{http_code}", "-H", "@-", &url])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("curl not available: {e}"))?;
    if let Some(mut si) = child.stdin.take() {
        let _ = writeln!(si, "x-apikey: {}", api_key.trim());
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let (body, code) = text.rsplit_once('\n').unwrap_or((&text, "0"));
    match code.trim() {
        "200" => {}
        "404" => return Ok(None),
        "401" | "403" => return Err("VirusTotal refused the key".into()),
        "429" => return Err("VirusTotal's rate limit was reached (4 lookups a minute on the free key) — try again in a minute".into()),
        c => return Err(format!("HTTP {c} {}", String::from_utf8_lossy(&out.stderr).trim())),
    }
    let v: Value = serde_json::from_str(body).map_err(|e| format!("unreadable answer: {e}"))?;
    let _ = std::fs::create_dir_all(cache_dir());
    let _ = std::fs::write(cache_dir().join(format!("{sha256}.json")), body);
    let mut r = parse(sha256, &v);
    r.fetched = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    Ok(Some(r))
}
