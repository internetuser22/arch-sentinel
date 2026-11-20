use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Schedule {
    Hourly,
    Every6Hours,
    Every12Hours,
    Daily,
    Weekly,
}

impl Schedule {
    pub const ALL: [Schedule; 5] = [
        Schedule::Hourly,
        Schedule::Every6Hours,
        Schedule::Every12Hours,
        Schedule::Daily,
        Schedule::Weekly,
    ];
    pub fn label(self) -> &'static str {
        match self {
            Schedule::Hourly => "Every hour",
            Schedule::Every6Hours => "Every 6 hours",
            Schedule::Every12Hours => "Every 12 hours",
            Schedule::Daily => "Once a day",
            Schedule::Weekly => "Once a week",
        }
    }
    /// systemd OnCalendar expression.
    pub fn on_calendar(self) -> &'static str {
        match self {
            Schedule::Hourly => "hourly",
            Schedule::Every6Hours => "*-*-* 00/6:00:00",
            Schedule::Every12Hours => "*-*-* 00/12:00:00",
            Schedule::Daily => "daily",
            Schedule::Weekly => "weekly",
        }
    }
    pub fn seconds(self) -> u64 {
        match self {
            Schedule::Hourly => 3600,
            Schedule::Every6Hours => 6 * 3600,
            Schedule::Every12Hours => 12 * 3600,
            Schedule::Daily => 86400,
            Schedule::Weekly => 7 * 86400,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Priority {
    Idle,
    Low,
    Normal,
}

impl Priority {
    pub const ALL: [Priority; 3] = [Priority::Idle, Priority::Low, Priority::Normal];
    pub fn label(self) -> &'static str {
        match self {
            Priority::Idle => "Only when the computer is idle",
            Priority::Low => "Low (stays out of the way)",
            Priority::Normal => "Normal",
        }
    }
    pub fn nice(self) -> i32 {
        match self {
            Priority::Idle => 19,
            Priority::Low => 10,
            Priority::Normal => 0,
        }
    }
    /// ionice class: 3 idle, 2 best-effort.
    pub fn io_class(self) -> u8 {
        match self {
            Priority::Idle => 3,
            _ => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JobKind {
    Signatures,
    Integrity,
    Unowned,
    HomeCheck,
    Virus,
    Rootkit,
    Processes,
}

impl JobKind {
    pub const ALL: [JobKind; 7] = [
        JobKind::Signatures,
        JobKind::Integrity,
        JobKind::Unowned,
        JobKind::HomeCheck,
        JobKind::Virus,
        JobKind::Rootkit,
        JobKind::Processes,
    ];
    pub fn id(self) -> &'static str {
        match self {
            JobKind::Signatures => "signatures",
            JobKind::Integrity => "integrity",
            JobKind::Unowned => "unowned",
            JobKind::HomeCheck => "home",
            JobKind::Virus => "virus",
            JobKind::Rootkit => "rootkit",
            JobKind::Processes => "processes",
        }
    }
    pub fn from_id(s: &str) -> Option<JobKind> {
        JobKind::ALL.iter().copied().find(|k| k.id() == s)
    }
    pub fn title(self) -> &'static str {
        match self {
            JobKind::Signatures => "Virus signature updates (freshclam)",
            JobKind::Integrity => "Package file check (paccheck)",
            JobKind::Unowned => "Files no package owns",
            JobKind::HomeCheck => "Home folder check",
            JobKind::Virus => "Virus scan (ClamAV)",
            JobKind::Rootkit => "Rootkit check",
            JobKind::Processes => "Running programs check",
        }
    }
    pub fn short(self) -> &'static str {
        match self {
            JobKind::Signatures => "Signatures",
            JobKind::Integrity => "Package files",
            JobKind::Unowned => "Unowned files",
            JobKind::HomeCheck => "Home folder",
            JobKind::Virus => "Virus scan",
            JobKind::Rootkit => "Rootkits",
            JobKind::Processes => "Running programs",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BgJob {
    pub enabled: bool,
    pub schedule: Schedule,
    pub priority: Priority,
    /// CPU limit in percent of one core (0 = no limit).
    pub cpu_limit: u32,
    /// Wait up to this many minutes at random before starting.
    pub random_delay_min: u32,
    /// Run a missed run at next boot.
    pub catch_up: bool,
    /// Only start while on mains power.
    pub only_on_ac: bool,
    /// Show a desktop notification when something is found.
    pub notify: bool,
}

impl BgJob {
    fn new(enabled: bool, schedule: Schedule, priority: Priority) -> Self {
        Self {
            enabled,
            schedule,
            priority,
            cpu_limit: 0,
            random_delay_min: 15,
            catch_up: true,
            only_on_ac: false,
            notify: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub system_roots: Vec<String>,
    pub excluded: Vec<String>,
    pub ignore_patterns: Vec<String>,
    pub home: String,
    pub virus_targets: Vec<String>,
    pub virus_excluded: Vec<String>,
    /// Move confirmed viruses to quarantine automatically.
    pub quarantine: bool,
    pub vt_check: bool,
    pub vt_api_key: String,
    pub max_file_mb: u32,
    /// ClamAV options for Arch Sentinel's own scans (passed to clamscan; ClamAV's config files are never changed).
    pub clam: ClamOptions,
    pub stop_freshclam_daemon: bool,
    pub manual_priority: Priority,
    pub bg_signatures: BgJob,
    pub bg_integrity: BgJob,
    pub bg_unowned: BgJob,
    pub bg_home: BgJob,
    pub bg_virus: BgJob,
    pub bg_rootkit: BgJob,
    pub bg_processes: BgJob,
    pub net_refresh_secs: u32,
    /// 0 = no ClamAV, 1 = only files not from a package, 2 = every running file.
    pub process_clam_scope: u8,
    pub tray: bool,
    pub autostart: bool,
    pub watch_new_connections: bool,
    /// Threads per scan (0 = automatic: half the cores).
    pub scan_threads: u32,
    /// Most of the computer's CPU scans you start may use, in percent (0 = no cap).
    pub cpu_cap: u32,
    /// The tray hint was shown once.
    pub tray_hint_shown: bool,
    /// What the virus scan covers: 0 = unverified system files first, then the
    /// home folder; 1 = only unverified system files; 2 = only the home folder.
    pub virus_scope: u8,
    /// Paranoid: also look inside program files for signs of infection or packing.
    pub paranoid: bool,
    /// Also virus-scan drives outside the running system (USB sticks, extra disks).
    pub scan_external: bool,
    /// Checks that run with administrator rights (job ids).
    pub admin_jobs: Vec<String>,
    /// Minutes an administrator session stays open with nothing to do.
    pub admin_session_minutes: u32,
    /// Mount points of external drives switched off for scanning.
    pub external_skip: Vec<String>,
}

pub fn home_dir() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/root".into())
}

impl Default for Settings {
    fn default() -> Self {
        let home = home_dir();
        Self {
            system_roots: vec!["/usr".into(), "/etc".into(), "/opt".into(), "/boot".into(), "/srv".into()],
            excluded: vec![
                "/proc".into(),
                "/sys".into(),
                "/dev".into(),
                "/run".into(),
                "/tmp".into(),
                "/var/tmp".into(),
                "/var/cache".into(),
                "/var/log".into(),
                "/var/lib/pacman".into(),
                "/home".into(),
                "/root".into(),
                "/mnt".into(),
                "/media".into(),
                "/lost+found".into(),
                "/snapshots".into(),
                "/.snapshots".into(),
            ],
            ignore_patterns: vec![
                "/usr/lib/modules/*/modules.*".into(),
                "/usr/share/icons/*/icon-theme.cache".into(),
                "/usr/share/mime/*".into(),
                "/usr/share/info/dir".into(),
                "/usr/lib/locale/locale-archive".into(),
                "/usr/lib/gdk-pixbuf-2.0/*/loaders.cache".into(),
                "/usr/lib/gio/modules/giomodule.cache".into(),
                "/usr/lib/gtk-*/*/immodules.cache".into(),
                "/usr/share/glib-2.0/schemas/gschemas.compiled".into(),
                "/usr/share/applications/mimeinfo.cache".into(),
                "*/__pycache__/*".into(),
                "/etc/ld.so.cache".into(),
                "/etc/machine-id".into(),
                "/etc/ssh/ssh_host_*".into(),
                "/etc/pacman.d/gnupg/*".into(),
                "/etc/ssl/certs/*".into(),
                "/etc/ca-certificates/extracted/*".into(),
                "/etc/pacman.d/mirrorlist.pacnew".into(),
                "/etc/*.pacnew".into(),
                "/etc/*.pacsave".into(),
                "/boot/initramfs-*".into(),
                "/boot/vmlinuz-*".into(),
                "/boot/*-ucode.img".into(),
                "/etc/fonts/conf.d/*".into(),
                    ],
            home: home.clone(),
            virus_targets: vec![home.clone()],
            virus_excluded: vec![format!("{home}/.cache"), format!("{home}/.local/share/Steam")],
            quarantine: false,
            vt_check: true,
            vt_api_key: String::new(),
            max_file_mb: 100,
            clam: ClamOptions::default(),
            stop_freshclam_daemon: true,
            manual_priority: Priority::Normal,
            bg_signatures: BgJob::new(true, Schedule::Every6Hours, Priority::Low),
            bg_integrity: BgJob::new(false, Schedule::Daily, Priority::Idle),
            bg_unowned: BgJob::new(false, Schedule::Weekly, Priority::Idle),
            bg_home: BgJob::new(false, Schedule::Daily, Priority::Idle),
            bg_virus: BgJob::new(false, Schedule::Weekly, Priority::Idle),
            bg_rootkit: BgJob::new(false, Schedule::Daily, Priority::Idle),
            bg_processes: BgJob::new(false, Schedule::Every6Hours, Priority::Idle),
            net_refresh_secs: 2,
            process_clam_scope: 1,
            tray: true,
            autostart: false,
            watch_new_connections: false,
            scan_threads: 0,
            cpu_cap: 0,
            tray_hint_shown: false,
            virus_scope: 0,
            paranoid: false,
            scan_external: false,
            admin_jobs: vec![],
            admin_session_minutes: 30,
            external_skip: vec![],
        }
    }
}

pub fn data_dir() -> PathBuf {
    let base = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(home_dir()).join(".local/share"));
    base.join("arch-sentinel")
}

pub fn config_path() -> PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(home_dir()).join(".config"));
    base.join("arch-sentinel/settings.json")
}

impl Settings {
    pub fn load() -> Self {
        std::fs::read_to_string(config_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }
    pub fn save(&self) -> std::io::Result<()> {
        let p = config_path();
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)?;
        }
        std::fs::write(&p, serde_json::to_string_pretty(self).unwrap())?;
        // The file holds the VirusTotal key: keep it private.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))
    }
    pub fn bg(&self, k: JobKind) -> &BgJob {
        match k {
            JobKind::Signatures => &self.bg_signatures,
            JobKind::Integrity => &self.bg_integrity,
            JobKind::Unowned => &self.bg_unowned,
            JobKind::HomeCheck => &self.bg_home,
            JobKind::Virus => &self.bg_virus,
            JobKind::Rootkit => &self.bg_rootkit,
            JobKind::Processes => &self.bg_processes,
        }
    }
    pub fn bg_mut(&mut self, k: JobKind) -> &mut BgJob {
        match k {
            JobKind::Signatures => &mut self.bg_signatures,
            JobKind::Integrity => &mut self.bg_integrity,
            JobKind::Unowned => &mut self.bg_unowned,
            JobKind::HomeCheck => &mut self.bg_home,
            JobKind::Virus => &mut self.bg_virus,
            JobKind::Rootkit => &mut self.bg_rootkit,
            JobKind::Processes => &mut self.bg_processes,
        }
    }
}

/// Very small glob: `*` matches any run of characters (including `/`).
pub fn glob_match(pat: &str, s: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = s.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (usize::MAX, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = pi;
            mark = ti;
            pi += 1;
        } else if star != usize::MAX {
            pi = star + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::glob_match;
    #[test]
    fn globs() {
        assert!(glob_match("/usr/lib/modules/*/modules.*", "/usr/lib/modules/6.1/modules.dep"));
        assert!(glob_match("*/__pycache__/*", "/usr/lib/x/__pycache__/a.pyc"));
        assert!(!glob_match("/etc/*.pacnew", "/etc/foo"));
    }
}

pub const VIRUS_SCOPES: [(u8, &str, &str); 4] = [
    (0, "System files first, then home", "Unverified system files (no package owns them, or they failed the package check) first, then your home folder"),
    (1, "Only unverified system files", "Just the system files the Unowned files and Package files checks flagged"),
    (2, "Only my home folder", "Just the folders listed under Folders to scan"),
    (3, "Only external drives", "Just the drives outside the system (USB sticks, extra disks, other partitions) that are switched on in Settings"),
];

/// Kinds of "possibly unwanted" programs ClamAV can report.
pub const PUA_CATEGORIES: [(&str, &str); 10] = [
    ("Packed", "packed or compressed programs (often harmless)"),
    ("Tool", "general hacking and admin tools"),
    ("NetTool", "network tools such as port scanners"),
    ("PwTool", "password tools"),
    ("P2P", "file-sharing programs"),
    ("IRC", "chat programs"),
    ("RAT", "remote-control programs"),
    ("Spy", "spyware and keyloggers"),
    ("Server", "servers that open a port"),
    ("Scanner", "vulnerability scanners"),
];

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ClamOptions {
    /// Report possibly unwanted programs (PUA) too.
    pub detect_pua: bool,
    /// PUA kinds to leave out.
    pub pua_skip: Vec<String>,
    /// Most data to read from one archive or container, in MB.
    pub max_scan_mb: u32,
    /// Most files to look at inside one archive.
    pub max_files: u32,
    /// How many archives-inside-archives to open.
    pub max_recursion: u32,
    pub scan_archives: bool,
    pub heuristic_alerts: bool,
    /// Stop at the first heuristic match (faster).
    pub heuristic_first: bool,
    pub alert_macros: bool,
    pub alert_encrypted: bool,
    pub alert_broken: bool,
    /// Report files skipped for being too big instead of passing them silently.
    pub alert_exceeds_max: bool,
}

impl Default for ClamOptions {
    fn default() -> Self {
        Self {
            detect_pua: false,
            pua_skip: vec!["Packed".into(), "Tool".into()],
            max_scan_mb: 400,
            max_files: 10000,
            max_recursion: 17,
            scan_archives: true,
            heuristic_alerts: true,
            heuristic_first: false,
            alert_macros: false,
            alert_encrypted: false,
            alert_broken: false,
            alert_exceeds_max: false,
        }
    }
}

impl ClamOptions {
    /// The clamscan flags these choices mean (with the per-file size limit).
    pub fn flags(&self, max_file_mb: u32) -> Vec<String> {
        let yn = |b: bool| if b { "yes" } else { "no" };
        let mut f = vec![
            format!("--max-filesize={max_file_mb}M"),
            format!("--max-scansize={}M", self.max_scan_mb.max(max_file_mb)),
            format!("--max-files={}", self.max_files),
            format!("--max-recursion={}", self.max_recursion),
            format!("--scan-archive={}", yn(self.scan_archives)),
            format!("--heuristic-alerts={}", yn(self.heuristic_alerts)),
            format!("--heuristic-scan-precedence={}", yn(self.heuristic_first)),
            format!("--alert-macros={}", yn(self.alert_macros)),
            format!("--alert-encrypted={}", yn(self.alert_encrypted)),
            format!("--alert-broken={}", yn(self.alert_broken)),
            format!("--alert-exceeds-max={}", yn(self.alert_exceeds_max)),
            format!("--detect-pua={}", yn(self.detect_pua)),
        ];
        if self.detect_pua {
            for c in &self.pua_skip {
                f.push(format!("--exclude-pua={c}"));
            }
        }
        f
    }
}

/// The checks that can run with administrator rights, with what it adds.
pub const ADMIN_CAPABLE: [(JobKind, &str); 6] = [
    (JobKind::Integrity, "reads files only root may read, so their checksums can be checked too"),
    (JobKind::Unowned, "looks inside root-only folders such as /etc/sudoers.d or /boot"),
    (JobKind::HomeCheck, "reads files in your home that belong to other users"),
    (JobKind::Virus, "scans files only root may read"),
    (JobKind::Rootkit, "sees every process and kernel detail, not only yours"),
    (JobKind::Processes, "checks programs run by every user and by the system, not only yours"),
];
