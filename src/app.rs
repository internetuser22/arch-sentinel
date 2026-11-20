//! The window: shared state, styling, sidebar, dashboard and the check pages.
//! Network, quarantine, background-job and settings pages live in `pages.rs`.

use crate::background;
use crate::clam;
use crate::jobs::{Finding, Job, Sev};
use crate::net::{self, Conn, Rule, Verification};
use crate::pkg;
use crate::quarantine;
use crate::rootkit;
use crate::settings::{config_path, JobKind, Settings};
use eframe::egui::{self, Color32, RichText, Ui};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const BG: Color32 = Color32::from_rgb(0x14, 0x17, 0x1c);
pub const PANEL: Color32 = Color32::from_rgb(0x1b, 0x1f, 0x26);
pub const CARD: Color32 = Color32::from_rgb(0x22, 0x27, 0x30);
pub const ACCENT: Color32 = Color32::from_rgb(0x2e, 0xb8, 0xa6);
pub const TEXT_DIM: Color32 = Color32::from_rgb(0x8b, 0x95, 0xa5);
pub const RED: Color32 = Color32::from_rgb(0xe5, 0x53, 0x4b);
pub const AMBER: Color32 = Color32::from_rgb(0xe8, 0xa3, 0x3d);
pub const YELLOW: Color32 = Color32::from_rgb(0xc9, 0xc2, 0x5a);
pub const BLUE: Color32 = Color32::from_rgb(0x5b, 0x9b, 0xd5);
pub const GREEN: Color32 = Color32::from_rgb(0x4c, 0xc2, 0x6e);

pub fn sev_color(s: Sev) -> Color32 {
    match s {
        Sev::High => RED,
        Sev::Medium => AMBER,
        Sev::Low => YELLOW,
        Sev::Info => BLUE,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Page {
    Overview,
    Job(JobKind),
    Quarantine,
    Network,
    Background,
    Settings,
    Recover,
    Sandbox,
    Snapshots,
}

#[derive(Default, Clone)]
pub struct SysStatus {
    pub loaded: bool,
    pub packages: usize,
    pub clam: Option<(String, String, String)>,
    pub freshclam_daemon: String,
    pub snitch_active: String,
    pub snitch_enabled: String,
    pub snitch_cfg: Option<(String, bool)>,
    pub snitch_popups: bool,
    pub snitch_timeout: u32,
    pub snitch_ui_running: bool,
    pub timers: HashMap<JobKind, background::TimerStatus>,
    pub tools: Vec<(&'static str, bool)>,
    pub drives: Vec<crate::drives::Drive>,
}

fn load_status() -> SysStatus {
    let mut timers = HashMap::new();
    for k in JobKind::ALL {
        timers.insert(k, background::timer_status(k));
    }
    SysStatus {
        loaded: true,
        packages: pkg::package_count(),
        clam: clam::version(),
        freshclam_daemon: net::service_state("clamav-freshclam.service"),
        snitch_active: net::service_state("opensnitchd.service"),
        snitch_enabled: net::service_enabled("opensnitchd.service"),
        snitch_cfg: net::opensnitch_config(),
        snitch_popups: net::ui_prompt_settings().0,
        snitch_timeout: net::ui_prompt_settings().1,
        snitch_ui_running: !net::ui_pids().is_empty(),
        timers,
        tools: rootkit::external_tools(),
        drives: crate::drives::external_drives(),
    }
}

pub enum RowAction {
    Copy(String),
    Open(String),
    Ignore(String),
    Quarantine(String, String),
    Exclude(String),
    /// Zero-fill and delete (asks first).
    Shred(String, String),
    /// Run the VirusTotal check again for this finding.
    RetryVt(String),
    /// Reinstall one package with pacman.
    Reinstall(String),
    /// Open the file in the sandbox page.
    Sandbox(String),
    /// Show the VirusTotal report (path, sha256 when known).
    VtReport(String, Option<String>),
}

/// The VirusTotal report window.
#[derive(Clone, Default)]
pub struct VtWindow {
    pub path: String,
    pub sha256: String,
    pub report: Option<crate::vt::VtReport>,
    pub unknown: bool,
    pub error: Option<String>,
    pub loading: bool,
}

/// The zero-fill-and-delete confirmation.
#[derive(Clone)]
pub struct ShredAsk {
    pub path: String,
    pub threat: String,
    pub entry: Option<quarantine::Entry>,
    pub package: Option<String>,
    pub fs: String,
}

#[derive(Default)]
pub struct Shared {
    pub toasts: Vec<(String, bool)>,
    pub rules: Option<Vec<(String, Rule)>>,
    pub rule_errors: Vec<String>,
    pub verify: HashMap<String, Verification>,
    pub verifying: bool,
    pub quarantine: Vec<quarantine::Entry>,
    pub busy: Option<String>,
    /// Output of `timeshift --list`.
    pub timeshift_list: Option<String>,
}

pub struct App {
    pub s: Settings,
    pub page: Page,
    pub jobs: HashMap<JobKind, Job>,
    pub vt_job: Job,
    pub ext_job: Job,
    /// Reinstalling packages that failed the package check.
    pub fix_job: Job,
    pub recheck_after_fix: Arc<AtomicBool>,
    pub foreign_pkgs: Option<std::collections::HashSet<String>>,
    pub shred_ask: Option<ShredAsk>,
    pub shred_sure: bool,
    /// A Windows system file waiting for a second click to quarantine.
    pub confirm_win_quarantine: Option<String>,
    /// Experimental deleted-file recovery (PhotoRec).
    pub recover_job: Job,
    pub rec_parts: Vec<crate::recover::Partition>,
    pub rec_source: Option<String>,
    pub rec_dest: String,
    pub rec_kinds: Vec<String>,
    pub rec_only_free: bool,
    pub rec_scan_after: bool,
    pub rec_all_kinds: bool,
    pub rec_keep_damaged: bool,
    pub rec_scan_request: Arc<Mutex<Option<String>>>,
    /// Experimental throwaway sandbox.
    pub sandbox_job: Job,
    pub sbx_sample: String,
    pub sbx_secs: u64,
    pub sbx_wine: bool,
    pub sbx_sure: bool,
    pub sbx_auto_throw: bool,
    pub sbx_dir: Arc<Mutex<Option<PathBuf>>>,
    pub vt_window: Arc<Mutex<Option<VtWindow>>>,
    /// Re-running VirusTotal checks that failed.
    pub vt_retry_job: Job,
    pub snap: crate::snap_ui::SnapUi,
    /// Deleted files page: 0 = PhotoRec, 1 = File Rescue engine.
    pub rec_mode: u8,
    /// Quarantine buttons that need a second click: (entry id, action).
    pub q_confirm: Option<(String, &'static str)>,
    /// When the quarantine folder last changed, as last seen (re-read only when it changes).
    pub q_seen: Option<std::time::SystemTime>,
    pub rescue: crate::rescue_ui::RescueUi,
    /// "Run all checks": the checks still to run, one after another.
    pub run_queue: Vec<JobKind>,
    pub queue_current: Option<JobKind>,
    pub queue_total: usize,
    pub admin: HashMap<JobKind, bool>,
    pub filter: String,
    pub show_sev: [bool; 4],
    pub status: Arc<Mutex<SysStatus>>,
    pub status_tick: Arc<AtomicBool>,
    pub shared: Arc<Mutex<Shared>>,
    pub conns: Vec<Conn>,
    pub last_conn: Option<Instant>,
    pub conn_filter: String,
    pub hide_listening: bool,
    pub hide_local: bool,
    pub rule_name: String,
    pub rule_action: String,
    pub rule_operand: String,
    pub rule_data: String,
    pub toast: Option<(String, bool, Instant)>,
    pub new_root: String,
    pub new_exclude: String,
    pub new_skip_dir: String,
    pub new_pattern: String,
    pub new_target: String,
    pub show_key: bool,
    pub settings_dirty: bool,
    pub fw_choice: Option<net::FwMode>,
    /// Messages from later starts (right-click scans, "open the window").
    pub ipc_inbox: Arc<Mutex<Vec<String>>>,
    /// Files and folders waiting for a virus scan from the file manager.
    pub pending_scans: Vec<Vec<String>>,
    /// Targets for the next virus scan instead of the usual ones.
    custom_scan: Option<Vec<String>>,
    /// What the last virus scan covered, when it came from the file manager.
    pub last_custom: Option<Vec<String>>,
    /// A right-click scan's question about big files, and the answer.
    pub size_ask: clam::AskSlot,
    pub ask_limit: Option<u32>,
    pub fw_timeout: Option<u32>,
    pub tray: Option<crate::tray::TrayHandle>,
    pub quitting: bool,
    pub hidden: bool,
    pub watch_flag: Arc<AtomicBool>,
    pub alerts: Arc<Mutex<Vec<String>>>,
    pub recent_alerts: Vec<String>,
    last_tray_update: Option<Instant>,
    screenshot: Option<PathBuf>,
    frames: u32,
    shot_done: Arc<AtomicBool>,
    shot_requested: bool,
    /// ARCH_SENTINEL_SELFTEST=tray: close to the tray, reopen once, then quit.
    selftest: bool,
    selftest_round: u32,
    frames_at_open: u32,
}

impl App {
    pub fn new(egui_ctx: &egui::Context, screenshot: Option<PathBuf>, start_hidden: bool) -> Self {
        style(egui_ctx);
        let s = Settings::load();
        let mut jobs = HashMap::new();
        for k in JobKind::ALL {
            let j = Job::default();
            if let Some(r) = background::load_report(k) {
                j.load_report(&r);
            }
            jobs.insert(k, j);
        }
        let status = Arc::new(Mutex::new(SysStatus::default()));
        let tick = Arc::new(AtomicBool::new(true));
        {
            let status = status.clone();
            let tick = tick.clone();
            let ctx = egui_ctx.clone();
            std::thread::spawn(move || loop {
                if tick.swap(false, Ordering::Relaxed) {
                    let st = load_status();
                    *status.lock().unwrap() = st;
                    ctx.request_repaint();
                }
                for _ in 0..150 {
                    std::thread::sleep(Duration::from_millis(100));
                    if tick.load(Ordering::Relaxed) {
                        break;
                    }
                }
                tick.store(true, Ordering::Relaxed);
            });
        }
        let shared = Arc::new(Mutex::new(Shared { quarantine: quarantine::list(), ..Default::default() }));
        let tray = if s.tray && screenshot.is_none() { Some(crate::tray::start(egui_ctx)) } else { None };
        let watch_flag = Arc::new(AtomicBool::new(s.watch_new_connections));
        let alerts = Arc::new(Mutex::new(vec![]));
        if screenshot.is_none() {
            crate::tray::start_watcher(watch_flag.clone(), alerts.clone(), egui_ctx.clone());
        }
        let tray_error = tray.as_ref().and_then(|t| t.error.clone());
        let mut me = Self {
            s,
            page: Page::Overview,
            jobs,
            vt_job: Job::default(),
            ext_job: Job::default(),
            fix_job: Job::default(),
            recheck_after_fix: Arc::new(AtomicBool::new(false)),
            foreign_pkgs: None,
            shred_ask: None,
            shred_sure: false,
            confirm_win_quarantine: None,
            recover_job: Job::default(),
            rec_parts: vec![],
            rec_source: None,
            rec_dest: String::new(),
            rec_kinds: crate::recover::KINDS.iter().map(|k| k.0.to_string()).collect(),
            rec_only_free: true,
            rec_scan_after: true,
            rec_all_kinds: false,
            rec_keep_damaged: false,
            rec_scan_request: Arc::new(Mutex::new(None)),
            sandbox_job: Job::default(),
            sbx_sample: String::new(),
            sbx_secs: 20,
            sbx_wine: false,
            sbx_sure: false,
            sbx_auto_throw: true,
            sbx_dir: Arc::new(Mutex::new(None)),
            vt_window: Arc::new(Mutex::new(None)),
            vt_retry_job: Job::default(),
            snap: Default::default(),
            rec_mode: 1,
            q_confirm: None,
            q_seen: None,
            rescue: crate::rescue_ui::RescueUi::new(),
            run_queue: vec![],
            queue_current: None,
            queue_total: 0,
            admin: HashMap::new(),
            filter: String::new(),
            show_sev: [true; 4],
            status,
            status_tick: tick,
            shared,
            conns: net::connections(),
            last_conn: Some(Instant::now()),
            conn_filter: String::new(),
            hide_listening: false,
            hide_local: true,
            rule_name: String::new(),
            rule_action: "deny".into(),
            rule_operand: "process.path".into(),
            rule_data: String::new(),
            toast: None,
            new_root: String::new(),
            new_exclude: String::new(),
            new_skip_dir: String::new(),
            new_pattern: String::new(),
            new_target: String::new(),
            show_key: false,
            settings_dirty: false,
            fw_choice: None,
            ipc_inbox: Arc::new(Mutex::new(vec![])),
            pending_scans: vec![],
            custom_scan: None,
            last_custom: None,
            size_ask: Default::default(),
            ask_limit: None,
            fw_timeout: None,
            tray,
            quitting: false,
            hidden: start_hidden,
            watch_flag,
            alerts,
            recent_alerts: vec![],
            last_tray_update: None,
            screenshot,
            frames: 0,
            shot_done: Arc::new(AtomicBool::new(false)),
            shot_requested: false,
            selftest: std::env::var("ARCH_SENTINEL_SELFTEST").map(|v| v == "tray").unwrap_or(false),
            selftest_round: 0,
            frames_at_open: 0,
        };
        // Open on a chosen page: ARCH_SENTINEL_PAGE=network|quarantine|background|settings|<check id>
        if let Ok(p) = std::env::var("ARCH_SENTINEL_PAGE") {
            me.page = match p.as_str() {
                "network" => Page::Network,
                "quarantine" => Page::Quarantine,
                "background" => Page::Background,
                "settings" => Page::Settings,
                "recover" => Page::Recover,
                "sandbox" => Page::Sandbox,
                "snapshots" => Page::Snapshots,
                id => JobKind::from_id(id).map(Page::Job).unwrap_or(Page::Overview),
            };
        }
        crate::root::set_idle_minutes(me.s.admin_session_minutes as u64);
        for id in me.s.admin_jobs.clone() {
            if let Some(k) = JobKind::from_id(&id) {
                me.admin.insert(k, true);
            }
        }
        if let Some(e) = tray_error {
            me.toast(e, false);
        }
        // For pictures of "Run all checks" under way: ARCH_SENTINEL_RUN_ALL=1 (never as administrator).
        if std::env::var("ARCH_SENTINEL_RUN_ALL").is_ok() {
            me.admin.clear();
            me.run_all(egui_ctx);
        }
        // For pictures of File Rescue: ARCH_SENTINEL_RESCUE_PREVIEW=<disk image>.
        if let Ok(img) = std::env::var("ARCH_SENTINEL_RESCUE_PREVIEW") {
            me.page = Page::Recover;
            me.rec_mode = 1;
            me.rescue.path = img;
            me.rescue.previous = true;
            me.rescue_find_now(egui_ctx);
        }
        // For pictures of a scan scope: ARCH_SENTINEL_SCOPE_PREVIEW=<0..3> (not saved).
        if let Some(v) = std::env::var("ARCH_SENTINEL_SCOPE_PREVIEW").ok().and_then(|v| v.parse().ok()) {
            me.s.virus_scope = v;
            me.page = Page::Job(JobKind::Virus);
        }
        // For pictures of the retry banner: ARCH_SENTINEL_VT_FAIL_PREVIEW=1 (a pretend failure, no lookup).
        if std::env::var("ARCH_SENTINEL_VT_FAIL_PREVIEW").is_ok() {
            me.page = Page::Job(JobKind::Virus);
            let mut st = me.jobs[&JobKind::Virus].state.lock().unwrap();
            st.ever_ran = true;
            st.summary = "1 of 4495 files flagged by ClamAV.".into();
            st.findings.push(Finding {
                sev: Sev::High,
                kind: "Win.Trojan.Example".into(),
                path: "/home/user/Downloads/example.exe".into(),
                detail: "VirusTotal lookup failed: VirusTotal's rate limit was reached · sha256 c71dffca05ec8201cc77ea28252b7d59c1bd551daebee75e6d23f62827b8633d".into(),
            });
        }
        // For pictures of the report window: ARCH_SENTINEL_VT_PREVIEW=<sha256>.
        if let Ok(sha) = std::env::var("ARCH_SENTINEL_VT_PREVIEW") {
            me.page = Page::Quarantine;
            me.open_vt(egui_ctx, "(preview)".into(), Some(sha), false);
        }
        // For pictures of the warning window: ARCH_SENTINEL_SHRED_PREVIEW=<file>.
        if let Ok(p) = std::env::var("ARCH_SENTINEL_SHRED_PREVIEW") {
            me.page = Page::Job(JobKind::Virus);
            me.ask_shred(p, "Example.Threat".into(), None);
        }
        if me.screenshot.is_none() && !me.selftest {
            crate::ipc::listen(me.ipc_inbox.clone(), egui_ctx.clone());
        }
        me
    }

    /// Stop every running scan and give the programs they started a moment to end.
    pub fn stop_all(&self) {
        let mut any = false;
        for j in self.jobs.values().chain([&self.vt_job, &self.ext_job, &self.recover_job, &self.sandbox_job, &self.rescue.job, &self.vt_retry_job, &self.snap.job]) {
            if j.is_running() {
                j.stop();
                any = true;
            }
        }
        if any {
            for _ in 0..20 {
                if !self.jobs.values().any(|j| j.is_running()) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    pub fn queue_scan(&mut self, paths: Vec<String>) {
        let paths: Vec<String> = paths.into_iter().filter(|p| !p.trim().is_empty()).collect();
        if !paths.is_empty() {
            self.pending_scans.push(paths);
            self.page = Page::Job(JobKind::Virus);
        }
    }

    /// Read messages from later starts. True when the window should come up.
    fn process_inbox(&mut self) -> bool {
        let msgs: Vec<String> = std::mem::take(&mut *self.ipc_inbox.lock().unwrap());
        let mut show = false;
        for m in msgs {
            match m.as_str() {
                "@show" => show = true,
                "@noop" => {}
                _ => {
                    self.queue_scan(m.lines().map(|l| l.to_string()).collect());
                    show = true;
                }
            }
        }
        show
    }

    /// Start the next right-click scan once the virus scanner is free.
    fn run_pending_scans(&mut self, ctx: &egui::Context) {
        if self.pending_scans.is_empty() || self.jobs[&JobKind::Virus].is_running() || self.vt_job.is_running() {
            return;
        }
        let paths = self.pending_scans.remove(0);
        self.custom_scan = Some(paths);
        self.page = Page::Job(JobKind::Virus);
        self.start(ctx, JobKind::Virus);
    }

    pub fn tray_ready(&self) -> bool {
        self.tray.as_ref().map(|t| t.handle.is_some()).unwrap_or(false)
    }

    /// Do what a tray menu item asks. Returns true when the window should open.
    fn handle_tray_cmd(&mut self, ctx: &egui::Context, c: crate::tray::TrayCmd) -> bool {
        use crate::tray::TrayCmd::*;
        match c {
            Show => true,
            RunAll => {
                self.run_all(ctx);
                false
            }
            UpdateSignatures => {
                self.start(ctx, JobKind::Signatures);
                false
            }
            OpenNetwork => {
                self.page = Page::Network;
                true
            }
            OpenQuarantine => {
                self.page = Page::Quarantine;
                true
            }
            Quit => {
                self.quitting = true;
                false
            }
        }
    }

    /// Handle tray clicks while the window is open and keep the tray's status line current.
    fn tray_logic(&mut self, ctx: &egui::Context) {
        let cmds: Vec<crate::tray::TrayCmd> = match &self.tray {
            Some(t) => t.rx.try_iter().collect(),
            None => vec![],
        };
        for c in cmds {
            let open = self.handle_tray_cmd(ctx, c);
            if self.quitting {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            } else if open {
                ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            }
        }
        self.update_tray_status();
        if self.tray_ready() {
            ctx.request_repaint_after(Duration::from_secs(2));
        }
    }

    fn update_tray_status(&mut self) {
        let new_alerts: Vec<String> = std::mem::take(&mut *self.alerts.lock().unwrap());
        let got_alert = !new_alerts.is_empty();
        self.recent_alerts.extend(new_alerts);
        if self.recent_alerts.len() > 50 {
            let n = self.recent_alerts.len() - 50;
            self.recent_alerts.drain(..n);
        }
        if !(self.last_tray_update.map(|t| t.elapsed().as_secs() >= 2).unwrap_or(true) || got_alert) {
            return;
        }
        self.last_tray_update = Some(Instant::now());
        let running: Vec<&str> = JobKind::ALL.iter().filter(|k| self.jobs[k].is_running()).map(|k| k.short()).collect();
        let serious: usize = self.jobs.values().map(|j| j.state.lock().unwrap().count(Sev::High)).sum();
        let status = if !running.is_empty() {
            format!("Running: {}", running.join(", "))
        } else if serious > 0 {
            format!("{serious} serious finding(s) to review")
        } else {
            "No serious findings".to_string()
        };
        if let Some(h) = self.tray.as_ref().and_then(|t| t.handle.as_ref()) {
            h.update(|t| {
                t.status = status.clone();
                if got_alert {
                    t.alert = true;
                }
            });
        }
    }

    /// The window is closed: wait in the tray, still running tray actions and
    /// keeping its status current. Returns true to open the window again,
    /// false to quit.
    pub fn idle_in_tray(&mut self, ctx: &egui::Context) -> bool {
        if self.selftest {
            eprintln!("selftest: in the tray, opening the window again");
            self.selftest_round += 1;
            self.frames_at_open = self.frames;
            return true;
        }
        if self.settings_dirty {
            self.save_settings();
        }
        if !self.s.tray_hint_shown {
            self.s.tray_hint_shown = true;
            let _ = self.s.save();
            let _ = Command::new("notify-send")
                .args(["-a", "Arch Sentinel", "-i", "security-high", "Arch Sentinel is still running", "It keeps watching from the tray. Click the shield to open it, or choose Quit there."])
                .spawn();
        }
        loop {
            if self.process_inbox() || self.size_ask.lock().unwrap().question.is_some() {
                self.page = Page::Job(JobKind::Virus);
                return true;
            }
            let cmd = match &self.tray {
                Some(t) => t.rx.recv_timeout(Duration::from_millis(500)),
                None => return false,
            };
            match cmd {
                Ok(c) => {
                    let open = self.handle_tray_cmd(ctx, c);
                    if self.quitting {
                        return false;
                    }
                    if open {
                        return true;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return false,
            }
            self.advance_queue(ctx);
            self.update_tray_status();
        }
    }

    /// The order "Run all checks" uses: the checks that find unverified system
    /// files first, so the virus scan (last) can scan those files first.
    pub const RUN_ALL: [JobKind; 6] = [JobKind::Integrity, JobKind::Unowned, JobKind::HomeCheck, JobKind::Rootkit, JobKind::Processes, JobKind::Virus];

    /// Start "Run all checks": one check at a time, the virus scan last.
    pub fn run_all(&mut self, ctx: &egui::Context) {
        if !self.run_queue.is_empty() || self.queue_current.is_some() {
            self.toast("All checks are already running one after another.", false);
            return;
        }
        self.run_queue = Self::RUN_ALL.to_vec();
        self.queue_total = self.run_queue.len();
        self.advance_queue(ctx);
    }

    /// Start the next queued check once the current one has finished.
    pub fn advance_queue(&mut self, ctx: &egui::Context) {
        if let Some(k) = self.queue_current {
            let busy = self.jobs[&k].is_running() || (k == JobKind::Virus && self.vt_job.is_running());
            if busy {
                return;
            }
            self.queue_current = None;
        }
        while let Some(k) = (!self.run_queue.is_empty()).then(|| self.run_queue.remove(0)) {
            if self.jobs[&k].is_running() {
                // Already running on its own: wait for it like any other.
                self.queue_current = Some(k);
                return;
            }
            self.start(ctx, k);
            self.queue_current = Some(k);
            return;
        }
        if self.queue_total > 0 && self.queue_current.is_none() {
            self.queue_total = 0;
            self.toast("All checks are done — see the Dashboard.", true);
        }
    }

    /// Turn administrator rights on or off for a check, and remember it.
    pub fn set_admin(&mut self, k: JobKind, on: bool) {
        self.admin.insert(k, on);
        self.s.admin_jobs.retain(|x| x != k.id());
        if on {
            self.s.admin_jobs.push(k.id().to_string());
        }
        self.settings_dirty = true;
    }

    pub fn all_admin(&self) -> bool {
        crate::settings::ADMIN_CAPABLE.iter().all(|(k, _)| *self.admin.get(k).unwrap_or(&false))
    }

    pub fn job(&self, k: JobKind) -> &Job {
        &self.jobs[&k]
    }

    pub fn toast(&mut self, msg: impl Into<String>, ok: bool) {
        self.toast = Some((msg.into(), ok, Instant::now()));
    }

    pub fn save_settings(&mut self) {
        match self.s.save() {
            Ok(()) => self.settings_dirty = false,
            Err(e) => {
                self.settings_dirty = false;
                self.toast(format!("Couldn't save settings: {e}"), false)
            }
        }
    }

    /// Run a slow task off the window thread and report its result as a toast.
    pub fn task(&self, ctx: &egui::Context, label: &str, f: impl FnOnce(&Arc<Mutex<Shared>>) -> Result<String, String> + Send + 'static) {
        let shared = self.shared.clone();
        let ctx = ctx.clone();
        shared.lock().unwrap().busy = Some(label.to_string());
        std::thread::spawn(move || {
            let r = f(&shared);
            let mut sh = shared.lock().unwrap();
            sh.busy = None;
            match r {
                Ok(m) => sh.toasts.push((m, true)),
                Err(m) => sh.toasts.push((m, false)),
            }
            ctx.request_repaint();
        });
    }

    /// Build a command at the lowest priority, optionally capped and through pkexec.
    pub fn command(&self, admin: bool, program: &str, args: &[String]) -> Command {
        crate::par::command(&self.s, admin, program, args)
    }

    /// The virus scan's folders, plus (when turned on) the system files the
    /// unowned-files and package-files checks flagged.
    /// The unverified system files to scan first (by the chosen scope).
    pub fn unverified_targets(&self) -> Vec<String> {
        if self.s.virus_scope == 2 || self.s.virus_scope == 3 {
            return vec![];
        }
        let mut t = vec![];
        for k in [JobKind::Unowned, JobKind::Integrity] {
            t.extend(clam::unverified_paths(&self.jobs[&k].state.lock().unwrap().findings));
        }
        t.sort();
        t.dedup();
        t
    }

    /// The home folders to scan (by the chosen scope), then any external drives.
    pub fn home_targets(&self) -> Vec<String> {
        let mut t = if matches!(self.s.virus_scope, 1 | 3) { vec![] } else { self.s.virus_targets.clone() };
        if self.s.scan_external || self.s.virus_scope == 3 {
            t.extend(crate::drives::chosen(&self.s.external_skip).into_iter().map(|d| d.mount));
        }
        t
    }

    pub fn unverified_count(&self) -> (usize, bool) {
        let mut n = 0;
        let mut ran = true;
        for k in [JobKind::Unowned, JobKind::Integrity] {
            let st = self.jobs[&k].state.lock().unwrap();
            ran &= st.ever_ran;
            n += clam::unverified_paths(&st.findings).len();
        }
        (n, ran)
    }

    pub fn start(&mut self, ctx: &egui::Context, k: JobKind) {
        let admin = *self.admin.get(&k).unwrap_or(&false);
        let job = self.job(k).clone();
        if job.is_running() {
            return;
        }
        let c2 = ctx.clone();
        let repaint = move || c2.request_repaint();
        let s = self.s.clone();
        let capped = self.s.cpu_cap > 0 && self.s.cpu_cap < 100;
        match k {
            JobKind::Signatures => {
                let cmd = self.command(true, "/usr/bin/freshclam", &["--stdout".into()]);
                let tick = self.status_tick.clone();
                job.run_command(
                    repaint,
                    cmd,
                    true,
                    |l| vec![crate::jobs::Msg::Log(l.to_string()), crate::jobs::Msg::Progress(l.to_string())],
                    move |code, em| {
                        em.done(if code == 0 {
                            "Virus signatures are up to date.".to_string()
                        } else {
                            format!("freshclam finished with code {code} (126/127 means administrator rights were refused).")
                        });
                        tick.store(true, Ordering::Relaxed);
                    },
                );
            }
            JobKind::Integrity => job.run_thread(repaint, move |em| pkg::scan_integrity(&s, admin, em)),
            // Administrator runs, and runs under a CPU cap, go through a helper process.
            JobKind::Unowned | JobKind::HomeCheck | JobKind::Rootkit | JobKind::Processes if admin || capped => {
                if let Err(e) = self.s.save() {
                    self.toast(format!("Couldn't save settings for the administrator run: {e}"), false);
                    return;
                }
                let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default();
                let args = ["--helper".to_string(), k.id().to_string(), "--settings".to_string(), config_path().display().to_string()];
                let cmd = self.command(true, &exe, &args);
                job.run_command(repaint, cmd, admin, |l| vec![crate::jobs::Msg::Log(l.to_string())], move |code, em| {
                    if admin && (code == 126 || code == 127) {
                        em.done("Administrator rights were refused.");
                    }
                });
            }
            JobKind::Unowned => job.run_thread(repaint, move |em| {
                crate::par::lowest_priority_thread();
                pkg::scan_unowned(&s, em)
            }),
            JobKind::HomeCheck => job.run_thread(repaint, move |em| {
                crate::par::lowest_priority_thread();
                pkg::scan_home(&s, em)
            }),
            JobKind::Rootkit => job.run_thread(repaint, move |em| {
                crate::par::lowest_priority_thread();
                rootkit::run_builtin(em, crate::par::threads(&s))
            }),
            JobKind::Processes => job.run_thread(repaint, move |em| {
                crate::par::lowest_priority_thread();
                crate::procs::scan_processes(&s, em)
            }),
            JobKind::Virus => {
                let vt_job = self.vt_job.clone();
                *vt_job.state.lock().unwrap() = Default::default();
                let c3 = ctx.clone();
                let shared = self.shared.clone();
                let (first, targets) = match self.custom_scan.take() {
                    Some(p) => {
                        self.last_custom = Some(p.clone());
                        (vec![], p)
                    }
                    None => {
                        self.last_custom = None;
                        (self.unverified_targets(), self.home_targets())
                    }
                };
                let custom = self.last_custom.is_some();
                let ask = self.size_ask.clone();
                job.run_thread(repaint, move |em| {
                    crate::par::lowest_priority_thread();
                    let found = if custom {
                        clam::scan_custom(&s, &targets, admin, em, &ask)
                    } else {
                        clam::scan_parallel(&s, &first, &targets, admin, em)
                    };
                    if found.is_empty() {
                        return;
                    }
                    if s.vt_check && !s.vt_api_key.is_empty() {
                        let key = s.vt_api_key.clone();
                        let auto_q = s.quarantine;
                        let rp = move || c3.request_repaint();
                        let vstate = vt_job.state.clone();
                        vt_job.run_thread(rp, move |em| {
                            clam::verify_findings(&key, &found, em);
                            if auto_q {
                                let list: Vec<Finding> = vstate.lock().unwrap().findings.clone();
                                for f in list.iter().filter(|f| f.detail.contains("CONFIRMED")) {
                                    match quarantine::quarantine(&f.path, &f.kind) {
                                        Ok(_) => em.log(format!("Quarantined {}", f.path)),
                                        Err(e) => em.log(format!("Couldn't quarantine {}: {e}", f.path)),
                                    }
                                }
                                shared.lock().unwrap().quarantine = quarantine::list();
                            }
                        });
                    } else if s.quarantine && !s.vt_check {
                        for f in &found {
                            if let Err(e) = quarantine::quarantine(&f.path, &f.kind) {
                                em.log(format!("Couldn't quarantine {}: {e}", f.path));
                            }
                        }
                        shared.lock().unwrap().quarantine = quarantine::list();
                    }
                });
            }
        }
    }
}

pub fn style(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();
    v.panel_fill = BG;
    v.window_fill = PANEL;
    v.extreme_bg_color = Color32::from_rgb(0x10, 0x12, 0x16);
    v.faint_bg_color = Color32::from_rgb(0x1e, 0x22, 0x2a);
    v.selection.bg_fill = ACCENT.linear_multiply(0.45);
    v.hyperlink_color = ACCENT;
    v.widgets.inactive.bg_fill = Color32::from_rgb(0x2a, 0x30, 0x3a);
    v.widgets.inactive.weak_bg_fill = Color32::from_rgb(0x2a, 0x30, 0x3a);
    v.widgets.hovered.weak_bg_fill = Color32::from_rgb(0x34, 0x3c, 0x48);
    v.widgets.active.weak_bg_fill = ACCENT.linear_multiply(0.6);
    ctx.set_visuals(v);
    ctx.global_style_mut(|s| {
        s.spacing.item_spacing = egui::vec2(8.0, 6.0);
        s.spacing.button_padding = egui::vec2(10.0, 5.0);
        s.text_styles.insert(egui::TextStyle::Heading, egui::FontId::proportional(22.0));
        s.text_styles.insert(egui::TextStyle::Body, egui::FontId::proportional(14.0));
        s.text_styles.insert(egui::TextStyle::Button, egui::FontId::proportional(14.0));
    });
}

pub fn card<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    egui::Frame::new()
        .fill(CARD)
        .corner_radius(8.0)
        .inner_margin(egui::Margin::same(14))
        .show(ui, |ui| ui.vertical(|ui| add(ui)).inner)
        .inner
}

pub fn pill(ui: &mut Ui, text: &str, color: Color32) {
    egui::Frame::new()
        .fill(color.linear_multiply(0.22))
        .corner_radius(10.0)
        .inner_margin(egui::Margin::symmetric(8, 2))
        .show(ui, |ui| {
            ui.label(RichText::new(text).color(color).size(12.0).strong());
        });
}

pub fn primary(text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text.to_string()).color(Color32::WHITE)).fill(ACCENT.linear_multiply(0.8))
}

pub fn ago(t: Option<std::time::SystemTime>) -> String {
    let Some(t) = t else { return "never".into() };
    let secs = std::time::SystemTime::now().duration_since(t).map(|d| d.as_secs()).unwrap_or(0);
    if secs < 60 {
        "just now".into()
    } else if secs < 3600 {
        format!("{} min ago", secs / 60)
    } else if secs < 86400 {
        format!("{} h ago", secs / 3600)
    } else {
        format!("{} days ago", secs / 86400)
    }
}

pub fn state_color(s: &str) -> Color32 {
    match s {
        "active" | "enabled" => GREEN,
        "inactive" | "disabled" => TEXT_DIM,
        "failed" => RED,
        _ => AMBER,
    }
}

fn shorten(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let cut: String = s.chars().take(n).collect();
        format!("{cut}…")
    }
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.tray_logic(ctx);
        self.advance_queue(ctx);
        if self.queue_current.is_some() {
            ctx.request_repaint_after(Duration::from_millis(500));
        }
        if self.process_inbox() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        }
        let rec_done = self.rec_scan_request.lock().unwrap().take();
        if let Some(d) = rec_done {
            self.queue_scan(vec![d]);
        }
        self.run_pending_scans(ctx);
        if !self.fix_job.is_running() && self.recheck_after_fix.swap(false, Ordering::Relaxed) {
            self.foreign_pkgs = None;
            self.start(ctx, JobKind::Integrity);
        }
        if self.size_ask.lock().unwrap().question.is_some() && self.page != Page::Job(JobKind::Virus) {
            self.page = Page::Job(JobKind::Virus);
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        }
        if !self.pending_scans.is_empty() {
            ctx.request_repaint_after(Duration::from_millis(500));
        }
        self.watch_flag.store(self.s.watch_new_connections, Ordering::Relaxed);
        if ctx.input(|i| i.viewport().close_requested()) && self.settings_dirty {
            self.save_settings();
        }
    }

    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.hidden = false;
        self.frames += 1;
        if self.selftest {
            ctx.request_repaint();
            if self.frames - self.frames_at_open == 60 {
                eprintln!("selftest: window {} drew 60 frames, closing it", self.selftest_round + 1);
                if self.selftest_round >= 1 {
                    self.quitting = true;
                }
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
        if self.screenshot.is_some() {
            ctx.request_repaint();
            if self.frames >= 120 && !self.shot_requested {
                self.shot_requested = true;
                let path = self.screenshot.clone().unwrap();
                let done = self.shot_done.clone();
                let c2 = ctx.clone();
                ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::ScreenshotCallback::new(move |img| {
                    if let Err(e) = save_png(&path, &img) {
                        eprintln!("Couldn't save the picture: {e}");
                    }
                    done.store(true, Ordering::Relaxed);
                    c2.request_repaint();
                })));
            }
            if self.shot_done.load(Ordering::Relaxed) {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            if self.frames > 1500 {
                eprintln!("The picture never arrived.");
                std::process::exit(1);
            }
        }
        {
            let msgs: Vec<(String, bool)> = std::mem::take(&mut self.shared.lock().unwrap().toasts);
            if let Some((m, ok)) = msgs.into_iter().last() {
                self.toast(m, ok);
            }
        }
        if self.jobs.values().any(|j| j.is_running()) || self.vt_job.is_running() || self.shared.lock().unwrap().busy.is_some() {
            ctx.request_repaint_after(Duration::from_millis(250));
        }

        self.sidebar(ui);
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(BG).inner_margin(egui::Margin::symmetric(24, 18)))
            .show(ui, |ui| {
                self.toast_bar(ui);
                match self.page {
                    Page::Overview => self.overview(ui),
                    Page::Job(k) => self.job_page(ui, k),
                    Page::Quarantine => self.quarantine_page(ui),
                    Page::Network => self.network_page(ui),
                    Page::Background => self.background_page(ui),
                    Page::Settings => self.settings_page(ui),
                    Page::Recover => self.recover_page(ui),
                    Page::Sandbox => self.sandbox_page(ui),
                    Page::Snapshots => self.snapshots_page(ui),
                }
            });
        self.shred_dialog(&ctx);
        self.vt_dialog(&ctx);
        if self.settings_dirty {
            self.save_settings();
        }
    }
}

fn save_png(path: &PathBuf, img: &egui::ColorImage) -> std::io::Result<()> {
    if let Some(d) = path.parent() {
        if !d.as_os_str().is_empty() {
            std::fs::create_dir_all(d)?;
        }
    }
    let f = std::fs::File::create(path)?;
    let mut enc = png::Encoder::new(std::io::BufWriter::new(f), img.size[0] as u32, img.size[1] as u32);
    enc.set_color(png::ColorType::Rgba);
    enc.set_depth(png::BitDepth::Eight);
    let mut w = enc.write_header().map_err(std::io::Error::other)?;
    let data: Vec<u8> = img.pixels.iter().flat_map(|p| p.to_array()).collect();
    w.write_image_data(&data).map_err(std::io::Error::other)?;
    Ok(())
}

impl App {
    fn sidebar(&mut self, ui: &mut Ui) {
        let jobs: Vec<(JobKind, usize, Color32, bool)> = JobKind::ALL
            .iter()
            .filter(|k| **k != JobKind::Signatures)
            .map(|k| {
                let st = self.jobs[k].state.lock().unwrap();
                let h = st.count(Sev::High);
                let m = st.count(Sev::Medium);
                let (n, c) = if h > 0 { (h, RED) } else { (m, AMBER) };
                (*k, n, c, st.running || (*k == JobKind::Virus && self.vt_job.is_running()))
            })
            .collect();
        let q = self.shared.lock().unwrap().quarantine.len();
        let sig_running = self.jobs[&JobKind::Signatures].is_running();
        let recover_running = self.recover_job.is_running() || self.rescue.job.is_running();
        let sandbox_running = self.sandbox_job.is_running();
        let snap_running = self.snap.job.is_running();
        let mut goto: Option<Page> = None;
        let current = self.page;
        egui::Panel::left("nav")
            .exact_size(230.0)
            .resizable(false)
            .frame(egui::Frame::new().fill(PANEL).inner_margin(egui::Margin::symmetric(12, 16)))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let (r, p) = ui.allocate_painter(egui::vec2(30.0, 30.0), egui::Sense::hover());
                    let c = r.rect.center();
                    let pts = vec![
                        c + egui::vec2(0.0, -13.0),
                        c + egui::vec2(11.0, -8.0),
                        c + egui::vec2(9.0, 6.0),
                        c + egui::vec2(0.0, 13.0),
                        c + egui::vec2(-9.0, 6.0),
                        c + egui::vec2(-11.0, -8.0),
                    ];
                    p.add(egui::Shape::convex_polygon(pts, ACCENT, egui::Stroke::NONE));
                    p.line_segment([c + egui::vec2(-5.0, 0.0), c + egui::vec2(-1.0, 4.0)], egui::Stroke::new(2.5, BG));
                    p.line_segment([c + egui::vec2(-1.0, 4.0), c + egui::vec2(6.0, -5.0)], egui::Stroke::new(2.5, BG));
                    ui.vertical(|ui| {
                        ui.label(RichText::new("Arch Sentinel").size(17.0).strong().color(Color32::WHITE));
                        ui.label(RichText::new("system security").size(11.0).color(TEXT_DIM));
                    });
                });
                ui.add_space(14.0);
                let mut nav = |ui: &mut Ui, page: Page, label: &str, badge: Option<(usize, Color32)>, running: bool| {
                    let selected = current == page;
                    let fill = if selected { ACCENT.linear_multiply(0.22) } else { Color32::TRANSPARENT };
                    let resp = egui::Frame::new()
                        .fill(fill)
                        .corner_radius(6.0)
                        .inner_margin(egui::Margin::symmetric(10, 7))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(label).color(if selected { Color32::WHITE } else { Color32::from_gray(200) }));
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if running {
                                        ui.add(egui::Spinner::new().size(12.0));
                                    } else if let Some((n, c)) = badge {
                                        if n > 0 {
                                            pill(ui, &n.to_string(), c);
                                        }
                                    }
                                });
                            });
                        })
                        .response
                        .interact(egui::Sense::click());
                    if resp.clicked() {
                        goto = Some(page);
                    }
                };
                ui.label(RichText::new("OVERVIEW").size(11.0).color(TEXT_DIM));
                nav(ui, Page::Overview, "Dashboard", None, false);
                ui.add_space(6.0);
                ui.label(RichText::new("CHECKS").size(11.0).color(TEXT_DIM));
                for (k, n, c, r) in &jobs {
                    nav(ui, Page::Job(*k), k.short(), Some((*n, *c)), *r);
                }
                nav(ui, Page::Quarantine, "Quarantine", Some((q, AMBER)), false);
                nav(ui, Page::Recover, "Deleted files (exp.)", None, recover_running);
                nav(ui, Page::Sandbox, "Sandbox (exp.)", None, sandbox_running);
                nav(ui, Page::Snapshots, "Snapshots (exp.)", None, snap_running);
                ui.add_space(6.0);
                ui.label(RichText::new("NETWORK").size(11.0).color(TEXT_DIM));
                nav(ui, Page::Network, "Connections & rules", None, false);
                ui.add_space(6.0);
                ui.label(RichText::new("SETUP").size(11.0).color(TEXT_DIM));
                nav(ui, Page::Background, "Background jobs", None, sig_running);
                nav(ui, Page::Settings, "Settings", None, false);
            });
        if let Some(p) = goto {
            self.page = p;
        }
    }

    fn toast_bar(&mut self, ui: &mut Ui) {
        let busy = self.shared.lock().unwrap().busy.clone();
        if let Some(b) = busy {
            ui.horizontal(|ui| {
                ui.add(egui::Spinner::new());
                ui.label(RichText::new(b).color(TEXT_DIM));
            });
        }
        if let Some((m, ok, t)) = self.toast.clone() {
            if t.elapsed().as_secs() < 8 {
                let mut close = false;
                egui::Frame::new()
                    .fill(if ok { GREEN.linear_multiply(0.18) } else { RED.linear_multiply(0.2) })
                    .corner_radius(6.0)
                    .inner_margin(egui::Margin::symmetric(12, 8))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(&m).color(Color32::WHITE));
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                close = ui.small_button("x").clicked();
                            });
                        });
                    });
                if close {
                    self.toast = None;
                }
                ui.add_space(8.0);
                ui.ctx().request_repaint_after(Duration::from_secs(1));
            } else {
                self.toast = None;
            }
        }
    }

    // ---------------- Dashboard ----------------

    fn overview(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        let st = self.status.lock().unwrap().clone();
        let mut run_all = false;
        let mut dash_admin: Option<bool> = None;
        ui.horizontal(|ui| {
            ui.heading(RichText::new("Dashboard").color(Color32::WHITE));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                run_all = ui
                    .add_enabled(self.queue_current.is_none(), primary("Run all checks"))
                    .on_hover_text("Package files, unowned files, home folder, rootkits and running programs first, one after another — then the virus scan, which starts with the unverified system files they found")
                    .clicked();
                let mut all = self.all_admin();
                if ui
                    .checkbox(&mut all, "as administrator")
                    .on_hover_text("Tick \"Run as administrator\" for every check at once (Settings → Administrator rights has them one by one). Your password is asked once for the whole run.")
                    .changed()
                {
                    dash_admin = Some(all);
                }
                if ui.button("Refresh status").clicked() {
                    self.status_tick.store(true, Ordering::Relaxed);
                }
            });
        });
        if let Some(on) = dash_admin {
            for (k, _) in crate::settings::ADMIN_CAPABLE {
                self.set_admin(k, on);
            }
        }
        if run_all {
            self.run_all(&ctx);
        }
        ui.label(RichText::new("Package integrity, stray files, viruses, rootkits and network rules in one place.").color(TEXT_DIM));
        if let Some(cur) = self.queue_current {
            let done = self.queue_total.saturating_sub(self.run_queue.len() + 1);
            let mut cancel = false;
            ui.add_space(6.0);
            egui::Frame::new().fill(ACCENT.linear_multiply(0.15)).corner_radius(6.0).inner_margin(egui::Margin::symmetric(12, 8)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.add(egui::Spinner::new());
                    ui.label(RichText::new(format!("Running all checks one after another: {} of {} — {}", done + 1, self.queue_total, cur.short())).color(Color32::WHITE));
                    if !self.run_queue.is_empty() {
                        ui.label(RichText::new(format!("then {}", self.run_queue.iter().map(|k| k.short()).collect::<Vec<_>>().join(", "))).size(12.0).color(TEXT_DIM));
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        cancel = ui.button("Skip the rest").on_hover_text("Lets the current check finish, then stops").clicked();
                    });
                });
            });
            if cancel {
                self.run_queue.clear();
            }
        }
        ui.add_space(12.0);

        ui.columns(4, |cols| {
            card(&mut cols[0], |ui| {
                ui.set_min_height(92.0);
                ui.set_width(ui.available_width());
                ui.label(RichText::new("Installed packages").color(TEXT_DIM).size(12.0));
                ui.label(RichText::new(if st.loaded { st.packages.to_string() } else { "…".into() }).size(26.0).strong().color(Color32::WHITE));
                ui.label(RichText::new("from the pacman database").color(TEXT_DIM).size(12.0));
            });
            card(&mut cols[1], |ui| {
                ui.set_min_height(92.0);
                ui.set_width(ui.available_width());
                ui.label(RichText::new("Virus signatures").color(TEXT_DIM).size(12.0));
                match &st.clam {
                    Some((eng, db, date)) => {
                        ui.label(RichText::new(format!("v{db}")).size(26.0).strong().color(Color32::WHITE));
                        ui.label(RichText::new(format!("ClamAV {eng} · {}", date.get(4..10).unwrap_or(date))).color(TEXT_DIM).size(12.0));
                    }
                    None => {
                        ui.label(RichText::new(if st.loaded { "missing" } else { "…" }).size(26.0).strong().color(AMBER));
                        ui.label(RichText::new("install the clamav package").color(TEXT_DIM).size(12.0));
                    }
                }
            });
            card(&mut cols[2], |ui| {
                ui.set_min_height(92.0);
                ui.set_width(ui.available_width());
                ui.label(RichText::new("Signature updates").color(TEXT_DIM).size(12.0));
                let t = st.timers.get(&JobKind::Signatures).cloned().unwrap_or_default();
                if t.active == "active" {
                    ui.label(RichText::new("On a timer").size(20.0).strong().color(GREEN));
                    ui.label(RichText::new(format!("next: {}", t.next)).color(TEXT_DIM).size(12.0));
                } else if st.freshclam_daemon == "active" {
                    ui.label(RichText::new("Running as daemon").size(20.0).strong().color(AMBER));
                    ui.label(RichText::new("switch to a timer in Background jobs").color(TEXT_DIM).size(12.0));
                } else {
                    ui.label(RichText::new(if st.loaded { "Not scheduled" } else { "…" }).size(20.0).strong().color(AMBER));
                    ui.label(RichText::new("set a timer in Background jobs").color(TEXT_DIM).size(12.0));
                }
            });
            card(&mut cols[3], |ui| {
                ui.set_min_height(92.0);
                ui.set_width(ui.available_width());
                ui.label(RichText::new("OpenSnitch firewall").color(TEXT_DIM).size(12.0));
                let a = if st.loaded { st.snitch_active.clone() } else { "…".into() };
                ui.label(RichText::new(&a).size(20.0).strong().color(state_color(&a)));
                if let Some((def, intercept)) = &st.snitch_cfg {
                    ui.label(RichText::new(format!("default: {def}{}", if *intercept { ", intercepts unknown" } else { "" })).color(TEXT_DIM).size(12.0));
                }
            });
        });
        ui.add_space(14.0);
        ui.label(RichText::new("CHECKS").size(11.0).color(TEXT_DIM));
        ui.add_space(4.0);
        let kinds = [JobKind::Integrity, JobKind::Unowned, JobKind::HomeCheck, JobKind::Virus, JobKind::Rootkit, JobKind::Processes];
        let mut go: Option<JobKind> = None;
        let mut open: Option<Page> = None;
        let connected = self.conns.iter().filter(|c| c.state == "Connected").count();
        let listening = self.conns.iter().filter(|c| c.state == "Listening").count();
        let mut slots: Vec<Option<JobKind>> = kinds.iter().map(|k| Some(*k)).collect();
        slots.push(None); // network card
        for row in slots.chunks(3) {
            ui.columns(3, |cols| {
                for (i, slot) in row.iter().enumerate() {
                    let ui = &mut cols[i];
                    match slot {
                        Some(k) => {
                            card(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.set_min_height(112.0);
                                let s = self.jobs[k].state.lock().unwrap();
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(k.short()).strong().size(16.0).color(Color32::WHITE));
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        if s.running && self.jobs[k].is_paused() {
                                            pill(ui, "paused", AMBER);
                                        } else if s.running {
                                            ui.add(egui::Spinner::new().size(14.0));
                                        } else if !s.ever_ran {
                                            pill(ui, "not run", TEXT_DIM);
                                        } else if s.count(Sev::High) > 0 {
                                            pill(ui, &format!("{} serious", s.count(Sev::High)), RED);
                                        } else if s.count(Sev::Medium) > 0 {
                                            pill(ui, &format!("{} to review", s.count(Sev::Medium)), AMBER);
                                        } else {
                                            pill(ui, "clean", GREEN);
                                        }
                                    });
                                });
                                ui.label(RichText::new(job_blurb(*k)).color(TEXT_DIM).size(12.0));
                                ui.add_space(4.0);
                                let line = if s.running {
                                    shorten(&s.progress, 56)
                                } else if s.ever_ran {
                                    format!("{} findings · {}{}", s.findings.len(), ago(s.finished_wall), if s.from_background { " (background)" } else { "" })
                                } else {
                                    "Never run on this computer".to_string()
                                };
                                ui.add(egui::Label::new(RichText::new(line).size(12.0).color(Color32::from_gray(190))).truncate());
                                ui.horizontal(|ui| {
                                    if ui.add_enabled(!s.running, egui::Button::new("Run")).clicked() {
                                        go = Some(*k);
                                    }
                                    if ui.button("Details").clicked() {
                                        open = Some(Page::Job(*k));
                                    }
                                });
                            });
                        }
                        None => {
                            card(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.set_min_height(112.0);
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new("Network").strong().size(16.0).color(Color32::WHITE));
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        if st.loaded {
                                            pill(ui, &format!("OpenSnitch {}", st.snitch_active), state_color(&st.snitch_active));
                                        }
                                    });
                                });
                                ui.label(RichText::new("Live connections per program, verified against packages, and OpenSnitch rules.").color(TEXT_DIM).size(12.0));
                                ui.add_space(4.0);
                                ui.label(RichText::new(format!("{connected} connected · {listening} listening")).size(12.0).color(Color32::from_gray(190)));
                                if ui.button("Open").clicked() {
                                    open = Some(Page::Network);
                                }
                            });
                        }
                    }
                }
            });
            ui.add_space(10.0);
        }
        if let Some(k) = go {
            self.start(&ctx, k);
        }
        if let Some(p) = open {
            self.page = p;
        }
        ui.add_space(14.0);
        ui.label(RichText::new("TOOLS ON THIS COMPUTER").size(11.0).color(TEXT_DIM));
        ui.horizontal_wrapped(|ui| {
            for (t, path) in [("paccheck", "/usr/bin/paccheck"), ("clamscan", "/usr/bin/clamscan"), ("freshclam", "/usr/bin/freshclam"), ("opensnitchd", "/usr/bin/opensnitchd"), ("opensnitch-ui", "/usr/bin/opensnitch-ui")] {
                let ok = std::path::Path::new(path).exists();
                pill(ui, &format!("{t}: {}", if ok { "installed" } else { "missing" }), if ok { GREEN } else { RED });
            }
            for (t, ok) in &st.tools {
                pill(ui, &format!("{t}: {}", if *ok { "installed" } else { "optional, not installed" }), if *ok { GREEN } else { TEXT_DIM });
            }
        });
    }

    // ---------------- Check pages ----------------

    fn job_page(&mut self, ui: &mut Ui, k: JobKind) {
        let ctx = ui.ctx().clone();
        let job = self.job(k).clone();
        let running = job.is_running();
        let mut run = false;
        let mut pause_refused = false;
        let mut admin_change: Option<bool> = None;
        ui.horizontal(|ui| {
            ui.heading(RichText::new(k.title()).color(Color32::WHITE));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if running {
                    if ui.button("Stop").clicked() {
                        job.stop();
                        if k == JobKind::Virus {
                            self.vt_job.stop();
                        }
                    }
                    let paused = job.is_paused();
                    if ui.button(if paused { "Resume" } else { "Pause" }).on_hover_text("Pause keeps everything found so far; Resume carries on where it stopped").clicked() {
                        if !job.set_paused(!paused) {
                            pause_refused = true;
                        }
                    }
                } else if k == JobKind::Virus && self.vt_job.is_running() {
                    let paused = self.vt_job.is_paused();
                    if ui.button(if paused { "Resume VirusTotal" } else { "Pause VirusTotal" }).clicked() {
                        self.vt_job.set_paused(!paused);
                    }
                    if ui.button("Stop").clicked() {
                        self.vt_job.stop();
                    }
                } else {
                    run = ui.add(primary("Run now")).clicked();
                }
                let cores = crate::par::ncpu() as u32;
                let cur = self.s.scan_threads;
                let label = |t: u32| if t == 0 { format!("Threads: automatic ({})", (cores / 2).max(1)) } else { format!("Threads: {t}") };
                egui::ComboBox::from_id_salt(("threads", k.id()))
                    .selected_text(label(cur))
                    .show_ui(ui, |ui| {
                        for t in 0..=cores {
                            if ui.selectable_label(cur == t, label(t)).clicked() {
                                self.s.scan_threads = t;
                                self.settings_dirty = true;
                            }
                        }
                    })
                    .response
                    .on_hover_text("How many threads this and every other scan uses (all at the lowest priority). More options under Background jobs.");
                let mut a = *self.admin.get(&k).unwrap_or(&false);
                if ui.checkbox(&mut a, "Run as administrator").on_hover_text("Asks for your password once per session so the scan can read every file and process. Set them all at once in Settings → Administrator rights.").changed() {
                    admin_change = Some(a);
                }
            });
        });
        if run {
            self.start(&ctx, k);
        }
        if let Some(a) = admin_change {
            self.set_admin(k, a);
        }
        if pause_refused {
            self.toast("Paused what could be paused; the part running with administrator rights keeps going.", false);
        }
        ui.label(RichText::new(job_help(k)).color(TEXT_DIM));
        if k == JobKind::Processes {
            if ui.checkbox(&mut self.s.paranoid, "Paranoid: also look inside running programs that aren't from a package").on_hover_text(PARANOID_TIP).changed() {
                self.settings_dirty = true;
            }
        }
        if k == JobKind::Integrity && !running {
            let (repo, aur) = self.failed_packages();
            let fixing = self.fix_job.is_running();
            if !repo.is_empty() || !aur.is_empty() || fixing || self.fix_job.state.lock().unwrap().ever_ran {
                let mut go = false;
                card(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal_wrapped(|ui| {
                        if !repo.is_empty() {
                            go = ui
                                .add_enabled(!fixing, primary(&format!("Reinstall {} package(s) that failed", repo.len())))
                                .on_hover_text(format!("pacman -S {} — pacman checks each package's signature, so you get clean copies", repo.join(" ")))
                                .clicked();
                        }
                        if fixing {
                            ui.add(egui::Spinner::new());
                            ui.label(RichText::new("Reinstalling…").color(TEXT_DIM));
                        }
                        if !aur.is_empty() {
                            ui.label(RichText::new(format!("{} from outside the official repos (reinstall with your AUR helper): {}", aur.len(), aur.join(", "))).size(12.0).color(AMBER));
                        }
                    });
                    let fs = self.fix_job.state.lock().unwrap();
                    if fs.ever_ran {
                        egui::CollapsingHeader::new(RichText::new(format!("pacman output{}", if fs.summary.is_empty() { String::new() } else { format!(" — {}", fs.summary) })).color(TEXT_DIM))
                            .id_salt("fix_out")
                            .default_open(fixing)
                            .show(ui, |ui| {
                                egui::ScrollArea::vertical().id_salt("fix_scroll").max_height(140.0).stick_to_bottom(true).show(ui, |ui| {
                                    for l in &fs.log {
                                        ui.label(RichText::new(l).monospace().size(11.5).color(Color32::from_gray(180)));
                                    }
                                });
                            });
                    }
                });
                if go {
                    self.reinstall(&ctx, repo);
                }
            }
        }
        if k == JobKind::Rootkit {
            let tools = self.status.lock().unwrap().tools.clone();
            let ext_running = self.ext_job.is_running();
            let mut run_tool: Option<&'static str> = None;
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Extra scanners:").color(TEXT_DIM));
                for (t, ok) in &tools {
                    if *ok {
                        if ui.add_enabled(!ext_running, egui::Button::new(format!("Run {t} (administrator)"))).clicked() {
                            run_tool = Some(t);
                        }
                    } else {
                        pill(ui, &format!("{t}: install it with pacman to use it here"), TEXT_DIM);
                    }
                }
            });
            if let Some(t) = run_tool {
                let args: Vec<String> = match t {
                    "rkhunter" => vec!["--check".into(), "--sk".into(), "--nocolors".into(), "--rwo".into()],
                    _ => vec!["sys".into()],
                };
                let cmd = self.command(true, &format!("/usr/bin/{t}"), &args);
                let c2 = ctx.clone();
                self.ext_job.run_command(move || c2.request_repaint(), cmd, true, rootkit::parse_external, move |code, em| {
                    em.done(format!("{t} finished (code {code})."));
                });
            }
            let es = self.ext_job.state.lock().unwrap();
            if es.running || es.ever_ran {
                egui::CollapsingHeader::new(RichText::new(format!("Extra scanner: {} warnings{}", es.findings.len(), if es.running { " (running…)" } else { "" })).color(TEXT_DIM))
                    .id_salt("ext")
                    .show(ui, |ui| {
                        egui::ScrollArea::vertical().id_salt("ext_s").max_height(140.0).show(ui, |ui| {
                            for f in &es.findings {
                                ui.label(RichText::new(&f.detail).monospace().size(12.0).color(AMBER));
                            }
                            for l in es.log.iter().rev().take(200).rev() {
                                ui.label(RichText::new(l).monospace().size(11.5).color(Color32::from_gray(170)));
                            }
                            if !es.summary.is_empty() {
                                ui.label(RichText::new(&es.summary).color(GREEN));
                            }
                        });
                    });
            }
        }
        if k == JobKind::Virus {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("What to scan:").color(TEXT_DIM));
                for (v, name, tip) in crate::settings::VIRUS_SCOPES {
                    if ui.selectable_label(self.s.virus_scope == v, name).on_hover_text(tip).clicked() {
                        self.s.virus_scope = v;
                        self.settings_dirty = true;
                    }
                }
                ui.separator();
                let drives = self.status.lock().unwrap().drives.clone();
                let tip = if drives.is_empty() {
                    "No drives outside the system are mounted right now.".to_string()
                } else {
                    format!(
                        "Also scan drives that aren't part of the system, after everything else:\n{}\nPick which ones in Settings.",
                        drives.iter().map(|d| format!("• {} — {}{}", d.mount, d.name(), if d.windows_system { "\n   Warning — Windows system partition: scan only; don't delete Windows' own files, and turn off Fast Startup before changing anything" } else { "" })).collect::<Vec<_>>().join("\n")
                    )
                };
                if self.s.virus_scope != 3 && ui.checkbox(&mut self.s.scan_external, format!("External drives ({})", drives.iter().filter(|d| !self.s.external_skip.contains(&d.mount)).count())).on_hover_text(tip).changed() {
                    self.settings_dirty = true;
                }
                if ui
                    .checkbox(&mut self.s.paranoid, "Paranoid")
                    .on_hover_text(PARANOID_TIP)
                    .changed()
                {
                    self.settings_dirty = true;
                }
            });
            ui.horizontal_wrapped(|ui| {
                if let Some(c) = &self.last_custom {
                    ui.label(RichText::new("Chosen in the file manager:").color(TEXT_DIM));
                    for t in c.iter().take(6) {
                        let parts: Vec<&str> = t.rsplitn(3, '/').collect();
                        let short = if parts.len() == 3 { format!("…/{}/{}", parts[1], parts[0]) } else { t.clone() };
                        pill(ui, &short, BLUE);
                    }
                    if c.len() > 6 {
                        pill(ui, &format!("+{} more", c.len() - 6), BLUE);
                    }
                } else {
                    let (n, ran) = self.unverified_count();
                    let scope = self.s.virus_scope;
                    ui.label(RichText::new("Scanning:").color(TEXT_DIM));
                    if scope == 0 || scope == 1 {
                        if ran {
                            pill(ui, &format!("1. {n} unverified system files"), AMBER);
                        } else {
                            pill(ui, "1. unverified system files (run Unowned files and Package files first)", TEXT_DIM);
                        }
                    }
                    if scope == 0 || scope == 2 {
                        for t in &self.s.virus_targets {
                            pill(ui, &if scope == 0 { format!("2. {t}") } else { t.clone() }, BLUE);
                        }
                    }
                    if self.s.scan_external || scope == 3 {
                        let drives = self.status.lock().unwrap().drives.clone();
                        let on: Vec<_> = drives.iter().filter(|d| !self.s.external_skip.contains(&d.mount)).collect();
                        for d in &on {
                            pill(ui, &format!("{}drive {}", if scope == 0 { "3. " } else { "" }, d.name()), Color32::from_rgb(0xa0, 0x8c, 0xe0));
                        }
                        if scope == 3 && on.is_empty() {
                            pill(ui, if drives.is_empty() { "no external drives are mounted" } else { "every external drive is switched off in Settings" }, AMBER);
                        }
                    }
                }
                if !self.pending_scans.is_empty() {
                    pill(ui, &format!("{} more right-click scan(s) waiting", self.pending_scans.len()), AMBER);
                }
                let vt = if self.s.vt_check && !self.s.vt_api_key.is_empty() {
                    ("VirusTotal second opinion: on", GREEN)
                } else if self.s.vt_check {
                    ("VirusTotal: add your key in Settings", AMBER)
                } else {
                    ("VirusTotal: off", TEXT_DIM)
                };
                pill(ui, vt.0, vt.1);
            });
        }
        ui.add_space(6.0);
        {
            let st = job.state.lock().unwrap();
            if running {
                ui.horizontal(|ui| {
                    ui.add(egui::Spinner::new());
                    let el = st.started.map(|s| s.elapsed().as_secs()).unwrap_or(0);
                    let p = if job.is_paused() { format!("Paused — {}", st.progress) } else { st.progress.clone() };
                    ui.add(egui::Label::new(RichText::new(format!("{p}  ({}:{:02})", el / 60, el % 60)).color(Color32::from_gray(210))).truncate());
                });
            } else if !st.summary.is_empty() {
                card(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        let color = if st.count(Sev::High) > 0 { RED } else if st.count(Sev::Medium) > 0 { AMBER } else { GREEN };
                        { let (r, _) = ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover()); ui.painter().circle_filled(r.center(), 5.0, color); }
                        ui.label(RichText::new(&st.summary).color(Color32::WHITE));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(RichText::new(format!("{} · took {:.0}s{}", ago(st.finished_wall), st.elapsed_secs, if st.from_background { " · background run" } else { "" })).color(TEXT_DIM).size(12.0));
                        });
                    });
                });
            } else if !st.ever_ran {
                card(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new("Not run yet. Press Run now, or schedule it under Background jobs.").color(TEXT_DIM));
                });
            }
        }

        if k == JobKind::Virus {
            self.size_question(ui);
        }

        if matches!(k, JobKind::Virus | JobKind::Processes) {
            let failed = self.failed_vt(k).len();
            let retrying = self.vt_retry_job.is_running();
            let rs = self.vt_retry_job.state.lock().unwrap();
            let (progress, summary) = (rs.progress.clone(), rs.summary.clone());
            drop(rs);
            if failed > 0 || retrying || !summary.is_empty() {
                let mut go = false;
                ui.horizontal(|ui| {
                    if retrying {
                        ui.add(egui::Spinner::new());
                        ui.label(RichText::new(progress).color(Color32::from_gray(210)));
                        if ui.button("Stop").clicked() {
                            self.vt_retry_job.stop();
                        }
                    } else {
                        if failed > 0 {
                            ui.label(RichText::new(format!("{failed} VirusTotal check(s) failed (no connection, rate limit or unreadable file).")).color(AMBER));
                            go = ui.add(primary(&format!("Retry {failed} failed"))).on_hover_text("Asks VirusTotal again, 4 a minute; waits and retries by itself when the limit is hit").clicked();
                        }
                        if !summary.is_empty() {
                            ui.label(RichText::new(summary).size(12.0).color(TEXT_DIM));
                        }
                    }
                });
                if go {
                    self.retry_vt(&ctx, k, None);
                }
            }
        }

        // VirusTotal results replace the plain ClamAV list once they exist.
        let show_job = if k == JobKind::Virus && self.vt_job.state.lock().unwrap().ever_ran { self.vt_job.clone() } else { job.clone() };
        if k == JobKind::Virus && self.vt_job.is_running() {
            let p = self.vt_job.state.lock().unwrap().progress.clone();
            ui.horizontal(|ui| {
                ui.add(egui::Spinner::new());
                ui.label(p);
            });
        }
        ui.add_space(6.0);
        self.filter_bar(ui, &show_job);
        if let Some(a) = self.findings_table(ui, &show_job, k) {
            self.do_row_action(&ctx, a);
        }
        let log: Vec<String> = show_job.state.lock().unwrap().log.clone();
        egui::CollapsingHeader::new(RichText::new(format!("Log ({} lines)", log.len())).color(TEXT_DIM)).id_salt(("log", k.id())).show(ui, |ui| {
            egui::ScrollArea::vertical().id_salt(("logs", k.id())).max_height(160.0).stick_to_bottom(true).show(ui, |ui| {
                for l in log.iter().rev().take(400).rev() {
                    ui.label(RichText::new(l).monospace().size(12.0).color(Color32::from_gray(180)));
                }
            });
        });
    }

    /// Ask about files over the size limit (right-click scans only).
    fn size_question(&mut self, ui: &mut Ui) {
        let q = self.size_ask.lock().unwrap().question.clone();
        let Some(q) = q else {
            self.ask_limit = None;
            return;
        };
        let mut answer: Option<Option<u32>> = None;
        let mut limit = self.ask_limit.unwrap_or(q.suggested_mb);
        let has_vt = self.s.vt_check && !self.s.vt_api_key.is_empty();
        let mut vt_huge = self.size_ask.lock().unwrap().vt_for_huge;
        egui::Frame::new()
            .fill(AMBER.linear_multiply(0.14))
            .stroke(egui::Stroke::new(1.0, AMBER))
            .corner_radius(8.0)
            .inner_margin(egui::Margin::same(14))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                let largest = q.files.iter().map(|f| f.1).max().unwrap_or(0) / 1_048_576;
                match q.kind {
                    clam::AskKind::TooBig => {
                        ui.label(RichText::new(format!(
                            "{} file(s) you picked are bigger than the {} MB scan limit (largest {largest} MB).",
                            q.files.len() + q.too_big_for_clamav.len(),
                            self.s.max_file_mb
                        )).strong().color(Color32::WHITE));
                        ui.label(RichText::new("Scan them anyway with a larger limit for this scan only? Your normal limit stays as it is. Big files take longer and need more memory.").color(TEXT_DIM));
                    }
                    clam::AskKind::HitLimit => {
                        ui.label(RichText::new(format!("{} file(s) weren't fully scanned: ClamAV stopped at a size, file-count or depth limit inside them.", q.files.len())).strong().color(Color32::WHITE));
                        ui.label(RichText::new("Rescan just these with higher limits for this scan only?").color(TEXT_DIM));
                    }
                }
                for f in q.files.iter().take(5) {
                    ui.label(RichText::new(format!("{}  ({} MB)", f.0, f.1 / 1_048_576)).monospace().size(12.0).color(Color32::from_gray(210)));
                }
                if q.files.len() > 5 {
                    ui.label(RichText::new(format!("…and {} more", q.files.len() - 5)).size(12.0).color(TEXT_DIM));
                }
                if !q.files.is_empty() {
                    ui.horizontal(|ui| {
                        let (label, max) = match q.kind {
                            clam::AskKind::TooBig => ("Temporary file size limit", clam::CLAM_MAX_MB),
                            clam::AskKind::HitLimit => ("Temporary limit per archive", 4000),
                        };
                        ui.label(label);
                        ui.add(egui::Slider::new(&mut limit, 10..=max).logarithmic(true).suffix(" MB"));
                    });
                }
                if !q.too_big_for_clamav.is_empty() {
                    ui.label(RichText::new(format!(
                        "{} file(s) are 2 GiB or larger, which ClamAV can't scan at any limit.",
                        q.too_big_for_clamav.len()
                    )).color(AMBER));
                    ui.add_enabled(has_vt, egui::Checkbox::new(&mut vt_huge, "Look those up on VirusTotal by fingerprint instead"))
                        .on_disabled_hover_text("Add your VirusTotal key in Settings");
                }
                ui.horizontal(|ui| {
                    let yes = match q.kind {
                        clam::AskKind::TooBig => format!("Scan them with a {limit} MB limit"),
                        clam::AskKind::HitLimit => format!("Rescan them with {limit} MB"),
                    };
                    if !q.files.is_empty() && ui.add(primary(&yes)).clicked() {
                        answer = Some(Some(limit));
                    }
                    let no = if q.kind == clam::AskKind::TooBig { "Skip them" } else { "Leave them" };
                    if ui.button(no).clicked() {
                        answer = Some(None);
                    }
                });
            });
        ui.add_space(6.0);
        self.ask_limit = Some(limit);
        let mut st = self.size_ask.lock().unwrap();
        st.vt_for_huge = vt_huge;
        if let Some(a) = answer {
            st.answer = Some(a);
            st.question = None;
            self.ask_limit = None;
        }
    }

    fn filter_bar(&mut self, ui: &mut Ui, job: &Job) {
        let st = job.state.lock().unwrap();
        let mut saved: Option<Result<PathBuf, String>> = None;
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("Filter by path or text…").desired_width(280.0));
            for (i, sev) in [Sev::High, Sev::Medium, Sev::Low, Sev::Info].iter().enumerate() {
                let n = st.count(*sev);
                let txt = RichText::new(format!("{} {}", sev.label(), n)).color(if self.show_sev[i] { sev_color(*sev) } else { TEXT_DIM });
                if ui.selectable_label(self.show_sev[i], txt).clicked() {
                    self.show_sev[i] = !self.show_sev[i];
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add_enabled(!st.findings.is_empty(), egui::Button::new("Save report")).clicked() {
                    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
                    let path = PathBuf::from(crate::settings::home_dir()).join(format!("arch-sentinel-report-{stamp}.txt"));
                    let mut text = format!("{}\n\n", st.summary);
                    for f in &st.findings {
                        text.push_str(&format!("[{}] {} — {} — {}\n", f.sev.label(), f.kind, f.path, f.detail));
                    }
                    saved = Some(std::fs::write(&path, text).map(|_| path).map_err(|e| e.to_string()));
                }
            });
        });
        drop(st);
        match saved {
            Some(Ok(p)) => self.toast(format!("Report saved to {}", p.display()), true),
            Some(Err(e)) => self.toast(format!("Couldn't save the report: {e}"), false),
            None => {}
        }
    }

    fn findings_table(&mut self, ui: &mut Ui, job: &Job, k: JobKind) -> Option<RowAction> {
        let st = job.state.lock().unwrap();
        let f = self.filter.to_lowercase();
        let mut rows: Vec<&Finding> = st
            .findings
            .iter()
            .filter(|x| {
                let i = match x.sev {
                    Sev::High => 0,
                    Sev::Medium => 1,
                    Sev::Low => 2,
                    Sev::Info => 3,
                };
                self.show_sev[i]
            })
            .filter(|x| f.is_empty() || x.path.to_lowercase().contains(&f) || x.detail.to_lowercase().contains(&f) || x.kind.to_lowercase().contains(&f))
            .collect();
        rows.sort_by(|a, b| a.sev.cmp(&b.sev).then(a.path.cmp(&b.path)));
        let mut action = None;
        let row_h = 26.0;
        let avail = ui.available_height() - 40.0;
        egui::Frame::new().fill(PANEL).corner_radius(6.0).inner_margin(egui::Margin::same(6)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.add_sized([70.0, 18.0], egui::Label::new(RichText::new("Level").size(12.0).color(TEXT_DIM)));
                ui.add_sized([150.0, 18.0], egui::Label::new(RichText::new(kind_header(k)).size(12.0).color(TEXT_DIM)));
                ui.label(RichText::new("Path · details").size(12.0).color(TEXT_DIM));
            });
            ui.separator();
            if rows.is_empty() {
                ui.add_space(20.0);
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new(if st.findings.is_empty() { "Nothing to show yet." } else { "No findings match the filter." }).color(TEXT_DIM));
                });
                ui.add_space(20.0);
                return;
            }
            egui::ScrollArea::vertical()
                .id_salt(("rows", k.id()))
                .max_height(avail.max(120.0))
                .auto_shrink([false, true])
                .show_rows(ui, row_h, rows.len(), |ui, range| {
                    for r in &rows[range] {
                        ui.horizontal(|ui| {
                            ui.set_height(row_h - 4.0);
                            ui.add_sized([70.0, 18.0], egui::Label::new(RichText::new(r.sev.label()).color(sev_color(r.sev)).strong().size(12.5)));
                            ui.add_sized([150.0, 18.0], egui::Label::new(RichText::new(&r.kind).size(12.5).color(Color32::from_gray(210))).truncate());
                            let is_file = r.path.starts_with('/');
                            let w = (ui.available_width() - 130.0).max(100.0);
                            ui.allocate_ui(egui::vec2(w, 20.0), |ui| {
                                ui.horizontal(|ui| {
                                    ui.add(egui::Label::new(RichText::new(&r.path).monospace().size(12.5).color(Color32::WHITE)).truncate());
                                    ui.add(egui::Label::new(RichText::new(&r.detail).size(12.0).color(TEXT_DIM)).truncate());
                                });
                            })
                            .response
                            .on_hover_text(format!("{}\n{}", r.path, r.detail));
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.menu_button("More", |ui| {
                                    if ui.button("Copy path").clicked() {
                                        action = Some(RowAction::Copy(r.path.clone()));
                                        ui.close();
                                    }
                                    if is_file && ui.button("Open its folder").clicked() {
                                        action = Some(RowAction::Open(r.path.clone()));
                                        ui.close();
                                    }
                                    if matches!(k, JobKind::Unowned | JobKind::HomeCheck) && is_file && ui.button("Ignore this path from now on").clicked() {
                                        action = Some(RowAction::Ignore(r.path.clone()));
                                        ui.close();
                                    }
                                    if clam::vt_failed(r) && ui.button("Retry VirusTotal").clicked() {
                                        action = Some(RowAction::RetryVt(r.path.clone()));
                                        ui.close();
                                    }
                                    if is_file && (r.detail.contains("VirusTotal") || matches!(k, JobKind::Virus | JobKind::Processes)) && ui.button("VirusTotal report").clicked() {
                                        let sha = r.detail.split("sha256 ").nth(1).map(|x| x.trim().trim_end_matches('…').to_string()).filter(|x| x.len() == 64);
                                        action = Some(RowAction::VtReport(r.path.clone(), sha));
                                        ui.close();
                                    }
                                    if k == JobKind::Integrity && !r.kind.contains(' ') && r.sev != Sev::Info && ui.button(format!("Reinstall package {}", r.kind)).clicked() {
                                        action = Some(RowAction::Reinstall(r.kind.clone()));
                                        ui.close();
                                    }
                                    if matches!(k, JobKind::Virus | JobKind::Unowned | JobKind::HomeCheck | JobKind::Processes) && is_file && std::path::Path::new(&r.path).is_file() {
                                        if ui.button(RichText::new("Zero-fill and delete…").color(RED)).clicked() {
                                            action = Some(RowAction::Shred(r.path.clone(), r.kind.clone()));
                                            ui.close();
                                        }
                                    }
                                    if matches!(k, JobKind::Virus | JobKind::Unowned | JobKind::HomeCheck | JobKind::Processes) && is_file && std::path::Path::new(&r.path).is_file() && ui.button("Test in the sandbox…").clicked() {
                                        action = Some(RowAction::Sandbox(r.path.clone()));
                                        ui.close();
                                    }
                                    if k == JobKind::Virus && is_file {
                                        if ui.button("Move to quarantine").clicked() {
                                            action = Some(RowAction::Quarantine(r.path.clone(), r.kind.clone()));
                                            ui.close();
                                        }
                                        if ui.button("Skip this folder in future scans").clicked() {
                                            action = Some(RowAction::Exclude(r.path.clone()));
                                            ui.close();
                                        }
                                    }
                                });
                                if k == JobKind::Virus && is_file && std::path::Path::new(&r.path).exists() && ui.small_button("Quarantine").clicked() {
                                    action = Some(RowAction::Quarantine(r.path.clone(), r.kind.clone()));
                                }
                            });
                        });
                    }
                });
        });
        action
    }

    pub fn ask_shred(&mut self, path: String, threat: String, entry: Option<quarantine::Entry>) {
        let package = match &entry {
            Some(e) => e.package.clone(),
            None => quarantine::owning_package(&path),
        };
        let fs = quarantine::fs_type(&path);
        self.shred_sure = false;
        self.shred_ask = Some(ShredAsk { path, threat, entry, package, fs });
    }

    /// The "are you sure" window for zero-fill and delete.
    fn shred_dialog(&mut self, ctx: &egui::Context) {
        let Some(a) = self.shred_ask.clone() else { return };
        let mut close = false;
        let mut go = false;
        let mut reinstall: Option<String> = None;
        let mut list_ts = false;
        egui::Window::new(RichText::new("Zero-fill and delete").color(RED).strong())
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .default_width(560.0)
            .show(ctx, |ui| {
                ui.label(RichText::new(if a.entry.is_some() { format!("Quarantined copy of {}", a.path) } else { a.path.clone() }).monospace().color(Color32::WHITE));
                if !a.threat.is_empty() {
                    ui.label(RichText::new(format!("Flagged as: {}", a.threat)).color(AMBER));
                }
                ui.add_space(6.0);
                ui.label(RichText::new("This overwrites the whole file with zeros, flushes it to the disk and deletes it. It can't be undone or put back, and nothing is kept in quarantine. Only do this if you're sure the file is malicious — if in doubt, quarantine it and get a VirusTotal second opinion first.").color(Color32::WHITE));
                ui.add_space(4.0);
                ui.label(RichText::new(format!("{} ({})", quarantine::fs_caveat(&a.fs), if a.fs.is_empty() { "unknown filesystem" } else { &a.fs })).size(12.0).color(TEXT_DIM));
                if crate::drives::is_windows_fs(&a.fs) {
                    ui.add_space(4.0);
                    let sys = crate::drives::in_windows_system_folder(&a.path);
                    ui.label(RichText::new(if sys {
                        "This file is inside Windows' own folders on a Windows partition. Deleting it can stop Windows from starting — the safest cure is Windows Defender from inside Windows."
                    } else {
                        "This file is on a Windows partition."
                    }).strong().color(RED));
                    ui.label(RichText::new(crate::drives::WARN_HIBERNATE).size(12.0).color(AMBER));
                } else if crate::drives::is_windows_program(&a.path) && a.entry.is_none() {
                    ui.add_space(4.0);
                    ui.label(RichText::new("This is a Windows program: it can't run on Linux by itself, only through Wine or on a Windows PC. If it sits inside a Wine prefix, deleting it may break that Windows app.").size(12.0).color(AMBER));
                }
                if let Some(p) = &a.package {
                    ui.add_space(4.0);
                    ui.label(RichText::new(format!("This file belongs to the package {p}. Deleting it will break that package; reinstalling the package puts back a clean, signed copy instead.")).color(AMBER));
                    if ui.button(format!("Reinstall {p} instead")).clicked() {
                        reinstall = Some(p.clone());
                    }
                }
                let timeshift = std::path::Path::new("/usr/bin/timeshift").exists() && a.fs == "btrfs";
                if timeshift {
                    ui.add_space(4.0);
                    ui.label(RichText::new(
                        "Timeshift is installed: its snapshots keep their own copy of system files (and of your home folder if your snapshots include @home). To remove every copy, delete the snapshots taken since this file appeared — once you're sure the system is clean. If you ever restore an older snapshot, scan again afterwards."
                    ).size(12.0).color(AMBER));
                    ui.horizontal(|ui| {
                        if ui.button("List Timeshift snapshots").on_hover_text("Runs timeshift --list (asks for your password)").clicked() {
                            list_ts = true;
                        }
                        if ui.button("Open Timeshift").clicked() {
                            let _ = Command::new("/usr/bin/timeshift-launcher").spawn();
                        }
                    });
                    if let Some(t) = self.shared.lock().unwrap().timeshift_list.clone() {
                        egui::ScrollArea::vertical().id_salt("ts_list").max_height(140.0).show(ui, |ui| {
                            ui.label(RichText::new(t).monospace().size(11.0).color(Color32::from_gray(190)));
                        });
                    }
                }
                ui.add_space(6.0);
                ui.checkbox(&mut self.shred_sure, "I'm sure this file is malicious and I want it gone for good");
                ui.horizontal(|ui| {
                    let btn = egui::Button::new(RichText::new("Zero-fill and delete").color(Color32::WHITE)).fill(RED.linear_multiply(0.8));
                    if ui.add_enabled(self.shred_sure, btn).clicked() {
                        go = true;
                    }
                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                });
            });
        if list_ts {
            self.task(ctx, "Reading Timeshift snapshots…", |sh| {
                let o = crate::root::output({ let mut pk = Command::new("pkexec"); pk.args(["/usr/bin/timeshift", "--list"]); pk }).map_err(|e| e.to_string())?;
                let text = String::from_utf8_lossy(&o.stdout).to_string();
                if !o.status.success() && text.trim().is_empty() {
                    return Err(format!("Couldn't list snapshots: {}", String::from_utf8_lossy(&o.stderr).trim()));
                }
                sh.lock().unwrap().timeshift_list = Some(text.trim().to_string());
                Ok("Timeshift snapshots listed in the delete window.".into())
            });
        }
        if let Some(p) = reinstall {
            self.shred_ask = None;
            self.reinstall(ctx, vec![p]);
            return;
        }
        if go {
            self.shred_ask = None;
            let path = a.path.clone();
            let entry = a.entry.clone();
            let jobs: Vec<Job> = [JobKind::Virus, JobKind::Unowned, JobKind::HomeCheck, JobKind::Processes].iter().map(|k| self.jobs[k].clone()).chain([self.vt_job.clone()]).collect();
            self.task(ctx, "Zero-filling and deleting…", move |sh| {
                let r = match &entry {
                    Some(e) => quarantine::shred_entry(e),
                    None => quarantine::shred_file(&path),
                };
                if r.is_ok() {
                    for j in &jobs {
                        for f in j.state.lock().unwrap().findings.iter_mut().filter(|f| f.path == path) {
                            f.sev = Sev::Info;
                            f.detail = format!("Zero-filled and deleted · {}", f.detail);
                        }
                    }
                }
                sh.lock().unwrap().quarantine = quarantine::list();
                r
            });
        } else if close {
            self.shred_ask = None;
        }
    }

    /// Packages that came from outside the official repositories (AUR and such).
    fn foreign(&mut self) -> std::collections::HashSet<String> {
        if self.foreign_pkgs.is_none() {
            let out = Command::new("pacman").arg("-Qmq").output().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
            self.foreign_pkgs = Some(out.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect());
        }
        self.foreign_pkgs.clone().unwrap_or_default()
    }

    /// Packages the last package check found problems in: (from the repos, from elsewhere).
    pub fn failed_packages(&mut self) -> (Vec<String>, Vec<String>) {
        let mut pkgs: Vec<String> = self.jobs[&JobKind::Integrity]
            .state
            .lock()
            .unwrap()
            .findings
            .iter()
            .filter(|f| f.sev != Sev::Info && !f.kind.contains(' ') && f.path.starts_with('/'))
            .map(|f| f.kind.clone())
            .collect();
        pkgs.sort();
        pkgs.dedup();
        let foreign = self.foreign();
        pkgs.into_iter().partition(|p| !foreign.contains(p))
    }

    /// Reinstall packages with pacman (signed packages, so a clean copy).
    pub fn reinstall(&mut self, ctx: &egui::Context, pkgs: Vec<String>) {
        if self.fix_job.is_running() {
            self.toast("Already reinstalling packages — wait for it to finish.", false);
            return;
        }
        let foreign = self.foreign();
        let (repo, aur): (Vec<String>, Vec<String>) = pkgs.into_iter().partition(|p| !foreign.contains(p));
        if repo.is_empty() {
            self.toast(format!("{} come(s) from outside the official repositories — reinstall with your AUR helper.", aur.join(", ")), false);
            return;
        }
        let mut args = vec!["-S".to_string(), "--noconfirm".to_string()];
        args.extend(repo.iter().cloned());
        let cmd = crate::par::command(&self.s, true, "/usr/bin/pacman", &args);
        let c2 = ctx.clone();
        let recheck = self.recheck_after_fix.clone();
        let n = repo.len();
        self.page = Page::Job(JobKind::Integrity);
        self.fix_job.run_command(
            move || c2.request_repaint(),
            cmd,
            true,
            |l| vec![crate::jobs::Msg::Log(l.to_string()), crate::jobs::Msg::Progress(l.to_string())],
            move |code, em| {
                em.done(match code {
                    0 => {
                        recheck.store(true, Ordering::Relaxed);
                        format!("Reinstalled {n} package(s). Checking them again…")
                    }
                    126 | 127 => "Administrator rights were refused.".to_string(),
                    c => format!("pacman stopped with code {c} — see its output (is another pacman running?)."),
                });
            },
        );
        if !aur.is_empty() {
            self.toast(format!("Skipped {} from outside the official repositories: {}", aur.len(), aur.join(", ")), false);
        }
    }

    /// Open the VirusTotal report for a file: from the saved copy when there is
    /// one (no lookup used), otherwise by asking VirusTotal.
    pub fn open_vt(&mut self, ctx: &egui::Context, path: String, sha: Option<String>, refresh: bool) {
        let sha = match sha.or_else(|| clam::sha256_file(&path).ok()) {
            Some(s) => s,
            None => {
                self.toast(format!("Couldn't read {path} to fingerprint it."), false);
                return;
            }
        };
        let cached = if refresh { None } else { crate::vt::cached(&sha) };
        let have = cached.is_some();
        *self.vt_window.lock().unwrap() = Some(VtWindow { path, sha256: sha.clone(), report: cached, loading: !have, ..Default::default() });
        if have {
            return;
        }
        if self.s.vt_api_key.trim().is_empty() {
            if let Some(w) = self.vt_window.lock().unwrap().as_mut() {
                w.loading = false;
                w.error = Some("Add your VirusTotal key in Settings to look files up.".into());
            }
            return;
        }
        let key = self.s.vt_api_key.clone();
        let slot = self.vt_window.clone();
        let c2 = ctx.clone();
        std::thread::spawn(move || {
            let r = crate::vt::fetch(&key, &sha);
            if let Some(w) = slot.lock().unwrap().as_mut() {
                if w.sha256 == sha {
                    w.loading = false;
                    match r {
                        Ok(Some(rep)) => w.report = Some(rep),
                        Ok(None) => w.unknown = true,
                        Err(e) => w.error = Some(e),
                    }
                }
            }
            c2.request_repaint();
        });
    }

    fn vt_dialog(&mut self, ctx: &egui::Context) {
        let Some(w) = self.vt_window.lock().unwrap().clone() else { return };
        let mut open = true;
        let mut refresh = false;
        egui::Window::new(RichText::new("VirusTotal report").strong().color(Color32::WHITE))
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .default_size([760.0, 600.0])
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(RichText::new(&w.path).monospace().color(Color32::WHITE));
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("sha256 {}", w.sha256)).monospace().size(11.0).color(TEXT_DIM));
                    if ui.small_button("Copy").clicked() {
                        ui.ctx().copy_text(w.sha256.clone());
                    }
                });
                ui.add_space(6.0);
                if w.loading {
                    ui.horizontal(|ui| {
                        ui.add(egui::Spinner::new());
                        ui.label("Asking VirusTotal (only the fingerprint is sent)…");
                    });
                    return;
                }
                if let Some(e) = &w.error {
                    ui.label(RichText::new(e).color(RED));
                    return;
                }
                if w.unknown {
                    ui.label(RichText::new("VirusTotal has never seen this file.").strong().color(AMBER));
                    ui.label(RichText::new("That's neither good nor bad: most files people make or download privately were never uploaded. It means there's no second opinion — rely on the ClamAV result, the Paranoid check and the sandbox. You could upload the file on virustotal.com yourself, but anyone can then download it, so never upload anything private.").color(Color32::from_gray(220)));
                    return;
                }
                let Some(r) = &w.report else { return };
                let (level, sev, headline, why) = crate::vt::assess(r);
                let color = match level {
                    crate::vt::Level::Malicious => RED,
                    crate::vt::Level::Suspicious => AMBER,
                    _ => GREEN,
                };
                let _ = sev;
                egui::Frame::new().fill(color.linear_multiply(0.15)).corner_radius(8.0).inner_margin(egui::Margin::same(12)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new(level.word()).size(20.0).strong().color(color));
                    ui.label(RichText::new(headline.split_once(" - ").map(|x| x.1).unwrap_or(&headline)).color(Color32::WHITE));
                });
                ui.add_space(6.0);
                // A bar: malicious / suspicious / harmless+undetected.
                let total = r.total().max(1) as f32;
                let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 12.0), egui::Sense::hover());
                let p = ui.painter();
                p.rect_filled(rect, 4.0, Color32::from_gray(60));
                let mw = rect.width() * r.malicious as f32 / total;
                let sw = rect.width() * r.suspicious as f32 / total;
                p.rect_filled(egui::Rect::from_min_size(rect.min, egui::vec2(mw, rect.height())), 4.0, RED);
                p.rect_filled(egui::Rect::from_min_size(rect.min + egui::vec2(mw, 0.0), egui::vec2(sw, rect.height())), 0.0, AMBER);
                ui.label(RichText::new(format!(
                    "{} malicious · {} suspicious · {} harmless · {} found nothing{}",
                    r.malicious,
                    r.suspicious,
                    r.harmless,
                    r.undetected,
                    if r.unsupported > 0 { format!(" · {} couldn't read this file type", r.unsupported) } else { String::new() }
                )).size(12.0).color(TEXT_DIM));
                ui.add_space(6.0);
                egui::ScrollArea::vertical().max_height(420.0).show(ui, |ui| {
                    ui.label(RichText::new("What this means").strong().color(Color32::WHITE));
                    for b in &why {
                        ui.label(RichText::new(format!("• {b}")).color(Color32::from_gray(225)));
                    }
                    ui.add_space(6.0);
                    if !r.flagged.is_empty() {
                        ui.label(RichText::new(format!("Engines that flag it ({})", r.flagged.len())).strong().color(Color32::WHITE));
                        egui::Grid::new("vt_engines").num_columns(3).spacing([14.0, 3.0]).striped(true).show(ui, |ui| {
                            for e in &r.flagged {
                                ui.label(RichText::new(&e.name).color(if e.major { Color32::WHITE } else { Color32::from_gray(190) }).strong());
                                ui.label(RichText::new(&e.result).monospace().size(12.0).color(if e.category == "malicious" { RED } else { AMBER }));
                                ui.label(RichText::new(if e.generic { "generic guess" } else { "named threat" }).size(11.5).color(TEXT_DIM));
                                ui.end_row();
                            }
                        });
                        ui.label(RichText::new("Bold white names are large, long-established vendors. \"Generic guess\" names describe how a file looks (packed, unusual, machine-learning score), not a known virus.").size(11.5).color(TEXT_DIM));
                        ui.add_space(6.0);
                    }
                    if !r.label.is_empty() || !r.families.is_empty() || !r.categories.is_empty() || !r.vt_names.is_empty() {
                        ui.label(RichText::new("Threat names").strong().color(Color32::WHITE));
                        if !r.label.is_empty() {
                            ui.label(format!("VirusTotal's summary label: {}", r.label));
                        }
                        if !r.categories.is_empty() {
                            ui.label(format!("Kind: {}", r.categories.iter().map(|c| format!("{} ({})", c.0, c.1)).collect::<Vec<_>>().join(", ")));
                        }
                        if !r.families.is_empty() {
                            ui.label(format!("Family names independent engines agree on: {}", r.families.iter().map(|c| format!("{} ({} engines)", c.0, c.1)).collect::<Vec<_>>().join(", ")));
                        }
                        if !r.vt_names.is_empty() {
                            ui.label(format!("Names VirusTotal collected: {}", r.vt_names.iter().map(|c| format!("{} ({})", c.0, c.1)).collect::<Vec<_>>().join(", ")));
                        }
                        ui.add_space(6.0);
                    }
                    ui.label(RichText::new("About the file").strong().color(Color32::WHITE));
                    egui::Grid::new("vt_facts").num_columns(2).spacing([14.0, 3.0]).show(ui, |ui| {
                        let mut row = |k: &str, v: String| {
                            if !v.is_empty() {
                                ui.label(RichText::new(k).color(TEXT_DIM));
                                ui.label(v);
                                ui.end_row();
                            }
                        };
                        row("Type", r.type_desc.clone());
                        row("Size", if r.size > 0 { format!("{} KB", r.size / 1024) } else { String::new() });
                        row("Known names", r.names.join(", "));
                        row("First seen", if r.first_seen > 0 { crate::vt::ymd(r.first_seen) } else { String::new() });
                        row("Last analysed", if r.last_analysis > 0 { crate::vt::ymd(r.last_analysis) } else { String::new() });
                        row("Times submitted", if r.times_submitted > 0 { r.times_submitted.to_string() } else { String::new() });
                        row("Signed by", if r.signer.is_empty() { String::new() } else { format!("{} ({})", r.signer, r.sig_verified) });
                        row("Product", r.product.clone());
                        row("Community votes", if r.votes_harmless + r.votes_malicious > 0 { format!("{} harmless / {} malicious (reputation {})", r.votes_harmless, r.votes_malicious, r.reputation) } else { String::new() });
                        row("Tags", r.tags.join(", "));
                        row("Detection rules", r.yara.join(", "));
                        row(
                            "Sandboxes",
                            r.sandboxes.iter().map(|s| format!("{}: {}{}", s.0, s.1, if s.2.is_empty() { String::new() } else { format!(" ({})", s.2) })).collect::<Vec<_>>().join("; "),
                        );
                        row("Report fetched", if r.fetched > 0 { crate::vt::ymd(r.fetched) } else { String::new() });
                    });
                });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Open on virustotal.com").clicked() {
                        let _ = Command::new("xdg-open").arg(r.url()).spawn();
                    }
                    if ui.button("Look up again").on_hover_text("Uses one of your lookups (4 a minute on the free key)").clicked() {
                        refresh = true;
                    }
                });
            });
        if !open {
            *self.vt_window.lock().unwrap() = None;
        } else if refresh {
            self.open_vt(ctx, w.path.clone(), Some(w.sha256.clone()), true);
        }
    }

    /// The job whose list shows VirusTotal results for a check page.
    fn vt_target(&self, k: JobKind) -> Job {
        if k == JobKind::Virus && self.vt_job.state.lock().unwrap().ever_ran {
            self.vt_job.clone()
        } else {
            self.jobs[&k].clone()
        }
    }

    /// Findings on a page whose VirusTotal check failed.
    pub fn failed_vt(&self, k: JobKind) -> Vec<Finding> {
        self.vt_target(k).state.lock().unwrap().findings.iter().filter(|f| clam::vt_failed(f)).cloned().collect()
    }

    /// Run the failed VirusTotal checks again (all of them, or only `only`), and put
    /// the new answers in place of the failures.
    pub fn retry_vt(&mut self, ctx: &egui::Context, k: JobKind, only: Option<String>) {
        if self.vt_retry_job.is_running() || self.vt_job.is_running() {
            self.toast("VirusTotal checks are already running — wait for them to finish.", false);
            return;
        }
        if self.s.vt_api_key.trim().is_empty() {
            self.toast("Add your VirusTotal key in Settings first.", false);
            return;
        }
        let target = self.vt_target(k);
        let failed: Vec<Finding> = self.failed_vt(k).into_iter().filter(|f| only.as_ref().map(|p| &f.path == p).unwrap_or(true)).collect();
        if failed.is_empty() {
            self.toast("No failed VirusTotal checks to retry.", true);
            return;
        }
        let items: Vec<(Finding, Option<String>)> = failed.iter().map(|f| (f.clone(), clam::sha_in(&f.detail))).collect();
        let key = self.s.vt_api_key.clone();
        let c2 = ctx.clone();
        let n = items.len();
        self.vt_retry_job.run_thread(move || c2.request_repaint(), move |em| {
            clam::verify_list(&key, &items, em);
            let answers = em.findings();
            let mut st = target.state.lock().unwrap();
            let mut fixed = 0;
            for a in answers {
                if let Some(old) = st.findings.iter_mut().find(|x| x.path == a.path && clam::vt_failed(x)) {
                    if !clam::vt_failed(&a) {
                        fixed += 1;
                    }
                    old.sev = a.sev;
                    old.detail = a.detail.clone();
                }
            }
            drop(st);
            em.done(format!("Retried {n} VirusTotal check(s): {fixed} answered{}.", if fixed < n { format!(", {} still failing", n - fixed) } else { String::new() }));
        });
    }

    fn do_row_action(&mut self, ctx: &egui::Context, a: RowAction) {
        match a {
            RowAction::Copy(p) => {
                ctx.copy_text(p);
                self.toast("Path copied.", true);
            }
            RowAction::Open(p) => {
                let dir = std::path::Path::new(&p).parent().map(|d| d.display().to_string()).unwrap_or(p);
                let _ = Command::new("xdg-open").arg(dir).spawn();
            }
            RowAction::Ignore(p) => {
                if !self.s.ignore_patterns.contains(&p) {
                    self.s.ignore_patterns.push(p.clone());
                    self.settings_dirty = true;
                }
                for k in [JobKind::Unowned, JobKind::HomeCheck] {
                    self.jobs[&k].state.lock().unwrap().findings.retain(|f| f.path != p);
                }
                self.toast(format!("{p} will be ignored (Settings → Ignore patterns)."), true);
            }
            RowAction::Exclude(p) => {
                let dir = std::path::Path::new(&p).parent().map(|d| d.display().to_string()).unwrap_or(p);
                if !self.s.virus_excluded.contains(&dir) {
                    self.s.virus_excluded.push(dir.clone());
                    self.settings_dirty = true;
                }
                self.toast(format!("Future virus scans skip {dir}."), true);
            }
            RowAction::Shred(p, threat) => {
                self.ask_shred(p, threat, None);
            }
            RowAction::Reinstall(pkg) => {
                self.reinstall(ctx, vec![pkg]);
            }
            RowAction::VtReport(p, sha) => {
                self.open_vt(ctx, p, sha, false);
            }
            RowAction::RetryVt(p) => {
                let k = if let Page::Job(k) = self.page { k } else { JobKind::Virus };
                self.retry_vt(ctx, k, Some(p));
            }
            RowAction::Sandbox(p) => {
                self.sbx_sample = p;
                self.sbx_sure = false;
                self.page = Page::Sandbox;
            }
            RowAction::Quarantine(p, threat) if crate::drives::in_windows_system_folder(&p) && crate::drives::on_windows_fs(&p) && self.confirm_win_quarantine.as_deref() != Some(p.as_str()) => {
                let _ = threat;
                self.confirm_win_quarantine = Some(p.clone());
                self.toast(format!("{p} is inside Windows' own folders: moving it can stop Windows from starting. The safest cure is Windows Defender from inside Windows. Click Quarantine again to move it anyway."), false);
            }
            RowAction::Quarantine(p, threat) => {
                self.confirm_win_quarantine = None;
                let path = p.clone();
                let vjob = self.vt_job.clone();
                let job = self.job(JobKind::Virus).clone();
                self.task(ctx, &format!("Moving {p} to quarantine…"), move |sh| {
                    let r = quarantine::quarantine(&path, &threat);
                    sh.lock().unwrap().quarantine = quarantine::list();
                    r.map(|_| {
                        for j in [&vjob, &job] {
                            for f in j.state.lock().unwrap().findings.iter_mut().filter(|f| f.path == path) {
                                f.detail = format!("In quarantine · {}", f.detail);
                                f.sev = Sev::Info;
                            }
                        }
                        format!("{path} is in quarantine.")
                    })
                });
            }
        }
    }
}

pub const PARANOID_TIP: &str = "After ClamAV, also look inside every program file (Linux and Windows) at the spots viruses usually hide: where the program starts running, memory that is both writable and runnable, packed or encrypted code, data glued on at the end, odd loaders and library paths, code-injection and reverse-shell patterns, and text used by miners and backdoors. Signs add up to a score; only files that score high are listed, and serious ones go to VirusTotal too. It's a guess, not proof.";

fn kind_header(k: JobKind) -> &'static str {
    match k {
        JobKind::Integrity => "Package",
        JobKind::Virus => "Threat",
        _ => "Kind",
    }
}

fn job_blurb(k: JobKind) -> &'static str {
    match k {
        JobKind::Integrity => "Installed files checked against package checksums (paccheck).",
        JobKind::Unowned => "System files that no package put there.",
        JobKind::HomeCheck => "Programs, autostart entries and odd permissions in your home.",
        JobKind::Virus => "ClamAV scan with a VirusTotal second opinion.",
        JobKind::Rootkit => "Hidden processes and modules, preload tricks, rootkit files.",
        JobKind::Processes => "Every running program and library: from a package? unchanged? virus-free?",
        JobKind::Signatures => "freshclam on a timer.",
    }
}

fn job_help(k: JobKind) -> &'static str {
    match k {
        JobKind::Integrity => "Every file each installed package put on the system is compared with the package's recorded SHA-256 checksum, size and permissions. Changed programs in /usr/bin or /usr/lib are the serious ones; edited settings in /etc are usually you.",
        JobKind::Unowned => "Walks the system folders and lists everything the package database doesn't know about. Programs and setuid files no package installed deserve a look; generated caches are ignored by the patterns in Settings.",
        JobKind::HomeCheck => "Nothing in your home comes from a package, so this looks for what attackers leave there: program files in hidden or cache folders, things that start automatically, suspicious shell start-up lines and setuid files.",
        JobKind::Virus => "Scans with ClamAV. Anything it flags is fingerprinted and looked up on VirusTotal so you can tell a real threat from a false positive, then you can quarantine it.",
        JobKind::Rootkit => "Built-in checks: processes hidden from the process list, kernel modules hidden from the module list, /etc/ld.so.preload, files hiding in /dev, programs running from temp folders or deleted files, setuid files no package installed, root-level accounts, and the core system tools verified against their packages.",
        JobKind::Processes => "Optional deeper look at what's running right now. Each running program and the libraries it has loaded are matched to the package that installed them and checked against that package's checksums; programs running from temp folders or deleted files are flagged, and ClamAV can scan the files themselves (choose how much in Settings).",
        JobKind::Signatures => "",
    }
}
