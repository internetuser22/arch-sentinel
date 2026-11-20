//! Background jobs: every scan runs on its own thread (or as a helper process,
//! possibly elevated with pkexec) and streams messages into a shared state the
//! UI reads each frame.

use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub enum Sev {
    High,
    Medium,
    Low,
    Info,
}

impl Sev {
    pub fn label(self) -> &'static str {
        match self {
            Sev::High => "High",
            Sev::Medium => "Medium",
            Sev::Low => "Low",
            Sev::Info => "Info",
        }
    }
    pub fn code(self) -> &'static str {
        match self {
            Sev::High => "H",
            Sev::Medium => "M",
            Sev::Low => "L",
            Sev::Info => "I",
        }
    }
    pub fn from_code(s: &str) -> Sev {
        match s {
            "H" => Sev::High,
            "M" => Sev::Medium,
            "L" => Sev::Low,
            _ => Sev::Info,
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    pub sev: Sev,
    pub kind: String,
    pub path: String,
    pub detail: String,
}

/// Messages a scanner emits. The same messages travel over a helper
/// process's stdout as tab-separated lines (see `encode`/`decode`).
#[derive(Clone, Debug)]
pub enum Msg {
    Progress(String),
    Log(String),
    Find(Finding),
    Done(String),
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\t', "\\t").replace('\n', "\\n")
}
fn unesc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('t') => out.push('\t'),
                Some('n') => out.push('\n'),
                Some(o) => out.push(o),
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out
}

pub fn encode(m: &Msg) -> String {
    match m {
        Msg::Progress(s) => format!("@P\t{}", esc(s)),
        Msg::Log(s) => format!("@L\t{}", esc(s)),
        Msg::Done(s) => format!("@D\t{}", esc(s)),
        Msg::Find(f) => format!(
            "@F\t{}\t{}\t{}\t{}",
            f.sev.code(),
            esc(&f.kind),
            esc(&f.path),
            esc(&f.detail)
        ),
    }
}

pub fn decode(line: &str) -> Option<Msg> {
    let mut parts = line.split('\t');
    let tag = parts.next()?;
    match tag {
        "@P" => Some(Msg::Progress(unesc(parts.next().unwrap_or("")))),
        "@L" => Some(Msg::Log(unesc(parts.next().unwrap_or("")))),
        "@D" => Some(Msg::Done(unesc(parts.next().unwrap_or("")))),
        "@F" => {
            let sev = Sev::from_code(parts.next()?);
            let kind = unesc(parts.next().unwrap_or(""));
            let path = unesc(parts.next().unwrap_or(""));
            let detail = unesc(parts.next().unwrap_or(""));
            Some(Msg::Find(Finding { sev, kind, path, detail }))
        }
        _ => None,
    }
}

#[derive(Default)]
pub struct JobState {
    pub running: bool,
    pub started: Option<Instant>,
    pub started_wall: Option<SystemTime>,
    pub finished_wall: Option<SystemTime>,
    pub elapsed_secs: f32,
    pub progress: String,
    pub log: Vec<String>,
    pub findings: Vec<Finding>,
    pub summary: String,
    pub ever_ran: bool,
    pub elevated: bool,
    pub from_background: bool,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Report {
    pub job: String,
    pub finished_unix: u64,
    pub seconds: f32,
    pub summary: String,
    pub findings: Vec<Finding>,
    pub log: Vec<String>,
}

impl JobState {
    pub fn count(&self, sev: Sev) -> usize {
        self.findings.iter().filter(|f| f.sev == sev).count()
    }
}

#[derive(Clone)]
pub struct Job {
    pub state: Arc<Mutex<JobState>>,
    pub cancel: Arc<AtomicBool>,
    pub pause: Arc<AtomicBool>,
    pub child: Arc<Mutex<Option<crate::root::Sig>>>,
}

impl Default for Job {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(JobState::default())),
            cancel: Arc::new(AtomicBool::new(false)),
            pause: Arc::new(AtomicBool::new(false)),
            child: Arc::new(Mutex::new(None)),
        }
    }
}

/// Handed to a scanner so it can report what it sees.
pub struct Emitter {
    state: Arc<Mutex<JobState>>,
    cancel: Arc<AtomicBool>,
    pause: Arc<AtomicBool>,
    repaint: Box<dyn Fn() + Send>,
    last_repaint: Instant,
    echo: bool,
}

impl Emitter {
    /// An emitter for helper mode: every message goes to stdout for the parent.
    pub fn printer() -> Emitter {
        Emitter {
            state: Arc::new(Mutex::new(JobState::default())),
            cancel: Arc::new(AtomicBool::new(false)),
            pause: Arc::new(AtomicBool::new(false)),
            repaint: Box::new(|| {}),
            last_repaint: Instant::now(),
            echo: true,
        }
    }

    pub fn emit(&mut self, m: Msg) {
        if self.echo {
            print_msg(&m);
            // Keep findings too, so a helper's own summary can count them.
            if let Msg::Find(f) = m {
                self.state.lock().unwrap().findings.push(f);
            }
            return;
        }
        {
            let mut st = self.state.lock().unwrap();
            match m {
                Msg::Progress(s) => st.progress = s,
                Msg::Log(s) => {
                    if st.log.len() < 20_000 {
                        st.log.push(s)
                    }
                }
                Msg::Find(f) => {
                    if st.findings.len() < 200_000 {
                        st.findings.push(f)
                    }
                }
                Msg::Done(s) => st.summary = s,
            }
        }
        if self.last_repaint.elapsed().as_millis() > 100 {
            self.last_repaint = Instant::now();
            (self.repaint)();
        }
    }
    /// Stop and pause switches for worker threads.
    pub fn cancel_flag(&self) -> Ctl {
        Ctl { cancel: self.cancel.clone(), pause: self.pause.clone() }
    }
    /// The job's state, for a helper thread that updates the progress line.
    pub fn state_handle(&self) -> Arc<Mutex<JobState>> {
        self.state.clone()
    }
    /// Wake the window now (for example to show a question).
    pub fn repaint_now(&mut self) {
        self.last_repaint = Instant::now();
        (self.repaint)();
    }
    /// Drop findings that match (for example ones replaced by a rescan).
    pub fn remove_findings(&mut self, pred: impl Fn(&Finding) -> bool) {
        self.state.lock().unwrap().findings.retain(|f| !pred(f));
    }
    pub fn paused(&self) -> bool {
        self.pause.load(Ordering::Relaxed)
    }
    /// Wait here while the job is paused (returns at once when stopped).
    pub fn wait_if_paused(&self) {
        self.cancel_flag().wait_if_paused();
    }
    pub fn findings(&self) -> Vec<Finding> {
        self.state.lock().unwrap().findings.clone()
    }
    pub fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
    pub fn progress(&mut self, s: impl Into<String>) {
        self.emit(Msg::Progress(s.into()))
    }
    pub fn log(&mut self, s: impl Into<String>) {
        self.emit(Msg::Log(s.into()))
    }
    pub fn find(&mut self, sev: Sev, kind: &str, path: impl Into<String>, detail: impl Into<String>) {
        self.emit(Msg::Find(Finding {
            sev,
            kind: kind.to_string(),
            path: path.into(),
            detail: detail.into(),
        }))
    }
    pub fn done(&mut self, s: impl Into<String>) {
        self.emit(Msg::Done(s.into()))
    }
}

/// An emitter for helper mode: prints every message to stdout.
pub fn print_msg(m: &Msg) {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{}", encode(m));
    let _ = out.flush();
}

impl Job {
    pub fn is_running(&self) -> bool {
        self.state.lock().unwrap().running
    }

    fn begin(&self, elevated: bool) -> bool {
        let mut st = self.state.lock().unwrap();
        if st.running {
            return false;
        }
        *st = JobState {
            running: true,
            started: Some(Instant::now()),
            started_wall: Some(SystemTime::now()),
            ever_ran: true,
            elevated,
            ..Default::default()
        };
        self.cancel.store(false, Ordering::Relaxed);
        self.pause.store(false, Ordering::Relaxed);
        true
    }

    fn emitter(&self, repaint: impl Fn() + Send + Clone + 'static) -> Emitter {
        Emitter {
            state: self.state.clone(),
            cancel: self.cancel.clone(),
            pause: self.pause.clone(),
            repaint: Box::new(repaint),
            last_repaint: Instant::now(),
            echo: false,
        }
    }

    fn finish(state: &Arc<Mutex<JobState>>) {
        let mut st = state.lock().unwrap();
        st.running = false;
        st.finished_wall = Some(SystemTime::now());
        if let Some(s) = st.started {
            st.elapsed_secs = s.elapsed().as_secs_f32();
        }
        st.progress.clear();
    }

    /// Run a scanner on the current thread (background mode, no window).
    pub fn run_inline<F: FnOnce(&mut Emitter)>(&self, f: F) {
        if !self.begin(false) {
            return;
        }
        let mut em = self.emitter(|| {});
        f(&mut em);
        Job::finish(&self.state);
    }

    /// Fill this job with a saved report (from a background run).
    pub fn load_report(&self, r: &Report) {
        let mut st = self.state.lock().unwrap();
        if st.running || (st.ever_ran && st.started.is_some()) {
            return;
        }
        st.findings = r.findings.clone();
        st.summary = r.summary.clone();
        st.log = r.log.clone();
        st.ever_ran = true;
        st.elapsed_secs = r.seconds;
        st.started_wall = Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(r.finished_unix.saturating_sub(r.seconds as u64)));
        st.finished_wall = Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(r.finished_unix));
        st.from_background = true;
    }

    pub fn report(&self, job: &str) -> Report {
        let st = self.state.lock().unwrap();
        Report {
            job: job.to_string(),
            finished_unix: st
                .finished_wall
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0),
            seconds: st.elapsed_secs,
            summary: st.summary.clone(),
            findings: st.findings.clone(),
            log: st.log.iter().rev().take(500).rev().cloned().collect(),
        }
    }

    /// Run a scanner function on a thread inside this process.
    pub fn run_thread<F>(&self, repaint: impl Fn() + Send + Clone + 'static, f: F)
    where
        F: FnOnce(&mut Emitter) + Send + 'static,
    {
        if !self.begin(false) {
            return;
        }
        let mut em = self.emitter(repaint.clone());
        let state = self.state.clone();
        std::thread::spawn(move || {
            f(&mut em);
            Job::finish(&state);
            repaint();
        });
    }

    /// Run an external program and turn each output line into messages with `parse`.
    /// Lines in the helper protocol (`@P`, `@F`...) are decoded directly.
    pub fn run_command<P>(
        &self,
        repaint: impl Fn() + Send + Clone + 'static,
        cmd: Command,
        elevated: bool,
        parse: P,
        on_exit: impl FnOnce(i32, &mut Emitter) + Send + 'static,
    ) where
        P: Fn(&str) -> Vec<Msg> + Send + Sync + 'static,
    {
        if !self.begin(elevated) {
            return;
        }
        let mut em = self.emitter(repaint.clone());
        let state = self.state.clone();
        let child_slot = self.child.clone();
        let cancel = self.cancel.clone();
        let parse = Arc::new(parse);
        em.log(format!("$ {}", describe(&cmd)));
        std::thread::spawn(move || {
            // Administrator commands go through the session (one password prompt).
            let child = match crate::root::spawn(cmd) {
                Ok(c) => c,
                Err(e) => {
                    em.log(format!("Could not start: {e}"));
                    em.done(format!("Could not start the program: {e}"));
                    Job::finish(&state);
                    repaint();
                    return;
                }
            };
            *child_slot.lock().unwrap() = Some(child.sig.clone());
            let mut code = -1;
            let mut killed = false;
            loop {
                match child.rx.recv_timeout(std::time::Duration::from_millis(300)) {
                    Ok(crate::root::Ev::Out(line)) | Ok(crate::root::Ev::Err(line)) => {
                        if line.starts_with('@') {
                            if let Some(m) = decode(&line) {
                                em.emit(m);
                                continue;
                            }
                        }
                        for m in parse(&line) {
                            em.emit(m);
                        }
                    }
                    Ok(crate::root::Ev::Exit(c)) => {
                        code = c;
                        break;
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }
                if cancel.load(Ordering::Relaxed) && !killed {
                    killed = true;
                    child.sig.send(libc::SIGCONT);
                    child.sig.send(libc::SIGTERM);
                }
            }
            *child_slot.lock().unwrap() = None;
            if cancel.load(Ordering::Relaxed) {
                em.log("Stopped.".to_string());
            }
            on_exit(code, &mut em);
            Job::finish(&state);
            repaint();
        });
    }

    pub fn stop(&self) {
        self.cancel.store(true, Ordering::Relaxed);
        self.pause.store(false, Ordering::Relaxed);
        if let Some(sig) = self.child.lock().unwrap().as_ref() {
            sig.send(libc::SIGCONT);
            sig.send(libc::SIGTERM);
        }
    }

    pub fn is_paused(&self) -> bool {
        self.pause.load(Ordering::Relaxed)
    }

    /// Pause or resume. Threads wait at their next step; programs this job
    /// started are frozen (SIGSTOP) and thawed (SIGCONT). Returns false when a
    /// program running with administrator rights couldn't be paused.
    pub fn set_paused(&self, on: bool) -> bool {
        self.pause.store(on, Ordering::Relaxed);
        let mut ok = true;
        if let Some(sig) = self.child.lock().unwrap().as_ref() {
            ok = sig.send(if on { libc::SIGSTOP } else { libc::SIGCONT });
        }
        {
            let mut st = self.state.lock().unwrap();
            st.log.push(if on { "Paused.".to_string() } else { "Resumed.".to_string() });
        }
        ok
    }
}

/// Stop/pause switches shared with worker threads.
#[derive(Clone)]
pub struct Ctl {
    pub cancel: Arc<AtomicBool>,
    pub pause: Arc<AtomicBool>,
}

impl Ctl {
    pub fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
    pub fn wait_if_paused(&self) {
        while self.pause.load(Ordering::Relaxed) && !self.cancelled() {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }
}

pub fn describe(cmd: &Command) -> String {
    let mut s = cmd.get_program().to_string_lossy().to_string();
    for a in cmd.get_args() {
        s.push(' ');
        s.push_str(&a.to_string_lossy());
    }
    s
}
