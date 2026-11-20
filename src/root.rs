//! One administrator session instead of a password prompt per task.
//!
//! The first task that needs administrator rights starts a small helper of this
//! same program through pkexec (one password prompt). Every later administrator
//! task in this session is handed to that helper over its private stdin/stdout
//! pipes — nothing else on the computer can reach it — and it runs the task as
//! root, streaming the output back. The helper ends when the app quits, when you
//! end the session, or after it has been idle for a while.
//!
//! Commands built the usual way (`pkexec prog args…`, optionally behind a
//! `systemd-run --user --scope` CPU cap) are recognised and sent to the session
//! automatically, so callers barely change.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};

pub enum Ev {
    Out(String),
    Err(String),
    Exit(i32),
}

pub struct Broker {
    stdin: Mutex<Option<ChildStdin>>,
    routes: Mutex<HashMap<u64, Sender<Ev>>>,
    alive: AtomicBool,
    next: AtomicU64,
    child: Mutex<Child>,
}

impl Broker {
    fn send(&self, v: serde_json::Value) -> bool {
        let mut g = self.stdin.lock().unwrap();
        match g.as_mut() {
            Some(s) => writeln!(s, "{v}").and_then(|_| s.flush()).is_ok(),
            None => false,
        }
    }
}

static BROKER: Mutex<Option<Arc<Broker>>> = Mutex::new(None);
static LAUNCH: Mutex<()> = Mutex::new(());
/// Minutes of no administrator tasks before the session ends by itself.
static IDLE_MINUTES: AtomicU64 = AtomicU64::new(30);

pub fn set_idle_minutes(m: u64) {
    IDLE_MINUTES.store(m.max(1), Ordering::Relaxed);
}

/// Is an administrator session open right now?
pub fn active() -> bool {
    BROKER.lock().unwrap().as_ref().map(|b| b.alive.load(Ordering::Relaxed)).unwrap_or(false)
}

/// End the session: the helper stops (anything it's still running is stopped too).
pub fn end_session() {
    if let Some(b) = BROKER.lock().unwrap().take() {
        b.stdin.lock().unwrap().take();
        b.alive.store(false, Ordering::Relaxed);
        let _ = b.child.lock().unwrap().wait();
    }
}

fn launch() -> std::io::Result<Arc<Broker>> {
    let exe = std::env::current_exe()?;
    let mut child = Command::new("/usr/bin/pkexec")
        .arg(&exe)
        .arg("--root-broker")
        .arg(IDLE_MINUTES.load(Ordering::Relaxed).to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdout = child.stdout.take().ok_or_else(|| std::io::Error::other("no output"))?;
    let mut reader = BufReader::new(stdout);
    let mut first = String::new();
    // Waits here while the password prompt is up.
    reader.read_line(&mut first)?;
    if first.trim() != "ready" {
        let _ = child.wait();
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "administrator rights were refused"));
    }
    let b = Arc::new(Broker {
        stdin: Mutex::new(child.stdin.take()),
        routes: Mutex::new(HashMap::new()),
        alive: AtomicBool::new(true),
        next: AtomicU64::new(1),
        child: Mutex::new(child),
    });
    let b2 = b.clone();
    std::thread::spawn(move || {
        for line in reader.lines().map_while(Result::ok) {
            let mut it = line.splitn(3, '\t');
            let (Some(id), Some(kind)) = (it.next().and_then(|x| x.parse::<u64>().ok()), it.next()) else { continue };
            let rest = it.next().unwrap_or("").to_string();
            let mut routes = b2.routes.lock().unwrap();
            if let Some(tx) = routes.get(&id) {
                let ev = match kind {
                    "o" => Ev::Out(rest),
                    "e" => Ev::Err(rest),
                    _ => Ev::Exit(rest.trim().parse().unwrap_or(-1)),
                };
                let exit = matches!(ev, Ev::Exit(_));
                let _ = tx.send(ev);
                if exit {
                    routes.remove(&id);
                }
            }
        }
        // The helper ended (quit, idle, or killed): finish whatever was still waiting.
        b2.alive.store(false, Ordering::Relaxed);
        for (_, tx) in b2.routes.lock().unwrap().drain() {
            let _ = tx.send(Ev::Err("The administrator session ended.".into()));
            let _ = tx.send(Ev::Exit(255));
        }
    });
    Ok(b)
}

/// The running session, starting one (with a password prompt) when needed.
fn broker() -> std::io::Result<Arc<Broker>> {
    let _one_at_a_time = LAUNCH.lock().unwrap();
    if let Some(b) = BROKER.lock().unwrap().clone() {
        if b.alive.load(Ordering::Relaxed) {
            return Ok(b);
        }
    }
    let b = launch()?;
    *BROKER.lock().unwrap() = Some(b.clone());
    Ok(b)
}

/// How to signal a running task (local process group, or a task in the session).
#[derive(Clone)]
pub enum Sig {
    Local(i32),
    Root(Arc<Broker>, u64),
    None,
}

impl Sig {
    /// Send a signal; false when it couldn't be delivered.
    pub fn send(&self, sig: i32) -> bool {
        match self {
            Sig::Local(pgid) => unsafe { libc::kill(-pgid, sig) == 0 },
            Sig::Root(b, id) => b.send(serde_json::json!({"op": "signal", "id": id, "sig": sig})),
            Sig::None => false,
        }
    }
}

/// A started task: its output and exit arrive on `rx`.
pub struct AnyChild {
    pub rx: Receiver<Ev>,
    pub sig: Sig,
}

/// If this command asks for administrator rights (pkexec), the argv to run as root.
fn root_argv(cmd: &Command) -> Option<Vec<String>> {
    let prog = cmd.get_program().to_string_lossy().to_string();
    let args: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().to_string()).collect();
    if prog.ends_with("pkexec") {
        return Some(args);
    }
    if prog.ends_with("systemd-run") {
        if let Some(i) = args.iter().position(|a| a.ends_with("pkexec")) {
            // Keep the CPU cap, as a system scope (the helper runs as root).
            let mut v = vec![prog];
            v.extend(args[..i].iter().filter(|a| *a != "--user").cloned());
            v.extend(args[i + 1..].iter().cloned());
            return Some(v);
        }
    }
    None
}

/// Start a command: administrator ones go to the session, the rest run here.
pub fn spawn(mut cmd: Command) -> std::io::Result<AnyChild> {
    let (tx, rx) = channel();
    if let Some(argv) = root_argv(&cmd) {
        match broker() {
            Ok(b) => {
                let id = b.next.fetch_add(1, Ordering::Relaxed);
                b.routes.lock().unwrap().insert(id, tx.clone());
                let cwd = cmd.get_current_dir().map(|d| d.display().to_string());
                if !b.send(serde_json::json!({"op": "run", "id": id, "argv": argv, "cwd": cwd})) {
                    b.routes.lock().unwrap().remove(&id);
                    let _ = tx.send(Ev::Err("The administrator session isn't answering.".into()));
                    let _ = tx.send(Ev::Exit(255));
                    return Ok(AnyChild { rx, sig: Sig::None });
                }
                return Ok(AnyChild { rx, sig: Sig::Root(b, id) });
            }
            Err(_) => {
                // Same meaning as pkexec's own "refused".
                let _ = tx.send(Ev::Err("Administrator rights were refused.".into()));
                let _ = tx.send(Ev::Exit(126));
                return Ok(AnyChild { rx, sig: Sig::None });
            }
        }
    }
    cmd.process_group(0).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    let pgid = child.id() as i32;
    let out = child.stdout.take();
    let err = child.stderr.take();
    let t1 = {
        let tx = tx.clone();
        std::thread::spawn(move || {
            if let Some(o) = out {
                for l in BufReader::new(o).lines().map_while(Result::ok) {
                    let _ = tx.send(Ev::Out(l));
                }
            }
        })
    };
    let t2 = {
        let tx = tx.clone();
        std::thread::spawn(move || {
            if let Some(e) = err {
                for l in BufReader::new(e).lines().map_while(Result::ok) {
                    let _ = tx.send(Ev::Err(l));
                }
            }
        })
    };
    std::thread::spawn(move || {
        let _ = t1.join();
        let _ = t2.join();
        let code = child.wait().ok().and_then(|s| s.code()).unwrap_or(-1);
        let _ = tx.send(Ev::Exit(code));
    });
    Ok(AnyChild { rx, sig: Sig::Local(pgid) })
}

/// Like `Command::output()`, but administrator commands go through the session.
pub fn output(cmd: Command) -> std::io::Result<std::process::Output> {
    use std::os::unix::process::ExitStatusExt;
    let c = spawn(cmd)?;
    let (mut out, mut err, mut code) = (String::new(), String::new(), -1);
    for ev in c.rx {
        match ev {
            Ev::Out(l) => {
                out.push_str(&l);
                out.push('\n');
            }
            Ev::Err(l) => {
                err.push_str(&l);
                err.push('\n');
            }
            Ev::Exit(c) => {
                code = c;
                break;
            }
        }
    }
    let raw = if code >= 0 { (code & 0xff) << 8 } else { 9 };
    Ok(std::process::Output { status: std::process::ExitStatus::from_raw(raw), stdout: out.into_bytes(), stderr: err.into_bytes() })
}

// ---------- the helper side (runs as root) ----------

/// `--root-broker [idle minutes]`: run tasks for the app until it closes our stdin.
pub fn broker_main(idle_minutes: u64) -> i32 {
    let out = Arc::new(Mutex::new(std::io::stdout()));
    let say = {
        let out = out.clone();
        move |s: String| {
            let mut o = out.lock().unwrap();
            let _ = writeln!(o, "{s}");
            let _ = o.flush();
        }
    };
    say("ready".into());
    let groups: Arc<Mutex<HashMap<u64, i32>>> = Arc::new(Mutex::new(HashMap::new()));
    let last = Arc::new(Mutex::new(std::time::Instant::now()));
    {
        let groups = groups.clone();
        let last = last.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(20));
            let idle = groups.lock().unwrap().is_empty() && last.lock().unwrap().elapsed().as_secs() > idle_minutes * 60;
            if idle {
                std::process::exit(0);
            }
        });
    }
    for line in std::io::stdin().lock().lines().map_while(Result::ok) {
        *last.lock().unwrap() = std::time::Instant::now();
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
        let id = v["id"].as_u64().unwrap_or(0);
        match v["op"].as_str() {
            Some("run") => {
                let argv: Vec<String> = v["argv"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect()).unwrap_or_default();
                if argv.is_empty() {
                    say(format!("{id}\tx\t127"));
                    continue;
                }
                let mut c = Command::new(&argv[0]);
                c.args(&argv[1..]).process_group(0).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
                if let Some(d) = v["cwd"].as_str() {
                    c.current_dir(d);
                }
                match c.spawn() {
                    Err(e) => {
                        say(format!("{id}\te\tCould not start {}: {e}", argv[0]));
                        say(format!("{id}\tx\t127"));
                    }
                    Ok(mut child) => {
                        groups.lock().unwrap().insert(id, child.id() as i32);
                        let o = child.stdout.take();
                        let e = child.stderr.take();
                        let s1 = say.clone();
                        let t1 = std::thread::spawn(move || {
                            if let Some(o) = o {
                                for l in BufReader::new(o).lines().map_while(Result::ok) {
                                    s1(format!("{id}\to\t{l}"));
                                }
                            }
                        });
                        let s2 = say.clone();
                        let t2 = std::thread::spawn(move || {
                            if let Some(e) = e {
                                for l in BufReader::new(e).lines().map_while(Result::ok) {
                                    s2(format!("{id}\te\t{l}"));
                                }
                            }
                        });
                        let s3 = say.clone();
                        let groups = groups.clone();
                        let last = last.clone();
                        std::thread::spawn(move || {
                            let _ = t1.join();
                            let _ = t2.join();
                            let code = child.wait().ok().and_then(|s| s.code()).unwrap_or(-1);
                            groups.lock().unwrap().remove(&id);
                            *last.lock().unwrap() = std::time::Instant::now();
                            s3(format!("{id}\tx\t{code}"));
                        });
                    }
                }
            }
            Some("signal") => {
                let sig = v["sig"].as_i64().unwrap_or(15) as i32;
                if let Some(pg) = groups.lock().unwrap().get(&id) {
                    unsafe {
                        libc::kill(-pg, sig);
                    }
                }
            }
            _ => {}
        }
    }
    // The app went away: stop everything it started.
    for (_, pg) in groups.lock().unwrap().iter() {
        unsafe {
            libc::kill(-pg, libc::SIGCONT);
            libc::kill(-pg, libc::SIGTERM);
        }
    }
    0
}
