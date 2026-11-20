//! Reading whole disks needs administrator rights. Instead of starting the app from a
//! terminal with sudo, it can restart itself through the system's own password prompt:
//! pkexec (polkit) on Linux, the administrator prompt on macOS, and UAC on Windows.

use std::path::{Path, PathBuf};
use std::process::{Child, Command};

#[cfg(target_os = "linux")]
pub fn is_admin() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("Uid:")).map(|l| l.split_whitespace().nth(2) == Some("0")))
        .unwrap_or(false)
}

#[cfg(all(unix, not(target_os = "linux")))]
pub fn is_admin() -> bool {
    Command::new("id").arg("-u").output().map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0").unwrap_or(false)
}

#[cfg(windows)]
pub fn is_admin() -> bool {
    // Only administrators may open a physical drive.
    std::fs::File::open(r"\\.\PhysicalDrive0").is_ok()
}

/// The person's own home folder, also when running with administrator rights.
pub fn user_home() -> Option<PathBuf> {
    if let Ok(h) = std::env::var("FILE_RESCUE_HOME") {
        if !h.is_empty() {
            return Some(PathBuf::from(h));
        }
    }
    // Started with sudo or pkexec: HOME may be root's, so use the real user's home.
    #[cfg(unix)]
    if is_admin() {
        if let Some((uid, _)) = real_user() {
            if let Some((_, home)) = passwd(uid) {
                return Some(home);
            }
        }
    }
    std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from)
}

/// A request to restart with administrator rights, waiting for the new window.
pub struct Pending {
    child: Child,
    ready: PathBuf,
}

pub enum State {
    Waiting,
    /// The new window is up: this one can close.
    Ready,
    Failed(String),
}

impl Pending {
    pub fn poll(&mut self) -> State {
        if self.ready.exists() {
            let _ = std::fs::remove_file(&self.ready);
            return State::Ready;
        }
        match self.child.try_wait() {
            Ok(Some(st)) if !self.ready.exists() => State::Failed(if st.code() == Some(126) || st.code() == Some(1) {
                "Administrator rights weren't given (the password prompt was cancelled).".into()
            } else {
                format!("Couldn't restart with administrator rights ({st}).")
            }),
            _ => State::Waiting,
        }
    }
}

pub fn restart_as_admin() -> Result<Pending, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let ready = std::env::temp_dir().join(format!("file-rescue-ready-{}", std::process::id()));
    let _ = std::fs::remove_file(&ready);
    let child = spawn(&exe, &ready)?;
    Ok(Pending { child, ready })
}

#[cfg(target_os = "linux")]
fn spawn(exe: &Path, ready: &Path) -> Result<Child, String> {
    let mut cmd = Command::new("pkexec");
    // pkexec starts with a clean environment; pass on what a window needs.
    cmd.arg("env");
    let mut pass = |k: &str, v: Option<String>| {
        if let Some(v) = v.filter(|v| !v.is_empty()) {
            cmd.arg(format!("{k}={v}"));
        }
    };
    let home = std::env::var("HOME").ok();
    pass("DISPLAY", std::env::var("DISPLAY").ok());
    pass(
        "XAUTHORITY",
        std::env::var("XAUTHORITY").ok().or_else(|| home.as_ref().map(|h| format!("{h}/.Xauthority")).filter(|p| Path::new(p).exists())),
    );
    pass("WAYLAND_DISPLAY", std::env::var("WAYLAND_DISPLAY").ok());
    pass("XDG_RUNTIME_DIR", std::env::var("XDG_RUNTIME_DIR").ok());
    pass("XDG_SESSION_TYPE", std::env::var("XDG_SESSION_TYPE").ok());
    pass("DBUS_SESSION_BUS_ADDRESS", std::env::var("DBUS_SESSION_BUS_ADDRESS").ok());
    pass("FILE_RESCUE_HOME", home);
    pass("LANG", std::env::var("LANG").ok());
    // Who to give recovered files back to.
    if let Some((uid, gid)) = own_ids() {
        pass("FILE_RESCUE_UID", Some(uid.to_string()));
        pass("FILE_RESCUE_GID", Some(gid.to_string()));
    }
    cmd.arg(exe).arg("--ready-file").arg(ready);
    cmd.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            "This computer has no pkexec (polkit) to ask for the password. Install the \"polkit\" package, or start File Rescue with sudo.".into()
        } else {
            format!("Couldn't ask for administrator rights: {e}")
        }
    })
}

#[cfg(target_os = "macos")]
fn spawn(exe: &Path, ready: &Path) -> Result<Child, String> {
    let q = |p: &Path| p.display().to_string().replace('\'', "'\\''");
    let home = std::env::var("HOME").unwrap_or_default().replace('\'', "'\\''");
    let (uid, gid) = own_ids().unwrap_or((0, 0));
    let script = format!(
        "FILE_RESCUE_HOME='{home}' FILE_RESCUE_UID={uid} FILE_RESCUE_GID={gid} '{}' --ready-file '{}' > /dev/null 2>&1 &",
        q(exe),
        q(ready)
    );
    let apple = format!("do shell script \"{}\" with administrator privileges", script.replace('\\', "\\\\").replace('"', "\\\""));
    // osascript returns once the program has started; the ready file tells when its window is up.
    Command::new("osascript").arg("-e").arg(apple).spawn().map_err(|e| format!("Couldn't ask for administrator rights: {e}"))
}

#[cfg(windows)]
fn spawn(exe: &Path, ready: &Path) -> Result<Child, String> {
    let ps = format!(
        "Start-Process -FilePath '{}' -ArgumentList '--ready-file','\"{}\"' -Verb RunAs",
        exe.display().to_string().replace('\'', "''"),
        ready.display().to_string().replace('\'', "''")
    );
    Command::new("powershell")
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &ps])
        .spawn()
        .map_err(|e| format!("Couldn't ask for administrator rights: {e}"))
}

/// This process's own user and group ids (to hand to the administrator copy).
#[cfg(unix)]
fn own_ids() -> Option<(u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    // A file we create belongs to us: the simplest portable way to learn our ids.
    let p = std::env::temp_dir().join(format!("file-rescue-id-{}", std::process::id()));
    std::fs::write(&p, b"").ok()?;
    let m = std::fs::metadata(&p).ok();
    let _ = std::fs::remove_file(&p);
    m.map(|m| (m.uid(), m.gid()))
}

/// A line of /etc/passwd for this user id: (primary group, home folder).
#[cfg(unix)]
fn passwd(uid: u32) -> Option<(u32, PathBuf)> {
    std::fs::read_to_string("/etc/passwd").ok()?.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 6 && f[2].parse() == Ok(uid)).then(|| (f[3].parse().unwrap_or(uid), PathBuf::from(f[5])))
    })
}

/// The person who really started File Rescue, when it runs as administrator:
/// told by our own restart (FILE_RESCUE_UID), by pkexec (PKEXEC_UID) or by sudo (SUDO_UID).
#[cfg(unix)]
pub fn real_user() -> Option<(u32, u32)> {
    let num = |k: &str| std::env::var(k).ok().and_then(|v| v.trim().parse::<u32>().ok());
    let uid = num("FILE_RESCUE_UID").or_else(|| num("PKEXEC_UID")).or_else(|| num("SUDO_UID")).filter(|&u| u != 0)?;
    let gid = num("FILE_RESCUE_GID")
        .or_else(|| num("SUDO_GID").filter(|_| num("SUDO_UID") == Some(uid)))
        .or_else(|| passwd(uid).map(|p| p.0))
        .unwrap_or(uid);
    Some((uid, gid))
}

#[cfg(not(unix))]
pub fn real_user() -> Option<(u32, u32)> {
    None
}

/// Who recovered files should belong to: the real user, or else whoever owns the
/// folder they're saved in (when that isn't the administrator).
#[cfg(unix)]
fn owner_for(out: &Path) -> Option<(u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    if !is_admin() {
        return None;
    }
    real_user().or_else(|| {
        let m = out.ancestors().find_map(|a| std::fs::metadata(a).ok())?;
        (m.uid() != 0).then(|| (m.uid(), m.gid()))
    })
}

/// Files saved while running as administrator would belong to root; give the file
/// and the folders made for it back to the person.
#[cfg(unix)]
pub fn give_back(file: &Path, out: &Path) {
    let Some((uid, gid)) = owner_for(out) else { return };
    for p in file.ancestors() {
        let _ = std::os::unix::fs::lchown(p, Some(uid), Some(gid));
        if p == out || !p.starts_with(out) {
            break;
        }
    }
}

/// After a recovery, also fix anything in the output folder still owned by root
/// (for example from an earlier run), so the person can open, move and delete it all.
#[cfg(unix)]
pub fn give_back_folder(out: &Path) {
    use std::os::unix::fs::MetadataExt;
    let Some((uid, gid)) = owner_for(out) else { return };
    let mut stack = vec![out.to_path_buf()];
    let mut seen = 0usize;
    while let Some(p) = stack.pop() {
        seen += 1;
        if seen > 1_000_000 {
            break;
        }
        let Ok(m) = std::fs::symlink_metadata(&p) else { continue };
        if m.uid() == 0 {
            let _ = std::os::unix::fs::lchown(&p, Some(uid), Some(gid));
        }
        if m.is_dir() {
            if let Ok(rd) = std::fs::read_dir(&p) {
                stack.extend(rd.flatten().map(|e| e.path()));
            }
        }
    }
}

#[cfg(not(unix))]
pub fn give_back(_file: &Path, _out: &Path) {}

#[cfg(not(unix))]
pub fn give_back_folder(_out: &Path) {}
