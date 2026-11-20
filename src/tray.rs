//! Tray (taskbar) icon so Arch Sentinel can keep running with its window
//! closed, plus a login autostart entry and a connection watcher that warns
//! about programs not installed by any package going online.

use crate::settings::home_dir;
use eframe::egui;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TrayCmd {
    Show,
    RunAll,
    UpdateSignatures,
    OpenNetwork,
    OpenQuarantine,
    Quit,
}

pub struct SentinelTray {
    tx: Sender<TrayCmd>,
    ctx: egui::Context,
    pub status: String,
    pub alert: bool,
}

impl SentinelTray {
    fn send(&self, c: TrayCmd) {
        let _ = self.tx.send(c);
        self.ctx.request_repaint();
    }
}

/// A small shield drawn in code (ARGB32, network byte order).
fn shield_icon(size: i32, alert: bool) -> ksni::Icon {
    let mut data = Vec::with_capacity((size * size * 4) as usize);
    let (r, g, b) = if alert { (0xe5u8, 0x53u8, 0x4bu8) } else { (0x2eu8, 0xb8u8, 0xa6u8) };
    let s = size as f32;
    for y in 0..size {
        for x in 0..size {
            let fx = (x as f32 + 0.5) / s;
            let fy = (y as f32 + 0.5) / s;
            // Shield: flat top, sides narrowing to a point at the bottom.
            let half = if fy < 0.55 { 0.42 } else { 0.42 * (1.0 - (fy - 0.55) / 0.43).max(0.0) };
            let inside = fy > 0.08 && fy < 0.98 && (fx - 0.5).abs() < half;
            // A check mark cut out of it.
            let on_check = {
                let d1 = ((fx - 0.30) - (fy - 0.50)).abs() < 0.07 && fx > 0.28 && fx < 0.46 && fy > 0.42 && fy < 0.68;
                let d2 = ((fx - 0.44) + (fy - 0.66)).abs() < 0.07 && fx > 0.42 && fx < 0.72 && fy > 0.30 && fy < 0.70;
                d1 || d2
            };
            if inside && !on_check {
                data.extend_from_slice(&[0xff, r, g, b]);
            } else if inside {
                data.extend_from_slice(&[0xff, 0x14, 0x17, 0x1c]);
            } else {
                data.extend_from_slice(&[0, 0, 0, 0]);
            }
        }
    }
    ksni::Icon { width: size, height: size, data }
}

impl ksni::Tray for SentinelTray {
    fn id(&self) -> String {
        "arch-sentinel".into()
    }
    fn title(&self) -> String {
        "Arch Sentinel".into()
    }
    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        vec![shield_icon(22, self.alert), shield_icon(32, self.alert), shield_icon(64, self.alert)]
    }
    fn status(&self) -> ksni::Status {
        if self.alert { ksni::Status::NeedsAttention } else { ksni::Status::Active }
    }
    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip { title: "Arch Sentinel".into(), description: self.status.clone(), ..Default::default() }
    }
    fn activate(&mut self, _x: i32, _y: i32) {
        self.alert = false;
        self.send(TrayCmd::Show);
    }
    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::*;
        let item = |label: &str, icon: &str, c: TrayCmd| -> ksni::MenuItem<Self> {
            StandardItem {
                label: label.into(),
                icon_name: icon.into(),
                activate: Box::new(move |t: &mut Self| {
                    if c == TrayCmd::Show {
                        t.alert = false;
                    }
                    t.send(c)
                }),
                ..Default::default()
            }
            .into()
        };
        vec![
            StandardItem { label: self.status.clone(), enabled: false, ..Default::default() }.into(),
            MenuItem::Separator,
            item("Open Arch Sentinel", "security-high", TrayCmd::Show),
            item("Run all checks", "system-search", TrayCmd::RunAll),
            item("Update virus signatures", "view-refresh", TrayCmd::UpdateSignatures),
            item("Connections & rules", "network-wired", TrayCmd::OpenNetwork),
            item("Quarantine", "folder-locked", TrayCmd::OpenQuarantine),
            MenuItem::Separator,
            item("Quit", "application-exit", TrayCmd::Quit),
        ]
    }
}

pub struct TrayHandle {
    pub handle: Option<ksni::blocking::Handle<SentinelTray>>,
    pub rx: Receiver<TrayCmd>,
    pub error: Option<String>,
}

pub fn start(ctx: &egui::Context) -> TrayHandle {
    use ksni::blocking::TrayMethods;
    let (tx, rx) = std::sync::mpsc::channel();
    let t = SentinelTray { tx, ctx: ctx.clone(), status: "Starting…".into(), alert: false };
    match t.spawn() {
        Ok(h) => TrayHandle { handle: Some(h), rx, error: None },
        Err(e) => TrayHandle { handle: None, rx, error: Some(format!("No tray area found ({e}); closing the window will quit.")) },
    }
}

// ---------- autostart ----------

fn autostart_path() -> PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from(home_dir()).join(".config"));
    base.join("autostart/arch-sentinel.desktop")
}

pub fn set_autostart(on: bool) -> Result<String, String> {
    let p = autostart_path();
    if on {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
        }
        let text = format!(
            "[Desktop Entry]\nType=Application\nName=Arch Sentinel\nComment=Security checks for Arch Linux\nExec=\"{}\" --tray\nIcon=security-high\nTerminal=false\nX-GNOME-Autostart-enabled=true\n",
            exe.display()
        );
        std::fs::write(&p, text).map_err(|e| e.to_string())?;
        Ok("Arch Sentinel will start in the tray when you log in.".into())
    } else {
        let _ = std::fs::remove_file(&p);
        Ok("Arch Sentinel won't start at login any more.".into())
    }
}

// ---------- connection watcher ----------

/// Every few seconds, look for connections from programs no package installed
/// and send one desktop notification per new program.
pub fn start_watcher(enabled: Arc<AtomicBool>, alerts: Arc<Mutex<Vec<String>>>, ctx: egui::Context) {
    std::thread::spawn(move || {
        let mut owned: Option<HashSet<String>> = None;
        let mut warned: HashSet<String> = HashSet::new();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(5));
            if !enabled.load(Ordering::Relaxed) {
                continue;
            }
            if owned.is_none() {
                owned = crate::pkg::load_owned(false).ok().map(|d| d.files);
            }
            let Some(files) = owned.as_ref() else { continue };
            for c in crate::net::connections() {
                if !c.program.starts_with('/') || c.remote_port == 0 || c.remote_ip.starts_with("127.") || c.remote_ip == "::1" {
                    continue;
                }
                if files.contains(&c.program) || warned.contains(&c.program) {
                    continue;
                }
                if c.program.starts_with("/var/lib/flatpak") || c.program.contains("/.local/share/flatpak/") {
                    continue;
                }
                warned.insert(c.program.clone());
                let msg = format!("{} (not from a package) connected to {}", c.program, c.remote);
                let _ = std::process::Command::new("notify-send")
                    .args(["-a", "Arch Sentinel", "-i", "security-medium", "Unpackaged program went online", &msg])
                    .spawn();
                alerts.lock().unwrap().push(msg);
                ctx.request_repaint();
            }
        }
    });
}
