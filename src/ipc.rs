//! One running copy: later starts (a right-click "Scan" in the file manager,
//! or opening the app again) hand their request to the copy already running
//! through a private socket, then exit.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub fn socket_path() -> PathBuf {
    let dir = std::env::var("XDG_RUNTIME_DIR").map(PathBuf::from).unwrap_or_else(|_| std::env::temp_dir());
    dir.join(format!("arch-sentinel-{}.sock", unsafe { libc::getuid() }))
}

/// Give a message to the running copy. False when none is running.
pub fn send(msg: &str) -> bool {
    match UnixStream::connect(socket_path()) {
        Ok(mut s) => s.write_all(msg.as_bytes()).is_ok(),
        Err(_) => false,
    }
}

/// Listen for messages from later starts; each one lands in `inbox`.
pub fn listen(inbox: Arc<Mutex<Vec<String>>>, ctx: eframe::egui::Context) {
    let path = socket_path();
    if UnixStream::connect(&path).is_ok() {
        return; // another copy is already listening
    }
    let _ = std::fs::remove_file(&path);
    let Ok(listener) = UnixListener::bind(&path) else { return };
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut s = stream;
            let mut text = String::new();
            if s.read_to_string(&mut text).is_ok() && !text.is_empty() {
                inbox.lock().unwrap().push(text);
                ctx.request_repaint();
            }
        }
    });
}
