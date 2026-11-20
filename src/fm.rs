//! "Scan for viruses (Arch Sentinel)" in the file manager's right-click menu:
//! Dolphin (KDE), Nautilus (GNOME) and Nemo (Cinnamon).

use crate::settings::home_dir;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

const LABEL: &str = "Scan for viruses (Arch Sentinel)";

fn data_home() -> PathBuf {
    std::env::var("XDG_DATA_HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from(home_dir()).join(".local/share"))
}

fn dolphin_user() -> PathBuf {
    data_home().join("kio/servicemenus/arch-sentinel-scan.desktop")
}
fn nautilus_user() -> PathBuf {
    data_home().join(format!("nautilus/scripts/{LABEL}"))
}
fn nemo_user() -> PathBuf {
    data_home().join("nemo/actions/arch-sentinel-scan.nemo_action")
}
pub const DOLPHIN_SYSTEM: &str = "/usr/share/kio/servicemenus/arch-sentinel-scan.desktop";

pub fn dolphin_menu(exe: &str) -> String {
    format!(
        "[Desktop Entry]\nType=Service\nMimeType=all/all;\nX-KDE-ServiceTypes=KonqPopupMenu/Plugin\nActions=archSentinelScan;\nX-KDE-Priority=TopLevel\n\n[Desktop Action archSentinelScan]\nName={LABEL}\nIcon=security-high\nExec=\"{exe}\" --scan %F\n"
    )
}

pub fn nemo_action(exe: &str) -> String {
    format!("[Nemo Action]\nName={LABEL}\nComment=Scan with ClamAV using several threads\nExec=\"{exe}\" --scan %F\nIcon-Name=security-high\nSelection=notnone\nExtensions=any;\n")
}

fn nautilus_script(exe: &str) -> String {
    format!("#!/bin/sh\n# Added by Arch Sentinel\nIFS='\n'\nexec \"{exe}\" --scan $NAUTILUS_SCRIPT_SELECTED_FILE_PATHS\n")
}

/// Whether a right-click entry exists (installed by the package or by you).
pub fn installed() -> bool {
    dolphin_user().exists() || std::path::Path::new(DOLPHIN_SYSTEM).exists() || nautilus_user().exists() || nemo_user().exists()
}

pub fn from_package() -> bool {
    std::path::Path::new(DOLPHIN_SYSTEM).exists()
}

fn write_exec(p: &PathBuf, text: &str) -> std::io::Result<()> {
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    std::fs::write(p, text)?;
    // Dolphin only runs service menus in your own folder when they're executable.
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755))
}

pub fn install() -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?.display().to_string();
    let mut done = vec![];
    if !from_package() {
        write_exec(&dolphin_user(), &dolphin_menu(&exe)).map_err(|e| e.to_string())?;
        done.push("Dolphin");
    }
    write_exec(&nautilus_user(), &nautilus_script(&exe)).map_err(|e| e.to_string())?;
    done.push("Nautilus (Scripts submenu)");
    if !std::path::Path::new("/usr/share/nemo/actions/arch-sentinel-scan.nemo_action").exists() {
        write_exec(&nemo_user(), &nemo_action(&exe)).map_err(|e| e.to_string())?;
        done.push("Nemo");
    }
    Ok(format!("Right-click \"{LABEL}\" added for {}. Dolphin may need a restart to show it.", done.join(", ")))
}

pub fn remove() -> Result<String, String> {
    for p in [dolphin_user(), nautilus_user(), nemo_user()] {
        let _ = std::fs::remove_file(p);
    }
    Ok(if from_package() {
        "Removed your own entries; the installed package still adds the Dolphin entry.".into()
    } else {
        "Right-click scan entries removed.".into()
    })
}
