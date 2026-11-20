//! The "File Rescue" mode of the Deleted files page: find deleted files on a
//! disk (by name and by content), then virus-scan them in memory, zero-fill them
//! in place, or recover them with their original names.

use crate::app::*;
use crate::jobs::{Finding, Sev};
use crate::rescue::model::{Found, Method, Volume};
use eframe::egui::{self, Color32, RichText, Ui};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Row {
    pub f: Found,
    pub sel: bool,
    pub status: String,
    pub threat: Option<(Sev, String)>,
    pub sha: Option<String>,
    pub wiped: bool,
}

#[derive(Default)]
pub struct RescueState {
    pub rows: Vec<Row>,
    pub volumes: Vec<Volume>,
    pub mounted: Vec<String>,
    pub source: String,
}

#[derive(Default)]
pub struct RescueUi {
    pub path: String,
    pub undelete: bool,
    pub deep: bool,
    pub previous: bool,
    pub filter: String,
    pub only_flagged: bool,
    pub dest: String,
    pub wipe_ask: bool,
    pub wipe_sure: bool,
    pub devices: Vec<crate::rescue::disk::DeviceInfo>,
    pub state: Arc<Mutex<RescueState>>,
    pub job: crate::jobs::Job,
}

impl RescueUi {
    pub fn new() -> Self {
        Self { undelete: true, deep: true, previous: false, ..Default::default() }
    }
}

fn practice_image() -> String {
    crate::settings::data_dir().join("practice-disk.img").display().to_string()
}

fn needs_admin(path: &str) -> bool {
    path.starts_with("/dev/")
}

fn helper_cmd(s: &crate::settings::Settings, path: &str, args: Vec<String>) -> std::process::Command {
    let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default();
    let mut a = vec!["--helper".to_string(), "rescue".to_string()];
    a.extend(args);
    crate::par::command(s, needs_admin(path), &exe, &a)
}

fn write_json<T: serde::Serialize>(name: &str, v: &T) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    let p = std::env::temp_dir().join(format!("arch-sentinel-rescue-{}-{name}.json", std::process::id()));
    std::fs::write(&p, serde_json::to_string(v).ok()?).ok()?;
    let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    Some(p.display().to_string())
}

impl App {
    fn rescue_run(&mut self, ctx: &egui::Context, what: &str) {
        let r = &self.rescue;
        if r.job.is_running() {
            return;
        }
        let s = self.s.clone();
        let path = r.path.trim().to_string();
        let state = r.state.clone();
        let c2 = ctx.clone();
        let repaint = move || c2.request_repaint();
        let selected: Vec<(usize, Found)> = state.lock().unwrap().rows.iter().enumerate().filter(|(_, x)| x.sel).map(|(i, x)| (i, x.f.clone())).collect();
        match what {
            "find" => {
                let args = vec!["find".into(), path.clone(), b(r.undelete), b(r.deep), b(r.previous)];
                {
                    let mut st = state.lock().unwrap();
                    *st = RescueState { source: path.clone(), ..Default::default() };
                }
                r.job.run_thread(repaint, move |em| {
                    let cmd = helper_cmd(&s, &path, args);
                    crate::par::stream_command(cmd, em, &|_| vec![], &mut |line, _| {
                        if let Some(j) = line.strip_prefix("@R\t") {
                            if let Ok(f) = serde_json::from_str::<Found>(j) {
                                state.lock().unwrap().rows.push(Row { f, sel: false, status: String::new(), threat: None, sha: None, wiped: false });
                            }
                        } else if let Some(j) = line.strip_prefix("@V\t") {
                            if let Ok(v) = serde_json::from_str::<Volume>(j) {
                                state.lock().unwrap().volumes.push(v);
                            }
                        }
                    });
                });
            }
            "scan" => {
                let _ = self.s.save();
                let Some(items) = write_json("items", &selected) else { return };
                let shm = format!("/dev/shm/arch-sentinel-rescue-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0));
                let args = vec!["scan".into(), path.clone(), items.clone(), crate::settings::config_path().display().to_string(), shm.clone()];
                for (i, _) in &selected {
                    if let Some(row) = state.lock().unwrap().rows.get_mut(*i) {
                        row.status = "Scanning…".into();
                    }
                }
                r.job.run_thread(repaint, move |em| {
                    let cmd = helper_cmd(&s, &path, args);
                    let st2 = state.clone();
                    crate::par::stream_command(cmd, em, &|_| vec![], &mut |line, _| {
                        if let Some(rest) = line.strip_prefix("@H\t") {
                            if let Some((i, h)) = rest.split_once('\t') {
                                if let Ok(i) = i.parse::<usize>() {
                                    if let Some(row) = st2.lock().unwrap().rows.get_mut(i) {
                                        row.sha = Some(h.to_string());
                                    }
                                }
                            }
                        } else if let Some(rest) = line.strip_prefix("@S\t") {
                            if let Some((i, why)) = rest.split_once('\t') {
                                if let Ok(i) = i.parse::<usize>() {
                                    if let Some(row) = st2.lock().unwrap().rows.get_mut(i) {
                                        row.status = format!("Not scanned: {why}");
                                    }
                                }
                            }
                        }
                    });
                    // Tie each finding (named <index>.<ext> in memory) back to its row.
                    let found: Vec<Finding> = em.findings();
                    let mut st = state.lock().unwrap();
                    for (i, _) in &selected {
                        if let Some(row) = st.rows.get_mut(*i) {
                            if row.status == "Scanning…" {
                                row.status = "Scanned: clean".into();
                            }
                        }
                    }
                    for f in found {
                        let name = std::path::Path::new(&f.path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                        if let Some(i) = name.split('.').next().and_then(|x| x.parse::<usize>().ok()) {
                            if let Some(row) = st.rows.get_mut(i) {
                                let worse = row.threat.as_ref().map(|t| f.sev < t.0).unwrap_or(true);
                                if worse {
                                    row.threat = Some((f.sev, format!("{} — {}", f.kind, f.detail)));
                                }
                                row.status = format!("FLAGGED: {}", f.kind);
                            }
                        }
                    }
                    let flagged = st.rows.iter().filter(|r| r.threat.is_some()).count();
                    drop(st);
                    if flagged > 0 {
                        let _ = std::process::Command::new("notify-send")
                            .args(["-a", "Arch Sentinel", "-i", "security-low", &format!("{flagged} deleted file(s) flagged"), "They're marked in red on the Deleted files page."])
                            .spawn();
                    }
                    let _ = std::fs::remove_file(&items);
                });
            }
            "wipe" => {
                let volumes = state.lock().unwrap().volumes.clone();
                let (Some(items), Some(vols)) = (write_json("wipe", &selected), write_json("vols", &volumes)) else { return };
                let args = vec!["wipe".into(), path.clone(), items.clone(), vols.clone()];
                r.job.run_thread(repaint, move |em| {
                    let cmd = helper_cmd(&s, &path, args);
                    crate::par::stream_command(cmd, em, &|_| vec![], &mut |line, _| {
                        let mut st = state.lock().unwrap();
                        if let Some(i) = line.strip_prefix("@Z\t").and_then(|x| x.trim().parse::<usize>().ok()) {
                            if let Some(row) = st.rows.get_mut(i) {
                                row.wiped = true;
                                row.sel = false;
                                row.status = "Zero-filled in place".into();
                                row.f.note = "Zero-filled".into();
                            }
                        } else if let Some(rest) = line.strip_prefix("@S\t") {
                            if let Some((i, why)) = rest.split_once('\t') {
                                if let Some(row) = i.parse::<usize>().ok().and_then(|i| st.rows.get_mut(i)) {
                                    row.status = format!("Left alone: {why}");
                                }
                            }
                        } else if let Some(m) = line.strip_prefix("@M\t") {
                            st.mounted = m.split_whitespace().map(|x| x.to_string()).collect();
                        }
                    });
                    let _ = std::fs::remove_file(&items);
                    let _ = std::fs::remove_file(&vols);
                });
            }
            "recover" => {
                let dest = r.dest.trim().to_string();
                let Some(items) = write_json("recover", &selected) else { return };
                let args = vec!["recover".into(), path.clone(), items.clone(), dest];
                r.job.run_thread(repaint, move |em| {
                    let cmd = helper_cmd(&s, &path, args);
                    crate::par::stream_command(cmd, em, &|_| vec![], &mut |_, _| {});
                    let _ = std::fs::remove_file(&items);
                });
            }
            _ => {}
        }
    }

    pub fn rescue_find_now(&mut self, ctx: &egui::Context) {
        self.rescue_run(ctx, "find");
    }

    pub fn rescue_panel(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        if self.rescue.devices.is_empty() {
            self.rescue.devices = crate::rescue::disk::list_devices();
        }
        let running = self.rescue.job.is_running();
        let mut action: Option<&str> = None;
        card(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new("Your File Rescue engine reads the disk itself: it finds deleted files with their real names and folders on FAT, exFAT and NTFS, finds files by their content on any disk, and finds partitions that were deleted. Then you can virus-scan them right where they are (read into memory, nothing written to the disk), zero-fill them in place, or recover them.").size(12.5).color(Color32::from_gray(220)));
            ui.add_space(6.0);
            ui.add_enabled_ui(!running, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Disk");
                    let shown = if self.rescue.path.is_empty() { "choose a disk, partition or image…".to_string() } else { self.rescue.path.clone() };
                    egui::ComboBox::from_id_salt("rsc_dev").selected_text(shown).width(380.0).show_ui(ui, |ui| {
                        for d in &self.rescue.devices {
                            let t = format!("{} — {} {}", d.path, crate::rescue::disk::human_size(d.size), d.label.trim());
                            ui.selectable_value(&mut self.rescue.path, d.path.clone(), t);
                        }
                        let p = practice_image();
                        if std::path::Path::new(&p).exists() {
                            ui.selectable_value(&mut self.rescue.path, p.clone(), "Practice disk image (safe to try everything on)");
                        }
                    });
                    ui.add(egui::TextEdit::singleline(&mut self.rescue.path).hint_text("or a disk image file").desired_width(260.0));
                    if ui.button("Make a practice disk").on_hover_text("A small disk image with deleted files on it, to try finding, scanning and wiping safely").clicked() {
                        let p = practice_image();
                        let _ = std::fs::create_dir_all(crate::settings::data_dir());
                        match crate::rescue::sample::make_sample(std::path::Path::new(&p)) {
                            Ok(()) => {
                                self.rescue.path = p;
                                self.toast("Practice disk image made — try it.", true);
                            }
                            Err(e) => self.toast(format!("Couldn't make it: {e}"), false),
                        }
                    }
                });
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.rescue.undelete, "By name (FAT, exFAT, NTFS)");
                    ui.checkbox(&mut self.rescue.deep, "By content (any disk, slower)");
                    ui.checkbox(&mut self.rescue.previous, "Deleted or replaced partitions");
                });
                ui.horizontal(|ui| {
                    if ui.add_enabled(!self.rescue.path.trim().is_empty(), primary("Find deleted files")).on_hover_text("Reads the disk only. A real disk asks for your password; an image file doesn't").clicked() {
                        action = Some("find");
                    }
                    if needs_admin(self.rescue.path.trim()) {
                        ui.label(RichText::new("Reading a whole disk asks for your password. Name search doesn't work on ext4 or btrfs — use content search there.").size(12.0).color(TEXT_DIM));
                    }
                });
            });
            if running {
                ui.horizontal(|ui| {
                    if ui.button("Stop").clicked() {
                        self.rescue.job.stop();
                    }
                    ui.add(egui::Spinner::new());
                    ui.label(self.rescue.job.state.lock().unwrap().progress.clone());
                });
            }
            let st = self.rescue.job.state.lock().unwrap();
            if !running && !st.summary.is_empty() {
                ui.label(RichText::new(&st.summary).color(Color32::WHITE));
            }
            // Everything the engine and ClamAV said, warnings included.
            if !st.log.is_empty() {
                let warns = st.log.iter().filter(|l| l.to_lowercase().contains("warning") || l.to_lowercase().contains("error") || l.starts_with("Couldn't")).count();
                egui::CollapsingHeader::new(RichText::new(format!("Log ({} lines{})", st.log.len(), if warns > 0 { format!(", {warns} warning(s)") } else { String::new() })).color(if warns > 0 { AMBER } else { TEXT_DIM }))
                    .id_salt("rsc_log")
                    .show(ui, |ui| {
                        egui::ScrollArea::vertical().id_salt("rsc_log_s").max_height(180.0).stick_to_bottom(true).show(ui, |ui| {
                            for l in st.log.iter().rev().take(400).rev() {
                                let low = l.to_lowercase();
                                let col = if low.contains("warning") || low.contains("error") { AMBER } else { Color32::from_gray(180) };
                                ui.label(RichText::new(l).monospace().size(11.5).color(col));
                            }
                        });
                    });
            }
        });
        if let Some(a) = action.take() {
            self.rescue_run(&ctx, a);
        }
        ui.add_space(6.0);

        // ---- results ----
        let n_rows = self.rescue.state.lock().unwrap().rows.len();
        if n_rows == 0 {
            return;
        }
        let mounted = self.rescue.state.lock().unwrap().mounted.clone();
        card(ui, |ui| {
            ui.set_width(ui.available_width());
            let (n_sel, n_flag, n_wiped) = {
                let st = self.rescue.state.lock().unwrap();
                (st.rows.iter().filter(|r| r.sel).count(), st.rows.iter().filter(|r| r.threat.is_some()).count(), st.rows.iter().filter(|r| r.wiped).count())
            };
            if n_flag > 0 {
                let mut show = false;
                egui::Frame::new().fill(RED.linear_multiply(0.15)).corner_radius(6.0).inner_margin(egui::Margin::symmetric(10, 6)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("{n_flag} deleted file(s) flagged by the virus scan — shown in red below, with what was found.")).strong().color(RED));
                        show = ui.button("Show only these").clicked();
                    });
                });
                if show {
                    self.rescue.only_flagged = true;
                }
                ui.add_space(4.0);
            }
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(format!("{n_rows} found · {n_sel} selected · {n_flag} flagged · {n_wiped} zero-filled")).strong().color(Color32::WHITE));
                ui.add(egui::TextEdit::singleline(&mut self.rescue.filter).hint_text("Filter by name or folder…").desired_width(200.0));
                ui.checkbox(&mut self.rescue.only_flagged, "Only flagged");
                let mut st = self.rescue.state.lock().unwrap();
                if ui.small_button("Select all").clicked() {
                    st.rows.iter_mut().filter(|r| !r.wiped).for_each(|r| r.sel = true);
                }
                if ui.small_button("None").clicked() {
                    st.rows.iter_mut().for_each(|r| r.sel = false);
                }
                if ui.small_button("Programs & archives").clicked() {
                    use crate::rescue::model::Category::*;
                    st.rows.iter_mut().for_each(|r| r.sel = !r.wiped && matches!(r.f.category(), Programs | Archives | Documents));
                }
                if ui.small_button("Flagged").clicked() {
                    st.rows.iter_mut().for_each(|r| r.sel = !r.wiped && r.threat.is_some());
                }
                // Select by extension: every type found, with how many (and how many are ticked).
                let mut exts: std::collections::BTreeMap<String, (usize, usize)> = Default::default();
                for r in st.rows.iter().filter(|r| !r.wiped) {
                    let e = if r.f.ext.is_empty() { "(no extension)".to_string() } else { r.f.ext.to_lowercase() };
                    let c = exts.entry(e).or_default();
                    c.0 += 1;
                    if r.sel {
                        c.1 += 1;
                    }
                }
                let mut toggle: Option<(String, bool)> = None;
                egui::ComboBox::from_id_salt("rsc_ext")
                    .selected_text("Select by extension…")
                    .height(360.0)
                    .show_ui(ui, |ui| {
                        if exts.is_empty() {
                            ui.label(RichText::new("Nothing to select").color(TEXT_DIM));
                        }
                        for (e, (n, on)) in &exts {
                            let all = *on == *n;
                            let label = if e.starts_with('(') { format!("{e}  {n}") } else { format!(".{e}  {n}") };
                            let mut ticked = all;
                            if ui.checkbox(&mut ticked, label).on_hover_text(if all { "Untick all of these" } else { "Tick all of these" }).changed() {
                                toggle = Some((e.clone(), ticked));
                            }
                        }
                    })
                    .response
                    .on_hover_text("Tick or untick every found file of one type at once");
                if let Some((e, on)) = toggle {
                    for r in st.rows.iter_mut().filter(|r| !r.wiped) {
                        let re = if r.f.ext.is_empty() { "(no extension)".to_string() } else { r.f.ext.to_lowercase() };
                        if re == e {
                            r.sel = on;
                        }
                    }
                }
            });
            ui.horizontal_wrapped(|ui| {
                ui.add_enabled_ui(!running && n_sel > 0, |ui| {
                    if ui.add(primary(&format!("Virus-scan {n_sel} in place"))).on_hover_text("Each file is read into memory and scanned (ClamAV, and Paranoid if it's on); nothing is written to the disk").clicked() {
                        action = Some("scan");
                    }
                    if ui.add(egui::Button::new(RichText::new(format!("Zero-fill {n_sel} in place…")).color(Color32::WHITE)).fill(RED.linear_multiply(0.7))).clicked() {
                        self.rescue.wipe_ask = true;
                        self.rescue.wipe_sure = false;
                    }
                    ui.separator();
                    ui.add(egui::TextEdit::singleline(&mut self.rescue.dest).hint_text("recover into… (a folder on another drive)").desired_width(260.0));
                    let src = self.rescue.path.trim().to_string();
                    let dest_dev = crate::recover::device_of(self.rescue.dest.trim());
                    let same = !self.rescue.dest.trim().is_empty() && needs_admin(&src) && (dest_dev.starts_with(&src) || src.starts_with(&dest_dev) && !dest_dev.is_empty());
                    if ui.add_enabled(self.rescue.dest.trim().starts_with('/') && !same, egui::Button::new(format!("Recover {n_sel}"))).on_hover_text("Copies them out with their original names and folders").clicked() {
                        action = Some("recover");
                    }
                    if same {
                        ui.label(RichText::new("That folder is on the disk you're recovering from — pick another drive.").size(12.0).color(RED));
                    }
                });
            });
            if !mounted.is_empty() {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("Zero-filling needs the disk unmounted: {} is in use.", mounted.join(", "))).color(AMBER));
                    if ui.button("Unmount it").on_hover_text("udisksctl unmount — close any files open on it first").clicked() {
                        let m = mounted.clone();
                        let state = self.rescue.state.clone();
                        self.task(&ctx, "Unmounting…", move |_| {
                            for d in &m {
                                let o = std::process::Command::new("udisksctl").args(["unmount", "-b", d]).output().map_err(|e| e.to_string())?;
                                if !o.status.success() {
                                    return Err(format!("Couldn't unmount {d}: {}", String::from_utf8_lossy(&o.stderr).trim()));
                                }
                            }
                            state.lock().unwrap().mounted.clear();
                            Ok("Unmounted. You can zero-fill now.".into())
                        });
                    }
                });
            }
            ui.add_space(4.0);
            // The list.
            let filter = self.rescue.filter.to_lowercase();
            let only_flagged = self.rescue.only_flagged;
            let mut vt_open: Option<(String, String)> = None;
            let mut st = self.rescue.state.lock().unwrap();
            let idx: Vec<usize> = st
                .rows
                .iter()
                .enumerate()
                .filter(|(_, r)| !only_flagged || r.threat.is_some())
                .filter(|(_, r)| filter.is_empty() || r.f.full_path().to_lowercase().contains(&filter))
                .map(|(i, _)| i)
                .collect();
            egui::ScrollArea::vertical().id_salt("rsc_rows").max_height(ui.available_height().max(200.0)).auto_shrink([false, true]).show_rows(ui, 22.0, idx.len(), |ui, range| {
                for &i in &idx[range] {
                    let r = &mut st.rows[i];
                    ui.horizontal(|ui| {
                        ui.add_enabled(!r.wiped, egui::Checkbox::without_text(&mut r.sel));
                        let col = if r.wiped { TEXT_DIM } else if r.threat.is_some() { RED } else { Color32::WHITE };
                        ui.allocate_ui_with_layout(egui::vec2(360.0, 18.0), egui::Layout::left_to_right(egui::Align::Center), |ui| {
                            ui.set_min_width(360.0);
                            ui.add(egui::Label::new(RichText::new(r.f.full_path()).size(12.5).color(col)).truncate()).on_hover_text(&r.f.note);
                        });
                        ui.add_sized([70.0, 18.0], egui::Label::new(RichText::new(crate::rescue::disk::human_size(r.f.size)).size(12.0).color(TEXT_DIM)));
                        ui.add_sized([90.0, 18.0], egui::Label::new(RichText::new(r.f.category().label()).size(12.0).color(TEXT_DIM)).truncate());
                        ui.add_sized([60.0, 18.0], egui::Label::new(RichText::new(r.f.chance.label()).size(12.0).color(match r.f.chance {
                            crate::rescue::model::Chance::Good => GREEN,
                            crate::rescue::model::Chance::Fair => YELLOW,
                            _ => TEXT_DIM,
                        })));
                        ui.add_sized([70.0, 18.0], egui::Label::new(RichText::new(if r.f.method == Method::Undelete { "by name" } else { "by content" }).size(12.0).color(TEXT_DIM)));
                        let status = match &r.threat {
                            Some((_, t)) => t.clone(),
                            None => r.status.clone(),
                        };
                        ui.add(egui::Label::new(RichText::new(status).size(12.0).color(if r.threat.is_some() { RED } else if r.wiped { GREEN } else { TEXT_DIM })).truncate());
                        if let Some(h) = &r.sha {
                            if ui.small_button("VirusTotal").clicked() {
                                vt_open = Some((r.f.full_path(), h.clone()));
                            }
                        }
                    });
                }
            });
            drop(st);
            if let Some((p, h)) = vt_open {
                self.open_vt(&ctx, p, Some(h), false);
            }
        });
        if let Some(a) = action {
            self.rescue_run(&ctx, a);
        }
        self.rescue_wipe_dialog(&ctx);
    }

    fn rescue_wipe_dialog(&mut self, ctx: &egui::Context) {
        if !self.rescue.wipe_ask {
            return;
        }
        let n = self.rescue.state.lock().unwrap().rows.iter().filter(|r| r.sel).count();
        let path = self.rescue.path.clone();
        let mut go = false;
        let mut close = false;
        egui::Window::new(RichText::new("Zero-fill deleted files in place").color(RED).strong())
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .default_width(560.0)
            .show(ctx, |ui| {
                ui.label(RichText::new(format!("{n} deleted file(s) on {path}")).color(Color32::WHITE));
                ui.add_space(4.0);
                for t in [
                    "Their bytes are overwritten with zeros right where they lie, so they can't be recovered any more. This can't be undone.",
                    "Only pieces the file system marks as free are touched; any file whose space is (partly) in use again, or that can't be checked, is left alone and you're told why. Files you still have are never written to.",
                    "The disk must not be mounted while this runs; you'll be offered to unmount it. A real disk asks for your password.",
                    "On SSDs and copy-on-write file systems old copies can survive elsewhere on the drive.",
                ] {
                    ui.label(RichText::new(format!("• {t}")).size(12.5).color(Color32::from_gray(220)));
                }
                ui.add_space(6.0);
                ui.checkbox(&mut self.rescue.wipe_sure, "I want these deleted files gone for good");
                ui.horizontal(|ui| {
                    if ui.add_enabled(self.rescue.wipe_sure, egui::Button::new(RichText::new("Zero-fill them").color(Color32::WHITE)).fill(RED.linear_multiply(0.8))).clicked() {
                        go = true;
                    }
                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                });
            });
        if go {
            self.rescue.wipe_ask = false;
            self.rescue_run(ctx, "wipe");
        } else if close {
            self.rescue.wipe_ask = false;
        }
    }
}

fn b(v: bool) -> String {
    if v { "1".into() } else { "0".into() }
}
