//! The "Snapshots (experimental)" page.

use crate::app::*;
use crate::snap::Snapshot;
use eframe::egui::{self, Color32, RichText, Ui};
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct SnapUi {
    pub job: crate::jobs::Job,
    pub rows: Arc<Mutex<Vec<(Snapshot, bool)>>>,
    pub understood: bool,
    pub filter: String,
}

impl App {
    pub fn snapshots_page(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        let running = self.snap.job.is_running();
        ui.horizontal(|ui| {
            ui.heading(RichText::new("Snapshots").color(Color32::WHITE));
            pill(ui, "experimental", AMBER);
        });
        ui.label(RichText::new("Virus-scans your btrfs snapshots (Timeshift, Snapper) — so a snapshot you might restore one day isn't hiding something.").color(TEXT_DIM));
        ui.add_space(6.0);
        egui::Frame::new().fill(RED.linear_multiply(0.14)).stroke(egui::Stroke::new(1.0, RED)).corner_radius(8.0).inner_margin(egui::Margin::same(12)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new("Read this before you start").strong().size(16.0).color(RED));
            for t in [
                "This needs administrator rights. To reach the snapshots, the app mounts your drive's top level READ-ONLY in a private folder under /run for the length of the scan, and unmounts it afterwards — also when you stop the scan. Nothing inside a snapshot is changed.",
                "It's heavy: a snapshot of the system holds every file of your system at that moment, and each snapshot is scanned in full. Several snapshots can take hours and keep the disk busy (everything still runs at the lowest priority).",
                "Files found in a snapshot can't be quarantined, cleaned or deleted from here — snapshots are read-only on purpose, and changing them by hand can break them. If a snapshot is infected, delete that whole snapshot in Timeshift or Snapper, and don't restore it.",
                "Most snapshot files are the same as your current ones, so they'll usually give the same results as a normal scan. Old snapshots can still hold files you've since removed.",
                "If the app or computer stops in the middle, a read-only mount can be left under /run; it goes away at the next restart and does no harm.",
            ] {
                ui.label(RichText::new(format!("• {t}")).size(12.5).color(Color32::from_gray(225)));
            }
            ui.add_space(4.0);
            ui.checkbox(&mut self.snap.understood, RichText::new("I understand — let me scan snapshots").strong());
        });
        ui.add_space(8.0);
        if !self.snap.understood {
            return;
        }
        if crate::snap::btrfs_devices().is_empty() {
            card(ui, |ui| {
                ui.label(RichText::new("No btrfs drives are mounted, so there are no snapshots to scan.").color(TEXT_DIM));
            });
            return;
        }
        let mut find = false;
        let mut scan = false;
        card(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                find = ui.add_enabled(!running, primary("Find snapshots")).on_hover_text("Asks for your password once per session").clicked();
                if running {
                    if ui.button("Stop").clicked() {
                        self.snap.job.stop();
                    }
                    ui.add(egui::Spinner::new());
                    ui.add(egui::Label::new(self.snap.job.state.lock().unwrap().progress.clone()).truncate());
                }
            });
            let mut rows = self.snap.rows.lock().unwrap();
            if rows.is_empty() {
                ui.label(RichText::new("Press Find snapshots to list them.").color(TEXT_DIM));
                return;
            }
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("{} snapshot(s)", rows.len())).strong().color(Color32::WHITE));
                ui.add(egui::TextEdit::singleline(&mut self.snap.filter).hint_text("Filter by date or path…").desired_width(200.0));
                if ui.small_button("Newest only").on_hover_text("Tick the newest snapshot of each kind (system, home)").clicked() {
                    let mut seen = std::collections::HashSet::new();
                    let mut order: Vec<usize> = (0..rows.len()).collect();
                    order.sort_by(|&a, &b| rows[b].0.otime.cmp(&rows[a].0.otime));
                    for r in rows.iter_mut() {
                        r.1 = false;
                    }
                    for i in order {
                        let key = (rows[i].0.dev.clone(), rows[i].0.holds());
                        if seen.insert(key) {
                            rows[i].1 = true;
                        }
                    }
                }
                if ui.small_button("Home folders only").clicked() {
                    for r in rows.iter_mut() {
                        r.1 = r.0.holds() == "home folders";
                    }
                }
                if ui.small_button("All").clicked() {
                    rows.iter_mut().for_each(|r| r.1 = true);
                }
                if ui.small_button("None").clicked() {
                    rows.iter_mut().for_each(|r| r.1 = false);
                }
            });
            let f = self.snap.filter.to_lowercase();
            egui::ScrollArea::vertical().id_salt("snap_rows").max_height(200.0).show(ui, |ui| {
                for (s, sel) in rows.iter_mut().filter(|r| f.is_empty() || r.0.path.to_lowercase().contains(&f) || r.0.otime.contains(&f)) {
                    ui.horizontal(|ui| {
                        ui.checkbox(sel, "");
                        ui.add_sized([150.0, 18.0], egui::Label::new(RichText::new(&s.otime).monospace().size(12.0).color(Color32::WHITE)));
                        ui.add_sized([80.0, 18.0], egui::Label::new(RichText::new(s.tool()).size(12.0).color(TEXT_DIM)));
                        ui.add_sized([110.0, 18.0], egui::Label::new(RichText::new(s.holds()).size(12.0).color(Color32::from_gray(210))));
                        ui.add(egui::Label::new(RichText::new(&s.path).monospace().size(11.5).color(TEXT_DIM)).truncate());
                    });
                }
            });
            let n = rows.iter().filter(|r| r.1).count();
            ui.horizontal(|ui| {
                scan = ui.add_enabled(!running && n > 0, egui::Button::new(RichText::new(format!("Scan {n} snapshot(s)")).color(Color32::WHITE)).fill(RED.linear_multiply(0.7))).on_hover_text("Mounts them read-only, scans with ClamAV (and Paranoid when it's on), then unmounts").clicked();
                ui.label(RichText::new("Uses your ClamAV options, threads and VirusTotal settings.").size(12.0).color(TEXT_DIM));
            });
        });
        if find {
            let s = self.s.clone();
            let rows = self.snap.rows.clone();
            rows.lock().unwrap().clear();
            let c2 = ctx.clone();
            self.snap.job.run_thread(move || c2.request_repaint(), move |em| {
                let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default();
                let cmd = crate::par::command(&s, true, &exe, &["--helper".into(), "snap".into(), "list".into()]);
                crate::par::stream_command(cmd, em, &|_| vec![], &mut |line, _| {
                    if let Some(j) = line.strip_prefix("@N\t") {
                        if let Ok(sn) = serde_json::from_str::<Snapshot>(j) {
                            rows.lock().unwrap().push((sn, false));
                        }
                    }
                });
                rows.lock().unwrap().sort_by(|a, b| b.0.otime.cmp(&a.0.otime));
            });
        }
        if scan {
            let _ = self.s.save();
            let s = self.s.clone();
            let picked: Vec<Snapshot> = self.snap.rows.lock().unwrap().iter().filter(|r| r.1).map(|r| r.0.clone()).collect();
            let c2 = ctx.clone();
            self.snap.job.run_thread(move || c2.request_repaint(), move |em| {
                let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default();
                let cfg = crate::settings::config_path().display().to_string();
                let mut devs: Vec<String> = picked.iter().map(|p| p.dev.clone()).collect();
                devs.sort();
                devs.dedup();
                for dev in devs {
                    if em.cancelled() {
                        break;
                    }
                    let paths: Vec<String> = picked.iter().filter(|p| p.dev == dev).map(|p| p.path.clone()).collect();
                    em.log(format!("Scanning {} snapshot(s) on {dev}", paths.len()));
                    let script = crate::snap::scan_script(&exe, &cfg, &dev, &paths);
                    let cmd = crate::par::command(&s, true, "/bin/sh", &["-c".to_string(), script]);
                    crate::par::stream_command(cmd, em, &|_| vec![], &mut |_, _| {});
                }
                let n = em.findings().iter().filter(|f| f.detail.starts_with("ClamAV match")).count();
                if !em.cancelled() {
                    em.done(format!("Scanned {} snapshot(s): ClamAV flagged {n} file(s). The snapshots were unmounted again.", picked.len()));
                }
            });
        }
        ui.add_space(6.0);
        // Results.
        let st = self.snap.job.state.lock().unwrap();
        if !st.findings.is_empty() || !st.summary.is_empty() {
            let mut vt: Option<(String, String)> = None;
            card(ui, |ui| {
                ui.set_width(ui.available_width());
                if !st.summary.is_empty() {
                    ui.label(RichText::new(&st.summary).color(Color32::WHITE));
                }
                let mut rows: Vec<&crate::jobs::Finding> = st.findings.iter().collect();
                rows.sort_by(|a, b| a.sev.cmp(&b.sev));
                egui::ScrollArea::vertical().id_salt("snap_found").max_height(260.0).show(ui, |ui| {
                    for f in rows.iter().take(1000) {
                        ui.horizontal(|ui| {
                            ui.add_sized([60.0, 16.0], egui::Label::new(RichText::new(f.sev.label()).color(sev_color(f.sev)).strong().size(12.0)));
                            ui.add_sized([170.0, 16.0], egui::Label::new(RichText::new(&f.kind).size(12.0).color(Color32::from_gray(210))).truncate());
                            ui.add(egui::Label::new(RichText::new(crate::snap::readable_path(&f.path)).monospace().size(11.5).color(Color32::WHITE)).truncate())
                                .on_hover_text(&f.detail);
                            if let Some(h) = crate::clam::sha_in(&f.detail) {
                                if ui.small_button("VirusTotal").clicked() {
                                    vt = Some((crate::snap::readable_path(&f.path), h));
                                }
                            }
                        });
                    }
                });
                // Which snapshots had something, so you know which ones to delete in Timeshift.
                let snaps: Vec<Snapshot> = self.snap.rows.lock().unwrap().iter().map(|r| r.0.clone()).collect();
                let mut hit: std::collections::BTreeMap<String, (String, usize)> = Default::default();
                for f in rows.iter().filter(|f| f.sev == crate::jobs::Sev::High || f.sev == crate::jobs::Sev::Medium) {
                    if let Some(sn) = crate::snap::snapshot_of(&snaps, &crate::snap::readable_path(&f.path)) {
                        let e = hit.entry(sn.path.clone()).or_insert((format!("{} — {} ({})", sn.otime, sn.holds(), sn.tool()), 0));
                        e.1 += 1;
                    }
                }
                if !hit.is_empty() {
                    ui.add_space(4.0);
                    ui.label(RichText::new("Snapshots with findings:").strong().color(Color32::WHITE));
                    for (_, (what, n)) in &hit {
                        ui.label(RichText::new(format!("• {what}: {n} file(s)")).color(AMBER));
                    }
                }
                if rows.iter().any(|f| f.sev == crate::jobs::Sev::High) {
                    ui.label(RichText::new("To get rid of an infected snapshot, delete it in Timeshift (or Snapper) — and don't restore it.").color(AMBER));
                    if std::path::Path::new("/usr/bin/timeshift-launcher").exists() && ui.button("Open Timeshift").clicked() {
                        let _ = std::process::Command::new("/usr/bin/timeshift-launcher").spawn();
                    }
                }
            });
            drop(st);
            if let Some((p, h)) = vt {
                self.open_vt(&ctx, p, Some(h), false);
            }
        }
    }
}
