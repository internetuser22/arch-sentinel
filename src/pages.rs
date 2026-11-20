//! Network, quarantine, background-job and settings pages.

use crate::app::*;
use crate::background;
use crate::clam;
use crate::net::{self, Conn, Trust};
use crate::pkg;
use crate::quarantine;
use crate::settings::{config_path, JobKind, Schedule, Settings};
use eframe::egui::{self, Color32, RichText, Ui};
use std::process::Command;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

pub fn admin_sh(script: &str) -> Result<String, String> {
    let o = crate::root::output({ let mut pk = Command::new("pkexec"); pk.args(["/bin/sh", "-c", script]); pk }).map_err(|e| e.to_string())?;
    if o.status.success() {
        Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
    } else if o.status.code() == Some(126) || o.status.code() == Some(127) {
        Err("Administrator rights were refused.".into())
    } else {
        Err(format!("Failed: {}", String::from_utf8_lossy(&o.stderr).trim()))
    }
}

fn list_editor(ui: &mut Ui, id: &str, title: &str, list: &mut Vec<String>, new: &mut String) -> bool {
    let mut changed = false;
    ui.label(RichText::new(title).color(TEXT_DIM));
    let mut remove = None;
    ui.horizontal_wrapped(|ui| {
        for (i, item) in list.iter().enumerate() {
            egui::Frame::new()
                .fill(Color32::from_rgb(0x2a, 0x30, 0x3a))
                .corner_radius(10.0)
                .inner_margin(egui::Margin::symmetric(8, 2))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(item).monospace().size(12.0));
                        if ui.small_button("x").clicked() {
                            remove = Some(i);
                        }
                    });
                });
        }
    });
    if let Some(i) = remove {
        list.remove(i);
        changed = true;
    }
    ui.horizontal(|ui| {
        let r = ui.add(egui::TextEdit::singleline(new).id_salt(("add", id)).hint_text("add…").desired_width(320.0));
        let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if (ui.button("Add").clicked() || enter) && !new.trim().is_empty() {
            list.push(new.trim().to_string());
            new.clear();
            changed = true;
        }
    });
    ui.add_space(4.0);
    changed
}

impl App {
    // ---------------- Quarantine ----------------

    pub fn quarantine_page(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        let mut refresh = false;
        ui.horizontal(|ui| {
            ui.heading(RichText::new("Quarantine").color(Color32::WHITE));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                refresh = ui.button("Refresh").clicked();
            });
        });
        // Only re-read the records when the folder itself changed (one quick look at its
        // "last changed" time), so changes made elsewhere — a background scan, another copy
        // of the app — show up without any repeated work.
        let changed = std::fs::metadata(quarantine::dir()).and_then(|m| m.modified()).ok();
        if refresh || changed != self.q_seen {
            self.shared.lock().unwrap().quarantine = quarantine::list();
            self.q_seen = changed;
        }
        ui.label(RichText::new("Flagged files are locked away here with no permissions, together with where they came from. Put a file back if it was a false positive, try to clean it, or delete it for good.").color(TEXT_DIM));
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("Kept in {} — the same folder for every version of the app; updates never touch it.", quarantine::dir().display())).size(12.0).color(TEXT_DIM));
            if ui.small_button("Open folder").clicked() {
                let _ = std::fs::create_dir_all(quarantine::dir());
                let _ = Command::new("xdg-open").arg(quarantine::dir()).spawn();
            }
        });
        ui.add_space(8.0);
        let entries = self.shared.lock().unwrap().quarantine.clone();
        if entries.is_empty() {
            card(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("Quarantine is empty. Files you quarantine from a virus scan show up here; the history below shows what happened to earlier ones.").color(TEXT_DIM));
            });
            ui.add_space(6.0);
            self.quarantine_history(ui);
            return;
        }
        let mut shred: Option<quarantine::Entry> = None;
        let mut to_sandbox: Option<String> = None;
        let mut vt_open: Option<(String, String)> = None;
        let busy = self.shared.lock().unwrap().busy.is_some();
        egui::ScrollArea::vertical().show(ui, |ui| {
            for e in entries {
                card(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&e.threat).strong().color(RED));
                        ui.label(RichText::new(&e.original_path).monospace().color(Color32::WHITE));
                    });
                    ui.label(
                        RichText::new(format!(
                            "{} KB · quarantined {} · mode {:o}{}{}",
                            e.size / 1024,
                            e.quarantined_at.replace('T', " ").trim_end_matches('Z'),
                            e.mode,
                            e.package.as_ref().map(|p| format!(" · from package {p}")).unwrap_or_default(),
                            if e.elevated { " · needed administrator rights" } else { "" }
                        ))
                        .size(12.0)
                        .color(TEXT_DIM),
                    );
                    ui.label(RichText::new(format!("sha256 {}", e.sha256)).monospace().size(11.0).color(TEXT_DIM));
                    if !e.note.is_empty() {
                        ui.label(RichText::new(&e.note).color(GREEN));
                    }
                    ui.horizontal(|ui| {
                        let e1 = e.clone();
                        let arm_put = self.q_confirm.as_ref() == Some(&(e.id.clone(), "put"));
                        if ui
                            .add_enabled(!busy, egui::Button::new(if arm_put { RichText::new("Click again to put it back").color(AMBER) } else { RichText::new("Put back") }))
                            .on_hover_text("Move it back to its original folder with its old permissions (asks for a second click)")
                            .clicked()
                        {
                            if arm_put {
                                self.q_confirm = None;
                                self.task(&ctx, "Putting the file back…", move |sh| {
                                    let r = quarantine::restore(&e1);
                                    sh.lock().unwrap().quarantine = quarantine::list();
                                    r
                                });
                            } else {
                                self.q_confirm = Some((e.id.clone(), "put"));
                            }
                        }
                        let e2 = e.clone();
                        let tip = if e.package.is_some() {
                            "Reinstall the package that owns it, which brings back a clean original"
                        } else {
                            "Rescan with current signatures; for zip-style archives, remove only the infected parts"
                        };
                        if ui.add_enabled(!busy, egui::Button::new("Try to clean")).on_hover_text(tip).clicked() {
                            self.task(&ctx, "Trying to clean the file…", move |sh| {
                                let r = quarantine::clean(&e2);
                                sh.lock().unwrap().quarantine = quarantine::list();
                                r
                            });
                        }
                        let has_report = crate::vt::cached(&e.sha256).is_some();
                        if ui
                            .add_enabled(!busy && (has_report || !self.s.vt_api_key.is_empty()), egui::Button::new(if has_report { "VirusTotal report" } else { "Ask VirusTotal" }))
                            .on_hover_text("Look up this file's fingerprint on VirusTotal and read the full report")
                            .clicked()
                        {
                            vt_open = Some((e.original_path.clone(), e.sha256.clone()));
                        }
                        if ui.add_enabled(!busy, egui::Button::new("Test in sandbox…")).on_hover_text("Unpack it or run it in a throwaway sandbox with no network, and see what it tries to do").clicked() {
                            to_sandbox = Some(crate::quarantine::store_file(&e.id));
                        }
                        if ui.add_enabled(!busy, egui::Button::new(RichText::new("Zero-fill and delete…").color(RED))).on_hover_text("Overwrite with zeros, then delete (asks first)").clicked() {
                            shred = Some(e.clone());
                        }
                        let e4 = e.clone();
                        let arm_del = self.q_confirm.as_ref() == Some(&(e.id.clone(), "delete"));
                        if ui
                            .add_enabled(!busy, egui::Button::new(RichText::new(if arm_del { "Click again to delete it for good" } else { "Delete for good" }).color(RED)))
                            .on_hover_text("Deletes the quarantined copy; it can't be brought back (asks for a second click)")
                            .clicked()
                        {
                            if arm_del {
                                self.q_confirm = None;
                                self.task(&ctx, "Deleting…", move |sh| {
                                    let r = quarantine::delete(&e4);
                                    sh.lock().unwrap().quarantine = quarantine::list();
                                    r
                                });
                            } else {
                                self.q_confirm = Some((e.id.clone(), "delete"));
                            }
                        }
                    });
                });
                ui.add_space(6.0);
            }
        });
        ui.add_space(6.0);
        self.quarantine_history(ui);
        if let Some(e) = shred {
            self.ask_shred(e.original_path.clone(), e.threat.clone(), Some(e));
        }
        if let Some((p, sha)) = vt_open {
            self.open_vt(&ctx, p, Some(sha), false);
        }
        if let Some(p) = to_sandbox {
            self.sbx_sample = p;
            self.sbx_sure = false;
            self.page = crate::app::Page::Sandbox;
        }
    }

    fn quarantine_history(&mut self, ui: &mut Ui) {
        let h = quarantine::history(300);
        egui::CollapsingHeader::new(RichText::new(format!("History ({} event(s))", h.len())).color(TEXT_DIM)).id_salt("q_hist").default_open(true).show(ui, |ui| {
            if h.is_empty() {
                ui.label(RichText::new("Nothing yet. From now on every quarantine, put-back, clean and delete is recorded here, with the app version that did it.").size(12.0).color(TEXT_DIM));
                return;
            }
            egui::ScrollArea::vertical().id_salt("q_hist_s").max_height(220.0).show(ui, |ui| {
                egui::Grid::new("q_hist_g").num_columns(4).spacing([12.0, 3.0]).striped(true).show(ui, |ui| {
                    for (t, ver, action, path, threat) in &h {
                        ui.label(RichText::new(t.replace('T', " ").trim_end_matches('Z')).monospace().size(11.5).color(TEXT_DIM));
                        let col = if action.starts_with("put back") { AMBER } else if action.contains("delete") { RED } else { Color32::WHITE };
                        ui.label(RichText::new(action).size(12.0).color(col));
                        ui.add(egui::Label::new(RichText::new(format!("{path}  ({threat})")).size(12.0).color(Color32::from_gray(210))).truncate());
                        ui.label(RichText::new(format!("v{ver}")).size(11.0).color(TEXT_DIM));
                        ui.end_row();
                    }
                });
            });
        });
    }

    // ---------------- Network ----------------

    pub fn network_page(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        let refresh = Duration::from_secs(self.s.net_refresh_secs.max(1) as u64);
        if self.last_conn.map(|t| t.elapsed() >= refresh).unwrap_or(true) {
            self.conns = net::connections();
            self.last_conn = Some(Instant::now());
        }
        ctx.request_repaint_after(refresh);
        let st = self.status.lock().unwrap().clone();

        ui.heading(RichText::new("Connections & firewall rules").color(Color32::WHITE));
        ui.label(RichText::new("Every open connection with the program behind it. Verify checks each program against the package it came from; rules are written for the OpenSnitch service on this computer.").color(TEXT_DIM));
        ui.add_space(6.0);
        let mut service: Option<&'static str> = None;
        card(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("OpenSnitch").strong().color(Color32::WHITE));
                pill(ui, &st.snitch_active, state_color(&st.snitch_active));
                pill(ui, &st.snitch_enabled, state_color(&st.snitch_enabled));
                if let Some((def, intercept)) = &st.snitch_cfg {
                    ui.label(RichText::new(format!("Default action: {def}{}", if *intercept { " · asks about unknown connections" } else { "" })).color(TEXT_DIM));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    for (label, verb) in [("Restart", "restart"), ("Stop", "stop"), ("Start", "start")] {
                        if ui.button(label).clicked() {
                            service = Some(verb);
                        }
                    }
                });
            });
        });
        if let Some(verb) = service {
            let tick = self.status_tick.clone();
            self.task(&ctx, &format!("OpenSnitch: {verb}…"), move |_| {
                let o = crate::root::output({ let mut pk = Command::new("pkexec"); pk.args(["systemctl", verb, "opensnitchd.service"]); pk }).map_err(|e| e.to_string())?;
                tick.store(true, Ordering::Relaxed);
                if o.status.success() {
                    Ok(format!("OpenSnitch: {verb} done."))
                } else {
                    Err(String::from_utf8_lossy(&o.stderr).trim().to_string())
                }
            });
        }
        ui.add_space(6.0);
        self.firewall_mode_card(ui, &st);
        ui.add_space(6.0);

        let rules = self.shared.lock().unwrap().rules.clone();
        let verify = self.shared.lock().unwrap().verify.clone();
        let verifying = self.shared.lock().unwrap().verifying;
        let mut start_verify = false;
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("{} connections", self.conns.len())).strong().color(Color32::WHITE));
            ui.add(egui::TextEdit::singleline(&mut self.conn_filter).hint_text("Filter program, address, port…").desired_width(240.0));
            ui.checkbox(&mut self.hide_listening, "Hide listening");
            ui.checkbox(&mut self.hide_local, "Hide this-computer-only");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                start_verify = ui
                    .add_enabled(!verifying, egui::Button::new(if verifying { "Verifying…" } else { "Verify programs" }))
                    .on_hover_text("Check each program is from a package and still matches its checksums (paccheck)")
                    .clicked();
            });
        });
        if start_verify {
            let mut progs: Vec<String> = self.conns.iter().map(|c| c.program.clone()).collect();
            progs.sort();
            progs.dedup();
            let shared = self.shared.clone();
            shared.lock().unwrap().verifying = true;
            let c2 = ctx.clone();
            std::thread::spawn(move || {
                let owner = pkg::load_owned(true).map(|d| d.owner).unwrap_or_default();
                for p in progs {
                    let v = net::verify_program(&p, &owner);
                    shared.lock().unwrap().verify.insert(p, v);
                    c2.request_repaint();
                }
                shared.lock().unwrap().verifying = false;
                c2.request_repaint();
            });
        }
        let f = self.conn_filter.to_lowercase();
        let conns: Vec<Conn> = self
            .conns
            .iter()
            .filter(|c| !(self.hide_listening && (c.state == "Listening" || c.state == "Open")))
            .filter(|c| !(self.hide_local && (c.remote_ip.starts_with("127.") || c.remote_ip == "::1") && c.remote_port != 0))
            .filter(|c| f.is_empty() || c.program.to_lowercase().contains(&f) || c.remote.contains(&f) || c.local.contains(&f))
            .cloned()
            .collect();
        let mut make_rule: Option<(String, String, String)> = None;
        let table_h = (ui.available_height() * 0.5).max(160.0);
        egui::Frame::new().fill(PANEL).corner_radius(6.0).inner_margin(egui::Margin::same(6)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            let widths = [50.0, 230.0, 165.0, 185.0, 78.0, 150.0];
            ui.horizontal(|ui| {
                for (h, w) in ["Proto", "Program", "Local", "Remote", "State", "Check"].iter().zip(widths) {
                    ui.add_sized([w, 18.0], egui::Label::new(RichText::new(*h).size(12.0).color(TEXT_DIM)));
                }
                ui.label(RichText::new("OpenSnitch rule").size(12.0).color(TEXT_DIM));
            });
            ui.separator();
            if conns.is_empty() {
                ui.label(RichText::new("No connections match.").color(TEXT_DIM));
            }
            egui::ScrollArea::vertical().id_salt("conns").max_height(table_h).auto_shrink([false, true]).show_rows(ui, 24.0, conns.len(), |ui, range| {
                for c in &conns[range] {
                    ui.horizontal(|ui| {
                        let warn = net::port_warning(c.remote_port);
                        ui.add_sized([widths[0], 18.0], egui::Label::new(RichText::new(c.proto).size(12.0).color(TEXT_DIM)));
                        let name = std::path::Path::new(&c.program).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or(c.program.clone());
                        let name = if c.program.starts_with('(') { c.program.clone() } else { name };
                        ui.add_sized([widths[1], 18.0], egui::Label::new(RichText::new(format!("{name}{}", c.pid.map(|p| format!("  ({p})")).unwrap_or_default())).color(Color32::WHITE).size(12.5)).truncate())
                            .on_hover_text(&c.program);
                        ui.add_sized([widths[2], 18.0], egui::Label::new(RichText::new(&c.local).monospace().size(11.5).color(Color32::from_gray(190))).truncate());
                        ui.add_sized([widths[3], 18.0], egui::Label::new(RichText::new(&c.remote).monospace().size(11.5).color(if warn.is_some() { RED } else { Color32::from_gray(220) })).truncate())
                            .on_hover_text(warn.unwrap_or("remote end"));
                        let sc = match c.state {
                            "Connected" => GREEN,
                            "Listening" | "Open" => BLUE,
                            _ => TEXT_DIM,
                        };
                        ui.add_sized([widths[4], 18.0], egui::Label::new(RichText::new(c.state).size(12.0).color(sc)));
                        let (vt, vc, vnote) = match verify.get(&c.program) {
                            Some(v) => {
                                let col = match v.trust {
                                    Trust::Verified => GREEN,
                                    Trust::NotPackaged => AMBER,
                                    Trust::Changed | Trust::Suspicious => RED,
                                    Trust::Replaced => YELLOW,
                                    Trust::Unknown => TEXT_DIM,
                                };
                                (v.trust.label().to_string(), col, v.note.clone())
                            }
                            None => ("—".to_string(), TEXT_DIM, "press Verify programs".to_string()),
                        };
                        let (vt, vc) = if warn.is_some() { (format!("{vt} · odd port"), RED) } else { (vt, vc) };
                        ui.add_sized([widths[5], 18.0], egui::Label::new(RichText::new(vt).size(12.0).color(vc)).truncate())
                            .on_hover_text(format!("{vnote}{}", warn.map(|w| format!("\nRemote {w}")).unwrap_or_default()));
                        match rules.as_ref().and_then(|r| net::matching_rule(r, c)) {
                            Some(r) => {
                                ui.label(RichText::new(format!("{} · {}", r.action, r.name)).size(12.0).color(if r.action == "allow" { GREEN } else { RED }));
                            }
                            None => {
                                if c.program.starts_with('/') {
                                    if ui.small_button("Block").on_hover_text("Fill in an OpenSnitch rule that denies this program").clicked() {
                                        make_rule = Some(("deny".into(), "process.path".into(), c.program.clone()));
                                    }
                                    if ui.small_button("Allow").clicked() {
                                        make_rule = Some(("allow".into(), "process.path".into(), c.program.clone()));
                                    }
                                }
                                if c.remote_port != 0 && ui.small_button("Block address").clicked() {
                                    make_rule = Some(("deny".into(), "dest.ip".into(), c.remote_ip.clone()));
                                }
                            }
                        }
                    });
                }
            });
        });
        if let Some((a, o, d)) = make_rule {
            let short = std::path::Path::new(&d).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or(d.clone());
            self.rule_name = format!("{a}-{short}");
            self.rule_action = a;
            self.rule_operand = o;
            self.rule_data = d;
        }
        ui.add_space(8.0);

        let mut load = false;
        let mut delete: Option<String> = None;
        let mut toggle: Option<(String, net::Rule)> = None;
        let mut save_new = false;
        let errs = self.shared.lock().unwrap().rule_errors.clone();
        ui.columns(2, |cols| {
            card(&mut cols[0], |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(RichText::new("OpenSnitch rules").strong().color(Color32::WHITE));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        load = ui
                            .button(if rules.is_some() { "Reload" } else { "Load rules" })
                            .on_hover_text("The rules folder is only readable by the administrator, so this asks for your password")
                            .clicked();
                    });
                });
                match &rules {
                    None => {
                        ui.label(RichText::new("Press Load rules to see what OpenSnitch allows and denies, and which rule covers each connection.").color(TEXT_DIM));
                    }
                    Some(list) => {
                        if list.is_empty() {
                            ui.label(RichText::new("No rules yet.").color(TEXT_DIM));
                        }
                        egui::ScrollArea::vertical().id_salt("rules").max_height(170.0).show(ui, |ui| {
                            for (file, r) in list {
                                ui.horizontal(|ui| {
                                    pill(ui, &r.action, if r.action == "allow" { GREEN } else { RED });
                                    ui.add(egui::Label::new(RichText::new(&r.name).color(if r.enabled { Color32::WHITE } else { TEXT_DIM }).size(12.5)).truncate());
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        if ui.small_button("Delete").on_hover_text("Delete this rule").clicked() {
                                            delete = Some(file.clone());
                                        }
                                        if ui.small_button(if r.enabled { "Turn off" } else { "Turn on" }).clicked() {
                                            toggle = Some((file.clone(), r.clone()));
                                        }
                                        ui.add(egui::Label::new(RichText::new(r.summary()).color(TEXT_DIM).size(12.0)).truncate());
                                    });
                                });
                            }
                        });
                        for e in &errs {
                            ui.label(RichText::new(e).size(11.0).color(AMBER));
                        }
                    }
                }
            });
            card(&mut cols[1], |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("New rule").strong().color(Color32::WHITE));
                egui::Grid::new("newrule").num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
                    ui.label("Name");
                    ui.add(egui::TextEdit::singleline(&mut self.rule_name).hint_text("block-telemetry").desired_width(250.0));
                    ui.end_row();
                    ui.label("Action");
                    ui.horizontal(|ui| {
                        for a in ["allow", "deny", "reject"] {
                            ui.selectable_value(&mut self.rule_action, a.to_string(), a);
                        }
                    });
                    ui.end_row();
                    ui.label("When the");
                    egui::ComboBox::from_id_salt("operand").selected_text(net::operand_label(&self.rule_operand).to_string()).show_ui(ui, |ui| {
                        for o in ["process.path", "process.command", "dest.host", "dest.ip", "dest.port", "dest.network", "user.id", "protocol"] {
                            ui.selectable_value(&mut self.rule_operand, o.to_string(), net::operand_label(o));
                        }
                    });
                    ui.end_row();
                    ui.label("is");
                    ui.add(egui::TextEdit::singleline(&mut self.rule_data).hint_text("/usr/bin/app, example.com, 10.0.0.0/8…").desired_width(250.0));
                    ui.end_row();
                });
                let ok = !self.rule_name.trim().is_empty() && !self.rule_data.trim().is_empty();
                save_new = ui
                    .add_enabled(ok, egui::Button::new("Save rule to OpenSnitch"))
                    .on_hover_text("Writes the rule into OpenSnitch's rules folder (asks for your password); OpenSnitch picks it up right away")
                    .clicked();
            });
        });
        if load {
            self.task(&ctx, "Reading OpenSnitch rules…", |sh| {
                let o = crate::root::output({ let mut pk = Command::new("pkexec"); pk.args(["/bin/sh", "-c", &net::dump_rules_script()]); pk }).map_err(|e| e.to_string())?;
                if !o.status.success() {
                    return Err(format!("Couldn't read the rules: {}", String::from_utf8_lossy(&o.stderr).trim()));
                }
                let (r, errs) = net::parse_rule_dump(&String::from_utf8_lossy(&o.stdout));
                let n = r.len();
                let mut s = sh.lock().unwrap();
                s.rules = Some(r);
                s.rule_errors = errs;
                Ok(format!("Loaded {n} OpenSnitch rules."))
            });
        }
        if let Some(file) = delete {
            self.task(&ctx, "Deleting rule…", move |sh| {
                admin_sh(&net::delete_rule_script(&file))?;
                if let Some(l) = sh.lock().unwrap().rules.as_mut() {
                    l.retain(|x| x.0 != file);
                }
                Ok("Rule deleted.".into())
            });
        }
        if let Some((file, r)) = toggle {
            self.task(&ctx, "Updating rule…", move |sh| {
                let mut r2 = r.clone();
                r2.enabled = !r2.enabled;
                r2.updated = net::now_rfc3339();
                admin_sh(&net::write_rule_script(&file, &r2).map_err(|e| e.to_string())?)?;
                if let Some(l) = sh.lock().unwrap().rules.as_mut() {
                    for x in l.iter_mut().filter(|x| x.0 == file) {
                        x.1 = r2.clone();
                    }
                }
                Ok(format!("Rule {} is now {}.", r2.name, if r2.enabled { "on" } else { "off" }))
            });
        }
        if save_new {
            let rule = net::new_rule(self.rule_name.trim(), &self.rule_action, &self.rule_operand, self.rule_data.trim());
            let file = net::rule_file_name(&rule.name);
            self.task(&ctx, "Saving rule…", move |sh| {
                admin_sh(&net::write_rule_script(&file, &rule).map_err(|e| e.to_string())?)?;
                if let Some(l) = sh.lock().unwrap().rules.as_mut() {
                    l.retain(|x| x.0 != file);
                    l.push((file.clone(), rule.clone()));
                }
                Ok(format!("Saved rule {} ({}).", rule.name, rule.action))
            });
        }
    }

    fn firewall_mode_card(&mut self, ui: &mut Ui, st: &SysStatus) {
        let ctx = ui.ctx().clone();
        let deny = st.snitch_cfg.as_ref().map(|c| c.0 == "deny").unwrap_or(false);
        let current = if !deny {
            net::FwMode::Allow
        } else if st.snitch_popups {
            net::FwMode::Ask
        } else {
            net::FwMode::Deny
        };
        let mut choice = self.fw_choice.unwrap_or(current);
        let mut timeout = self.fw_timeout.unwrap_or(st.snitch_timeout.max(5));
        let mut apply = false;
        let mut essentials = false;
        card(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("When a program connects and no rule covers it").strong().color(Color32::WHITE));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let (t, c) = if st.snitch_ui_running { ("pop-up app running", GREEN) } else { ("pop-up app not running", AMBER) };
                    pill(ui, t, c);
                    pill(ui, &format!("now: {}", match current { net::FwMode::Ask => "deny + ask", net::FwMode::Deny => "deny", net::FwMode::Allow => "allow" }), if current == net::FwMode::Allow { AMBER } else { GREEN });
                });
            });
            ui.horizontal(|ui| {
                for m in [net::FwMode::Ask, net::FwMode::Deny, net::FwMode::Allow] {
                    ui.radio_value(&mut choice, m, m.label());
                }
            });
            ui.add_enabled_ui(choice == net::FwMode::Ask, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Time to answer a pop-up:").color(TEXT_DIM));
                    ui.add(egui::Slider::new(&mut timeout, 5..=120).suffix(" s"));
                });
            });
            ui.horizontal(|ui| {
                apply = ui.add(primary("Apply")).on_hover_text("Changes OpenSnitch's settings (asks for your password) and restarts it and its pop-up app").clicked();
                essentials = ui
                    .button("Add allow rules for essentials")
                    .on_hover_text("pacman, freshclam, NetworkManager, DNS and time sync, and curl to VirusTotal only — so updates and lookups keep working under deny")
                    .clicked();
                ui.label(RichText::new("Tip: add the essentials before switching to deny.").size(12.0).color(TEXT_DIM));
            });
        });
        self.fw_choice = Some(choice);
        self.fw_timeout = Some(timeout);
        if apply {
            let tick = self.status_tick.clone();
            self.task(&ctx, "Changing OpenSnitch's default…", move |_| {
                let r = net::apply_firewall_mode(choice, timeout);
                tick.store(true, Ordering::Relaxed);
                r
            });
            self.fw_choice = None;
            self.fw_timeout = None;
        }
        if essentials {
            self.task(&ctx, "Adding allow rules for essentials…", move |sh| {
                let rules = net::essential_rules();
                let mut script = String::from("set -e\n");
                for (file, r) in &rules {
                    script.push_str(&net::write_rule_script(file, r).map_err(|e| e.to_string())?);
                    script.push('\n');
                }
                admin_sh(&script)?;
                let n = rules.len();
                if let Some(l) = sh.lock().unwrap().rules.as_mut() {
                    for (file, r) in rules {
                        l.retain(|x| x.0 != file);
                        l.push((file, r));
                    }
                }
                Ok(format!("Added {n} allow rules for essentials."))
            });
        }
    }

    // ---------------- Deleted files (experimental) ----------------

    pub fn recover_page(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        if self.rec_parts.is_empty() {
            self.rec_parts = crate::recover::partitions();
        }
        let running = self.recover_job.is_running();
        ui.horizontal(|ui| {
            ui.heading(RichText::new("Deleted files").color(Color32::WHITE));
            pill(ui, "experimental", AMBER);
        });
        ui.horizontal(|ui| {
            ui.label(RichText::new("How:").color(TEXT_DIM));
            ui.selectable_value(&mut self.rec_mode, 1, "File Rescue — find, then scan, wipe or recover in place")
                .on_hover_text("Your File Rescue engine: real names on FAT/exFAT/NTFS, content search everywhere, deleted partitions");
            ui.selectable_value(&mut self.rec_mode, 0, "PhotoRec — copy everything out to another drive")
                .on_hover_text("TestDisk's PhotoRec: hundreds of file types by content, copied to another drive and then scanned");
        });
        ui.add_space(6.0);
        if self.rec_mode == 1 {
            self.rescue_panel(ui);
            return;
        }
        ui.label(RichText::new("Recovers deleted files from a drive with PhotoRec (part of TestDisk) and can hand them straight to the virus scan — for example to check whether something malicious was there and got deleted.").color(TEXT_DIM));
        ui.add_space(6.0);
        egui::Frame::new().fill(AMBER.linear_multiply(0.12)).corner_radius(8.0).inner_margin(egui::Margin::same(12)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new("Before you start").strong().color(AMBER));
            for t in [
                "PhotoRec only reads the drive you recover from. Recovered files must go to a different drive — writing to the same one can overwrite the very files you're trying to get back.",
                "SSDs usually erase deleted space soon after (TRIM), so there may be little or nothing left to find. Hard disks and USB sticks keep more.",
                "File names and folders aren't recovered: files are named by where they were found (f0012345.elf). Big or fragmented files can come back damaged.",
                "On btrfs and some other filesystems PhotoRec can't tell deleted space from used space, so it searches the whole partition and also brings back files that still exist — that can take hours and a lot of room.",
            ] {
                ui.label(RichText::new(format!("• {t}")).size(12.5).color(Color32::from_gray(225)));
            }
        });
        ui.add_space(8.0);
        if !crate::recover::installed() {
            card(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("PhotoRec isn't installed. It comes with the testdisk package from the official repositories.").color(Color32::WHITE));
                if ui.add(primary("Install TestDisk")).on_hover_text("pacman -S testdisk (asks for your password)").clicked() {
                    self.task(&ctx, "Installing TestDisk…", |_| {
                        admin_sh("pacman -S --noconfirm --needed testdisk").map(|_| "TestDisk is installed.".to_string())
                    });
                }
            });
            ui.add_space(6.0);
        }
        egui::ScrollArea::vertical().show(ui, |ui| {
            card(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.add_enabled_ui(!running, |ui| {
                    egui::Grid::new("rec_grid").num_columns(2).spacing([14.0, 8.0]).show(ui, |ui| {
                        ui.label("Recover from");
                        ui.horizontal(|ui| {
                            let shown = self.rec_source.clone().and_then(|p| self.rec_parts.iter().find(|x| x.path == p).map(|x| x.describe())).unwrap_or_else(|| "choose a drive…".into());
                            egui::ComboBox::from_id_salt("rec_src").selected_text(shown).width(520.0).show_ui(ui, |ui| {
                                for p in &self.rec_parts {
                                    let text = format!("{}{}", p.describe(), if p.system() { "  (system)" } else { "" });
                                    ui.selectable_value(&mut self.rec_source, Some(p.path.clone()), text);
                                }
                            });
                            if ui.button("Refresh").clicked() {
                                self.rec_parts = crate::recover::partitions();
                            }
                        });
                        ui.end_row();
                        ui.label("Put recovered files in");
                        ui.add(egui::TextEdit::singleline(&mut self.rec_dest).hint_text("a folder on a different drive").desired_width(520.0));
                        ui.end_row();
                    });
                    // Suggestions: a folder on each other drive.
                    let src = self.rec_source.clone().unwrap_or_default();
                    let drives = self.status.lock().unwrap().drives.clone();
                    let mut sugg: Vec<String> = drives.iter().filter(|d| d.dev != src && !d.read_only).map(|d| format!("{}/arch-sentinel-recovered", d.mount)).collect();
                    if crate::recover::device_of(&crate::settings::home_dir()) != src {
                        sugg.push(format!("{}/arch-sentinel-recovered", crate::settings::home_dir()));
                    }
                    if !sugg.is_empty() {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(RichText::new("Suggestions:").size(12.0).color(TEXT_DIM));
                            for sgt in sugg {
                                let free = crate::recover::free_bytes(&sgt) / 1_073_741_824;
                                if ui.small_button(format!("{sgt} ({free} GB free)")).clicked() {
                                    self.rec_dest = sgt;
                                }
                            }
                        });
                    }
                    ui.add_space(6.0);
                    ui.label(RichText::new("What to recover").color(TEXT_DIM));
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut self.rec_all_kinds, false, "Only file types that can carry viruses");
                        ui.radio_value(&mut self.rec_all_kinds, true, "Every deleted file (photos, documents, music, everything)");
                    });
                    if self.rec_all_kinds {
                        ui.label(RichText::new("For when a virus deleted or encrypted your files (ransomware, wipers): brings back everything PhotoRec can find — hundreds of file types. Expect lots of files with numbered names, some old versions and some fragments; sort them by type afterwards.").size(12.0).color(Color32::from_gray(215)));
                    } else {
                        ui.label(RichText::new("Look for these kinds of files (all can carry malware):").size(12.0).color(TEXT_DIM));
                    }
                    ui.add_enabled_ui(!self.rec_all_kinds, |ui| ui.horizontal_wrapped(|ui| {
                        for (k, tip) in crate::recover::KINDS {
                            let mut on = self.rec_kinds.iter().any(|x| x == k);
                            if ui.checkbox(&mut on, k).on_hover_text(tip).changed() {
                                if on {
                                    self.rec_kinds.push(k.to_string());
                                } else {
                                    self.rec_kinds.retain(|x| x != k);
                                }
                            }
                        }
                    }));
                    ui.checkbox(&mut self.rec_keep_damaged, "Also keep files that could only be partly recovered")
                        .on_hover_text("Damaged files can still hold most of a photo or document; without this PhotoRec throws them away");
                    let src_part = self.rec_parts.iter().find(|x| Some(&x.path) == self.rec_source.as_ref()).cloned();
                    let free_ok = src_part.as_ref().map(|p| p.freespace_supported()).unwrap_or(true);
                    ui.add_enabled(free_ok, egui::Checkbox::new(&mut self.rec_only_free, "Only look in deleted (free) space"))
                        .on_disabled_hover_text("PhotoRec can't tell deleted space apart on this filesystem");
                    ui.checkbox(&mut self.rec_scan_after, "Virus-scan the recovered files when it's done");
                    if let Some(p) = &src_part {
                        if !free_ok {
                            ui.label(RichText::new(format!("{} is {}: PhotoRec will search the whole partition and also recover files that still exist. Expect it to take long and use a lot of room.", p.path, p.fstype)).size(12.0).color(AMBER));
                        }
                        if p.system() {
                            ui.label(RichText::new("This is a system drive: everything the computer writes while PhotoRec runs can overwrite deleted files. Close other programs while it runs.").size(12.0).color(AMBER));
                        }
                    }
                });
                // Check the plan and start.
                let src_part = self.rec_parts.iter().find(|x| Some(&x.path) == self.rec_source.as_ref()).cloned();
                let plan = src_part.map(|p| crate::recover::Plan {
                    source: p,
                    dest: self.rec_dest.trim().to_string(),
                    kinds: self.rec_kinds.clone(),
                    only_free: self.rec_only_free,
                    all_kinds: self.rec_all_kinds,
                    keep_damaged: self.rec_keep_damaged,
                });
                if let Some(w) = plan.as_ref().and_then(crate::recover::space_warning) {
                    ui.label(RichText::new(w).color(AMBER));
                }
                let problems = match &plan {
                    Some(p) => crate::recover::check(p),
                    None => vec!["Choose a drive to recover from.".to_string()],
                };
                for p in &problems {
                    ui.label(RichText::new(p).color(if p.contains("overwrite") { RED } else { TEXT_DIM }));
                }
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    if running {
                        if ui.button("Stop").on_hover_text("PhotoRec runs as administrator, so stopping it asks for your password").clicked() {
                            self.recover_job.stop();
                            let dest = self.rec_dest.trim().to_string();
                            self.task(&ctx, "Stopping PhotoRec…", move |_| {
                                admin_sh(&format!("pkill -TERM -f {}", crate::clam::shell_quote(&format!("photorec /log /d {dest}/recovered"))))
                                    .map(|_| "PhotoRec stopped.".to_string())
                            });
                        }
                        ui.add(egui::Spinner::new());
                        ui.label(self.recover_job.state.lock().unwrap().progress.clone());
                    } else if ui.add_enabled(problems.is_empty(), primary("Recover deleted files")).on_hover_text("Asks for your password: PhotoRec needs to read the raw drive").clicked() {
                        if let Some(plan) = plan.clone() {
                            let s = self.s.clone();
                            let req = self.rec_scan_request.clone();
                            let scan_after = self.rec_scan_after;
                            let c2 = ctx.clone();
                            self.recover_job.run_thread(move || c2.request_repaint(), move |em| {
                                crate::par::lowest_priority_thread();
                                if let Some(dest) = crate::recover::run(&s, &plan, em) {
                                    if scan_after {
                                        *req.lock().unwrap() = Some(dest);
                                    }
                                }
                            });
                        }
                    }
                });
            });
            ui.add_space(6.0);
            let st = self.recover_job.state.lock().unwrap();
            if st.ever_ran {
                card(ui, |ui| {
                    ui.set_width(ui.available_width());
                    if !st.summary.is_empty() {
                        ui.label(RichText::new(&st.summary).color(Color32::WHITE));
                    }
                    if !self.rec_dest.is_empty() && std::path::Path::new(self.rec_dest.trim()).exists() && ui.button("Open the recovered files folder").clicked() {
                        let _ = Command::new("xdg-open").arg(self.rec_dest.trim()).spawn();
                    }
                    egui::CollapsingHeader::new(RichText::new(format!("Log ({} lines) and recovered files ({})", st.log.len(), st.findings.len())).color(TEXT_DIM)).id_salt("rec_log").show(ui, |ui| {
                        egui::ScrollArea::vertical().id_salt("rec_log_s").max_height(220.0).show(ui, |ui| {
                            for l in &st.log {
                                ui.label(RichText::new(l).monospace().size(11.5).color(Color32::from_gray(190)));
                            }
                            for f in st.findings.iter().take(300) {
                                ui.label(RichText::new(format!("{}  {}", f.path, f.detail)).monospace().size(11.0).color(Color32::from_gray(160)));
                            }
                        });
                    });
                    if st.summary.starts_with("Recovered") && self.rec_scan_after {
                        ui.label(RichText::new("The recovered files are being virus-scanned — see the Virus scan page.").size(12.0).color(GREEN));
                    }
                });
            }
        });
    }

    // ---------------- Sandbox (experimental) ----------------

    pub fn sandbox_page(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        let running = self.sandbox_job.is_running();
        ui.horizontal(|ui| {
            ui.heading(RichText::new("Sandbox").color(Color32::WHITE));
            pill(ui, "experimental", AMBER);
        });
        ui.label(RichText::new("A throwaway box for suspicious files: unpack an archive there, or run a program there for a few seconds with no network, an empty home folder and no access to your files — and see what it tries to do. The box is deleted afterwards.").color(TEXT_DIM));
        ui.add_space(6.0);
        egui::Frame::new().fill(RED.linear_multiply(0.12)).corner_radius(8.0).inner_margin(egui::Margin::same(12)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new("This is a sandbox, not a separate computer").strong().color(RED));
            for t in [
                "Inside, the program has no network (connections and name lookups are recorded, never sent), sees an empty home folder, can't see your other programs, and is limited in memory, processes and time.",
                "It still runs on your real Linux kernel: malware that attacks the kernel itself could escape. Only run something you're prepared to risk; for real malware analysis use a virtual machine or a spare computer.",
                "A quiet run doesn't prove a file is safe — some malware waits, needs the internet, or checks for sandboxes before doing anything.",
            ] {
                ui.label(RichText::new(format!("• {t}")).size(12.5).color(Color32::from_gray(225)));
            }
        });
        ui.add_space(8.0);
        if !crate::sandbox::available() {
            card(ui, |ui| {
                ui.label(RichText::new("The sandbox needs bubblewrap and strace (packages bubblewrap and strace).").color(AMBER));
            });
            return;
        }
        egui::ScrollArea::vertical().show(ui, |ui| {
            card(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.add_enabled_ui(!running, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("File");
                        ui.add(egui::TextEdit::singleline(&mut self.sbx_sample).hint_text("full path of the file to test").desired_width(560.0));
                    });
                    let q = self.shared.lock().unwrap().quarantine.clone();
                    if !q.is_empty() {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(RichText::new("From quarantine:").size(12.0).color(TEXT_DIM));
                            for e in q.iter().take(8) {
                                let name = std::path::Path::new(&e.original_path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                                if ui.small_button(format!("{name} ({})", e.threat)).clicked() {
                                    self.sbx_sample = crate::quarantine::store_file(&e.id);
                                    self.sbx_sure = false;
                                }
                            }
                        });
                    }
                    let exists = std::path::Path::new(self.sbx_sample.trim()).is_file();
                    if !self.sbx_sample.trim().is_empty() && !exists {
                        ui.label(RichText::new("That file doesn't exist.").color(AMBER));
                    }
                    ui.add_space(6.0);
                    ui.separator();
                    ui.label(RichText::new("Unpack an archive").strong().color(Color32::WHITE));
                    ui.label(RichText::new("Extracts zip, 7z, rar, tar, iso, cab and more inside the box (safe from tricks like files escaping the folder), then virus-scans what came out. Nothing is run.").size(12.0).color(TEXT_DIM));
                    if ui.add_enabled(exists, primary("Unpack and scan")).clicked() {
                        let s = self.s.clone();
                        let sample = self.sbx_sample.trim().to_string();
                        let dirslot = self.sbx_dir.clone();
                        let req = self.rec_scan_request.clone();
                        let c2 = ctx.clone();
                        self.sandbox_job.run_thread(move || c2.request_repaint(), move |em| {
                            crate::par::lowest_priority_thread();
                            let dir = match crate::sandbox::new_dir() {
                                Ok(d) => d,
                                Err(e) => {
                                    em.done(format!("Couldn't make the sandbox: {e}"));
                                    return;
                                }
                            };
                            *dirslot.lock().unwrap() = Some(dir.clone());
                            if let Some(out) = crate::sandbox::unpack(&s, &sample, &dir, em) {
                                *req.lock().unwrap() = Some(out.display().to_string());
                            }
                        });
                    }
                    ui.add_space(6.0);
                    ui.separator();
                    ui.label(RichText::new("Run it and watch").strong().color(Color32::WHITE));
                    ui.label(RichText::new("Runs a Linux program or script (or a Windows program through Wine) inside the box and records network connections, name lookups, programs it starts, secrets it reaches for, start-up files it changes, and files it drops — which are then virus-scanned.").size(12.0).color(TEXT_DIM));
                    ui.horizontal(|ui| {
                        ui.label("Run for");
                        ui.add(egui::Slider::new(&mut self.sbx_secs, 5..=180).suffix(" s"));
                        let wine = crate::sandbox::wine_path().is_some();
                        ui.add_enabled(wine, egui::Checkbox::new(&mut self.sbx_wine, "Use Wine for Windows programs"))
                            .on_disabled_hover_text("Wine isn't installed");
                        ui.checkbox(&mut self.sbx_auto_throw, "Throw the box away afterwards");
                    });
                    ui.checkbox(&mut self.sbx_sure, "I understand this runs the file for real inside the sandbox");
                    if ui.add_enabled(exists && self.sbx_sure, egui::Button::new(RichText::new("Run in the sandbox").color(Color32::WHITE)).fill(RED.linear_multiply(0.7))).clicked() {
                        let s = self.s.clone();
                        let sample = self.sbx_sample.trim().to_string();
                        let secs = self.sbx_secs;
                        let wine = self.sbx_wine;
                        let throw = self.sbx_auto_throw;
                        let dirslot = self.sbx_dir.clone();
                        let c2 = ctx.clone();
                        self.sbx_sure = false;
                        self.sandbox_job.run_thread(move || c2.request_repaint(), move |em| {
                            let dir = match crate::sandbox::new_dir() {
                                Ok(d) => d,
                                Err(e) => {
                                    em.done(format!("Couldn't make the sandbox: {e}"));
                                    return;
                                }
                            };
                            *dirslot.lock().unwrap() = Some(dir.clone());
                            let summary_before;
                            let dropped = crate::sandbox::run_watch(&s, &sample, &dir, secs, wine, em);
                            summary_before = em.state_handle().lock().unwrap().summary.clone();
                            if !dropped.is_empty() && !em.cancelled() {
                                em.progress("Virus-scanning the files it dropped…");
                                let (_, found) = crate::clam::scan_files_parallel(&s, vec![], dropped.clone(), false, em);
                                if s.paranoid {
                                    crate::paranoid::inspect_files(dropped.iter().map(|d| d.0.clone()).collect(), crate::par::threads(&s), em);
                                }
                                em.done(format!("{summary_before} ClamAV flagged {} of the dropped file(s).", found.len()));
                            }
                            if throw {
                                if crate::sandbox::throw_away(&dir).is_ok() {
                                    *dirslot.lock().unwrap() = None;
                                    em.log("The sandbox was thrown away.");
                                }
                            }
                        });
                    }
                });
                if running {
                    ui.horizontal(|ui| {
                        if ui.button("Stop").clicked() {
                            self.sandbox_job.stop();
                        }
                        ui.add(egui::Spinner::new());
                        ui.label(self.sandbox_job.state.lock().unwrap().progress.clone());
                    });
                }
                let dir = self.sbx_dir.lock().unwrap().clone();
                if let Some(d) = dir {
                    if !running && d.exists() {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(format!("Sandbox kept at {}", d.display())).size(12.0).color(TEXT_DIM));
                            if ui.button("Open it").clicked() {
                                let _ = Command::new("xdg-open").arg(&d).spawn();
                            }
                            if ui.add(egui::Button::new(RichText::new("Throw the sandbox away").color(Color32::WHITE)).fill(RED.linear_multiply(0.6))).clicked() {
                                match crate::sandbox::throw_away(&d) {
                                    Ok(()) => {
                                        *self.sbx_dir.lock().unwrap() = None;
                                        self.toast("Sandbox thrown away.", true);
                                    }
                                    Err(e) => self.toast(format!("Couldn't remove it: {e}"), false),
                                }
                            }
                        });
                    }
                }
            });
            ui.add_space(6.0);
            let st = self.sandbox_job.state.lock().unwrap();
            if st.ever_ran {
                card(ui, |ui| {
                    ui.set_width(ui.available_width());
                    if !st.summary.is_empty() {
                        ui.label(RichText::new(&st.summary).color(Color32::WHITE));
                    }
                    let mut rows: Vec<&crate::jobs::Finding> = st.findings.iter().collect();
                    rows.sort_by(|a, b| a.sev.cmp(&b.sev));
                    for f in rows.iter().take(400) {
                        ui.horizontal(|ui| {
                            ui.add_sized([60.0, 16.0], egui::Label::new(RichText::new(f.sev.label()).color(sev_color(f.sev)).strong().size(12.0)));
                            ui.add_sized([150.0, 16.0], egui::Label::new(RichText::new(&f.kind).size(12.0).color(Color32::from_gray(210))).truncate());
                            ui.add(egui::Label::new(RichText::new(&f.path).monospace().size(12.0).color(Color32::WHITE)).truncate());
                            ui.add(egui::Label::new(RichText::new(&f.detail).size(11.5).color(TEXT_DIM)).truncate());
                        });
                    }
                    egui::CollapsingHeader::new(RichText::new(format!("Log ({} lines)", st.log.len())).color(TEXT_DIM)).id_salt("sbx_log").show(ui, |ui| {
                        egui::ScrollArea::vertical().id_salt("sbx_log_s").max_height(200.0).show(ui, |ui| {
                            for l in &st.log {
                                ui.label(RichText::new(l).monospace().size(11.5).color(Color32::from_gray(180)));
                            }
                        });
                    });
                });
            }
        });
    }

    // ---------------- Background jobs ----------------

    pub fn background_page(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        let st = self.status.lock().unwrap().clone();
        let mut apply = false;
        let mut refresh = false;
        ui.horizontal(|ui| {
            ui.heading(RichText::new("Background jobs").color(Color32::WHITE));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                apply = ui.add(primary("Apply scan timers")).on_hover_text("Writes your schedules as systemd user timers (no password needed)").clicked();
                refresh = ui.button("Refresh").clicked();
            });
        });
        if refresh {
            self.status_tick.store(true, Ordering::Relaxed);
        }
        if apply {
            self.save_settings();
            let s = self.s.clone();
            let tick = self.status_tick.clone();
            self.task(&ctx, "Setting up scan timers…", move |_| {
                let r = background::apply_user_timers(&s);
                tick.store(true, Ordering::Relaxed);
                r
            });
        }
        ui.label(RichText::new("Choose which checks run on their own, how often and how gently. Signature updates run freshclam as the administrator from a system timer — never as an always-running daemon.").color(TEXT_DIM));
        ui.add_space(8.0);

        let mut start_sig = false;
        egui::ScrollArea::vertical().show(ui, |ui| {
            card(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("Scan speed and CPU use").strong().color(Color32::WHITE));
                let cores = crate::par::ncpu();
                ui.label(
                    RichText::new(format!(
                        "Scans split their work over several threads. Every scan thread runs at the lowest priority (nice 19, idle disk access), so it only uses CPU time nothing else wants. This computer has {cores} cores."
                    ))
                    .size(12.0)
                    .color(TEXT_DIM),
                );
                ui.horizontal(|ui| {
                    ui.label("Presets:");
                    let presets: [(&str, u32, u32, &str); 3] = [
                        ("Gentle", 1, 25, "1 thread, at most a quarter of the computer"),
                        ("Balanced", 0, 0, "half the cores, no cap"),
                        ("Fastest", cores as u32, 0, "every core, no cap"),
                    ];
                    for (name, t, cap, tip) in presets {
                        let on = self.s.scan_threads == t && self.s.cpu_cap == cap;
                        if ui.selectable_label(on, name).on_hover_text(tip).clicked() {
                            self.s.scan_threads = t;
                            self.s.cpu_cap = cap;
                            self.settings_dirty = true;
                        }
                    }
                });
                egui::Grid::new("speed").num_columns(2).spacing([14.0, 6.0]).show(ui, |ui| {
                    ui.label(RichText::new("Threads per scan").color(TEXT_DIM));
                    let auto = (cores / 2).max(1);
                    if ui
                        .add(egui::Slider::new(&mut self.s.scan_threads, 0..=cores as u32).custom_formatter(move |v, _| {
                            if v == 0.0 { format!("automatic ({auto})") } else { format!("{v:.0}") }
                        }))
                        .changed()
                    {
                        self.settings_dirty = true;
                    }
                    ui.end_row();
                    ui.label(RichText::new("Most CPU scans may use").color(TEXT_DIM));
                    if ui
                        .add(egui::Slider::new(&mut self.s.cpu_cap, 0..=100).custom_formatter(|v, _| {
                            if v == 0.0 || v >= 100.0 { "no cap".into() } else { format!("{v:.0}% of the computer") }
                        }))
                        .on_hover_text("A hard cap enforced by systemd, even when nothing else is running")
                        .changed()
                    {
                        self.settings_dirty = true;
                    }
                    ui.end_row();
                });
                ui.label(
                    RichText::new(format!(
                        "Virus scans run one ClamAV process per thread and each needs about 1 GiB of memory; they use fewer when memory is short (about {:.0} GiB free now).",
                        crate::par::mem_available_gib()
                    ))
                    .size(12.0)
                    .color(TEXT_DIM),
                );
            });
            ui.add_space(6.0);
            card(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("Tray").strong().color(Color32::WHITE));
                ui.horizontal(|ui| {
                    if ui.checkbox(&mut self.s.tray, "Show a tray icon and keep running when the window is closed").changed() {
                        self.settings_dirty = true;
                    }
                    if ui.checkbox(&mut self.s.autostart, "Start in the tray when I log in").changed() {
                        self.settings_dirty = true;
                        match crate::tray::set_autostart(self.s.autostart) {
                            Ok(m) => self.toast(m, true),
                            Err(e) => self.toast(e, false),
                        }
                    }
                });
                ui.horizontal(|ui| {
                    if ui.checkbox(&mut self.s.watch_new_connections, "Tray alert when a program that isn't from a package opens a connection").changed() {
                        self.settings_dirty = true;
                    }
                });
            });
            ui.add_space(6.0);
            for k in JobKind::ALL {
                let timer = st.timers.get(&k).cloned().unwrap_or_default();
                let mut changed = false;
                let mut apply_sig: Option<bool> = None;
                let sig_log: Vec<String> = if k == JobKind::Signatures { self.jobs[&k].state.lock().unwrap().log.clone() } else { vec![] };
                let sig_summary = if k == JobKind::Signatures { self.jobs[&k].state.lock().unwrap().summary.clone() } else { String::new() };
                let sig_running = k == JobKind::Signatures && self.jobs[&k].is_running();
                let daemon = st.freshclam_daemon.clone();
                let mut stop_daemon = self.s.stop_freshclam_daemon;
                card(ui, |ui| {
                    ui.set_width(ui.available_width());
                    let bg = self.s.bg_mut(k);
                    ui.horizontal(|ui| {
                        changed |= ui.checkbox(&mut bg.enabled, "").changed();
                        ui.label(RichText::new(k.title()).strong().size(15.0).color(Color32::WHITE));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let a = if timer.active.is_empty() || timer.active == "inactive" && timer.last == "never" { "not installed".to_string() } else { timer.active.clone() };
                            pill(ui, &format!("timer: {a}"), state_color(&a));
                        });
                    });
                    ui.add_enabled_ui(bg.enabled, |ui| {
                        egui::Grid::new(("bg", k.id())).num_columns(4).spacing([14.0, 6.0]).show(ui, |ui| {
                            ui.label(RichText::new("How often").color(TEXT_DIM));
                            egui::ComboBox::from_id_salt(("sched", k.id())).selected_text(bg.schedule.label()).show_ui(ui, |ui| {
                                for x in Schedule::ALL {
                                    changed |= ui.selectable_value(&mut bg.schedule, x, x.label()).changed();
                                }
                            });
                            ui.label(RichText::new("CPU limit").color(TEXT_DIM));
                            changed |= ui
                                .add(egui::Slider::new(&mut bg.cpu_limit, 0..=100).custom_formatter(|v, _| if v == 0.0 { "no limit".into() } else { format!("{v:.0}% of the computer") }))
                                .changed();
                            ui.end_row();
                            ui.label(RichText::new("Random delay").color(TEXT_DIM));
                            changed |= ui.add(egui::Slider::new(&mut bg.random_delay_min, 0..=120).suffix(" min")).changed();
                            ui.end_row();
                        });
                        ui.horizontal(|ui| {
                            changed |= ui.checkbox(&mut bg.catch_up, "Catch up a missed run after start-up").changed();
                            changed |= ui.checkbox(&mut bg.only_on_ac, "Only on mains power").changed();
                            if k != JobKind::Signatures {
                                changed |= ui.checkbox(&mut bg.notify, "Notify me about serious findings").changed();
                            }
                        });
                    });
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("Last run: {} · next: {}", timer.last, timer.next)).size(12.0).color(TEXT_DIM));
                        if k == JobKind::Signatures {
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.button("Remove timer").clicked() {
                                    apply_sig = Some(false);
                                }
                                if ui.add(primary("Install timer")).on_hover_text("Asks for your password and installs a systemd timer that runs freshclam as root").clicked() {
                                    apply_sig = Some(true);
                                }
                                if ui.add_enabled(!sig_running, egui::Button::new("Update now")).on_hover_text("Runs freshclam once as the administrator").clicked() {
                                    start_sig = true;
                                }
                            });
                        }
                    });
                    if k == JobKind::Signatures {
                        ui.horizontal(|ui| {
                            changed |= ui.checkbox(&mut stop_daemon, "Also turn off the always-running freshclam daemon").changed();
                            ui.label(RichText::new(format!("(clamav-freshclam is {daemon})")).size(12.0).color(state_color(&daemon)));
                        });
                        if sig_running || !sig_log.is_empty() {
                            egui::CollapsingHeader::new(RichText::new("freshclam output").color(TEXT_DIM)).id_salt("fc_out").default_open(true).show(ui, |ui| {
                                egui::ScrollArea::vertical().id_salt("fc_scroll").max_height(120.0).stick_to_bottom(true).show(ui, |ui| {
                                    for l in &sig_log {
                                        ui.label(RichText::new(l).monospace().size(11.5).color(Color32::from_gray(180)));
                                    }
                                    if !sig_summary.is_empty() {
                                        ui.label(RichText::new(&sig_summary).color(GREEN));
                                    }
                                });
                            });
                        }
                    }
                });
                self.s.stop_freshclam_daemon = stop_daemon;
                if changed {
                    self.settings_dirty = true;
                }
                if let Some(enable) = apply_sig {
                    self.save_settings();
                    let s = self.s.clone();
                    let tick = self.status_tick.clone();
                    self.task(&ctx, if enable { "Installing the freshclam timer…" } else { "Removing the freshclam timer…" }, move |_| {
                        let script = clam::install_timer_script(&s, enable).map_err(|e| e.to_string())?;
                        let r = admin_sh(&script);
                        tick.store(true, Ordering::Relaxed);
                        r.map(|_| {
                            if enable {
                                format!("freshclam now runs {} as root.", s.bg_signatures.schedule.label().to_lowercase())
                            } else {
                                "freshclam timer removed.".to_string()
                            }
                        })
                    });
                }
                ui.add_space(6.0);
            }
            ui.label(RichText::new("Scans run as you from systemd user timers and save a report that shows up in the app next time. Background runs can't read what only the administrator can; run those checks by hand with \"Run as administrator\".").size(12.0).color(TEXT_DIM));
        });
        if start_sig {
            self.start(&ctx, JobKind::Signatures);
        }
    }

    // ---------------- Settings ----------------

    pub fn settings_page(&mut self, ui: &mut Ui) {
        let mut fm_action: Option<bool> = None;
        ui.heading(RichText::new("Settings").color(Color32::WHITE));
        ui.label(RichText::new("Changes are saved right away.").color(TEXT_DIM));
        ui.add_space(8.0);
        let mut changed = false;
        let mut area = egui::ScrollArea::vertical();
        // For pictures of the page: ARCH_SENTINEL_SCROLL=<pixels> opens it scrolled down.
        if let Some(y) = std::env::var("ARCH_SENTINEL_SCROLL").ok().and_then(|v| v.parse::<f32>().ok()) {
            area = area.vertical_scroll_offset(y);
        }
        let mut admin_set: Vec<(JobKind, bool)> = vec![];
        area.show(ui, |ui| {
            card(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("Administrator rights").strong().color(Color32::WHITE));
                ui.label(RichText::new("Checks ticked here run with administrator rights, so they see everything instead of only what your user may read. They share one password prompt per session. Your choices are remembered.").size(12.0).color(TEXT_DIM));
                ui.horizontal(|ui| {
                    if ui.button("Tick all").clicked() {
                        admin_set.extend(crate::settings::ADMIN_CAPABLE.iter().map(|(k, _)| (*k, true)));
                    }
                    if ui.button("Untick all").clicked() {
                        admin_set.extend(crate::settings::ADMIN_CAPABLE.iter().map(|(k, _)| (*k, false)));
                    }
                });
                egui::Grid::new("admin_grid").num_columns(2).spacing([14.0, 4.0]).show(ui, |ui| {
                    for (k, what) in crate::settings::ADMIN_CAPABLE {
                        let mut on = *self.admin.get(&k).unwrap_or(&false);
                        if ui.checkbox(&mut on, k.short()).changed() {
                            admin_set.push((k, on));
                        }
                        ui.label(RichText::new(what).size(12.0).color(TEXT_DIM));
                        ui.end_row();
                    }
                });
                ui.add_space(4.0);
                ui.label(RichText::new("You're asked for your password once: the first administrator task opens an administrator session, and every later one (checks, updates, firewall, quarantine, rescue) uses it without asking again. Only this app can use it, through a private connection. Background (timer) scans always run as you.").size(12.0).color(TEXT_DIM));
                ui.horizontal(|ui| {
                    let on = crate::root::active();
                    pill(ui, if on { "administrator session open" } else { "no administrator session" }, if on { GREEN } else { TEXT_DIM });
                    if on && ui.button("End it now").on_hover_text("The next administrator task asks for your password again").clicked() {
                        crate::root::end_session();
                    }
                    ui.label(RichText::new("Close it after").color(TEXT_DIM));
                    if ui.add(egui::Slider::new(&mut self.s.admin_session_minutes, 1..=240).suffix(" min idle")).changed() {
                        crate::root::set_idle_minutes(self.s.admin_session_minutes as u64);
                        changed = true;
                    }
                });
                ui.label(RichText::new("A new idle time applies to the next session.").size(11.0).color(TEXT_DIM));
            });
            ui.add_space(6.0);
            card(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("VirusTotal second opinion").strong().color(Color32::WHITE));
                ui.label(RichText::new("When ClamAV flags a file, its SHA-256 fingerprint (never the file itself) is looked up on VirusTotal to tell real threats from false positives. A free key comes with a VirusTotal account; the free tier allows 4 lookups a minute.").size(12.0).color(TEXT_DIM));
                changed |= ui.checkbox(&mut self.s.vt_check, "Check every virus ClamAV finds on VirusTotal").changed();
                ui.horizontal(|ui| {
                    ui.label("API key");
                    changed |= ui
                        .add(egui::TextEdit::singleline(&mut self.s.vt_api_key).password(!self.show_key).desired_width(420.0).hint_text("paste your VirusTotal key"))
                        .changed();
                    ui.checkbox(&mut self.show_key, "show");
                });
                changed |= ui.checkbox(&mut self.s.quarantine, "Move confirmed viruses to quarantine automatically").changed();
            });
            ui.add_space(6.0);
            card(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("Virus scan").strong().color(Color32::WHITE));
                changed |= list_editor(ui, "virus_t", "Folders to scan", &mut self.s.virus_targets, &mut self.new_target);
                changed |= list_editor(ui, "virus_x", "Folders to skip", &mut self.s.virus_excluded, &mut self.new_skip_dir);
                ui.horizontal(|ui| {
                    ui.label("What to scan:");
                    for (v, name, tip) in crate::settings::VIRUS_SCOPES {
                        changed |= ui.selectable_value(&mut self.s.virus_scope, v, name).on_hover_text(tip).changed();
                    }
                });
                changed |= ui
                    .checkbox(&mut self.s.scan_external, "Also scan drives outside the system (USB sticks, extra disks, other partitions), after everything else")
                    .changed();
                let drives = self.status.lock().unwrap().drives.clone();
                ui.add_enabled_ui(self.s.scan_external, |ui| {
                    if drives.is_empty() {
                        ui.label(RichText::new("No such drives are mounted right now.").size(12.0).color(TEXT_DIM));
                    }
                    for d in &drives {
                        let mut on = !self.s.external_skip.contains(&d.mount);
                        let text = format!("{} — {}  ({}, {})", d.mount, d.name(), d.dev, if d.fstype.is_empty() { "?" } else { &d.fstype });
                        if ui.checkbox(&mut on, text).changed() {
                            if on {
                                self.s.external_skip.retain(|m| m != &d.mount);
                            } else {
                                self.s.external_skip.push(d.mount.clone());
                            }
                            changed = true;
                        }
                        for w in d.warnings() {
                            ui.horizontal(|ui| {
                                ui.add_space(24.0);
                                ui.add(egui::Label::new(RichText::new(w).size(12.0).color(AMBER)).wrap());
                            });
                        }
                    }
                    ui.label(RichText::new("Big drives take a long time; switch off the ones you don't need. Drives plugged in later are included automatically unless you switch them off here.").size(12.0).color(TEXT_DIM));
                });
                ui.label(
                    RichText::new("Outside your home only system files no package owns, and package files that failed the check, are scanned — from the latest Unowned files and Package files results. Run as administrator to read root-only files.")
                        .size(12.0)
                        .color(TEXT_DIM),
                );
            });
            ui.add_space(6.0);
            card(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("ClamAV scan options").strong().color(Color32::WHITE));
                ui.label(
                    RichText::new("Used for Arch Sentinel's own scans only (passed to ClamAV each time it runs). ClamAV's configuration files are left as they are.")
                        .size(12.0)
                        .color(TEXT_DIM),
                );
                let o = &mut self.s.clam;
                ui.add_space(4.0);
                changed |= ui
                    .checkbox(&mut o.detect_pua, "Detect possibly unwanted programs (PUA)")
                    .on_hover_text("Adware, hacking tools, remote-control programs and the like. More findings, and more false alarms.")
                    .changed();
                ui.add_enabled_ui(o.detect_pua, |ui| {
                    ui.label(RichText::new("Leave out these kinds:").color(TEXT_DIM));
                    ui.horizontal_wrapped(|ui| {
                        for (cat, tip) in crate::settings::PUA_CATEGORIES {
                            let mut on = o.pua_skip.iter().any(|c| c == cat);
                            if ui.checkbox(&mut on, cat).on_hover_text(tip).changed() {
                                if on {
                                    o.pua_skip.push(cat.to_string());
                                } else {
                                    o.pua_skip.retain(|c| c != cat);
                                }
                                changed = true;
                            }
                        }
                    });
                });
                ui.add_space(4.0);
                egui::Grid::new("clam_sizes").num_columns(2).spacing([14.0, 6.0]).show(ui, |ui| {
                    ui.label("Skip files bigger than");
                    changed |= ui.add(egui::Slider::new(&mut self.s.max_file_mb, 5..=crate::clam::CLAM_MAX_MB).logarithmic(true).suffix(" MB")).changed();
                    ui.end_row();
                    let o = &mut self.s.clam;
                    ui.label("Most data read from one archive");
                    changed |= ui.add(egui::Slider::new(&mut o.max_scan_mb, 10..=4000).logarithmic(true).suffix(" MB")).changed();
                    ui.end_row();
                    ui.label("Most files looked at in one archive");
                    changed |= ui.add(egui::Slider::new(&mut o.max_files, 100..=100000).logarithmic(true)).changed();
                    ui.end_row();
                    ui.label("Archives inside archives, up to");
                    changed |= ui.add(egui::Slider::new(&mut o.max_recursion, 1..=64).suffix(" levels")).changed();
                    ui.end_row();
                });
                changed |= ui
                    .checkbox(&mut self.s.paranoid, "Paranoid: also look inside program files for signs of infection or packing")
                    .on_hover_text(crate::app::PARANOID_TIP)
                    .changed();
                let o = &mut self.s.clam;
                ui.horizontal_wrapped(|ui| {
                    changed |= ui.checkbox(&mut o.scan_archives, "Look inside archives").changed();
                    changed |= ui.checkbox(&mut o.heuristic_alerts, "Heuristic alerts").on_hover_text("Report suspicious patterns that aren't a known virus").changed();
                    changed |= ui.checkbox(&mut o.heuristic_first, "Stop at the first heuristic match").on_hover_text("Faster, reports less detail").changed();
                    changed |= ui.checkbox(&mut o.alert_macros, "Flag documents with macros").changed();
                    changed |= ui.checkbox(&mut o.alert_encrypted, "Flag encrypted archives and documents").on_hover_text("ClamAV can't look inside them").changed();
                    changed |= ui.checkbox(&mut o.alert_broken, "Flag broken program files").changed();
                    changed |= ui.checkbox(&mut o.alert_exceeds_max, "Flag files too big to scan").on_hover_text("Instead of silently passing them").changed();
                });
                ui.add(
                    egui::Label::new(RichText::new(format!("Flags used: {}", self.s.clam.flags(self.s.max_file_mb).join(" "))).monospace().size(11.0).color(TEXT_DIM))
                        .wrap(),
                );
                if ui.button("Restore ClamAV defaults").clicked() {
                    self.s.clam = crate::settings::ClamOptions::default();
                    self.s.max_file_mb = 100;
                    changed = true;
                }
            });
            ui.add_space(6.0);
            card(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("File manager").strong().color(Color32::WHITE));
                ui.label(
                    RichText::new("Adds \"Scan for viruses (Arch Sentinel)\" to the right-click menu of files and folders in Dolphin, Nautilus and Nemo. It scans just what you picked, with several threads, and opens here to show the results.")
                        .size(12.0)
                        .color(TEXT_DIM),
                );
                let on = crate::fm::installed();
                ui.horizontal(|ui| {
                    pill(ui, if on { "in the right-click menu" } else { "not in the right-click menu" }, if on { GREEN } else { TEXT_DIM });
                    if ui.button(if on { "Update entries" } else { "Add to right-click menu" }).clicked() {
                        fm_action = Some(true);
                    }
                    if on && ui.button("Remove").clicked() {
                        fm_action = Some(false);
                    }
                });
            });
            ui.add_space(6.0);
            card(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("Running programs check").strong().color(Color32::WHITE));
                ui.horizontal(|ui| {
                    ui.label("Scan running program files with ClamAV:");
                    for (v, l) in [(0u8, "no"), (1, "only those not from a package"), (2, "all of them (slower)")] {
                        changed |= ui.selectable_value(&mut self.s.process_clam_scope, v, l).changed();
                    }
                });
            });
            ui.add_space(6.0);
            card(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("Files no package owns").strong().color(Color32::WHITE));
                changed |= list_editor(ui, "roots", "System folders to check", &mut self.s.system_roots, &mut self.new_root);
                changed |= list_editor(ui, "excl", "Never look inside", &mut self.s.excluded, &mut self.new_exclude);
                changed |= list_editor(ui, "pats", "Ignore patterns (* matches anything)", &mut self.s.ignore_patterns, &mut self.new_pattern);
                ui.horizontal(|ui| {
                    ui.label("Home folder");
                    changed |= ui.text_edit_singleline(&mut self.s.home).changed();
                });
            });
            ui.add_space(6.0);
            card(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("Network").strong().color(Color32::WHITE));
                ui.horizontal(|ui| {
                    ui.label("Refresh the connection list every");
                    changed |= ui.add(egui::Slider::new(&mut self.s.net_refresh_secs, 1..=30).suffix(" s")).changed();
                });
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.button("Restore default settings").clicked() {
                    let key = std::mem::take(&mut self.s.vt_api_key);
                    self.s = Settings::default();
                    self.s.vt_api_key = key;
                    changed = true;
                }
                ui.label(RichText::new(format!("Saved in {}", config_path().display())).size(12.0).color(TEXT_DIM));
            });
        });
        for (k, on) in admin_set {
            self.set_admin(k, on);
        }
        match fm_action {
            Some(true) => match crate::fm::install() {
                Ok(m) => self.toast(m, true),
                Err(e) => self.toast(format!("Couldn't add the right-click entries: {e}"), false),
            },
            Some(false) => match crate::fm::remove() {
                Ok(m) => self.toast(m, true),
                Err(e) => self.toast(e, false),
            },
            None => {}
        }
        if changed {
            self.settings_dirty = true;
        }
    }
}
