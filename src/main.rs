mod app;
mod background;
mod clam;
mod drives;
mod fm;
mod ipc;
mod jobs;
mod net;
mod pages;
mod paranoid;
mod par;
mod pkg;
mod procs;
mod quarantine;
mod recover;
mod rescue;
mod rescue_ui;
mod root;
mod rootkit;
mod sandbox;
mod settings;
mod snap;
mod snap_ui;
mod tray;
mod vt;

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

fn usage() {
    println!(
        "Arch Sentinel — package integrity, unowned files, virus scanning, rootkit checks and network rules for Arch Linux\n\n\
         arch-sentinel                       open the window\n\
         arch-sentinel --screenshot FILE.png draw ~120 frames, save a picture of the window and exit\n\
         arch-sentinel --background JOB      run one scan without a window and save its report\n\
                                             (JOB: integrity, unowned, home, virus, rootkit, processes)\n\
         arch-sentinel --tray                start hidden in the tray\n\
         arch-sentinel --inspect FILE...     Paranoid check of program files (prints a score and the reasons)\n\
         arch-sentinel --scan PATH...        virus-scan these files or folders (used by the file manager's right-click menu)"
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut screenshot: Option<PathBuf> = None;
    let mut start_hidden = false;
    let mut scan_paths: Vec<String> = vec![];
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                usage();
                return;
            }
            "--screenshot" => {
                screenshot = args.get(i + 1).map(PathBuf::from);
                i += 1;
            }
            "--tray" => start_hidden = true,
            "--root-broker" => {
                // The administrator session (started through pkexec by the window).
                let minutes = args.get(i + 1).and_then(|m| m.parse().ok()).unwrap_or(30);
                std::process::exit(root::broker_main(minutes));
            }
            "--sandbox-run" | "--sandbox-unpack" => {
                // Try a file in a throwaway sandbox from the command line; prints what it found.
                let file = args.get(i + 1).cloned().unwrap_or_default();
                let secs: u64 = args.get(i + 2).and_then(|v| v.parse().ok()).unwrap_or(20);
                let s = settings::Settings::load();
                let mut em = jobs::Emitter::printer();
                let Ok(dir) = sandbox::new_dir() else {
                    eprintln!("couldn't make the sandbox");
                    std::process::exit(1);
                };
                if args[i] == "--sandbox-run" {
                    sandbox::run_watch(&s, &file, &dir, secs, true, &mut em);
                } else {
                    sandbox::unpack(&s, &file, &dir, &mut em);
                }
                let _ = sandbox::throw_away(&dir);
                return;
            }
            "--inspect" => {
                // Paranoid check of the given program files, printed (score, file, reasons).
                for p in &args[i + 1..] {
                    match paranoid::inspect(p) {
                        Some(v) => println!("{}\t{}\t{}", v.score, p, v.reasons.join("; ")),
                        None => println!("-\t{p}\tnot a program file"),
                    }
                }
                return;
            }
            "--scan" => {
                // From the file manager's right-click menu: everything after is a file or folder.
                let cwd = std::env::current_dir().unwrap_or_default();
                scan_paths = args[i + 1..]
                    .iter()
                    .map(|p| {
                        let p = std::path::Path::new(p);
                        if p.is_absolute() { p.to_path_buf() } else { cwd.join(p) }
                    })
                    .map(|p| p.display().to_string())
                    .collect();
                break;
            }
            "--background" => {
                let id = args.get(i + 1).cloned().unwrap_or_default();
                std::process::exit(background::run_background(&id));
            }
            "--helper" => {
                // Used by the window when a scan runs with administrator rights (pkexec).
                let id = args.get(i + 1).cloned().unwrap_or_default();
                if id == "snap" {
                    // Snapshots (as root): `snap list`, or `snap scan --settings <file> <mount> <path>…`.
                    unsafe {
                        libc::setpriority(libc::PRIO_PROCESS, 0, par::NICE);
                    }
                    match args.get(i + 2).map(|s| s.as_str()) {
                        Some("list") => snap::list(),
                        Some("scan") => {
                            let s: settings::Settings = args
                                .get(i + 4)
                                .and_then(|p| std::fs::read_to_string(p).ok())
                                .and_then(|t| serde_json::from_str(&t).ok())
                                .unwrap_or_default();
                            let mount = args.get(i + 5).cloned().unwrap_or_default();
                            snap::scan(&s, &mount, &args[(i + 6).min(args.len())..]);
                        }
                        _ => std::process::exit(2),
                    }
                    return;
                }
                if id == "rescue" {
                    unsafe {
                        libc::setpriority(libc::PRIO_PROCESS, 0, par::NICE);
                    }
                    std::process::exit(rescue::helper::main(&args[i + 2..]));
                }
                let cfg = args.iter().position(|a| a == "--settings").and_then(|p| args.get(p + 1));
                let s: settings::Settings = cfg
                    .and_then(|p| std::fs::read_to_string(p).ok())
                    .and_then(|t| serde_json::from_str(&t).ok())
                    .unwrap_or_default();
                let mut em = jobs::Emitter::printer();
                unsafe {
                    libc::setpriority(libc::PRIO_PROCESS, 0, par::NICE);
                }
                match id.as_str() {
                    "unowned" => pkg::scan_unowned(&s, &mut em),
                    "home" => pkg::scan_home(&s, &mut em),
                    "rootkit" => rootkit::run_builtin(&mut em, par::threads(&s)),
                    "processes" => procs::scan_processes(&s, &mut em),
                    "integrity" => pkg::scan_integrity(&s, false, &mut em),
                    "virus" => {
                        clam::scan_parallel(&s, &[], &s.virus_targets, false, &mut em);
                    }
                    _ => {
                        eprintln!("unknown helper {id}");
                        std::process::exit(2);
                    }
                }
                return;
            }
            _ => {}
        }
        i += 1;
    }

    // One egui context lives for the whole run, so the window can be closed
    // to the tray and opened again (Wayland can't hide a window, so closing
    // it for real is the only way to get it off the screen).
    let selftest = std::env::var("ARCH_SENTINEL_SELFTEST").is_ok();
    if screenshot.is_none() && !selftest {
        // Already running? Hand the request over and stop here.
        let msg = if !scan_paths.is_empty() {
            scan_paths.join("\n")
        } else if start_hidden {
            "@noop".to_string()
        } else {
            "@show".to_string()
        };
        if ipc::send(&msg) {
            return;
        }
    }
    if !scan_paths.is_empty() {
        start_hidden = false;
    }
    let ctx = eframe::egui::Context::default();
    let mut app = app::App::new(&ctx, screenshot.clone(), start_hidden);
    if !scan_paths.is_empty() {
        app.queue_scan(scan_paths.clone());
    }
    let slot: Rc<RefCell<Option<app::App>>> = Rc::new(RefCell::new(Some(app)));
    let mut first = true;
    loop {
        let in_tray_now = first && start_hidden && slot.borrow().as_ref().map(|a| a.tray_ready()).unwrap_or(false);
        first = false;
        if !in_tray_now {
            let quiet = screenshot.is_some() || std::env::var("ARCH_SENTINEL_SELFTEST").is_ok();
            let options = native_options(quiet);
            let slot2 = slot.clone();
            let result = eframe::run_native_ext(
                "Arch Sentinel",
                options,
                Some(ctx.clone()),
                Box::new(move |cc| {
                    let app = slot2.borrow_mut().take().expect("app state");
                    app::style(&cc.egui_ctx);
                    Ok(Box::new(Holder { slot: slot2.clone(), app: Some(app) }))
                }),
            );
            if let Err(e) = result {
                eprintln!("Couldn't open the window: {e}");
                std::process::exit(1);
            }
        }
        let mut guard = slot.borrow_mut();
        let Some(app) = guard.as_mut() else { break };
        if screenshot.is_some() || app.quitting || !app.tray_ready() || !app.s.tray {
            break;
        }
        // Window closed: keep running in the tray until asked to open again or quit.
        if !app.idle_in_tray(&ctx) {
            break;
        }
    }
    // Stop running scans (and the programs they started), then end the process.
    if let Some(app) = slot.borrow().as_ref() {
        app.stop_all();
    }
    root::end_session();
    std::process::exit(0);
}

fn native_options(screenshot: bool) -> eframe::NativeOptions {
    let mut viewport = eframe::egui::ViewportBuilder::default()
        .with_title("Arch Sentinel")
        .with_inner_size([1280.0, 800.0])
        .with_min_inner_size([900.0, 560.0])
        .with_app_id("arch-sentinel");
    if screenshot {
        viewport = viewport.with_active(false);
        #[cfg(target_os = "windows")]
        {
            viewport = viewport.with_window_level(eframe::egui::WindowLevel::AlwaysOnBottom);
        }
    }
    #[allow(unused_mut)]
    let mut options = eframe::NativeOptions { viewport, run_and_return: true, ..Default::default() };
    #[cfg(target_os = "macos")]
    if screenshot {
        options.event_loop_builder = Some(Box::new(|b| {
            use eframe::winit::platform::macos::EventLoopBuilderExtMacOS;
            b.with_activate_ignoring_other_apps(false);
        }));
    }
    options
}

/// Lends the long-lived app state to one window; gives it back when the window closes.
struct Holder {
    slot: Rc<RefCell<Option<app::App>>>,
    app: Option<app::App>,
}

impl eframe::App for Holder {
    fn logic(&mut self, ctx: &eframe::egui::Context, frame: &mut eframe::Frame) {
        if let Some(a) = self.app.as_mut() {
            eframe::App::logic(a, ctx, frame);
        }
    }
    fn ui(&mut self, ui: &mut eframe::egui::Ui, frame: &mut eframe::Frame) {
        if let Some(a) = self.app.as_mut() {
            eframe::App::ui(a, ui, frame);
        }
    }
}

impl Drop for Holder {
    fn drop(&mut self) {
        if let Some(a) = self.app.take() {
            *self.slot.borrow_mut() = Some(a);
        }
    }
}
