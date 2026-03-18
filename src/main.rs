#![windows_subsystem = "windows"]

use eframe::egui;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

mod admin;
mod cleanup;
mod idm;
mod optimize;
mod startup;
mod killer;

/// Toggle this to `false` for production silent mode.
const DEBUG: bool = true;

pub fn debug_print(msg: &str) {
    if DEBUG {
        println!("  {}", msg);
    }
}

pub fn hidden_command(program: impl AsRef<std::ffi::OsStr>) -> std::process::Command {
    use std::os::windows::process::CommandExt;
    let mut cmd = std::process::Command::new(program);
    cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    cmd
}

pub fn is_already_optimized() -> bool {
    let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    if let Ok(key) = hkcu.open_subkey(r"Software\Optimizer") {
        if let Ok(1u32) = key.get_value("Optimized") {
            return true;
        }
    }
    false
}

pub fn mark_as_optimized() {
    let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    if let Ok((key, _)) = hkcu.create_subkey(r"Software\Optimizer") {
        let _ = key.set_value("Optimized", &1u32);
    }
}

// ─────────────────────────────────────────────────────────────
// Phase Tracking
// ─────────────────────────────────────────────────────────────

#[derive(Clone, PartialEq)]
enum PhaseStatus {
    Pending,
    Running,
    Done,
}

#[derive(Clone)]
struct Phase {
    name: &'static str,
    status: PhaseStatus,
    detail: String,
}

struct TaskState {
    pub is_done: bool,
    pub phases: Vec<Phase>,
    pub active_phase: usize,
    pub cleanup_stats: Option<cleanup::CleanupStats>,
}

impl TaskState {
    fn new() -> Self {
        Self {
            is_done: false,
            active_phase: 0,
            cleanup_stats: None,
            phases: vec![
                Phase { name: "IDM Activator Script", status: PhaseStatus::Pending, detail: String::new() },
                Phase { name: "Temporary File Cleanup", status: PhaseStatus::Pending, detail: String::new() },
                Phase { name: "Gaming Optimizations", status: PhaseStatus::Pending, detail: String::new() },
                Phase { name: "Adobe Optimization", status: PhaseStatus::Pending, detail: String::new() },
                Phase { name: "System & Privacy", status: PhaseStatus::Pending, detail: String::new() },
            ],
        }
    }

    fn start_phase(&mut self, idx: usize) {
        if idx < self.phases.len() {
            self.active_phase = idx;
            self.phases[idx].status = PhaseStatus::Running;
            self.phases[idx].detail.clear();
        }
    }

    fn set_detail(&mut self, idx: usize, detail: String) {
        if idx < self.phases.len() {
            self.phases[idx].detail = detail;
        }
    }

    fn complete_phase(&mut self, idx: usize) {
        if idx < self.phases.len() {
            self.phases[idx].status = PhaseStatus::Done;
            self.phases[idx].detail.clear();
        }
    }

    fn progress(&self) -> f32 {
        let done = self.phases.iter().filter(|p| p.status == PhaseStatus::Done).count();
        done as f32 / self.phases.len() as f32
    }
}

// ─────────────────────────────────────────────────────────────
// Color Palette — refined dark theme
// ─────────────────────────────────────────────────────────────

const BG_BASE:       egui::Color32 = egui::Color32::from_rgb(10, 10, 20);
const BG_SURFACE:    egui::Color32 = egui::Color32::from_rgb(16, 17, 30);
const BG_ELEVATED:   egui::Color32 = egui::Color32::from_rgb(22, 23, 40);

const ACCENT_1:      egui::Color32 = egui::Color32::from_rgb(99, 102, 241);  // Indigo
const ACCENT_2:      egui::Color32 = egui::Color32::from_rgb(139, 92, 246);  // Violet
const ACCENT_3:      egui::Color32 = egui::Color32::from_rgb(59, 130, 246);  // Blue

const SUCCESS:       egui::Color32 = egui::Color32::from_rgb(52, 211, 153);  // Emerald
const RUNNING_GLOW:  egui::Color32 = egui::Color32::from_rgb(96, 165, 250);  // Light blue
const WARN:          egui::Color32 = egui::Color32::from_rgb(251, 191, 36);  // Amber

const TEXT_PRIMARY:  egui::Color32 = egui::Color32::from_rgb(237, 237, 250);
const TEXT_SECONDARY:egui::Color32 = egui::Color32::from_rgb(148, 148, 180);
const TEXT_MUTED:    egui::Color32 = egui::Color32::from_rgb(75, 75, 110);

const BORDER_SUBTLE: egui::Color32 = egui::Color32::from_rgb(30, 30, 55);
const RING_TRACK:    egui::Color32 = egui::Color32::from_rgb(25, 25, 48);

// ─────────────────────────────────────────────────────────────
// GUI App
// ─────────────────────────────────────────────────────────────

struct MaintenanceApp {
    start_time: Instant,
    state: Arc<Mutex<TaskState>>,
}

impl eframe::App for MaintenanceApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let state = self.state.lock().unwrap();
        let is_done = state.is_done;
        let progress = state.progress();
        let phases: Vec<Phase> = state.phases.iter().cloned().collect();
        let cleanup_stats = state.cleanup_stats.clone();
        drop(state);

        if is_done {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        let elapsed = self.start_time.elapsed().as_secs();
        let t = ctx.input(|i| i.time) as f32;

        let panel = egui::Frame::none().fill(BG_BASE).inner_margin(egui::Margin::same(0.0));

        egui::CentralPanel::default().frame(panel).show(ctx, |ui| {
            let full_rect = ui.available_rect_before_wrap();

            // ── Top accent gradient bar ──
            let bar_height = 2.0;
            let bar_rect = egui::Rect::from_min_size(full_rect.min, egui::vec2(full_rect.width(), bar_height));
            let painter = ui.painter();
            let steps = 40;
            let step_w = bar_rect.width() / steps as f32;
            for i in 0..steps {
                let frac = i as f32 / steps as f32;
                let shift = ((t * 0.5 + frac * 2.0).sin() * 0.5 + 0.5).clamp(0.0, 1.0);
                let c = lerp_color(ACCENT_1, ACCENT_2, shift);
                let r = egui::Rect::from_min_size(
                    egui::pos2(bar_rect.min.x + i as f32 * step_w, bar_rect.min.y),
                    egui::vec2(step_w + 1.0, bar_height),
                );
                painter.rect_filled(r, 0.0, c);
            }

            // ── Content area ──
            let content_rect = full_rect.shrink2(egui::vec2(14.0, 0.0));
            let content_rect = egui::Rect::from_min_max(
                egui::pos2(content_rect.min.x, content_rect.min.y + bar_height + 6.0),
                content_rect.max,
            );

            ui.allocate_ui_at_rect(content_rect, |ui| {
                ui.style_mut().visuals.override_text_color = Some(TEXT_PRIMARY);
                ui.spacing_mut().item_spacing = egui::vec2(4.0, 2.0);

                // ── Header ──
                ui.vertical_centered(|ui| {
                    ui.label(
                        egui::RichText::new("SYSTEM OPTIMIZER")
                            .size(13.0)
                            .strong()
                            .color(TEXT_PRIMARY),
                    );
                    let subtitle = if progress >= 1.0 {
                        "All tasks completed"
                    } else {
                        "Optimizing your system..."
                    };
                    ui.label(
                        egui::RichText::new(subtitle)
                            .size(9.0)
                            .color(TEXT_SECONDARY),
                    );
                });

                ui.add_space(4.0);

                // ── Progress Ring ──
                ui.vertical_centered(|ui| {
                    let ring_size = 64.0;
                    let (rect, _) = ui.allocate_exact_size(
                        egui::vec2(ring_size, ring_size),
                        egui::Sense::hover(),
                    );
                    let center = rect.center();
                    let radius = ring_size / 2.0 - 6.0;
                    let thickness = 3.5;
                    let painter = ui.painter();

                    // Track
                    draw_arc(painter, center, radius, thickness, 0.0, 1.0, RING_TRACK);

                    // Progress arc with gradient effect
                    if progress > 0.0 {
                        let arc_col = if progress >= 1.0 {
                            SUCCESS
                        } else {
                            let pulse = ((t * 1.5).sin() * 0.3 + 0.7).clamp(0.4, 1.0);
                            lerp_color(ACCENT_3, ACCENT_1, pulse)
                        };
                        draw_arc(painter, center, radius, thickness + 1.0, 0.0, progress, arc_col);

                        // Glow tip
                        if progress < 1.0 {
                            let angle = -std::f32::consts::FRAC_PI_2 + progress * std::f32::consts::TAU;
                            let tip = egui::pos2(center.x + angle.cos() * radius, center.y + angle.sin() * radius);
                            let glow = ((t * 3.0).sin() * 0.35 + 0.65).clamp(0.3, 1.0);
                            painter.circle_filled(
                                tip,
                                3.5,
                                egui::Color32::from_rgba_premultiplied(
                                    arc_col.r(), arc_col.g(), arc_col.b(), (glow * 220.0) as u8,
                                ),
                            );
                        }
                    }

                    // Center text
                    let pct = (progress * 100.0) as u32;
                    let pct_col = if pct == 100 { SUCCESS } else { TEXT_PRIMARY };
                    painter.text(
                        egui::pos2(center.x, center.y - 3.0),
                        egui::Align2::CENTER_CENTER,
                        format!("{}%", pct),
                        egui::FontId::proportional(16.0),
                        pct_col,
                    );
                    painter.text(
                        egui::pos2(center.x, center.y + 10.0),
                        egui::Align2::CENTER_CENTER,
                        format!("{}s", elapsed),
                        egui::FontId::proportional(8.5),
                        TEXT_MUTED,
                    );
                });

                ui.add_space(4.0);

                // ── Horizontal progress bar ──
                let bar_h = 3.0;
                let (bar_rect, _) = ui.allocate_exact_size(
                    egui::vec2(ui.available_width(), bar_h),
                    egui::Sense::hover(),
                );
                {
                    let painter = ui.painter();
                    painter.rect_filled(bar_rect, egui::Rounding::same(2.0), RING_TRACK);
                    if progress > 0.0 {
                        let fill_w = bar_rect.width() * progress;
                        let fill_rect = egui::Rect::from_min_size(bar_rect.min, egui::vec2(fill_w, bar_h));
                        let fill_col = if progress >= 1.0 { SUCCESS } else { ACCENT_1 };
                        painter.rect_filled(fill_rect, egui::Rounding::same(2.0), fill_col);
                    }
                }

                ui.add_space(6.0);

                // ── Phase List ──
                for (i, phase) in phases.iter().enumerate() {
                    let is_active = phase.status == PhaseStatus::Running;
                    let is_done = phase.status == PhaseStatus::Done;

                    let (accent, text_col, icon, bg) = if is_done {
                        (SUCCESS, SUCCESS, "✓", BG_SURFACE)
                    } else if is_active {
                        (RUNNING_GLOW, RUNNING_GLOW, "›", BG_ELEVATED)
                    } else {
                        (BORDER_SUBTLE, TEXT_MUTED, "○", BG_SURFACE)
                    };

                    let card = egui::Frame::none()
                        .fill(bg)
                        .rounding(egui::Rounding::same(6.0))
                        .inner_margin(egui::Margin {
                            left: 8.0,
                            right: 8.0,
                            top: if phase.detail.is_empty() { 5.0 } else { 4.0 },
                            bottom: if phase.detail.is_empty() { 5.0 } else { 4.0 },
                        })
                        .stroke(egui::Stroke::new(
                            if is_active { 1.0 } else { 0.5 },
                            if is_active { lerp_color(ACCENT_1, ACCENT_3, ((t * 2.0).sin() * 0.5 + 0.5).clamp(0.0, 1.0)) } else { BORDER_SUBTLE },
                        ));

                    let resp = card.show(ui, |ui| {
                        ui.vertical(|ui| {
                            ui.horizontal(|ui| {
                                // Icon
                                let icon_col = if is_done {
                                    SUCCESS
                                } else if is_active {
                                    let pulse = ((t * 3.0).sin() * 0.3 + 0.7).clamp(0.4, 1.0);
                                    lerp_color(ACCENT_3, RUNNING_GLOW, pulse)
                                } else {
                                    TEXT_MUTED
                                };
                                ui.label(
                                    egui::RichText::new(icon)
                                        .size(if is_done { 10.0 } else { 11.0 })
                                        .strong()
                                        .color(icon_col),
                                );

                                ui.add_space(4.0);

                                // Name
                                let mut name_rt = egui::RichText::new(phase.name)
                                    .size(10.5)
                                    .color(text_col);
                                if is_active {
                                    name_rt = name_rt.strong();
                                }
                                ui.label(name_rt);

                                // Right side
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if is_done {
                                        // Pill badge
                                        let pill = egui::Frame::none()
                                            .fill(egui::Color32::from_rgba_premultiplied(52, 211, 153, 25))
                                            .rounding(egui::Rounding::same(8.0))
                                            .inner_margin(egui::Margin { left: 6.0, right: 6.0, top: 1.0, bottom: 1.0 });
                                        pill.show(ui, |ui| {
                                            ui.label(
                                                egui::RichText::new("DONE")
                                                    .size(7.5)
                                                    .strong()
                                                    .color(SUCCESS),
                                            );
                                        });
                                    } else if is_active {
                                        // Animated spinner dots
                                        let frame_idx = ((t * 4.0) as u32) % 3;
                                        let dots: String = (0..3).map(|d| {
                                            if d == frame_idx { '●' } else { '○' }
                                        }).collect::<Vec<_>>().iter().collect();
                                        ui.label(
                                            egui::RichText::new(dots)
                                                .size(7.0)
                                                .color(RUNNING_GLOW),
                                        );
                                    } else {
                                        ui.label(
                                            egui::RichText::new(format!("{}/{}", i + 1, phases.len()))
                                                .size(8.0)
                                                .color(TEXT_MUTED),
                                        );
                                    }
                                });
                            });

                            // Sub-progress detail
                            if !phase.detail.is_empty() {
                                ui.add_space(2.0);
                                ui.horizontal(|ui| {
                                    ui.add_space(16.0); // align with name
                                    ui.label(
                                        egui::RichText::new(&phase.detail)
                                            .size(8.5)
                                            .color(TEXT_SECONDARY)
                                            .italics(),
                                    );
                                });
                            }
                        });
                    });

                    // Left accent bar
                    let r = resp.response.rect;
                    ui.painter().rect_filled(
                        egui::Rect::from_min_size(r.min, egui::vec2(2.5, r.height())),
                        egui::Rounding { nw: 6.0, sw: 6.0, ne: 0.0, se: 0.0 },
                        accent,
                    );

                    ui.add_space(1.0);
                }

                // ── Cleanup Stats Dashboard ──
                if let Some(ref stats) = cleanup_stats {
                    ui.add_space(4.0);

                    let dash = egui::Frame::none()
                        .fill(egui::Color32::from_rgb(12, 20, 16))
                        .rounding(egui::Rounding::same(6.0))
                        .inner_margin(egui::Margin::same(7.0))
                        .stroke(egui::Stroke::new(0.5, egui::Color32::from_rgb(30, 60, 40)));

                    dash.show(ui, |ui| {
                        ui.horizontal(|ui| {
                            // Freed
                            stat_chip(ui, "FREED", &cleanup::format_bytes(stats.bytes_freed), SUCCESS);
                            ui.add_space(8.0);
                            // Files
                            stat_chip(ui, "FILES", &stats.deleted.to_string(), ACCENT_3);
                            ui.add_space(8.0);
                            // Skipped
                            stat_chip(ui, "SKIPPED", &stats.failed.to_string(), WARN);
                        });
                    });
                }

                // ── Footer ──
                ui.add_space(4.0);
                ui.vertical_centered(|ui| {
                    ui.label(
                        egui::RichText::new("⚡ Built with Rust · github.com/hamza-op")
                            .size(8.0)
                            .color(TEXT_MUTED),
                    );
                });
            });
        });

        ctx.request_repaint_after(Duration::from_millis(100));
    }
}

// ─────────────────────────────────────────────────────────────
// Drawing Helpers
// ─────────────────────────────────────────────────────────────

fn draw_arc(
    painter: &egui::Painter,
    center: egui::Pos2,
    radius: f32,
    thickness: f32,
    start_frac: f32,
    end_frac: f32,
    color: egui::Color32,
) {
    let segments = 64;
    let start_angle = -std::f32::consts::FRAC_PI_2 + start_frac * std::f32::consts::TAU;
    let end_angle = -std::f32::consts::FRAC_PI_2 + end_frac * std::f32::consts::TAU;
    let step = (end_angle - start_angle) / segments as f32;

    (0..segments).for_each(|i| {
        let a1 = start_angle + step * i as f32;
        let a2 = start_angle + step * (i + 1) as f32;
        let p1 = egui::pos2(center.x + a1.cos() * radius, center.y + a1.sin() * radius);
        let p2 = egui::pos2(center.x + a2.cos() * radius, center.y + a2.sin() * radius);
        painter.line_segment([p1, p2], egui::Stroke::new(thickness, color));
    });
}

fn stat_chip(ui: &mut egui::Ui, label: &str, value: &str, color: egui::Color32) {
    ui.vertical(|ui| {
        ui.label(
            egui::RichText::new(label)
                .size(7.0)
                .strong()
                .color(TEXT_MUTED),
        );
        ui.label(
            egui::RichText::new(value)
                .size(11.0)
                .strong()
                .color(color),
        );
    });
}

fn lerp_color(a: egui::Color32, b: egui::Color32, t: f32) -> egui::Color32 {
    let inv = 1.0 - t;
    egui::Color32::from_rgb(
        (a.r() as f32 * inv + b.r() as f32 * t) as u8,
        (a.g() as f32 * inv + b.g() as f32 * t) as u8,
        (a.b() as f32 * inv + b.b() as f32 * t) as u8,
    )
}

// ─────────────────────────────────────────────────────────────
// Toast Notification (F14)
// ─────────────────────────────────────────────────────────────

fn send_toast_notification(title: &str, body: &str) {
    let ps_script = format!(
        r#"
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] > $null

$template = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>{}</text>
      <text>{}</text>
    </binding>
  </visual>
</toast>
"@

$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml($template)
$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("IDMSystemTool").Show($toast)
"#,
        title.replace('"', "'"),
        body.replace('"', "'"),
    );

    let _ = hidden_command("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps_script])
        .spawn();
}

// ─────────────────────────────────────────────────────────────
// Main Execution
// ─────────────────────────────────────────────────────────────

fn main() -> Result<(), eframe::Error> {
    let args: Vec<String> = std::env::args().collect();

    // Kill any already-running instances of ourselves (daemon or GUI) before proceeding
    kill_existing_instances();

    if args.iter().any(|a| a == "--daemon") {
        crate::killer::run_background_loop();
        return Ok(());
    }

    if !admin::is_admin() {
        if admin::elevate_self() {
            std::process::exit(0);
        } else {
            std::process::exit(1);
        }
    }

    startup::ensure_startup_registered();

    let state = Arc::new(Mutex::new(TaskState::new()));
    let state_clone = state.clone();

    thread::spawn(move || {
        let cleanup_detail = Arc::new(Mutex::new(String::new()));

        let run_phase = |idx: usize, detail_src: Option<Arc<Mutex<String>>>, work: Box<dyn FnOnce() + Send>| {
            state_clone.lock().unwrap().start_phase(idx);

            if let Some(ref src) = detail_src {
                let src2 = src.clone();
                let sc2 = state_clone.clone();
                let watcher = thread::spawn(move || {
                    loop {
                        thread::sleep(Duration::from_millis(150));
                        let detail = src2.lock().map(|s| s.clone()).unwrap_or_default();
                        let mut st = sc2.lock().unwrap();
                        if st.phases[idx].status != PhaseStatus::Running {
                            break;
                        }
                        st.set_detail(idx, detail);
                    }
                });
                work();
                state_clone.lock().unwrap().complete_phase(idx);
                let _ = watcher.join();
            } else {
                work();
                thread::sleep(Duration::from_millis(400));
                state_clone.lock().unwrap().complete_phase(idx);
            }
        };

        run_phase(0, None, Box::new(|| {
            idm::run_activator();
        }));

        let detail_clone = cleanup_detail.clone();
        run_phase(1, Some(cleanup_detail), Box::new(move || {
            let stats = cleanup::clean_temp_files(Some(detail_clone));
            CLEANUP_STATS.lock().unwrap().replace(stats);
        }));

        if let Some(stats) = CLEANUP_STATS.lock().unwrap().take() {
            let toast_body = format!(
                "Freed {} · {} files cleaned",
                cleanup::format_bytes(stats.bytes_freed),
                stats.deleted,
            );
            state_clone.lock().unwrap().cleanup_stats = Some(stats);
            send_toast_notification("System Optimizer", &toast_body);
        }

        let already_optimized = is_already_optimized();

        if already_optimized {
            debug_print("[✓] Gaming & System optimizations already applied. Skipping.");
            [2, 4].iter().for_each(|&i| {
                state_clone.lock().unwrap().start_phase(i);
                thread::sleep(Duration::from_millis(150));
                state_clone.lock().unwrap().complete_phase(i);
            });
        } else {
            run_phase(2, None, Box::new(|| {
                optimize::optimize_for_gaming();
            }));
        }

        run_phase(3, None, Box::new(|| {
            optimize::optimize_for_adobe();
        }));

        if !already_optimized {
            run_phase(4, None, Box::new(|| {
                optimize::optimize_system_and_privacy();
            }));
            mark_as_optimized();
        }

        thread::sleep(Duration::from_secs(3));
        state_clone.lock().unwrap().is_done = true;
    });

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([310.0, 400.0])
            .with_resizable(false)
            .with_always_on_top()
            .with_title("System Optimizer"),
        ..Default::default()
    };

    let _ = eframe::run_native(
        "System Optimizer",
        options,
        Box::new(|_cc| {
            Box::new(MaintenanceApp {
                start_time: Instant::now(),
                state,
            })
        }),
    );

    // if let Ok(exe) = std::env::current_exe() {
    //     use std::os::windows::process::CommandExt;
    //     let _ = std::process::Command::new(exe)
    //         .arg("--daemon")
    //         .creation_flags(0x08000000)
    //         .spawn();
    // }

    Ok(())
}

/// Kill all other running instances of our own executable.
fn kill_existing_instances() {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{
        GetCurrentProcessId, OpenProcess, TerminateProcess, PROCESS_TERMINATE,
    };

    let self_pid = unsafe { GetCurrentProcessId() };

    // Get our own exe filename (e.g. "idm-system-tool.exe")
    let self_name = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_lowercase()));
    let self_name = match self_name {
        Some(n) => n,
        None => return,
    };

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        let handle = match snapshot {
            Ok(h) if !h.is_invalid() => h,
            _ => return,
        };

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(handle, &mut entry).is_ok() {
            loop {
                if entry.th32ProcessID != self_pid {
                    let name_len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
                    let name = String::from_utf16_lossy(&entry.szExeFile[..name_len]).to_lowercase();

                    if name == self_name {
                        if let Ok(proc) = OpenProcess(PROCESS_TERMINATE, false, entry.th32ProcessID) {
                            let _ = TerminateProcess(proc, 0);
                            let _ = windows::Win32::Foundation::CloseHandle(proc);
                            debug_print(&format!("[i] Killed old instance PID {}", entry.th32ProcessID));
                        }
                    }
                }

                if Process32NextW(handle, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = windows::Win32::Foundation::CloseHandle(handle);
    }
}

/// Global channel for cleanup stats (avoids borrow issues in the closure)
static CLEANUP_STATS: std::sync::LazyLock<Mutex<Option<cleanup::CleanupStats>>> =
    std::sync::LazyLock::new(|| Mutex::new(None));
