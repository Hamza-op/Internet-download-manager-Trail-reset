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
    if let Ok(key) = hkcu.open_subkey(r"Software\MetaLensOptimizer") {
        if let Ok(1u32) = key.get_value("Optimized") {
            return true;
        }
    }
    false
}

pub fn mark_as_optimized() {
    let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    if let Ok((key, _)) = hkcu.create_subkey(r"Software\MetaLensOptimizer") {
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
    icon: &'static str,
    name: &'static str,
    status: PhaseStatus,
}

struct TaskState {
    pub is_done: bool,
    pub phases: Vec<Phase>,
    pub active_phase: usize,
}

impl TaskState {
    fn new() -> Self {
        Self {
            is_done: false,
            active_phase: 0,
            phases: vec![
                Phase { icon: "🔑", name: "IDM Activation Reset", status: PhaseStatus::Pending },
                Phase { icon: "🧹", name: "Temporary File Cleanup", status: PhaseStatus::Pending },
                Phase { icon: "🎮", name: "Gaming Optimizations", status: PhaseStatus::Pending },
                Phase { icon: "🎨", name: "Adobe Optimization", status: PhaseStatus::Pending },
                Phase { icon: "🛡", name: "System & Privacy", status: PhaseStatus::Pending },
            ],
        }
    }

    fn start_phase(&mut self, idx: usize) {
        if idx < self.phases.len() {
            self.active_phase = idx;
            self.phases[idx].status = PhaseStatus::Running;
        }
    }

    fn complete_phase(&mut self, idx: usize) {
        if idx < self.phases.len() {
            self.phases[idx].status = PhaseStatus::Done;
        }
    }

    fn progress(&self) -> f32 {
        let done = self.phases.iter().filter(|p| p.status == PhaseStatus::Done).count();
        done as f32 / self.phases.len() as f32
    }
}

// ─────────────────────────────────────────────────────────────
// Color Palette
// ─────────────────────────────────────────────────────────────

const BG_DARK: egui::Color32 = egui::Color32::from_rgb(8, 8, 18);
const BG_CARD: egui::Color32 = egui::Color32::from_rgb(18, 18, 34);
const BG_CARD_ACTIVE: egui::Color32 = egui::Color32::from_rgb(24, 22, 44);
const ACCENT_CYAN: egui::Color32 = egui::Color32::from_rgb(56, 189, 248);
const ACCENT_BLUE: egui::Color32 = egui::Color32::from_rgb(99, 102, 241);
const ACCENT_PURPLE: egui::Color32 = egui::Color32::from_rgb(168, 85, 247);
const ACCENT_GREEN: egui::Color32 = egui::Color32::from_rgb(74, 222, 128);
const ACCENT_AMBER: egui::Color32 = egui::Color32::from_rgb(251, 191, 36);
const TEXT_PRIMARY: egui::Color32 = egui::Color32::from_rgb(240, 240, 255);
const TEXT_DIM: egui::Color32 = egui::Color32::from_rgb(90, 90, 130);
const BORDER_DIM: egui::Color32 = egui::Color32::from_rgb(32, 32, 56);
const RING_BG: egui::Color32 = egui::Color32::from_rgb(28, 28, 50);

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
        let phases = state.phases.clone();
        drop(state);

        if is_done {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        let elapsed = self.start_time.elapsed().as_secs();
        let t = ctx.input(|i| i.time) as f32;

        let panel_frame = egui::Frame::none().fill(BG_DARK).inner_margin(egui::Margin::same(0.0));

        egui::CentralPanel::default().frame(panel_frame).show(ctx, |ui| {
            let full_rect = ui.available_rect_before_wrap();

            // ── Animated background orbs ──
            draw_bg_orbs(ui.painter(), full_rect, t);

            // Content with padding
            ui.allocate_ui_at_rect(full_rect.shrink2(egui::vec2(28.0, 20.0)), |ui| {
                ui.style_mut().visuals.override_text_color = Some(TEXT_PRIMARY);
                ui.spacing_mut().item_spacing = egui::vec2(8.0, 4.0);

                // ── Title ──
                ui.vertical_centered(|ui| {
                    ui.add_space(2.0);
                    let wave = ((t * 1.0).sin() * 0.5 + 0.5).clamp(0.0, 1.0);
                    let title_c = lerp_color(ACCENT_CYAN, ACCENT_PURPLE, wave);
                    ui.label(
                        egui::RichText::new("SYSTEM OPTIMIZER")
                            .size(22.0)
                            .strong()
                            .color(title_c),
                    );
                });

                ui.add_space(12.0);

                // ── Circular Progress Ring ──
                ui.vertical_centered(|ui| {
                    let ring_size = 100.0;
                    let (rect, _) = ui.allocate_exact_size(
                        egui::vec2(ring_size, ring_size),
                        egui::Sense::hover(),
                    );
                    let center = rect.center();
                    let radius = ring_size / 2.0 - 6.0;
                    let thickness = 5.0;

                    let painter = ui.painter();

                    // Background ring
                    draw_arc(painter, center, radius, thickness, 0.0, 1.0, RING_BG);

                    // Progress arc
                    if progress > 0.0 {
                        let arc_color = if progress >= 1.0 {
                            ACCENT_GREEN
                        } else {
                            let shimmer = ((t * 2.0).sin() * 0.4 + 0.6).clamp(0.2, 1.0);
                            lerp_color(ACCENT_BLUE, ACCENT_CYAN, shimmer)
                        };
                        draw_arc(painter, center, radius, thickness + 1.0, 0.0, progress, arc_color);

                        // Glow dot at arc tip
                        if progress < 1.0 {
                            let angle =
                                -std::f32::consts::FRAC_PI_2 + progress * std::f32::consts::TAU;
                            let tip = egui::pos2(
                                center.x + angle.cos() * radius,
                                center.y + angle.sin() * radius,
                            );
                            let glow_a = ((t * 4.0).sin() * 0.3 + 0.7).clamp(0.4, 1.0);
                            painter.circle_filled(
                                tip,
                                5.0,
                                egui::Color32::from_rgba_premultiplied(
                                    arc_color.r(),
                                    arc_color.g(),
                                    arc_color.b(),
                                    (glow_a * 200.0) as u8,
                                ),
                            );
                        }
                    }

                    // Center percentage text
                    let pct = (progress * 100.0) as u32;
                    let pct_color = if pct == 100 { ACCENT_GREEN } else { TEXT_PRIMARY };
                    painter.text(
                        center,
                        egui::Align2::CENTER_CENTER,
                        format!("{}%", pct),
                        egui::FontId::proportional(24.0),
                        pct_color,
                    );
                });

                ui.add_space(8.0);

                // ── Info badges ──
                let username = std::env::var("USERNAME").unwrap_or_else(|_| "User".to_string());
                ui.vertical_centered(|ui| {
                    ui.horizontal(|ui| {
                        let center_offset =
                            (ui.available_width() - 260.0_f32.min(ui.available_width())) / 2.0;
                        ui.add_space(center_offset.max(0.0));
                        mini_badge(ui, &format!("👤 {}", username), TEXT_DIM);
                        mini_badge(ui, &format!("⏱ {}s", elapsed), ACCENT_AMBER);
                        mini_badge(ui, "🛡 Admin", ACCENT_GREEN);
                    });
                });

                ui.add_space(14.0);

                // ── Phase Cards with left accent bar ──
                phases.iter().enumerate().for_each(|(i, phase)| {
                    let (accent_col, text_col, is_active) = match phase.status {
                        PhaseStatus::Done => (ACCENT_GREEN, ACCENT_GREEN, false),
                        PhaseStatus::Running => (ACCENT_CYAN, ACCENT_CYAN, true),
                        PhaseStatus::Pending => (BORDER_DIM, TEXT_DIM, false),
                    };

                    let card_bg = if is_active { BG_CARD_ACTIVE } else { BG_CARD };

                    let card = egui::Frame::none()
                        .fill(card_bg)
                        .rounding(egui::Rounding::same(8.0))
                        .inner_margin(egui::Margin {
                            left: 14.0,
                            right: 14.0,
                            top: 8.0,
                            bottom: 8.0,
                        })
                        .stroke(egui::Stroke::new(1.0, BORDER_DIM));

                    let response = card.show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(phase.icon).size(16.0));
                            ui.add_space(6.0);

                            let mut name_rt =
                                egui::RichText::new(phase.name).size(13.5).color(text_col);
                            if is_active {
                                name_rt = name_rt.strong();
                            }
                            ui.label(name_rt);

                            // Right side status
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| match phase.status {
                                    PhaseStatus::Done => {
                                        ui.label(
                                            egui::RichText::new("✓").size(14.0).color(ACCENT_GREEN),
                                        );
                                    }
                                    PhaseStatus::Running => {
                                        let dots = match ((t * 3.0) as u32) % 4 {
                                            0 => "●○○",
                                            1 => "○●○",
                                            2 => "○○●",
                                            _ => "○●○",
                                        };
                                        ui.label(
                                            egui::RichText::new(dots).size(10.0).color(ACCENT_CYAN),
                                        );
                                    }
                                    PhaseStatus::Pending => {
                                        ui.label(
                                            egui::RichText::new(format!("{}/{}", i + 1, phases.len()))
                                                .size(10.0)
                                                .color(egui::Color32::from_rgb(50, 50, 75)),
                                        );
                                    }
                                },
                            );
                        });
                    });

                    // Paint left accent bar over the card
                    let card_rect = response.response.rect;
                    let accent_rect = egui::Rect::from_min_size(
                        card_rect.min,
                        egui::vec2(3.0, card_rect.height()),
                    );
                    let painter = ui.painter();
                    painter.rect_filled(
                        accent_rect,
                        egui::Rounding { nw: 8.0, sw: 8.0, ne: 0.0, se: 0.0 },
                        accent_col,
                    );

                    ui.add_space(3.0);
                });

                // ── Footer ──
                ui.add_space(8.0);
                ui.vertical_centered(|ui| {
                    ui.label(
                        egui::RichText::new("Built with 🦀 Rust  ·  github.com/hamza-op")
                            .size(10.5)
                            .color(egui::Color32::from_rgb(55, 55, 80)),
                    );
                });
            });
        });

        ctx.request_repaint();
    }
}

// ─────────────────────────────────────────────────────────────
// Drawing Helpers
// ─────────────────────────────────────────────────────────────

/// Draw soft floating background orbs
fn draw_bg_orbs(painter: &egui::Painter, rect: egui::Rect, t: f32) {
    let orbs: [(f32, f32, f32, egui::Color32); 3] = [
        (0.15, 0.3, 120.0, egui::Color32::from_rgba_premultiplied(99, 102, 241, 12)),
        (0.8, 0.7, 90.0, egui::Color32::from_rgba_premultiplied(168, 85, 247, 10)),
        (0.5, 0.85, 100.0, egui::Color32::from_rgba_premultiplied(56, 189, 248, 8)),
    ];

    orbs.iter().enumerate().for_each(|(i, (bx, by, r, col))| {
        let drift = (t * 0.3 + i as f32 * 2.0).sin() * 15.0;
        let center = egui::pos2(
            rect.min.x + rect.width() * bx + drift,
            rect.min.y + rect.height() * by + drift * 0.7,
        );
        painter.circle_filled(center, *r, *col);
    });
}

/// Draw a circular arc using line segments
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

fn mini_badge(ui: &mut egui::Ui, text: &str, color: egui::Color32) {
    ui.label(egui::RichText::new(text).size(11.0).color(color));
    ui.add_space(8.0);
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
// Main Execution
// ─────────────────────────────────────────────────────────────

fn main() -> Result<(), eframe::Error> {
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
        let run_phase = |idx: usize, work: fn()| {
            state_clone.lock().unwrap().start_phase(idx);
            work();
            thread::sleep(Duration::from_millis(400));
            state_clone.lock().unwrap().complete_phase(idx);
        };

        // Always run: IDM fix, temp clean, Adobe clean
        run_phase(0, || {
            idm::reset_activation();
            idm::fix_popup();
        });

        run_phase(1, || {
            cleanup::clean_temp_files();
        });

        // Skip gaming & system/privacy if already done
        let already_optimized = is_already_optimized();

        if already_optimized {
            debug_print("[✓] Gaming & System optimizations already applied. Skipping.");
            [2, 4].iter().for_each(|&i| {
                state_clone.lock().unwrap().start_phase(i);
                thread::sleep(Duration::from_millis(150));
                state_clone.lock().unwrap().complete_phase(i);
            });
        } else {
            run_phase(2, || {
                optimize::optimize_for_gaming();
            });
        }

        // Always run: Adobe clean
        run_phase(3, || {
            optimize::optimize_for_adobe();
        });

        if !already_optimized {
            run_phase(4, || {
                optimize::optimize_system_and_privacy();
            });

            mark_as_optimized();
        }

        // Show completed state for a few seconds
        thread::sleep(Duration::from_secs(3));
        state_clone.lock().unwrap().is_done = true;
    });

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([440.0, 560.0])
            .with_resizable(false)
            .with_always_on_top()
            .with_title("System Optimizer"),
        ..Default::default()
    };

    eframe::run_native(
        "System Optimizer",
        options,
        Box::new(|_cc| {
            Box::new(MaintenanceApp {
                start_time: Instant::now(),
                state,
            })
        }),
    )
}
