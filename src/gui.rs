use eframe::egui;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;

use crate::vault;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ActiveTab {
    Lock,
    Unlock,
    Details,
}

enum VaultTaskMsg {
    #[allow(dead_code)]
    Progress(String),
    Success(String),
    Error(String),
    ExitEncryptComplete(Result<(), String>),
    DecryptProgress(DecryptProgressInfo),
    EncryptProgress(EncryptProgressInfo),
    BatchProgress(BatchProgressInfo),
    BatchFolderCompleted {
        folder: PathBuf,
        is_encrypt: bool,
        result: Result<(), String>,
    },
    BatchAllCompleted {
        total: usize,
        success_count: usize,
        fail_count: usize,
        is_encrypt: bool,
    },
}

#[derive(Clone, Debug)]
pub struct DecryptProgressInfo {
    pub folder: PathBuf,
    pub completed: usize,
    pub total: usize,
    pub current_file: String,
    pub file_size: u64,
}

#[derive(Clone, Debug)]
pub struct EncryptProgressInfo {
    pub folder: PathBuf,
    pub completed: usize,
    pub total: usize,
    pub current_file: String,
    pub file_size: u64,
}

#[derive(Clone, Debug)]
pub struct BatchProgressInfo {
    pub current_folder_index: usize,
    pub total_folders: usize,
    pub folder_name: String,
    pub folder_path: PathBuf,
    pub is_encrypt: bool,
    pub folder_completed: usize,
    pub folder_total: usize,
    pub current_file: String,
    pub file_size: u64,
}

#[derive(Clone, Debug)]
pub struct ActiveProgressState {
    pub folder: PathBuf,
    pub is_decrypt: bool,
    pub completed: usize,
    pub total: usize,
    pub current_file: String,
    pub recent_files: Vec<(String, u64)>, // list of (relative_path, size)
    pub total_bytes_done: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BatchMode {
    Encrypt,
    Decrypt,
}

#[derive(Clone, Debug)]
pub struct BatchDialogState {
    pub mode: BatchMode,
    pub selected_paths: HashSet<PathBuf>,
    pub password: String,
    pub confirm_password: String,
    pub password_hint: String,
    pub show_password: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TrackedVault {
    pub path: PathBuf,
    pub name: String,
}

#[derive(Clone, Debug)]
pub struct FileTreeNode {
    pub name: String,
    pub path: PathBuf,
    pub is_dir: bool,
    pub size: u64,
    pub children: Vec<FileTreeNode>,
}

#[derive(Clone, Debug)]
pub struct VaultInspection {
    pub is_locked: bool,
    #[allow(dead_code)]
    pub exists: bool,
    pub encrypted_files: Vec<(String, u64)>, // (name, size)
    pub total_encrypted_bytes: u64,
    pub plain_tree: Vec<FileTreeNode>, // Recursive file & directory tree
    pub total_plain_bytes: u64,
    pub total_plain_files: usize,
    pub total_plain_dirs: usize,
    pub password_hint: Option<String>,
}

pub struct SecureVaultApp {
    // Left panel: tracked vaults
    tracked_vaults: Vec<TrackedVault>,
    selected_index: Option<usize>,
    selected_path: PathBuf,
    selected_name: String,
    selected_is_dir: bool,
    inspection: Option<VaultInspection>,
    inspection_cache: HashMap<PathBuf, VaultInspection>,
    expanded_folders: HashSet<PathBuf>, // Fold/collapse state for all folders (vaults, subfolders, .vault_data)

    // Active Tab in right panel
    active_tab: ActiveTab,

    // Passwords for right panel operations
    password: String,
    confirm_password: String,
    password_hint: String,
    show_password: bool,

    // Async worker feedback
    is_busy: bool,
    status_message: Option<(String, bool)>, // (message, is_error)
    progress_text: String,
    tx: Sender<VaultTaskMsg>,
    rx: Receiver<VaultTaskMsg>,

    // Real-time progress feedback
    active_progress: Option<ActiveProgressState>,

    // Batch operations
    batch_dialog: Option<BatchDialogState>,
    batch_running_info: Option<BatchProgressInfo>,

    // Session tracking of unlocked folders (Requirement 3)
    unlocked_during_session: HashSet<PathBuf>,

    // Exit confirmation & re-encryption dialog (Requirement 3)
    show_exit_dialog: bool,
    bypass_exit_check: bool,
    exit_password: String,
    exit_confirm_password: String,
    exit_password_hint: String,
    exit_show_password: bool,
    exit_error: Option<String>,
    is_exit_encrypting: bool,

    // Secondary confirmation dialog for removing a vault from management list (Requirement 1)
    confirm_remove_vault: Option<TrackedVault>,

    // Application directory where the executable resides
    app_dir: PathBuf,
}

// ── Font Setup for Chinese Character Support ──

pub fn setup_chinese_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    // Optically align emoji glyphs with Chinese & Latin text baselines
    for font_name in ["NotoEmoji-Regular", "emoji-icon-font"] {
        if let Some(font_data) = fonts.font_data.remove(font_name) {
            let mut tweaked = (*font_data).clone();
            tweaked.tweak.y_offset = 1.0;
            tweaked.tweak.y_offset_factor = 0.08;
            fonts.font_data.insert(font_name.to_string(), std::sync::Arc::new(tweaked));
        }
    }

    let candidate_paths = [
        // Windows
        "C:\\Windows\\Fonts\\msyh.ttc",
        "C:\\Windows\\Fonts\\msyh.ttf",
        "C:\\Windows\\Fonts\\simhei.ttf",
        "C:\\Windows\\Fonts\\simsun.ttc",
        // macOS
        "/System/Library/Fonts/PingFang.ttc",
        "/System/Library/Fonts/STHeiti Light.ttc",
        "/Library/Fonts/Arial Unicode.ttf",
        "/System/Library/Fonts/Supplemental/Songti.ttc",
    ];

    for path in candidate_paths {
        if Path::new(path).exists() {
            if let Ok(bytes) = std::fs::read(path) {
                fonts.font_data.insert(
                    "chinese_font".to_owned(),
                    std::sync::Arc::new(egui::FontData::from_owned(bytes)),
                );

                if let Some(prop) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
                    prop.push("chinese_font".to_owned());
                }
                if let Some(mono) = fonts.families.get_mut(&egui::FontFamily::Monospace) {
                    mono.push("chinese_font".to_owned());
                }
                break;
            }
        }
    }

    ctx.set_fonts(fonts);

    // Modern polished dark theme styling
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = egui::Color32::from_rgb(18, 22, 31);
    visuals.window_fill = egui::Color32::from_rgb(22, 27, 38);
    visuals.window_stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(45, 55, 78));
    visuals.window_corner_radius = egui::CornerRadius::same(10);

    visuals.extreme_bg_color = egui::Color32::from_rgb(14, 18, 26);
    visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(52, 65, 88));
    visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(26, 33, 46);
    visuals.widgets.inactive.corner_radius = egui::CornerRadius::same(6);

    visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.2, egui::Color32::from_rgb(80, 115, 175));
    visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(34, 43, 62);
    visuals.widgets.hovered.corner_radius = egui::CornerRadius::same(6);

    visuals.widgets.active.bg_stroke = egui::Stroke::new(1.5, egui::Color32::from_rgb(66, 133, 244));
    visuals.widgets.active.bg_fill = egui::Color32::from_rgb(40, 52, 78);
    visuals.widgets.active.corner_radius = egui::CornerRadius::same(6);

    visuals.widgets.open = visuals.widgets.active;
    ctx.set_visuals(visuals);
}

// ── UI Theme & Component Helpers ──

/// Helper to render a perfectly aligned status/badge pill
fn render_badge_pill(
    ui: &mut egui::Ui,
    icon: &str,
    text: &str,
    bg: egui::Color32,
    stroke: egui::Stroke,
    text_color: egui::Color32,
    height: f32,
    clickable: bool,
) -> egui::Response {
    let font_size = if height <= 22.0 { 11.0 } else { 12.0 };
    let font = egui::FontId::proportional(font_size);

    let has_icon = !icon.is_empty();
    let has_text = !text.is_empty();

    let icon_galley = if has_icon {
        Some(ui.painter().layout_no_wrap(icon.to_string(), font.clone(), text_color))
    } else {
        None
    };
    let text_galley = if has_text {
        Some(ui.painter().layout_no_wrap(text.to_string(), font, text_color))
    } else {
        None
    };

    let spacing = if has_icon && has_text { 4.0 } else { 0.0 };
    let icon_w = icon_galley.as_ref().map(|g| g.size().x).unwrap_or(0.0);
    let text_w = text_galley.as_ref().map(|g| g.size().x).unwrap_or(0.0);
    let pad_x = if height <= 22.0 { 7.0 } else { 9.0 };
    let total_w = pad_x * 2.0 + icon_w + spacing + text_w;

    let (rect, resp) = ui.allocate_exact_size(
        egui::vec2(total_w, height),
        if clickable { egui::Sense::click() } else { egui::Sense::hover() },
    );

    let corner_radius = height / 2.0;
    ui.painter().rect_filled(rect, corner_radius, bg);
    if stroke.width > 0.0 {
        ui.painter().rect_stroke(rect, corner_radius, stroke, egui::StrokeKind::Inside);
    }

    let target_center_y = rect.center().y;
    let start_x = rect.min.x + pad_x;

    if let Some(icon_g) = icon_galley {
        let icon_y = (target_center_y - icon_g.size().y / 2.0).round();
        ui.painter().galley(egui::pos2(start_x, icon_y), icon_g, text_color);
    }

    if let Some(text_g) = text_galley {
        let text_y = (target_center_y - text_g.size().y / 2.0).round();
        let text_x = if has_icon { start_x + icon_w + spacing } else { start_x };
        ui.painter().galley(egui::pos2(text_x, text_y), text_g, text_color);
    }

    resp
}

/// Status badge pill with custom translucent background and matching border
fn render_status_pill(ui: &mut egui::Ui, is_locked: bool) {
    let (bg, stroke, text_color, icon, text) = if is_locked {
        (
            egui::Color32::from_rgb(12, 42, 28),
            egui::Stroke::new(1.0, egui::Color32::from_rgb(16, 185, 129)),
            egui::Color32::from_rgb(230, 255, 245),
            "🔒",
            "已加密锁定",
        )
    } else {
        (
            egui::Color32::from_rgb(48, 34, 10),
            egui::Stroke::new(1.2, egui::Color32::from_rgb(245, 158, 11)),
            egui::Color32::from_rgb(255, 246, 214),
            "🔓",
            "明文未锁定",
        )
    };

    render_badge_pill(ui, icon, text, bg, stroke, text_color, 24.0, false);
}

/// Helper to render an icon + text button with pixel-perfect vertical centering
fn icon_text_button(
    ui: &mut egui::Ui,
    enabled: bool,
    icon: &str,
    text: &str,
    bg: egui::Color32,
    stroke: egui::Stroke,
    text_color: egui::Color32,
    size: egui::Vec2,
    corner_radius: f32,
) -> egui::Response {
    let effective_color = if enabled {
        text_color
    } else {
        egui::Color32::from_rgb(110, 125, 150)
    };

    let font_size = if size.y <= 24.0 {
        12.0
    } else if size.y <= 32.0 {
        12.5
    } else {
        13.0
    };
    let font = egui::FontId::proportional(font_size);

    let has_icon = !icon.is_empty();
    let has_text = !text.is_empty();

    let icon_galley = if has_icon {
        Some(ui.painter().layout_no_wrap(icon.to_string(), font.clone(), effective_color))
    } else {
        None
    };
    let text_galley = if has_text {
        Some(ui.painter().layout_no_wrap(text.to_string(), font, effective_color))
    } else {
        None
    };

    let spacing = if has_icon && has_text { 5.0 } else { 0.0 };
    let icon_w = icon_galley.as_ref().map(|g| g.size().x).unwrap_or(0.0);
    let text_w = text_galley.as_ref().map(|g| g.size().x).unwrap_or(0.0);
    let total_width = icon_w + spacing + text_w;

    let effective_size = egui::vec2(
        if size.x > 0.0 { size.x.max(total_width + 12.0) } else { total_width + 18.0 },
        size.y.max(22.0),
    );

    let (rect, resp) = ui.allocate_exact_size(
        effective_size,
        if enabled { egui::Sense::click() } else { egui::Sense::hover() },
    );

    if enabled {
        let fill = if resp.is_pointer_button_down_on() {
            egui::Color32::from_rgb(
                (bg.r() as f32 * 0.8) as u8,
                (bg.g() as f32 * 0.8) as u8,
                (bg.b() as f32 * 0.8) as u8,
            )
        } else if resp.hovered() {
            egui::Color32::from_rgb(
                (bg.r() as f32 * 1.2).min(255.0) as u8,
                (bg.g() as f32 * 1.2).min(255.0) as u8,
                (bg.b() as f32 * 1.2).min(255.0) as u8,
            )
        } else {
            bg
        };
        ui.painter().rect_filled(rect, corner_radius, fill);
        if stroke.width > 0.0 {
            ui.painter().rect_stroke(rect, corner_radius, stroke, egui::StrokeKind::Inside);
        }
    } else {
        ui.painter().rect_filled(rect, corner_radius, egui::Color32::from_rgb(32, 40, 54));
    }

    let start_x = (rect.min.x + (rect.width() - total_width) / 2.0).round();
    let target_center_y = rect.center().y;

    if let Some(icon_g) = icon_galley {
        let icon_y = (target_center_y - icon_g.size().y / 2.0).round();
        ui.painter().galley(egui::pos2(start_x, icon_y), icon_g, effective_color);
    }

    if let Some(text_g) = text_galley {
        let text_y = (target_center_y - text_g.size().y / 2.0).round();
        let text_x = if has_icon { start_x + icon_w + spacing } else { start_x };
        ui.painter().galley(egui::pos2(text_x, text_y), text_g, effective_color);
    }

    resp
}

/// Helper for modern segmented control tab buttons
fn render_tab_button(ui: &mut egui::Ui, current: ActiveTab, target: ActiveTab, icon: &str, label: &str) -> bool {
    let active = current == target;
    let (bg, stroke, text_color) = if active {
        (
            egui::Color32::from_rgb(37, 99, 235), // Royal blue
            egui::Stroke::NONE,
            egui::Color32::WHITE,
        )
    } else {
        (
            egui::Color32::from_rgb(25, 32, 45),
            egui::Stroke::new(1.0, egui::Color32::from_rgb(45, 56, 78)),
            egui::Color32::from_rgb(170, 185, 210),
        )
    };

    icon_text_button(
        ui,
        true,
        icon,
        label,
        bg,
        stroke,
        text_color,
        egui::vec2(105.0, 32.0),
        6.0,
    )
    .clicked()
}

/// Helper to render clean, consistently bordered input fields (visible without click/focus) with placeholder hint
fn bordered_text_edit<'a>(
    text: &'a mut String,
    password_mode: bool,
    min_width: f32,
    hint_text: &str,
) -> egui::TextEdit<'a> {
    egui::TextEdit::singleline(text)
        .password(password_mode)
        .hint_text(
            egui::RichText::new(hint_text)
                .size(11.5)
                .color(egui::Color32::from_rgb(115, 130, 155)),
        )
        .min_size(egui::vec2(min_width, 32.0))
        .frame(
            egui::Frame::default()
                .fill(egui::Color32::from_rgb(18, 23, 33))
                .stroke(egui::Stroke::new(1.2, egui::Color32::from_rgb(75, 95, 128)))
                .corner_radius(egui::CornerRadius::same(6))
                .inner_margin(egui::Margin::symmetric(10, 6)),
        )
}

/// Helper for primary action buttons (Lock, Unlock, Change PW)
fn primary_action_button(ui: &mut egui::Ui, enabled: bool, icon: &str, text: &str, bg_color: egui::Color32) -> egui::Response {
    icon_text_button(
        ui,
        enabled,
        icon,
        text,
        bg_color,
        egui::Stroke::NONE,
        egui::Color32::WHITE,
        egui::vec2(180.0, 36.0),
        6.0,
    )
}

/// Alert message banner (Success or Error) with multi-line wrap and action buttons
fn status_banner(ui: &mut egui::Ui, status_message: &mut Option<(String, bool)>) {
    let (msg, is_err) = match status_message.as_ref() {
        Some((m, e)) => (m.clone(), *e),
        None => return,
    };

    let is_warning = msg.starts_with("⚠️");
    let clean_msg = msg
        .trim_start_matches('✅')
        .trim_start_matches('❌')
        .trim_start_matches("⚠️")
        .trim();

    let (bg, stroke, text_color, icon) = if is_err {
        (
            egui::Color32::from_rgb(46, 18, 22),
            egui::Stroke::new(1.2, egui::Color32::from_rgb(239, 68, 68)),
            egui::Color32::from_rgb(255, 215, 220),
            "❌",
        )
    } else if is_warning {
        (
            egui::Color32::from_rgb(48, 36, 12),
            egui::Stroke::new(1.2, egui::Color32::from_rgb(245, 158, 11)),
            egui::Color32::from_rgb(254, 243, 199),
            "⚠️",
        )
    } else {
        (
            egui::Color32::from_rgb(12, 42, 30),
            egui::Stroke::new(1.2, egui::Color32::from_rgb(16, 185, 129)),
            egui::Color32::from_rgb(235, 255, 245),
            "✅",
        )
    };

    let is_long_or_multiline = clean_msg.contains('\n')
        || (is_err && (clean_msg.starts_with("失败:") || clean_msg.len() > 60));
    let mut should_dismiss = false;

    egui::Frame::default()
        .fill(bg)
        .stroke(stroke)
        .corner_radius(egui::CornerRadius::same(8))
        .inner_margin(egui::Margin::symmetric(14, 10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            if is_long_or_multiline {
                // Header row with Icon, Title, and Action Buttons (Copy + Close)
                ui.allocate_ui_with_layout(
                    egui::vec2(ui.available_width(), 22.0),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        let header_title = if is_err {
                            format!("{}  操作遇到错误", icon)
                        } else if is_warning {
                            format!("{}  操作提示 / 部分完成", icon)
                        } else {
                            format!("{}  操作提示", icon)
                        };
                        let header_color = if is_err {
                            egui::Color32::from_rgb(255, 120, 120)
                        } else if is_warning {
                            egui::Color32::from_rgb(251, 191, 36)
                        } else {
                            egui::Color32::from_rgb(52, 211, 153)
                        };
                        ui.label(
                            egui::RichText::new(header_title)
                                .size(13.0)
                                .strong()
                                .color(header_color),
                        );

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            // Close button
                            let (close_rect, close_resp) = ui.allocate_exact_size(egui::vec2(22.0, 22.0), egui::Sense::click());
                            if close_resp.hovered() {
                                let hover_bg = if is_err {
                                    egui::Color32::from_rgb(70, 25, 30)
                                } else if is_warning {
                                    egui::Color32::from_rgb(75, 55, 20)
                                } else {
                                    egui::Color32::from_rgb(20, 60, 40)
                                };
                                ui.painter().rect_filled(close_rect, 4.0, hover_bg);
                            }
                            let text_c = if close_resp.hovered() {
                                egui::Color32::WHITE
                            } else if is_err {
                                egui::Color32::from_rgb(190, 150, 155)
                            } else if is_warning {
                                egui::Color32::from_rgb(220, 190, 140)
                            } else {
                                egui::Color32::from_rgb(140, 185, 160)
                            };
                            ui.painter().text(
                                close_rect.center(),
                                egui::Align2::CENTER_CENTER,
                                "✕",
                                egui::FontId::proportional(11.0),
                                text_c,
                            );
                            if close_resp.on_hover_text("关闭提示").clicked() {
                                should_dismiss = true;
                            }

                            ui.add_space(4.0);

                            // Copy details button
                            let (copy_text, copy_bg, copy_stroke, copy_fg) = if is_err {
                                (
                                    "复制报错",
                                    egui::Color32::from_rgb(60, 25, 32),
                                    egui::Stroke::new(1.0, egui::Color32::from_rgb(110, 45, 55)),
                                    egui::Color32::from_rgb(255, 205, 210),
                                )
                            } else if is_warning {
                                (
                                    "复制详情",
                                    egui::Color32::from_rgb(65, 48, 18),
                                    egui::Stroke::new(1.0, egui::Color32::from_rgb(135, 95, 25)),
                                    egui::Color32::from_rgb(254, 230, 160),
                                )
                            } else {
                                (
                                    "复制详情",
                                    egui::Color32::from_rgb(20, 55, 38),
                                    egui::Stroke::new(1.0, egui::Color32::from_rgb(35, 95, 60)),
                                    egui::Color32::from_rgb(200, 245, 220),
                                )
                            };
                            if icon_text_button(
                                ui,
                                true,
                                "📋",
                                copy_text,
                                copy_bg,
                                copy_stroke,
                                copy_fg,
                                egui::vec2(76.0, 22.0),
                                4.0,
                            )
                            .on_hover_text("复制完整内容到剪贴板")
                            .clicked()
                            {
                                ui.ctx().copy_text(clean_msg.to_string());
                            }
                        });
                    },
                );

                ui.add_space(6.0);

                // Multi-line detail box with darker background
                let (box_bg, box_stroke) = if is_err {
                    (
                        egui::Color32::from_rgb(32, 12, 16),
                        egui::Stroke::new(1.0, egui::Color32::from_rgb(70, 28, 35)),
                    )
                } else if is_warning {
                    (
                        egui::Color32::from_rgb(34, 25, 8),
                        egui::Stroke::new(1.0, egui::Color32::from_rgb(85, 60, 18)),
                    )
                } else {
                    (
                        egui::Color32::from_rgb(8, 30, 20),
                        egui::Stroke::new(1.0, egui::Color32::from_rgb(20, 65, 42)),
                    )
                };
                egui::Frame::default()
                    .fill(box_bg)
                    .stroke(box_stroke)
                    .corner_radius(egui::CornerRadius::same(5))
                    .inner_margin(egui::Margin::symmetric(10, 8))
                    .show(ui, |ui| {
                        let text_to_show = clean_msg.strip_prefix("失败:").unwrap_or(clean_msg).trim();
                        let label = egui::Label::new(
                            egui::RichText::new(text_to_show)
                                .size(12.0)
                                .monospace()
                                .color(text_color),
                        )
                        .wrap_mode(egui::TextWrapMode::Wrap)
                        .selectable(true);

                        ui.add(label);
                    });
            } else {
                // Single/few line status (e.g. success, or short validation error)
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 4.0;
                    ui.label(
                        egui::RichText::new(format!("{}  {}", icon, clean_msg))
                            .size(13.0)
                            .strong()
                            .color(text_color),
                    );

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let (close_rect, close_resp) = ui.allocate_exact_size(egui::vec2(20.0, 20.0), egui::Sense::click());
                        if close_resp.hovered() {
                            let hover_bg = if is_err {
                                egui::Color32::from_rgb(70, 25, 30)
                            } else if is_warning {
                                egui::Color32::from_rgb(75, 55, 20)
                            } else {
                                egui::Color32::from_rgb(20, 60, 40)
                            };
                            ui.painter().rect_filled(close_rect, 4.0, hover_bg);
                        }
                        let text_c = if close_resp.hovered() {
                            egui::Color32::WHITE
                        } else if is_err {
                            egui::Color32::from_rgb(190, 150, 155)
                        } else if is_warning {
                            egui::Color32::from_rgb(220, 190, 140)
                        } else {
                            egui::Color32::from_rgb(140, 185, 160)
                        };
                        ui.painter().text(
                            close_rect.center(),
                            egui::Align2::CENTER_CENTER,
                            "✕",
                            egui::FontId::proportional(11.0),
                            text_c,
                        );
                        if close_resp.on_hover_text("关闭提示").clicked() {
                            should_dismiss = true;
                        }
                    });
                });
            }
        });

    if should_dismiss {
        *status_message = None;
    }
}

/// Metric card helper for the Details view
fn metric_card(ui: &mut egui::Ui, icon: &str, title: &str, value: &str, subtitle: &str, width: f32) {
    let pad_x = 12.0;
    egui::Frame::default()
        .fill(egui::Color32::from_rgb(20, 26, 38))
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(42, 54, 76)))
        .corner_radius(egui::CornerRadius::same(8))
        .inner_margin(egui::Margin::symmetric(pad_x as i8, 10))
        .show(ui, |ui| {
            ui.set_width((width - pad_x * 2.0).max(60.0));
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(format!("{}  {}", icon, title))
                        .size(12.0)
                        .weak(),
                );
            });
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(value)
                    .size(14.0)
                    .strong()
                    .color(egui::Color32::from_rgb(235, 245, 255)),
            );
            ui.add_space(2.0);
            ui.label(
                egui::RichText::new(subtitle)
                    .size(10.5)
                    .color(egui::Color32::from_rgb(130, 145, 170)),
            );
        });
}

/// Safely open a directory or reveal a file in the native operating system file manager
fn open_in_file_manager(path: &Path) {
    if !path.exists() {
        return;
    }
    #[cfg(target_os = "windows")]
    {
        if path.is_file() {
            let _ = std::process::Command::new("explorer")
                .arg(format!("/select,{}", path.display()))
                .spawn();
        } else {
            let _ = std::process::Command::new("explorer").arg(path).spawn();
        }
    }
    #[cfg(target_os = "macos")]
    {
        if path.is_file() {
            let _ = std::process::Command::new("open").arg("-R").arg(path).spawn();
        } else {
            let _ = std::process::Command::new("open").arg(path).spawn();
        }
    }
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        let folder = if path.is_file() {
            path.parent().unwrap_or(path)
        } else {
            path
        };
        let _ = std::process::Command::new("xdg-open").arg(folder).spawn();
    }
}

/// Safely open a file with the operating system's default application.
/// On Windows, invokes ShellExecuteW with verb "open"; if no default application is associated,
/// falls back to "openas" or OpenAs_RunDLL.
/// IMPORTANT: Never runs `explorer <file>` because on Windows explorer opens the containing directory instead of opening the file!
fn open_file_with_default_app(path: &Path) {
    if !path.exists() {
        return;
    }
    if path.is_dir() {
        open_in_file_manager(path);
        return;
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::ffi::OsStrExt;
        let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let wide_op_open: Vec<u16> = std::ffi::OsStr::new("open").encode_wide().chain(Some(0)).collect();
        let wide_op_openas: Vec<u16> = std::ffi::OsStr::new("openas").encode_wide().chain(Some(0)).collect();

        #[link(name = "shell32")]
        extern "system" {
            fn ShellExecuteW(
                hwnd: *mut std::ffi::c_void,
                lpOperation: *const u16,
                lpFile: *const u16,
                lpParameters: *const u16,
                lpDirectory: *const u16,
                nShowCmd: i32,
            ) -> isize;
        }

        unsafe {
            let res = ShellExecuteW(
                std::ptr::null_mut(),
                wide_op_open.as_ptr(),
                wide_path.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1, // SW_SHOWNORMAL
            );
            if res <= 32 {
                // If "open" fails (e.g. no associated default app, SE_ERR_NOASSOC = 31),
                // trigger Windows "Open With..." dialog using verb "openas"
                let res_openas = ShellExecuteW(
                    std::ptr::null_mut(),
                    wide_op_openas.as_ptr(),
                    wide_path.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    1,
                );
                if res_openas <= 32 {
                    // Fallback to rundll32 shell32.dll,OpenAs_RunDLL
                    let _ = std::process::Command::new("rundll32.exe")
                        .arg("shell32.dll,OpenAs_RunDLL")
                        .arg(path)
                        .spawn();
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(path).spawn();
    }
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        let _ = std::process::Command::new("xdg-open").arg(path).spawn();
    }
}

/// Universal helper: routes directories to file manager and files to default application
#[allow(dead_code)]
fn open_with_default_app(path: &Path) {
    if path.is_dir() {
        open_in_file_manager(path);
    } else {
        open_file_with_default_app(path);
    }
}

/// Generate a high-entropy 64-character random password using OsRng
fn generate_random_64_char_password() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?";
    use rand::Rng;
    let mut rng = rand::rngs::OsRng;
    (0..64)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

// ── Persistence Helpers ──

/// Retrieve the directory containing the running executable, falling back to current working directory
fn get_app_dir() -> PathBuf {
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            return parent.to_path_buf();
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn get_config_path() -> PathBuf {
    if let Ok(appdata) = std::env::var("APPDATA") {
        let dir = PathBuf::from(appdata).join("SecureVault");
        let _ = std::fs::create_dir_all(&dir);
        return dir.join("tracked_vaults.json");
    }
    if let Ok(home) = std::env::var("HOME") {
        let dir = PathBuf::from(home).join(".config").join("securevault");
        let _ = std::fs::create_dir_all(&dir);
        return dir.join("tracked_vaults.json");
    }
    PathBuf::from(".securevault_tracked.json")
}

fn load_tracked_vaults() -> Vec<TrackedVault> {
    let path = get_config_path();
    if let Ok(content) = std::fs::read_to_string(&path) {
        if let Ok(list) = serde_json::from_str::<Vec<TrackedVault>>(&content) {
            return list;
        }
    }

    // Default: if aabb on Desktop exists, include it for convenience
    let mut default_list = Vec::new();
    if let Ok(userprofile) = std::env::var("USERPROFILE") {
        let test_folder = PathBuf::from(userprofile).join("Desktop").join("aabb");
        if test_folder.exists() {
            default_list.push(TrackedVault {
                name: "aabb".into(),
                path: test_folder,
            });
        }
    }
    default_list
}

fn save_tracked_vaults(list: &[TrackedVault]) {
    let path = get_config_path();
    if let Ok(json) = serde_json::to_string_pretty(list) {
        let _ = std::fs::write(path, json);
    }
}

// ── Vault Inspection Helper (Requirement 2 & Hierarchical Folders) ──

fn scan_plain_dir_tree(dir: &Path) -> Vec<FileTreeNode> {
    let mut nodes = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        let mut entries: Vec<_> = entries.flatten().collect();
        // Sort: directories first, then alphabetical by name
        entries.sort_by(|a, b| {
            let a_is_dir = a.metadata().map(|m| m.is_dir()).unwrap_or(false);
            let b_is_dir = b.metadata().map(|m| m.is_dir()).unwrap_or(false);
            match (a_is_dir, b_is_dir) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a.file_name().cmp(&b.file_name()),
            }
        });

        for entry in entries {
            let fname = entry.file_name().to_string_lossy().to_string();
            if fname.starts_with('.') {
                continue;
            }
            if let Ok(meta) = entry.metadata() {
                let path = entry.path();
                if meta.is_dir() {
                    let children = scan_plain_dir_tree(&path);
                    let folder_size = sum_tree_size(&children);
                    nodes.push(FileTreeNode {
                        name: fname,
                        path,
                        is_dir: true,
                        size: folder_size,
                        children,
                    });
                } else {
                    nodes.push(FileTreeNode {
                        name: fname,
                        path,
                        is_dir: false,
                        size: meta.len(),
                        children: Vec::new(),
                    });
                }
            }
        }
    }
    nodes
}

fn sum_tree_size(nodes: &[FileTreeNode]) -> u64 {
    nodes
        .iter()
        .map(|n| if n.is_dir { sum_tree_size(&n.children) } else { n.size })
        .sum()
}

fn count_tree_items(nodes: &[FileTreeNode]) -> (usize, usize) {
    let mut files = 0;
    let mut dirs = 0;
    for n in nodes {
        if n.is_dir {
            dirs += 1;
            let (f, d) = count_tree_items(&n.children);
            files += f;
            dirs += d;
        } else {
            files += 1;
        }
    }
    (files, dirs)
}

fn collect_all_folder_paths(vaults: &[TrackedVault]) -> HashSet<PathBuf> {
    let mut set = HashSet::new();
    for v in vaults {
        set.insert(v.path.clone());
        set.insert(v.path.join(".vault_data"));
        fn recurse_dirs(dir: &Path, set: &mut HashSet<PathBuf>) {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.starts_with('.') {
                        continue;
                    }
                    if let Ok(meta) = entry.metadata() {
                        if meta.is_dir() {
                            let p = entry.path();
                            set.insert(p.clone());
                            recurse_dirs(&p, set);
                        }
                    }
                }
            }
        }
        recurse_dirs(&v.path, &mut set);
    }
    set
}

fn inspect_vault(path: &Path) -> VaultInspection {
    if !path.exists() || !path.is_dir() {
        return VaultInspection {
            is_locked: false,
            exists: false,
            encrypted_files: Vec::new(),
            total_encrypted_bytes: 0,
            plain_tree: Vec::new(),
            total_plain_bytes: 0,
            total_plain_files: 0,
            total_plain_dirs: 0,
            password_hint: None,
        };
    }

    let locked = vault::is_locked(path);
    let mut encrypted_files = Vec::new();
    let mut total_encrypted_bytes = 0;

    if locked {
        let password_hint = vault::read_vault_meta(path).ok().and_then(|(m, _)| m.password_hint);
        let data_dir = path.join(".vault_data");
        if let Ok(entries) = std::fs::read_dir(&data_dir) {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    if meta.is_file() {
                        let fname = entry.file_name().to_string_lossy().to_string();
                        let size = meta.len();
                        total_encrypted_bytes += size;
                        encrypted_files.push((fname, size));
                    }
                }
            }
        }
        VaultInspection {
            is_locked: true,
            exists: true,
            encrypted_files,
            total_encrypted_bytes,
            plain_tree: Vec::new(),
            total_plain_bytes: 0,
            total_plain_files: 0,
            total_plain_dirs: 0,
            password_hint,
        }
    } else {
        let plain_tree = scan_plain_dir_tree(path);
        let total_plain_bytes = sum_tree_size(&plain_tree);
        let (total_plain_files, total_plain_dirs) = count_tree_items(&plain_tree);
        VaultInspection {
            is_locked: false,
            exists: true,
            encrypted_files: Vec::new(),
            total_encrypted_bytes: 0,
            plain_tree,
            total_plain_bytes,
            total_plain_files,
            total_plain_dirs,
            password_hint: None,
        }
    }
}

/// Helper to render right-aligned or inline size labels without ever overlapping names
fn add_smart_size_label(ui: &mut egui::Ui, size_bytes: u64, color: egui::Color32) {
    let size_text = format_bytes(size_bytes);
    let font = egui::FontId::proportional(10.0);
    let size_w = ui.painter().layout_no_wrap(size_text.clone(), font, egui::Color32::WHITE).size().x;
    let row_left = ui.max_rect().min.x;
    let row_right = ui.max_rect().max.x;
    let current_x = ui.cursor().min.x;
    let used_w = (current_x - row_left).max(0.0);
    let target_w = (row_right - row_left).max(0.0);
    let min_gap = 8.0;

    if used_w + size_w + min_gap < target_w {
        ui.add_space((target_w - used_w - size_w - 4.0).max(0.0));
    } else {
        ui.add_space(min_gap);
    }
    ui.label(
        egui::RichText::new(size_text)
            .size(10.0)
            .color(color),
    );
}

/// Recursive renderer for folder and file tree nodes with expand/collapse and selection support
fn render_file_tree(
    ui: &mut egui::Ui,
    nodes: &[FileTreeNode],
    expanded_folders: &HashSet<PathBuf>,
    toggled_folders: &mut Vec<PathBuf>,
    selected_target: &mut Option<(PathBuf, String, bool)>,
    current_selected_path: &Path,
    depth: usize,
) {
    for node in nodes {
        if node.is_dir {
            let is_expanded = expanded_folders.contains(&node.path);
            let is_this_selected = current_selected_path == node.path;

            ui.allocate_ui_with_layout(
                egui::vec2(ui.available_width(), 22.0),
                egui::Layout::left_to_right(egui::Align::Center),
                |ui| {
                    if depth > 0 {
                        ui.add_space((depth as f32) * 12.0);
                    }

                    // 1. Subfolder arrow toggle button (18x18 square)
                    let (arrow_rect, arrow_resp) = ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::click());
                    if arrow_resp.hovered() {
                        ui.painter().rect_filled(arrow_rect, 3.0, egui::Color32::from_rgb(42, 54, 76));
                    }
                    let arrow_glyph = if is_expanded { "▼" } else { "▶" };
                    let arrow_color = if arrow_resp.hovered() {
                        egui::Color32::WHITE
                    } else {
                        egui::Color32::from_rgb(165, 180, 205)
                    };
                    ui.painter().text(
                        arrow_rect.center(),
                        egui::Align2::CENTER_CENTER,
                        arrow_glyph,
                        egui::FontId::proportional(10.0),
                        arrow_color,
                    );
                    if arrow_resp.on_hover_text("折叠/展开此子文件夹").clicked() {
                        toggled_folders.push(node.path.clone());
                    }

                    // 2. Folder icon and name clickable button
                    let folder_locked = vault::is_locked(&node.path);
                    let folder_icon = if folder_locked { "🔒" } else { "📁" };

                    let folder_btn = egui::Button::new(
                        egui::RichText::new(format!("{}  {}", folder_icon, node.name))
                            .size(11.5)
                            .strong()
                            .color(if is_this_selected {
                                egui::Color32::WHITE
                            } else if is_expanded {
                                egui::Color32::from_rgb(225, 235, 255)
                            } else {
                                egui::Color32::from_rgb(190, 205, 230)
                            }),
                    )
                    .fill(if is_this_selected {
                        egui::Color32::from_rgb(37, 99, 235)
                    } else {
                        egui::Color32::TRANSPARENT
                    })
                    .stroke(if is_this_selected {
                        egui::Stroke::new(1.0, egui::Color32::from_rgb(96, 165, 250))
                    } else {
                        egui::Stroke::NONE
                    })
                    .corner_radius(egui::CornerRadius::same(4))
                    .min_size(egui::vec2(0.0, 18.0));

                    let btn_resp = ui.add(folder_btn);
                    if btn_resp.double_clicked() {
                        open_in_file_manager(&node.path);
                    }
                    let folder_tooltip = format!(
                        "{} 目录: {}\n大小: {}\n路径: {}\n\n💡 提示: 单击选中此目录，双击在文件管理器中打开",
                        folder_icon,
                        node.name,
                        format_bytes(node.size),
                        node.path.display()
                    );
                    if btn_resp.on_hover_text(folder_tooltip).clicked() {
                        *selected_target = Some((node.path.clone(), node.name.clone(), true));
                    }

                    // 3. Child items count badge
                    let child_count = node.children.len();
                    ui.label(
                        egui::RichText::new(format!("({}项)", child_count))
                            .size(10.0)
                            .color(egui::Color32::from_rgb(125, 140, 165)),
                    );

                    // 4. Folder size (smart aligned, never overlapping)
                    add_smart_size_label(ui, node.size, egui::Color32::from_rgb(120, 135, 160));
                },
            );

            // If this subfolder is expanded, render its children recursively
            if is_expanded {
                if node.children.is_empty() {
                    ui.allocate_ui_with_layout(
                        egui::vec2(ui.available_width(), 18.0),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| {
                            ui.add_space(((depth + 1) as f32) * 12.0 + 18.0);
                            ui.label(egui::RichText::new("(空文件夹)").size(10.0).weak());
                        },
                    );
                } else {
                    render_file_tree(
                        ui,
                        &node.children,
                        expanded_folders,
                        toggled_folders,
                        selected_target,
                        current_selected_path,
                        depth + 1,
                    );
                }
            }
        } else {
            // Leaf File entry
            let is_this_selected = current_selected_path == node.path;
            ui.allocate_ui_with_layout(
                egui::vec2(ui.available_width(), 20.0),
                egui::Layout::left_to_right(egui::Align::Center),
                |ui| {
                    if depth > 0 {
                        ui.add_space((depth as f32) * 12.0);
                    }
                    ui.add_space(18.0); // Align with folder icon after arrow

                    let file_icon = match node.path.extension().and_then(|s| s.to_str()).unwrap_or("") {
                        "png" | "jpg" | "jpeg" | "gif" | "webp" => "🖼️",
                        "mp3" | "wav" | "flac" | "aac" => "🎵",
                        "mp4" | "mkv" | "avi" | "mov" => "🎬",
                        "zip" | "tar" | "gz" | "7z" | "rar" => "📦",
                        "txt" | "md" | "json" | "xml" | "toml" | "yaml" => "📝",
                        "rs" | "py" | "js" | "ts" | "c" | "cpp" | "sh" | "bat" => "💻",
                        "pdf" | "doc" | "docx" => "📄",
                        _ => "📄",
                    };

                    let file_btn = egui::Button::new(
                        egui::RichText::new(format!("{}  {}", file_icon, node.name))
                            .size(11.0)
                            .color(if is_this_selected {
                                egui::Color32::WHITE
                            } else {
                                egui::Color32::from_rgb(205, 220, 240)
                            }),
                    )
                    .fill(if is_this_selected {
                        egui::Color32::from_rgb(30, 58, 110)
                    } else {
                        egui::Color32::TRANSPARENT
                    })
                    .stroke(if is_this_selected {
                        egui::Stroke::new(1.0, egui::Color32::from_rgb(60, 100, 180))
                    } else {
                        egui::Stroke::NONE
                    })
                    .corner_radius(egui::CornerRadius::same(3))
                    .min_size(egui::vec2(0.0, 18.0));

                    let file_resp = ui.add(file_btn);
                    if file_resp.double_clicked() {
                        open_file_with_default_app(&node.path);
                    }
                    let file_tooltip = format!(
                        "{} 文件: {}\n大小: {}\n路径: {}\n\n💡 提示: 单击选中查看详情，双击使用系统默认程序打开文件",
                        file_icon,
                        node.name,
                        format_bytes(node.size),
                        node.path.display()
                    );
                    if file_resp.on_hover_text(file_tooltip).clicked() {
                        *selected_target = Some((node.path.clone(), node.name.clone(), false));
                    }

                    // File size (smart aligned, never overlapping)
                    add_smart_size_label(ui, node.size, egui::Color32::from_rgb(120, 135, 160));
                },
            );
        }
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

// ── Application Implementation ──

impl SecureVaultApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        setup_chinese_fonts(&cc.egui_ctx);

        let (tx, rx) = channel();
        let tracked_vaults = load_tracked_vaults();
        let selected_index = if !tracked_vaults.is_empty() {
            Some(0)
        } else {
            None
        };
        let (selected_path, selected_name, selected_is_dir) = if let Some(first) = tracked_vaults.first() {
            (first.path.clone(), first.name.clone(), true)
        } else {
            (PathBuf::new(), String::new(), true)
        };

        let active_tab = if selected_is_dir && selected_path.exists() && vault::is_locked(&selected_path) {
            ActiveTab::Unlock
        } else {
            ActiveTab::Lock
        };

        let inspection = if selected_is_dir && selected_path.exists() {
            Some(inspect_vault(&selected_path))
        } else {
            None
        };

        let mut inspection_cache = HashMap::new();
        if let Some(insp) = &inspection {
            inspection_cache.insert(selected_path.clone(), insp.clone());
        }
        for v in &tracked_vaults {
            if v.path != selected_path && v.path.exists() {
                inspection_cache.insert(v.path.clone(), inspect_vault(&v.path));
            }
        }

        let mut expanded_folders = HashSet::new();
        for v in &tracked_vaults {
            expanded_folders.insert(v.path.clone());
        }

        Self {
            tracked_vaults,
            selected_index,
            selected_path,
            selected_name,
            selected_is_dir,
            inspection,
            inspection_cache,
            expanded_folders,
            active_tab,
            password: String::new(),
            confirm_password: String::new(),
            password_hint: String::new(),
            show_password: false,
            is_busy: false,
            status_message: None,
            progress_text: String::new(),
            tx,
            rx,
            active_progress: None,
            batch_dialog: None,
            batch_running_info: None,
            unlocked_during_session: HashSet::new(),
            show_exit_dialog: false,
            bypass_exit_check: false,
            exit_password: String::new(),
            exit_confirm_password: String::new(),
            exit_password_hint: String::new(),
            exit_show_password: false,
            exit_error: None,
            is_exit_encrypting: false,
            confirm_remove_vault: None,
            app_dir: get_app_dir(),
        }
    }

    #[allow(dead_code)]
    fn current_vault(&self) -> Option<&TrackedVault> {
        self.selected_index.and_then(|idx| self.tracked_vaults.get(idx))
    }

    fn select_target(&mut self, path: PathBuf, name: String, is_dir: bool, parent_idx: Option<usize>) {
        if is_dir && path.exists() {
            let is_locked = vault::is_locked(&path);
            if self.active_tab != ActiveTab::Details {
                if is_locked {
                    self.active_tab = ActiveTab::Unlock;
                } else {
                    self.active_tab = ActiveTab::Lock;
                }
            }
        } else if !is_dir {
            let is_enc = path.extension().and_then(|e| e.to_str()) == Some("enc")
                || path.parent().map(|p| p.ends_with(".vault_data")).unwrap_or(false);
            if self.active_tab != ActiveTab::Details {
                if is_enc {
                    self.active_tab = ActiveTab::Unlock;
                } else {
                    self.active_tab = ActiveTab::Lock;
                }
            }
        }
        self.selected_path = path;
        self.selected_name = name;
        self.selected_is_dir = is_dir;
        if let Some(idx) = parent_idx {
            self.selected_index = Some(idx);
        }
        self.status_message = None;
        self.password.clear();
        self.confirm_password.clear();
        self.password_hint.clear();
        self.refresh_current_inspection();
    }

    fn refresh_current_inspection(&mut self) {
        if self.selected_is_dir && self.selected_path.exists() {
            let insp = inspect_vault(&self.selected_path);
            self.inspection_cache.insert(self.selected_path.clone(), insp.clone());
            self.inspection = Some(insp);
        } else if !self.selected_is_dir && self.selected_path.exists() {
            if let Some(parent) = self.selected_path.parent() {
                let insp = inspect_vault(parent);
                self.inspection_cache.insert(parent.to_path_buf(), insp.clone());
                self.inspection = Some(insp);
            } else {
                self.inspection = None;
            }
        } else {
            self.inspection = None;
        }
    }

    fn refresh_all_inspections(&mut self) {
        self.refresh_current_inspection();
        for v in &self.tracked_vaults {
            if v.path.exists() {
                self.inspection_cache.insert(v.path.clone(), inspect_vault(&v.path));
            }
        }
    }

    /// Retrieve all tracked folders that are currently decrypted / unencrypted
    fn get_unlocked_vaults(&self) -> Vec<PathBuf> {
        let mut list = Vec::new();

        // 1. All session-unlocked folders
        for p in &self.unlocked_during_session {
            if p.exists() && !vault::is_locked(p) && !list.contains(p) {
                list.push(p.clone());
            }
        }

        // 2. All managed folders in tracked list currently unlocked
        for item in &self.tracked_vaults {
            if item.path.exists() && !vault::is_locked(&item.path) && !list.contains(&item.path) {
                list.push(item.path.clone());
            }
        }

        list
    }
}

impl eframe::App for SecureVaultApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // High responsiveness during active background encryption/decryption
        if self.is_busy {
            ui.ctx().request_repaint();
        }

        // ── Check close request (Requirement 3: Exit Re-encrypt Prompt) ──
        if ui.input(|i| i.viewport().close_requested()) && !self.bypass_exit_check {
            let unlocked = self.get_unlocked_vaults();
            if !unlocked.is_empty() {
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.show_exit_dialog = true;
                self.exit_password.clear();
                self.exit_confirm_password.clear();
                self.exit_error = None;
            }
        }

        // ── Poll worker messages ──
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                VaultTaskMsg::Progress(txt) => {
                    self.progress_text = txt;
                }
                VaultTaskMsg::DecryptProgress(info) => {
                    let state = self.active_progress.get_or_insert_with(|| ActiveProgressState {
                        folder: info.folder.clone(),
                        is_decrypt: true,
                        completed: 0,
                        total: info.total,
                        current_file: String::new(),
                        recent_files: Vec::new(),
                        total_bytes_done: 0,
                    });
                    state.completed = info.completed;
                    state.total = info.total;
                    state.current_file = info.current_file.clone();
                    state.total_bytes_done += info.file_size;
                    state.recent_files.push((info.current_file, info.file_size));
                    if state.recent_files.len() > 60 {
                        state.recent_files.remove(0);
                    }
                    let pct = if info.total > 0 {
                        (info.completed as f64 / info.total as f64) * 100.0
                    } else {
                        0.0
                    };
                    self.progress_text = format!("正在解密还原: {} / {} 个文件 ({:.1}%)", info.completed, info.total, pct);
                }
                VaultTaskMsg::EncryptProgress(info) => {
                    let state = self.active_progress.get_or_insert_with(|| ActiveProgressState {
                        folder: info.folder.clone(),
                        is_decrypt: false,
                        completed: 0,
                        total: info.total,
                        current_file: String::new(),
                        recent_files: Vec::new(),
                        total_bytes_done: 0,
                    });
                    state.completed = info.completed;
                    state.total = info.total;
                    state.current_file = info.current_file.clone();
                    state.total_bytes_done += info.file_size;
                    state.recent_files.push((info.current_file, info.file_size));
                    if state.recent_files.len() > 60 {
                        state.recent_files.remove(0);
                    }
                    let pct = if info.total > 0 {
                        (info.completed as f64 / info.total as f64) * 100.0
                    } else {
                        0.0
                    };
                    self.progress_text = format!("正在加密锁定: {} / {} 个文件 ({:.1}%)", info.completed, info.total, pct);
                }
                VaultTaskMsg::BatchProgress(binfo) => {
                    self.batch_running_info = Some(binfo.clone());
                    let action = if binfo.is_encrypt { "加密" } else { "解密" };
                    let pct = if binfo.folder_total > 0 {
                        format!(" ({:.1}%)", (binfo.folder_completed as f64 / binfo.folder_total as f64) * 100.0)
                    } else {
                        String::new()
                    };
                    self.progress_text = format!(
                        "批量{}中 [{}/{}]: {} - 正在处理文件 {}/{}{}",
                        action,
                        binfo.current_folder_index + 1,
                        binfo.total_folders,
                        binfo.folder_name,
                        binfo.folder_completed,
                        binfo.folder_total,
                        pct
                    );
                }
                VaultTaskMsg::BatchFolderCompleted { folder, is_encrypt, result } => {
                    if folder.exists() {
                        self.inspection_cache.insert(folder.clone(), inspect_vault(&folder));
                    }
                    if is_encrypt {
                        self.unlocked_during_session.remove(&folder);
                    } else {
                        self.unlocked_during_session.insert(folder.clone());
                    }
                    if let Err(e) = result {
                        eprintln!("Batch error for {}: {}", folder.display(), e);
                    }
                }
                VaultTaskMsg::BatchAllCompleted { total, success_count, fail_count, is_encrypt } => {
                    self.is_busy = false;
                    self.active_progress = None;
                    self.batch_running_info = None;
                    self.progress_text.clear();
                    self.refresh_all_inspections();
                    let action = if is_encrypt { "加密" } else { "解密" };
                    if fail_count == 0 {
                        self.status_message = Some((
                            format!("✅ 批量{}全部完成！共成功处理 {} / {} 个项目。", action, success_count, total),
                            false,
                        ));
                    } else {
                        self.status_message = Some((
                            format!("⚠️ 批量{}完成：成功 {} / {} 个，失败 {} 个（详情请查看日志）。", action, success_count, total, fail_count),
                            true,
                        ));
                    }
                }
                VaultTaskMsg::Success(txt) => {
                    self.is_busy = false;
                    self.active_progress = None;
                    self.batch_running_info = None;
                    self.progress_text.clear();
                    self.status_message = Some((txt, false));
                    self.password.clear();
                    self.confirm_password.clear();
                    self.refresh_all_inspections();
                    if self.selected_is_dir && self.selected_path.exists() {
                        if vault::is_locked(&self.selected_path) {
                            self.active_tab = ActiveTab::Unlock;
                        } else {
                            self.active_tab = ActiveTab::Lock;
                        }
                    }
                }
                VaultTaskMsg::Error(err) => {
                    self.is_busy = false;
                    self.active_progress = None;
                    self.batch_running_info = None;
                    self.progress_text.clear();
                    self.status_message = Some((format!("失败: {}", err), true));
                    self.password.clear();
                    self.confirm_password.clear();
                    self.refresh_all_inspections();
                }
                VaultTaskMsg::ExitEncryptComplete(result) => {
                    self.is_exit_encrypting = false;
                    match result {
                        Ok(()) => {
                            self.bypass_exit_check = true;
                            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                        Err(e) => {
                            self.exit_error = Some(format!("加密失败: {}", e));
                        }
                    }
                }
            }
        }

        // ── Top Title Bar ──
        egui::Panel::top("top_header")
            .frame(
                egui::Frame::default()
                    .fill(egui::Color32::from_rgb(20, 25, 36))
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(36, 45, 62)))
                    .inner_margin(egui::Margin::symmetric(14, 8)),
            )
            .show(ui, |ui| {
                ui.allocate_ui_with_layout(
                    egui::vec2(ui.available_width(), 26.0),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        ui.label(
                            egui::RichText::new("🔐  SecureVault")
                                .size(16.0)
                                .strong()
                                .color(egui::Color32::WHITE),
                        );
                        ui.add_space(8.0);

                        // Version badge
                        egui::Frame::default()
                            .fill(egui::Color32::from_rgb(26, 44, 76))
                            .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(59, 130, 246)))
                            .corner_radius(egui::CornerRadius::same(10))
                            .inner_margin(egui::Margin::symmetric(8, 2))
                            .show(ui, |ui| {
                                ui.label(
                                    egui::RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                                        .size(11.0)
                                        .strong()
                                        .color(egui::Color32::from_rgb(190, 220, 255)),
                                );
                            });

                        ui.add_space(4.0);

                        // Portable tag
                        egui::Frame::default()
                            .fill(egui::Color32::from_rgb(18, 38, 28))
                            .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(16, 185, 129)))
                            .corner_radius(egui::CornerRadius::same(10))
                            .inner_margin(egui::Margin::symmetric(7, 2))
                            .show(ui, |ui| {
                                ui.label(
                                    egui::RichText::new("免安装绿色版")
                                        .size(10.5)
                                        .color(egui::Color32::from_rgb(167, 243, 208)),
                                );
                            });

                        ui.add_space(8.0);

                        // Quick action button in top header to open software directory
                        if icon_text_button(
                            ui,
                            true,
                            "📂",
                            "打开软件目录",
                            egui::Color32::from_rgb(28, 38, 54),
                            egui::Stroke::new(1.0, egui::Color32::from_rgb(52, 70, 98)),
                            egui::Color32::from_rgb(215, 230, 255),
                            egui::vec2(110.0, 24.0),
                            4.0,
                        )
                        .on_hover_text(format!("软件程序所在物理目录：\n{}\n\n点击直接在系统文件管理器中打开", self.app_dir.display()))
                        .clicked()
                        {
                            open_in_file_manager(&self.app_dir);
                        }

                        ui.add_space(6.0);
                        ui.label(
                            egui::RichText::new("军工级文件加密 · AES-256-GCM + Argon2id")
                                .size(11.0)
                                .color(egui::Color32::from_rgb(115, 130, 155)),
                        );

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if self.selected_is_dir && self.selected_path.exists() {
                                let locked = vault::is_locked(&self.selected_path);
                                render_status_pill(ui, locked);
                            }
                        });
                    },
                );
            });

        // ── Bottom Status Bar (Software Directory, Version, Engine Info) ──
        egui::Panel::bottom("bottom_status_bar")
            .frame(
                egui::Frame::default()
                    .fill(egui::Color32::from_rgb(16, 21, 30))
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(32, 42, 58)))
                    .inner_margin(egui::Margin::symmetric(14, 6)),
            )
            .show(ui, |ui| {
                ui.allocate_ui_with_layout(
                    egui::vec2(ui.available_width(), 20.0),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        ui.label(
                            egui::RichText::new("📂 软件所在文件夹:")
                                .size(11.5)
                                .strong()
                                .color(egui::Color32::from_rgb(180, 205, 235)),
                        );
                        ui.add_space(4.0);

                        let app_dir_str = self.app_dir.to_string_lossy().to_string();
                        let dir_resp = ui.add(
                            egui::Label::new(
                                egui::RichText::new(&app_dir_str)
                                    .monospace()
                                    .size(11.0)
                                    .color(egui::Color32::from_rgb(220, 235, 255)),
                            )
                            .truncate()
                            .sense(egui::Sense::click()),
                        );
                        if dir_resp.double_clicked() {
                            open_in_file_manager(&self.app_dir);
                        }
                        if dir_resp.clicked() {
                            ui.ctx().copy_text(app_dir_str.clone());
                            self.status_message = Some(("已复制软件所在文件夹路径到剪贴板".into(), false));
                        }
                        dir_resp.on_hover_text(format!(
                            "软件程序所在物理路径: {}\n\n💡 提示: 单击快速复制路径，双击在系统文件管理器中打开",
                            app_dir_str
                        ));

                        ui.add_space(8.0);
                        if icon_text_button(
                            ui,
                            true,
                            "↗",
                            "打开目录",
                            egui::Color32::from_rgb(26, 35, 50),
                            egui::Stroke::new(1.0, egui::Color32::from_rgb(48, 62, 86)),
                            egui::Color32::from_rgb(200, 215, 240),
                            egui::vec2(76.0, 20.0),
                            3.0,
                        )
                        .on_hover_text("在系统文件管理器中打开软件所在文件夹")
                        .clicked()
                        {
                            open_in_file_manager(&self.app_dir);
                        }

                        ui.add_space(4.0);
                        if icon_text_button(
                            ui,
                            true,
                            "📋",
                            "复制路径",
                            egui::Color32::from_rgb(26, 35, 50),
                            egui::Stroke::new(1.0, egui::Color32::from_rgb(48, 62, 86)),
                            egui::Color32::from_rgb(200, 215, 240),
                            egui::vec2(76.0, 20.0),
                            3.0,
                        )
                        .on_hover_text("复制软件所在文件夹路径到剪贴板")
                        .clicked()
                        {
                            ui.ctx().copy_text(app_dir_str.clone());
                            self.status_message = Some(("已复制软件所在文件夹路径到剪贴板".into(), false));
                        }

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(
                                egui::RichText::new(format!("SecureVault v{}", env!("CARGO_PKG_VERSION")))
                                    .size(11.0)
                                    .strong()
                                    .color(egui::Color32::from_rgb(145, 175, 215)),
                            );
                            ui.add_space(8.0);
                            ui.label(
                                egui::RichText::new("·")
                                    .size(12.0)
                                    .color(egui::Color32::from_rgb(70, 85, 110)),
                            );
                            ui.add_space(8.0);
                            ui.label(
                                egui::RichText::new("零知识端到端保护")
                                    .size(10.5)
                                    .color(egui::Color32::from_rgb(115, 135, 160)),
                            );
                        });
                    },
                );
            });

        // ── Left Sidebar (Takes full left column height from top to bottom) ──
        egui::Panel::left("left_sidebar")
            .default_size(384.0)
            .min_size(312.0)
            .max_size(650.0)
            .resizable(true)
            .frame(
                egui::Frame::default()
                    .fill(egui::Color32::from_rgb(18, 23, 33))
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(34, 43, 60)))
                    .inner_margin(egui::Margin::symmetric(10, 8)),
            )
            .show(ui, |ui| {
                self.ui_left_sidebar(ui);
            });

        // ── Central Operations Panel (Fills the remaining area) ──
        egui::CentralPanel::default()
            .frame(
                egui::Frame::default()
                    .fill(egui::Color32::from_rgb(14, 18, 26))
                    .inner_margin(egui::Margin::symmetric(16, 12)),
            )
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("central_panel_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        self.ui_central_panel(ui);
                    });
            });

        // ── Exit Re-encrypt Modal Dialog (Requirement 3) ──
        if self.show_exit_dialog {
            let screen_rect = ui.max_rect();
            ui.painter().rect_filled(screen_rect, 0.0, egui::Color32::from_rgba_premultiplied(0, 0, 0, 150));
            self.ui_exit_dialog(ui);
        }

        // ── Confirm Remove From List Modal Dialog (Requirement 1) ──
        if self.confirm_remove_vault.is_some() {
            let screen_rect = ui.max_rect();
            ui.painter().rect_filled(screen_rect, 0.0, egui::Color32::from_rgba_premultiplied(0, 0, 0, 150));
            self.ui_confirm_remove_dialog(ui);
        }

        // ── Batch Operation Modal Dialog ──
        if self.batch_dialog.is_some() {
            let screen_rect = ui.max_rect();
            ui.painter().rect_filled(screen_rect, 0.0, egui::Color32::from_rgba_premultiplied(0, 0, 0, 150));
            self.ui_batch_dialog(ui);
        }
    }
}

// ── UI Components Sub-methods ──

impl SecureVaultApp {
    fn ui_left_sidebar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.allocate_ui_with_layout(
            egui::vec2(ui.available_width(), 26.0),
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                ui.label(egui::RichText::new("📁  受保护文件夹").strong().size(13.0));
                ui.add_space(4.0);
                let count = self.tracked_vaults.len();
                egui::Frame::default()
                    .fill(egui::Color32::from_rgb(30, 38, 54))
                    .corner_radius(egui::CornerRadius::same(10))
                    .inner_margin(egui::Margin::symmetric(6, 1))
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new(count.to_string()).size(10.5).strong().color(egui::Color32::from_rgb(170, 185, 215)));
                    });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if icon_text_button(
                        ui,
                        true,
                        "➕",
                        "添加",
                        egui::Color32::from_rgb(37, 99, 235),
                        egui::Stroke::NONE,
                        egui::Color32::WHITE,
                        egui::vec2(58.0, 24.0),
                        5.0,
                    )
                    .on_hover_text("添加新的本地文件夹进行加密管理（支持单选或多选）")
                    .clicked()
                    {
                        if let Some(folders) = rfd::FileDialog::new().pick_folders() {
                            let mut added_any = false;
                            let mut last_selected = None;
                            for folder in folders {
                                let name = folder
                                    .file_name()
                                    .map(|n| n.to_string_lossy().to_string())
                                    .unwrap_or_else(|| "Folder".into());

                                if !self.tracked_vaults.iter().any(|v| v.path == folder) {
                                    self.expanded_folders.insert(folder.clone());
                                    self.tracked_vaults.push(TrackedVault {
                                        name: name.clone(),
                                        path: folder.clone(),
                                    });
                                    let new_idx = self.tracked_vaults.len() - 1;
                                    last_selected = Some((folder, name, true, Some(new_idx)));
                                    added_any = true;
                                }
                            }
                            if added_any {
                                save_tracked_vaults(&self.tracked_vaults);
                                if let Some((f_path, f_name, f_is_dir, f_idx)) = last_selected {
                                    self.select_target(f_path, f_name, f_is_dir, f_idx);
                                }
                            }
                        }
                    }

                    // Centered 24x24 refresh square button
                    let (refresh_rect, refresh_resp) = ui.allocate_exact_size(egui::vec2(24.0, 24.0), egui::Sense::click());
                    if refresh_resp.hovered() {
                        ui.painter().rect_filled(refresh_rect, 4.0, egui::Color32::from_rgb(42, 54, 76));
                    }
                    ui.painter().text(
                        refresh_rect.center(),
                        egui::Align2::CENTER_CENTER,
                        "🔄",
                        egui::FontId::proportional(12.0),
                        if refresh_resp.hovered() { egui::Color32::WHITE } else { egui::Color32::from_rgb(175, 190, 215) },
                    );
                    if refresh_resp.on_hover_text("刷新所有状态与文件清单").clicked() {
                        self.refresh_all_inspections();
                    }

                    // Quick toggle all expanded / collapsed
                    if !self.tracked_vaults.is_empty() {
                        let all_expanded = self.tracked_vaults.iter().all(|v| self.expanded_folders.contains(&v.path));
                        let (toggle_icon, toggle_label) = if all_expanded { ("⊟", "全部折叠") } else { ("⊞", "全部展开") };
                        if icon_text_button(
                            ui,
                            true,
                            toggle_icon,
                            toggle_label,
                            egui::Color32::from_rgb(26, 34, 48),
                            egui::Stroke::new(1.0, egui::Color32::from_rgb(46, 60, 84)),
                            egui::Color32::from_rgb(180, 195, 220),
                            egui::vec2(78.0, 24.0),
                            5.0,
                        )
                        .on_hover_text("展开或折叠所有受保护文件夹及内部所有子文件夹")
                        .clicked()
                        {
                            if all_expanded {
                                self.expanded_folders.clear();
                            } else {
                                self.expanded_folders = collect_all_folder_paths(&self.tracked_vaults);
                            }
                        }
                    }
                });
            },
        );

        // ── Batch Operation Buttons (批量加密 / 批量解密) ──
        if !self.tracked_vaults.is_empty() {
            let unlocked_count = self.tracked_vaults.iter().filter(|v| v.path.exists() && !vault::is_locked(&v.path)).count();
            let locked_count = self.tracked_vaults.iter().filter(|v| v.path.exists() && vault::is_locked(&v.path)).count();

            ui.add_space(4.0);
            ui.allocate_ui_with_layout(
                egui::vec2(ui.available_width(), 26.0),
                egui::Layout::left_to_right(egui::Align::Center),
                |ui| {
                    if icon_text_button(
                        ui,
                        unlocked_count > 0 && !self.is_busy,
                        "🔒",
                        &format!("批量加密 ({})", unlocked_count),
                        egui::Color32::from_rgb(16, 149, 90),
                        egui::Stroke::NONE,
                        egui::Color32::WHITE,
                        egui::vec2(0.0, 24.0),
                        4.0,
                    )
                    .on_hover_text(if unlocked_count > 0 {
                        "一键批量加密所有或选中的未锁定项目"
                    } else {
                        "当前没有未锁定的项目"
                    })
                    .clicked()
                    {
                        self.open_batch_dialog(BatchMode::Encrypt);
                    }

                    ui.add_space(4.0);

                    if icon_text_button(
                        ui,
                        locked_count > 0 && !self.is_busy,
                        "🔓",
                        &format!("批量解密 ({})", locked_count),
                        egui::Color32::from_rgb(217, 119, 6),
                        egui::Stroke::NONE,
                        egui::Color32::WHITE,
                        egui::vec2(0.0, 24.0),
                        4.0,
                    )
                    .on_hover_text(if locked_count > 0 {
                        "一键批量解密所有或选中的已加密项目"
                    } else {
                        "当前没有已加密的项目"
                    })
                    .clicked()
                    {
                        self.open_batch_dialog(BatchMode::Decrypt);
                    }
                },
            );
        }

        ui.add_space(4.0);
        ui.separator();
        ui.add_space(4.0);

        if self.tracked_vaults.is_empty() {
            ui.add_space(30.0);
            ui.vertical_centered(|ui| {
                ui.label(egui::RichText::new("暂无文件夹").weak().size(13.0));
                ui.add_space(4.0);
                ui.label(egui::RichText::new("点击右上角【➕ 添加】选择本地目录").weak().size(11.0));
            });
            return;
        }

        let mut selected_target: Option<(PathBuf, String, bool, Option<usize>)> = None;
        let mut toggled_folders: Vec<PathBuf> = Vec::new();

        egui::ScrollArea::vertical()
            .id_salt("tracked_vaults_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for (idx, vault_item) in self.tracked_vaults.iter().enumerate() {
                    let is_exact_selected = self.selected_path == vault_item.path;
                    let is_child_active = self.selected_index == Some(idx) && !is_exact_selected;
                    let locked = vault_item.path.exists() && vault::is_locked(&vault_item.path);
                    let exists = vault_item.path.exists();
                    let is_expanded = self.expanded_folders.contains(&vault_item.path);

                    let (card_bg, card_stroke) = if is_exact_selected {
                        (
                            egui::Color32::from_rgb(28, 36, 52),
                            egui::Stroke::new(1.5, egui::Color32::from_rgb(59, 130, 246)),
                        )
                    } else if is_child_active {
                        (
                            egui::Color32::from_rgb(24, 30, 44),
                            egui::Stroke::new(1.0, egui::Color32::from_rgb(45, 65, 95)),
                        )
                    } else {
                        (
                            egui::Color32::from_rgb(22, 28, 40),
                            egui::Stroke::new(1.0, egui::Color32::from_rgb(38, 48, 68)),
                        )
                    };

                    let initial_toggled_count = toggled_folders.len();
                    let mut arrow_rect_opt: Option<egui::Rect> = None;
                    let mut trash_rect_opt: Option<egui::Rect> = None;
                    let mut arrow_clicked = false;
                    let mut trash_clicked = false;
                    let mut arrow_hovered = false;
                    let mut trash_hovered = false;
                    let mut header_bottom_y = 0.0f32;

                    let card_frame_resp = egui::Frame::default()
                        .fill(card_bg)
                        .stroke(card_stroke)
                        .corner_radius(egui::CornerRadius::same(7))
                        .inner_margin(egui::Margin::symmetric(10, 8))
                        .show(ui, |ui| {
                            ui.allocate_ui_with_layout(
                                egui::vec2(ui.available_width(), 24.0),
                                egui::Layout::left_to_right(egui::Align::Center),
                                |ui| {
                                    // 1. Fold / Expand arrow toggle button (clean, 22x22 perfectly centered square)
                                    let (arrow_rect, arrow_resp) = ui.allocate_exact_size(egui::vec2(22.0, 22.0), egui::Sense::click());
                                    arrow_rect_opt = Some(arrow_rect);
                                    if arrow_resp.hovered() {
                                        arrow_hovered = true;
                                        ui.painter().rect_filled(arrow_rect, 4.0, egui::Color32::from_rgb(42, 54, 76));
                                    }
                                    let arrow_glyph = if is_expanded { "▼" } else { "▶" };
                                    let arrow_color = if arrow_resp.hovered() {
                                        egui::Color32::WHITE
                                    } else {
                                        egui::Color32::from_rgb(165, 180, 205)
                                    };
                                    ui.painter().text(
                                        arrow_rect.center(),
                                        egui::Align2::CENTER_CENTER,
                                        arrow_glyph,
                                        egui::FontId::proportional(11.0),
                                        arrow_color,
                                    );
                                    if arrow_resp.on_hover_text("折叠/展开文件夹内容").clicked() {
                                        toggled_folders.push(vault_item.path.clone());
                                        arrow_clicked = true;
                                    }

                                    ui.add_space(3.0);

                                    // 2. Status badge (matching 22px height pill, vertically centered, with live progress)
                                    let is_active_decrypting = self.active_progress.as_ref().map_or(false, |p| p.is_decrypt && p.folder == vault_item.path);
                                    let is_active_encrypting = self.active_progress.as_ref().map_or(false, |p| !p.is_decrypt && p.folder == vault_item.path);
                                    let is_batch_current = self.batch_running_info.as_ref().map_or(false, |b| b.folder_path == vault_item.path);

                                    let (status_icon, status_text_owned, status_border, status_text_color, status_bg) = if is_active_decrypting {
                                        let p = self.active_progress.as_ref().unwrap();
                                        let text = if p.total > 0 {
                                            format!("解密中 {}/{}", p.completed, p.total)
                                        } else {
                                            "解密中...".to_string()
                                        };
                                        ("🔄", text, egui::Color32::from_rgb(217, 119, 6), egui::Color32::WHITE, egui::Color32::from_rgb(50, 30, 10))
                                    } else if is_active_encrypting {
                                        let p = self.active_progress.as_ref().unwrap();
                                        let text = if p.total > 0 {
                                            format!("加密中 {}/{}", p.completed, p.total)
                                        } else {
                                            "加密中...".to_string()
                                        };
                                        ("🔄", text, egui::Color32::from_rgb(16, 185, 129), egui::Color32::WHITE, egui::Color32::from_rgb(12, 50, 30))
                                    } else if is_batch_current {
                                        let b = self.batch_running_info.as_ref().unwrap();
                                        let action = if b.is_encrypt { "加密中" } else { "解密中" };
                                        let text = if b.folder_total > 0 {
                                            format!("{} {}/{}", action, b.folder_completed, b.folder_total)
                                        } else {
                                            format!("{}...", action)
                                        };
                                        ("🔄", text, egui::Color32::from_rgb(59, 130, 246), egui::Color32::WHITE, egui::Color32::from_rgb(20, 45, 80))
                                    } else if !exists {
                                        ("❌", "不存在".to_string(), egui::Color32::from_rgb(239, 68, 68), egui::Color32::from_rgb(255, 210, 215), egui::Color32::from_rgb(46, 18, 22))
                                    } else if locked {
                                        ("🔒", "已加密".to_string(), egui::Color32::from_rgb(16, 185, 129), egui::Color32::from_rgb(230, 255, 245), egui::Color32::from_rgb(12, 42, 28))
                                    } else {
                                        ("🔓", "未锁定".to_string(), egui::Color32::from_rgb(245, 158, 11), egui::Color32::from_rgb(255, 246, 214), egui::Color32::from_rgb(48, 34, 10))
                                    };

                                    let badge_resp = render_badge_pill(
                                        ui,
                                        status_icon,
                                        &status_text_owned,
                                        status_bg,
                                        egui::Stroke::new(1.0, status_border),
                                        status_text_color,
                                        22.0,
                                        true,
                                    );

                                    if badge_resp
                                        .on_hover_text("点击选中此保险箱并在右侧进行加解密操作")
                                        .clicked()
                                    {
                                        selected_target = Some((vault_item.path.clone(), vault_item.name.clone(), true, Some(idx)));
                                    }

                                    ui.add_space(4.0);

                                    // 3. Vault Name button (22px height, vertically centered)
                                    let name_btn = egui::Button::new(
                                        egui::RichText::new(&vault_item.name)
                                            .size(13.0)
                                            .strong()
                                            .color(if is_exact_selected { egui::Color32::WHITE } else { egui::Color32::from_rgb(215, 230, 255) }),
                                    )
                                    .fill(if is_exact_selected { egui::Color32::from_rgb(37, 99, 235) } else { egui::Color32::from_rgb(25, 33, 48) })
                                    .stroke(if is_exact_selected { egui::Stroke::NONE } else { egui::Stroke::new(1.0, egui::Color32::from_rgb(45, 60, 85)) })
                                    .corner_radius(egui::CornerRadius::same(5))
                                    .min_size(egui::vec2(0.0, 22.0));

                                    let name_resp = ui.add(name_btn);
                                    if name_resp.double_clicked() {
                                        open_in_file_manager(&vault_item.path);
                                    }
                                    if name_resp.on_hover_text("单击选中此保险箱，双击在文件管理器中打开").clicked() {
                                        selected_target = Some((vault_item.path.clone(), vault_item.name.clone(), true, Some(idx)));
                                    }

                                    // 4. Trash button on the far right (22x22 perfectly centered square)
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        let (trash_rect, trash_resp) = ui.allocate_exact_size(egui::vec2(22.0, 22.0), egui::Sense::click());
                                        trash_rect_opt = Some(trash_rect);
                                        if trash_resp.hovered() {
                                            trash_hovered = true;
                                            ui.painter().rect_filled(trash_rect, 4.0, egui::Color32::from_rgb(60, 25, 30));
                                        }
                                        let trash_color = if trash_resp.hovered() {
                                            egui::Color32::from_rgb(255, 100, 100)
                                        } else {
                                            egui::Color32::from_rgb(140, 155, 180)
                                        };
                                        ui.painter().text(
                                            trash_rect.center(),
                                            egui::Align2::CENTER_CENTER,
                                            "🗑",
                                            egui::FontId::proportional(12.0),
                                            trash_color,
                                        );
                                        if trash_resp
                                            .on_hover_text("从管理列表中移除 (需要二次确认，不删除本地文件)")
                                            .clicked()
                                        {
                                            self.confirm_remove_vault = Some(vault_item.clone());
                                            trash_clicked = true;
                                        }
                                    });
                                },
                            );

                            ui.add_space(2.0);
                            let path_label_resp = ui.add(
                                egui::Label::new(
                                    egui::RichText::new(vault_item.path.to_string_lossy())
                                        .size(10.5)
                                        .monospace()
                                        .color(if is_exact_selected {
                                            egui::Color32::from_rgb(160, 190, 235)
                                        } else {
                                            egui::Color32::from_rgb(125, 140, 165)
                                        }),
                                )
                                .sense(egui::Sense::click()),
                            );
                            if path_label_resp.double_clicked() {
                                open_in_file_manager(&vault_item.path);
                            }
                            if path_label_resp.on_hover_text("单击选中此文件夹，双击在文件管理器中打开").clicked() {
                                selected_target = Some((vault_item.path.clone(), vault_item.name.clone(), true, Some(idx)));
                            }

                            header_bottom_y = ui.cursor().min.y;

                            // Foldable list of files / encrypted items under this folder
                            if is_expanded {
                                ui.add_space(4.0);
                                ui.separator();
                                ui.add_space(2.0);
                                let insp = if is_exact_selected {
                                    self.inspection.clone()
                                } else if let Some(cached) = self.inspection_cache.get(&vault_item.path) {
                                    Some(cached.clone())
                                } else if !self.is_busy {
                                    let fresh = inspect_vault(&vault_item.path);
                                    self.inspection_cache.insert(vault_item.path.clone(), fresh.clone());
                                    Some(fresh)
                                } else {
                                    None
                                };

                                if let Some(insp) = insp {
                                    egui::ScrollArea::horizontal()
                                        .id_salt(format!("vault_tree_hscroll_{}", idx))
                                        .auto_shrink([false, true])
                                        .show(ui, |ui| {
                                            if insp.is_locked {
                                                let data_dir = vault_item.path.join(".vault_data");
                                                let is_data_expanded = self.expanded_folders.contains(&data_dir);
                                                let is_data_selected = self.selected_path == data_dir;

                                                ui.allocate_ui_with_layout(
                                                    egui::vec2(ui.available_width(), 22.0),
                                                    egui::Layout::left_to_right(egui::Align::Center),
                                                    |ui| {
                                                        let (arrow_rect, arrow_resp) = ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::click());
                                                        if arrow_resp.hovered() {
                                                            ui.painter().rect_filled(arrow_rect, 3.0, egui::Color32::from_rgb(42, 54, 76));
                                                        }
                                                        let arrow_glyph = if is_data_expanded { "▼" } else { "▶" };
                                                        let arrow_color = if arrow_resp.hovered() {
                                                            egui::Color32::WHITE
                                                        } else {
                                                            egui::Color32::from_rgb(165, 180, 205)
                                                        };
                                                        ui.painter().text(
                                                            arrow_rect.center(),
                                                            egui::Align2::CENTER_CENTER,
                                                            arrow_glyph,
                                                            egui::FontId::proportional(10.0),
                                                            arrow_color,
                                                        );

                                                        let btn = egui::Button::new(
                                                            egui::RichText::new("📦  密文存储区 (.vault_data)")
                                                                .size(11.5)
                                                                .strong()
                                                                .color(if is_data_selected {
                                                                    egui::Color32::WHITE
                                                                } else {
                                                                    egui::Color32::from_rgb(215, 230, 255)
                                                                }),
                                                        )
                                                        .fill(if is_data_selected {
                                                            egui::Color32::from_rgb(37, 99, 235)
                                                        } else {
                                                            egui::Color32::TRANSPARENT
                                                        })
                                                        .stroke(if is_data_selected {
                                                            egui::Stroke::new(1.0, egui::Color32::from_rgb(96, 165, 250))
                                                        } else {
                                                            egui::Stroke::NONE
                                                        })
                                                        .corner_radius(egui::CornerRadius::same(4))
                                                        .min_size(egui::vec2(0.0, 18.0));
                                                        let btn_resp = ui.add(btn);
                                                        if btn_resp.double_clicked() {
                                                            open_in_file_manager(&data_dir);
                                                        }
                                                        let data_tooltip = format!(
                                                            "📦 密文存储区 (.vault_data)\n加密块数: {} 块\n总密文大小: {}\n路径: {}\n\n💡 提示: 单击选中此保险箱，双击在文件管理器中打开",
                                                            insp.encrypted_files.len(),
                                                            format_bytes(insp.total_encrypted_bytes),
                                                            data_dir.display()
                                                        );
                                                        if btn_resp.on_hover_text(data_tooltip).clicked() {
                                                            selected_target = Some((vault_item.path.clone(), vault_item.name.clone(), true, Some(idx)));
                                                        }

                                                        if arrow_resp.on_hover_text("折叠/展开密文存储区").clicked() {
                                                            toggled_folders.push(data_dir.clone());
                                                        }

                                                        ui.colored_label(
                                                            egui::Color32::from_rgb(52, 211, 153),
                                                            format!("{} 块 ({})", insp.encrypted_files.len(), format_bytes(insp.total_encrypted_bytes)),
                                                        );
                                                    },
                                                );

                                                if is_data_expanded {
                                                    ui.indent("enc_files_indent", |ui| {
                                                        if insp.encrypted_files.is_empty() {
                                                            ui.label(egui::RichText::new("(空)").weak().size(10.5));
                                                        } else {
                                                            for (fname, fsize) in &insp.encrypted_files {
                                                                let enc_path = data_dir.join(fname);
                                                                let is_enc_selected = self.selected_path == enc_path;

                                                                ui.allocate_ui_with_layout(
                                                                    egui::vec2(ui.available_width(), 20.0),
                                                                    egui::Layout::left_to_right(egui::Align::Center),
                                                                    |ui| {
                                                                        let enc_btn = egui::Button::new(
                                                                            egui::RichText::new(format!("🔒  {}", fname))
                                                                                .size(10.5)
                                                                                .monospace()
                                                                                .color(if is_enc_selected {
                                                                                    egui::Color32::WHITE
                                                                                } else {
                                                                                    egui::Color32::from_rgb(180, 195, 215)
                                                                                }),
                                                                        )
                                                                        .fill(if is_enc_selected {
                                                                            egui::Color32::from_rgb(30, 58, 110)
                                                                        } else {
                                                                            egui::Color32::TRANSPARENT
                                                                        })
                                                                        .stroke(if is_enc_selected {
                                                                            egui::Stroke::new(1.0, egui::Color32::from_rgb(60, 100, 180))
                                                                        } else {
                                                                            egui::Stroke::NONE
                                                                        })
                                                                        .corner_radius(egui::CornerRadius::same(3))
                                                                        .min_size(egui::vec2(0.0, 18.0));

                                                                        let enc_resp = ui.add(enc_btn);
                                                                        if enc_resp.double_clicked() {
                                                                            open_file_with_default_app(&enc_path);
                                                                        }
                                                                        let enc_tooltip = format!(
                                                                            "🔒 密文数据块: {}\n大小: {}\n路径: {}\n\n💡 提示: 单击查看密文数据块详情，双击使用默认程序打开",
                                                                            fname,
                                                                            format_bytes(*fsize),
                                                                            enc_path.display()
                                                                        );
                                                                        if enc_resp.on_hover_text(enc_tooltip).clicked() {
                                                                            selected_target = Some((enc_path, fname.clone(), false, Some(idx)));
                                                                        }

                                                                        add_smart_size_label(ui, *fsize, egui::Color32::from_rgb(140, 155, 180));
                                                                    },
                                                                );
                                                            }
                                                        }
                                                    });
                                                }
                                            } else {
                                                ui.allocate_ui_with_layout(
                                                    egui::vec2(ui.available_width(), 20.0),
                                                    egui::Layout::left_to_right(egui::Align::Center),
                                                    |ui| {
                                                        ui.label(egui::RichText::new("📂  明文目录清单:").size(11.5).strong());
                                                        ui.colored_label(
                                                            egui::Color32::from_rgb(255, 235, 170),
                                                            format!("{} 文件, {} 目录 ({})", insp.total_plain_files, insp.total_plain_dirs, format_bytes(insp.total_plain_bytes)),
                                                        );
                                                    },
                                                );

                                                if insp.plain_tree.is_empty() {
                                                    ui.indent("plain_files_indent", |ui| {
                                                        ui.label(egui::RichText::new("(空文件夹)").size(10.5).weak());
                                                    });
                                                } else {
                                                    let mut tree_target: Option<(PathBuf, String, bool)> = None;
                                                    render_file_tree(
                                                        ui,
                                                        &insp.plain_tree,
                                                        &self.expanded_folders,
                                                        &mut toggled_folders,
                                                        &mut tree_target,
                                                        &self.selected_path,
                                                        0,
                                                    );
                                                    if let Some((target_path, target_name, is_dir)) = tree_target {
                                                        selected_target = Some((target_path, target_name, is_dir, Some(idx)));
                                                    }
                                                }
                                            }
                                        });
                                }
                            }
                        });

                    let card_rect = card_frame_resp.response.rect;
                    let header_rect = egui::Rect::from_min_max(
                        card_rect.min,
                        egui::pos2(card_rect.max.x, header_bottom_y.max(card_rect.min.y + 24.0).min(card_rect.max.y)),
                    );
                    let target_card_rect = if is_expanded {
                        header_rect
                    } else {
                        card_rect
                    };

                    // Sense ONLY hover for card styling and cursor - NEVER consume or steal clicks from child widgets (arrow/trash/tree)!
                    let card_hover_interact = ui.interact(
                        target_card_rect,
                        ui.auto_id_with(("vault_card_hover_box", idx)),
                        egui::Sense::hover(),
                    );

                    let is_mouse_over_arrow_or_trash = ui.input(|i| {
                        i.pointer.hover_pos().map_or(false, |pos| {
                            arrow_rect_opt.map_or(false, |r| r.contains(pos))
                                || trash_rect_opt.map_or(false, |r| r.contains(pos))
                        })
                    });

                    if card_hover_interact.hovered() && !is_exact_selected {
                        ui.painter().rect_stroke(
                            target_card_rect,
                            egui::CornerRadius::same(7),
                            egui::Stroke::new(1.0, egui::Color32::from_rgb(70, 95, 140)),
                            egui::StrokeKind::Inside,
                        );
                    }

                    if card_hover_interact.hovered() && !arrow_hovered && !trash_hovered && !is_mouse_over_arrow_or_trash {
                        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                    }

                    // Card click switching directory:
                    // Only triggers if the user clicked inside the card bounding box,
                    // but NOT on the fold arrow, NOT on trash, NOT on any subfolder fold arrow,
                    // and no specific item (like a child file) was selected.
                    let was_clicked_in_card = ui.input(|i| {
                        if i.pointer.primary_clicked() {
                            i.pointer.interact_pos().map_or(false, |pos| target_card_rect.contains(pos))
                        } else {
                            false
                        }
                    });

                    let was_double_clicked_in_card = ui.input(|i| {
                        if i.pointer.button_double_clicked(egui::PointerButton::Primary) {
                            i.pointer.interact_pos().map_or(false, |pos| target_card_rect.contains(pos))
                        } else {
                            false
                        }
                    });

                    let was_clicked_on_arrow_or_trash = ui.input(|i| {
                        i.pointer.interact_pos().map_or(false, |pos| {
                            arrow_rect_opt.map_or(false, |r| r.contains(pos))
                                || trash_rect_opt.map_or(false, |r| r.contains(pos))
                        })
                    });

                    let toggled_any_folder = toggled_folders.len() > initial_toggled_count;

                    if was_double_clicked_in_card
                        && !arrow_clicked
                        && !trash_clicked
                        && !was_clicked_on_arrow_or_trash
                        && !toggled_any_folder
                        && selected_target.is_none()
                    {
                        open_in_file_manager(&vault_item.path);
                    }

                    if was_clicked_in_card
                        && !arrow_clicked
                        && !trash_clicked
                        && !was_clicked_on_arrow_or_trash
                        && !toggled_any_folder
                        && selected_target.is_none()
                    {
                        selected_target = Some((vault_item.path.clone(), vault_item.name.clone(), true, Some(idx)));
                    }

                    ui.add_space(5.0);
                }
            });

        // Apply toggled folder states safely outside immutable borrow
        for path in toggled_folders {
            if self.expanded_folders.contains(&path) {
                self.expanded_folders.remove(&path);
            } else {
                self.expanded_folders.insert(path);
            }
        }

        if let Some((target_path, target_name, is_dir, parent_idx)) = selected_target {
            self.select_target(target_path, target_name, is_dir, parent_idx);
        }
    }

    // ── Requirement 1: Secondary Confirmation Dialog for Removing Vault ──

    fn ui_confirm_remove_dialog(&mut self, ui: &mut egui::Ui) {
        let vault = match &self.confirm_remove_vault {
            Some(v) => v.clone(),
            None => return,
        };

        egui::Window::new("⚠️ 确认从管理列表移除")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .frame(
                egui::Frame::default()
                    .fill(egui::Color32::from_rgb(22, 28, 40))
                    .stroke(egui::Stroke::new(1.2, egui::Color32::from_rgb(60, 75, 105)))
                    .corner_radius(egui::CornerRadius::same(10))
                    .inner_margin(egui::Margin::symmetric(20, 16)),
            )
            .show(ui.ctx(), |ui| {
                ui.set_width(430.0);
                ui.add_space(4.0);

                ui.allocate_ui_with_layout(
                    egui::vec2(ui.available_width(), 24.0),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        ui.label(
                            egui::RichText::new("❓  确定要从软件管理列表中移除此文件夹吗？")
                                .strong()
                                .size(14.5)
                                .color(egui::Color32::WHITE),
                        );
                    },
                );
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new("仅从软件界面监控列表中移除记录，不会删除或修改您磁盘上的任何文件。")
                        .size(11.5)
                        .color(egui::Color32::from_rgb(140, 160, 185)),
                );

                ui.add_space(12.0);

                egui::Frame::default()
                    .fill(egui::Color32::from_rgb(16, 21, 31))
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(38, 48, 68)))
                    .corner_radius(egui::CornerRadius::same(6))
                    .inner_margin(egui::Margin::symmetric(12, 10))
                    .show(ui, |ui| {
                        ui.allocate_ui_with_layout(
                            egui::vec2(ui.available_width(), 20.0),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.label(egui::RichText::new("📁  文件夹名称:").size(12.0).weak());
                                ui.add_space(4.0);
                                ui.label(egui::RichText::new(&vault.name).size(13.0).strong().color(egui::Color32::from_rgb(220, 235, 255)));
                            },
                        );
                        ui.add_space(4.0);
                        ui.allocate_ui_with_layout(
                            egui::vec2(ui.available_width(), 20.0),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.label(egui::RichText::new("📍  本地路径:").size(12.0).weak());
                                ui.add_space(4.0);
                                ui.label(egui::RichText::new(vault.path.to_string_lossy()).size(11.0).monospace().color(egui::Color32::from_rgb(155, 175, 205)));
                            },
                        );
                    });

                ui.add_space(16.0);

                ui.allocate_ui_with_layout(
                    egui::vec2(ui.available_width(), 32.0),
                    egui::Layout::right_to_left(egui::Align::Center),
                    |ui| {
                        if icon_text_button(
                            ui,
                            true,
                            "🗑️",
                            "确认移除",
                            egui::Color32::from_rgb(220, 53, 69),
                            egui::Stroke::NONE,
                            egui::Color32::WHITE,
                            egui::vec2(105.0, 32.0),
                            6.0,
                        )
                        .clicked()
                        {
                            if let Some(pos) = self.tracked_vaults.iter().position(|v| v.path == vault.path) {
                                self.inspection_cache.remove(&vault.path);
                                self.tracked_vaults.remove(pos);
                                save_tracked_vaults(&self.tracked_vaults);
                                if self.tracked_vaults.is_empty() {
                                    self.selected_index = None;
                                    self.selected_path = PathBuf::new();
                                    self.selected_name.clear();
                                    self.selected_is_dir = true;
                                    self.inspection = None;
                                } else {
                                    let first = self.tracked_vaults[0].clone();
                                    self.select_target(first.path, first.name, true, Some(0));
                                }
                            }
                            self.confirm_remove_vault = None;
                        }

                        if icon_text_button(
                            ui,
                            true,
                            "❌",
                            "取消",
                            egui::Color32::from_rgb(34, 43, 60),
                            egui::Stroke::new(1.0, egui::Color32::from_rgb(55, 70, 95)),
                            egui::Color32::from_rgb(200, 215, 240),
                            egui::vec2(76.0, 32.0),
                            6.0,
                        )
                        .clicked()
                        {
                            self.confirm_remove_vault = None;
                        }
                    },
                );
                ui.add_space(2.0);
            });
    }

    fn ui_central_panel(&mut self, ui: &mut egui::Ui) {
        if self.tracked_vaults.is_empty() || self.selected_path.as_os_str().is_empty() {
            ui.centered_and_justified(|ui| {
                egui::Frame::default()
                    .fill(egui::Color32::from_rgb(20, 25, 36))
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(38, 48, 68)))
                    .corner_radius(egui::CornerRadius::same(10))
                    .inner_margin(egui::Margin::symmetric(36, 28))
                    .show(ui, |ui| {
                        ui.vertical_centered(|ui| {
                            ui.label(egui::RichText::new("🛡️").size(40.0));
                            ui.add_space(8.0);
                            ui.label(
                                egui::RichText::new(format!("欢迎使用 SecureVault 文件夹保险箱 v{}", env!("CARGO_PKG_VERSION")))
                                    .size(17.0)
                                    .strong()
                                    .color(egui::Color32::WHITE),
                            );
                            ui.add_space(6.0);
                            ui.label(
                                egui::RichText::new("请在左侧侧边栏中选择一个受保护文件夹，或点击【➕ 添加】选择本地文件夹。")
                                    .size(12.5)
                                    .color(egui::Color32::from_rgb(140, 155, 180)),
                            );
                            ui.add_space(4.0);
                            ui.label(
                                egui::RichText::new(format!("📂 软件所在文件夹：{}", self.app_dir.display()))
                                    .size(11.5)
                                    .color(egui::Color32::from_rgb(130, 155, 185)),
                            );
                            ui.add_space(14.0);
                            if icon_text_button(
                                ui,
                                true,
                                "➕",
                                "添加本地文件夹开始保护",
                                egui::Color32::from_rgb(37, 99, 235),
                                egui::Stroke::NONE,
                                egui::Color32::WHITE,
                                egui::vec2(200.0, 36.0),
                                6.0,
                            )
                            .clicked()
                            {
                                if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                                    let name = folder
                                        .file_name()
                                        .map(|n| n.to_string_lossy().to_string())
                                        .unwrap_or_else(|| "Folder".into());

                                    if !self.tracked_vaults.iter().any(|v| v.path == folder) {
                                        self.expanded_folders.insert(folder.clone());
                                        self.tracked_vaults.push(TrackedVault {
                                            name: name.clone(),
                                            path: folder.clone(),
                                        });
                                        save_tracked_vaults(&self.tracked_vaults);
                                        let new_idx = self.tracked_vaults.len() - 1;
                                        self.select_target(folder, name, true, Some(new_idx));
                                    }
                                }
                            }
                        });
                    });
            });
            return;
        }

        ui.set_width(ui.available_width());

        let mut return_to_parent: Option<(PathBuf, String, Option<usize>)> = None;
        let parent_vault = self.selected_index.and_then(|idx| self.tracked_vaults.get(idx)).cloned();

        if self.selected_is_dir {
            let is_locked = self.selected_path.exists() && vault::is_locked(&self.selected_path);
            let is_subfolder = parent_vault
                .as_ref()
                .map(|parent| parent.path != self.selected_path)
                .unwrap_or(false);

            // Path hero header card
            egui::Frame::default()
                .fill(egui::Color32::from_rgb(22, 28, 40))
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(42, 54, 76)))
                .corner_radius(egui::CornerRadius::same(8))
                .inner_margin(egui::Margin::symmetric(14, 10))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    let folder_icon = if is_locked {
                        "🔒"
                    } else if is_subfolder {
                        "📁"
                    } else {
                        "📂"
                    };

                    ui.vertical(|ui| {
                        // Row 1: Folder icon + Name + Subfolder Tag + Status Pill
                        ui.allocate_ui_with_layout(
                            egui::vec2(ui.available_width(), 26.0),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.label(egui::RichText::new(folder_icon).size(18.0));
                                ui.add_space(4.0);
                                let dir_name_resp = ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(&self.selected_name)
                                            .size(16.5)
                                            .strong()
                                            .color(egui::Color32::WHITE),
                                    )
                                    .sense(egui::Sense::click()),
                                );
                                if dir_name_resp.double_clicked() {
                                    open_in_file_manager(&self.selected_path);
                                }
                                dir_name_resp.on_hover_text("双击在系统文件管理器中打开此目录");
                                if is_subfolder {
                                    ui.add_space(6.0);
                                    render_badge_pill(
                                        ui,
                                        "📁",
                                        "子目录",
                                        egui::Color32::from_rgb(30, 45, 75),
                                        egui::Stroke::new(1.0, egui::Color32::from_rgb(59, 130, 246)),
                                        egui::Color32::from_rgb(147, 197, 253),
                                        22.0,
                                        false,
                                    );
                                }
                                ui.add_space(8.0);
                                render_status_pill(ui, is_locked);
                            },
                        );

                        ui.add_space(6.0);

                        // Row 2: Path text (left) + Action buttons [Copy Path] + [Open Folder] (right)
                        ui.allocate_ui_with_layout(
                            egui::vec2(ui.available_width(), 26.0),
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                // 1. Rightmost button: 打开目录
                                if icon_text_button(
                                    ui,
                                    true,
                                    "↗",
                                    "打开目录",
                                    egui::Color32::from_rgb(28, 36, 50),
                                    egui::Stroke::new(1.0, egui::Color32::from_rgb(48, 62, 86)),
                                    egui::Color32::from_rgb(200, 215, 235),
                                    egui::vec2(82.0, 24.0),
                                    4.0,
                                )
                                .on_hover_text("在系统文件管理器中打开此文件夹")
                                .clicked()
                                {
                                    open_in_file_manager(&self.selected_path);
                                }

                                ui.add_space(6.0);

                                // 2. Second right button: 复制路径
                                if icon_text_button(
                                    ui,
                                    true,
                                    "📋",
                                    "复制路径",
                                    egui::Color32::from_rgb(28, 36, 50),
                                    egui::Stroke::new(1.0, egui::Color32::from_rgb(48, 62, 86)),
                                    egui::Color32::from_rgb(200, 215, 235),
                                    egui::vec2(82.0, 24.0),
                                    4.0,
                                )
                                .on_hover_text("复制当前文件夹完整路径到剪贴板")
                                .clicked()
                                {
                                    ui.ctx().copy_text(self.selected_path.to_string_lossy().to_string());
                                    self.status_message = Some(("已将文件夹路径复制到剪贴板".into(), false));
                                }

                                // 3. Third right button (if subfolder): 返回主文件夹
                                if is_subfolder {
                                    if let Some(parent) = &parent_vault {
                                        ui.add_space(6.0);
                                        if icon_text_button(
                                            ui,
                                            true,
                                            "↩",
                                            &format!("返回主文件夹: {}", parent.name),
                                            egui::Color32::from_rgb(32, 45, 66),
                                            egui::Stroke::new(1.0, egui::Color32::from_rgb(55, 80, 115)),
                                            egui::Color32::from_rgb(180, 210, 255),
                                            egui::vec2(0.0, 24.0),
                                            4.0,
                                        )
                                        .on_hover_text("返回所属的主文件夹")
                                        .clicked()
                                        {
                                            return_to_parent = Some((parent.path.clone(), parent.name.clone(), self.selected_index));
                                        }
                                    }
                                }

                                ui.add_space(8.0);

                                // 4. Left side: Monospace path text, taking all remaining space
                                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(self.selected_path.to_string_lossy())
                                                .monospace()
                                                .size(11.5)
                                                .color(egui::Color32::from_rgb(155, 175, 205)),
                                        )
                                        .truncate(),
                                    )
                                    .on_hover_text(self.selected_path.to_string_lossy());
                                });
                            },
                        );
                    });
                });

            ui.add_space(8.0);

            // Action Tabs (Modern Segmented Control)
            ui.allocate_ui_with_layout(
                egui::vec2(ui.available_width(), 32.0),
                egui::Layout::left_to_right(egui::Align::Center),
                |ui| {
                    let prev_tab = self.active_tab;
                    if render_tab_button(ui, self.active_tab, ActiveTab::Lock, "🔒", "加密锁定") {
                        self.active_tab = ActiveTab::Lock;
                    }
                    if render_tab_button(ui, self.active_tab, ActiveTab::Unlock, "🔓", "解密还原") {
                        self.active_tab = ActiveTab::Unlock;
                    }
                    if render_tab_button(ui, self.active_tab, ActiveTab::Details, "ℹ️", "详细信息") {
                        self.active_tab = ActiveTab::Details;
                    }

                    if self.active_tab != prev_tab {
                        self.password.clear();
                        self.confirm_password.clear();
                        self.status_message = None;
                    }
                },
            );

            ui.add_space(8.0);

            // Main Tab Content Card Container
            egui::Frame::default()
                .fill(egui::Color32::from_rgb(22, 28, 40))
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(42, 54, 76)))
                .corner_radius(egui::CornerRadius::same(8))
                .inner_margin(egui::Margin::symmetric(20, 16))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    match self.active_tab {
                        ActiveTab::Lock => {
                            if is_locked {
                                let target_path = self.selected_path.clone();
                                self.ui_append_panel(ui, &target_path);
                            } else {
                                ui.label(
                                    egui::RichText::new(format!(
                                        "为文件夹【{}】设置加密保护密钥（支持中文密码、字母、数字、特殊符号）：",
                                        self.selected_name
                                    ))
                                    .size(13.0)
                                    .color(egui::Color32::from_rgb(210, 225, 245)),
                                );
                                ui.add_space(10.0);

                                egui::Grid::new("lock_grid").num_columns(2).spacing([12.0, 12.0]).show(ui, |ui| {
                                    ui.label(egui::RichText::new("设置新密码:").size(13.0));
                                    ui.allocate_ui_with_layout(
                                        egui::vec2(ui.available_width(), 32.0),
                                        egui::Layout::left_to_right(egui::Align::Center),
                                        |ui| {
                                            ui.add_enabled(
                                                !self.is_busy,
                                                bordered_text_edit(&mut self.password, !self.show_password, 260.0, "请输入加密密码 (支持中文)"),
                                            );
                                            ui.add_space(4.0);
                                            if icon_text_button(
                                                ui,
                                                !self.is_busy,
                                                "🎲",
                                                "随机生成 64 位密码",
                                                egui::Color32::from_rgb(32, 42, 60),
                                                egui::Stroke::new(1.0, egui::Color32::from_rgb(55, 75, 108)),
                                                egui::Color32::from_rgb(215, 230, 255),
                                                egui::vec2(165.0, 32.0),
                                                6.0,
                                            )
                                            .on_hover_text("一键生成 64 位高熵随机密码，自动填入并复制到剪贴板")
                                            .clicked()
                                            {
                                                let gen = generate_random_64_char_password();
                                                ui.ctx().copy_text(gen.clone());
                                                self.password = gen.clone();
                                                self.confirm_password = gen;
                                                self.show_password = true;
                                                self.status_message = Some(("已生成 64 位随机密码，并自动填入与复制到剪贴板！".into(), false));
                                            }
                                        },
                                    );
                                    ui.end_row();

                                    ui.label(egui::RichText::new("确认新密码:").size(13.0));
                                    ui.add_enabled(
                                        !self.is_busy,
                                        bordered_text_edit(&mut self.confirm_password, !self.show_password, 260.0, "请再次输入密码以确认"),
                                    );
                                    ui.end_row();

                                    ui.label(egui::RichText::new("密码提示 (选填):").size(13.0));
                                    ui.add_enabled(
                                        !self.is_busy,
                                        bordered_text_edit(&mut self.password_hint, false, 260.0, "用于帮自己回忆密码，如：老家门牌号"),
                                    );
                                    ui.end_row();
                                });

                                ui.add_space(6.0);
                                ui.checkbox(&mut self.show_password, "显示明文密码");
                                ui.add_space(4.0);
                                egui::Frame::default()
                                    .fill(egui::Color32::from_rgb(36, 28, 12))
                                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(180, 120, 20)))
                                    .corner_radius(egui::CornerRadius::same(6))
                                    .inner_margin(egui::Margin::symmetric(10, 6))
                                    .show(ui, |ui| {
                                        ui.label(
                                            egui::RichText::new("💡 密码安全提示：密码支持中文字符、字母、数字及各类特殊符号。采用零知识高强物理级原地加密，无后门与密码找回机制，请务必妥善记录并牢记密码！")
                                                .size(11.5)
                                                .color(egui::Color32::from_rgb(255, 220, 140)),
                                        );
                                    });
                                ui.add_space(10.0);

                                let action_title = if is_subfolder {
                                    format!("执行【{}】子目录原地加密锁定", self.selected_name)
                                } else {
                                    "执行原地加密锁定".to_string()
                                };

                                if primary_action_button(ui, !self.is_busy, "🔒", &action_title, egui::Color32::from_rgb(16, 149, 90)).clicked() {
                                    if self.password.is_empty() {
                                        self.status_message = Some(("密码不能为空，请输入密码或使用随机生成按钮".into(), true));
                                    } else if self.password != self.confirm_password {
                                        self.status_message = Some(("两次输入的密码不一致，请重新输入".into(), true));
                                    } else {
                                        let target_path = self.selected_path.clone();
                                        self.start_lock_task(&target_path);
                                    }
                                }

                                ui.add_space(8.0);
                                egui::Frame::default()
                                    .fill(egui::Color32::from_rgb(18, 26, 38))
                                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(45, 60, 85)))
                                    .corner_radius(egui::CornerRadius::same(6))
                                    .inner_margin(egui::Margin::symmetric(10, 8))
                                    .show(ui, |ui| {
                                        ui.set_width(ui.available_width());
                                        ui.label(
                                            egui::RichText::new("💡 安全声明：强烈建议在已开启全盘加密（Windows BitLocker、macOS FileVault 或 Linux LUKS）的磁盘环境中使用。固态硬盘（SSD）的磨损均衡机制可能导致粉碎前的底层旧闪存块在物理芯片级残留；配合系统全盘加密可彻底阻断任何硬件取证恢复。")
                                                .size(11.0)
                                                .color(egui::Color32::from_rgb(160, 185, 215)),
                                        );
                                    });
                            }
                        }
                        ActiveTab::Unlock => {
                            if !is_locked {
                                ui.allocate_ui_with_layout(
                                    egui::vec2(ui.available_width(), 24.0),
                                    egui::Layout::left_to_right(egui::Align::Center),
                                    |ui| {
                                        ui.label(
                                            egui::RichText::new("🔓  该文件夹当前已处于明文解密状态，文件可正常访问与编辑。")
                                                .size(13.0)
                                                .strong()
                                                .color(egui::Color32::from_rgb(255, 235, 170)),
                                        );
                                    },
                                );
                            } else {
                                if ui.add_enabled(!self.is_busy, egui::Button::new("继续加密新增文件 →")).clicked() {
                                    self.active_tab = ActiveTab::Lock;
                                    self.password.clear();
                                    self.confirm_password.clear();
                                    self.show_password = false;
                                    self.status_message = None;
                                }
                                ui.add_space(8.0);
                                ui.label(
                                    egui::RichText::new(format!(
                                        "请输入为【{}】加密时设置的密码进行解密还原：",
                                        self.selected_name
                                    ))
                                    .size(13.0)
                                    .color(egui::Color32::from_rgb(210, 225, 245)),
                                );
                                ui.add_space(10.0);

                                if let Some(hint) = self
                                    .inspection
                                    .as_ref()
                                    .and_then(|i| i.password_hint.as_deref())
                                    .filter(|h| !h.trim().is_empty())
                                {
                                    egui::Frame::default()
                                        .fill(egui::Color32::from_rgb(18, 38, 62))
                                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(59, 130, 246)))
                                        .corner_radius(egui::CornerRadius::same(6))
                                        .inner_margin(egui::Margin::symmetric(12, 8))
                                        .show(ui, |ui| {
                                            ui.allocate_ui_with_layout(
                                                egui::vec2(ui.available_width(), 20.0),
                                                egui::Layout::left_to_right(egui::Align::Center),
                                                |ui| {
                                                    ui.label(
                                                        egui::RichText::new("💡 密码提示：")
                                                            .size(13.0)
                                                            .strong()
                                                            .color(egui::Color32::from_rgb(147, 197, 253)),
                                                    );
                                                    ui.label(
                                                        egui::RichText::new(hint)
                                                            .size(13.0)
                                                            .strong()
                                                            .color(egui::Color32::WHITE),
                                                    );
                                                },
                                            );
                                        });
                                    ui.add_space(8.0);
                                }

                                egui::Grid::new("unlock_grid").num_columns(2).spacing([12.0, 12.0]).show(ui, |ui| {
                                    ui.label(egui::RichText::new("输入解密密码:").size(13.0));
                                    ui.add_enabled(
                                        !self.is_busy,
                                        bordered_text_edit(
                                            &mut self.password,
                                            !self.show_password,
                                            260.0,
                                            "请输入加密时设置的原始密码 (支持中文)",
                                        ),
                                    );
                                    ui.end_row();
                                });

                                ui.add_space(6.0);
                                ui.checkbox(&mut self.show_password, "显示明文密码");
                                ui.add_space(4.0);
                                egui::Frame::default()
                                    .fill(egui::Color32::from_rgb(18, 28, 44))
                                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(45, 85, 140)))
                                    .corner_radius(egui::CornerRadius::same(6))
                                    .inner_margin(egui::Margin::symmetric(10, 6))
                                    .show(ui, |ui| {
                                        ui.label(
                                            egui::RichText::new("💡 解密提示：请输入加密时设置的原始密码（支持中文输入）。采用零知识保护，若密码错误将无法还原文件，多次尝试不会损坏已有密文数据。")
                                                .size(11.5)
                                                .color(egui::Color32::from_rgb(190, 220, 255)),
                                        );
                                    });
                                ui.add_space(10.0);

                                let action_title = if is_subfolder {
                                    format!("执行【{}】子目录解密还原", self.selected_name)
                                } else {
                                    "执行解密还原".to_string()
                                };

                                if primary_action_button(ui, !self.is_busy, "🔓", &action_title, egui::Color32::from_rgb(217, 119, 6)).clicked() {
                                    if self.password.is_empty() {
                                        self.status_message = Some(("请输入解密密码".into(), true));
                                    } else {
                                        let target_path = self.selected_path.clone();
                                        self.start_unlock_task(&target_path);
                                    }
                                }
                            }
                        }
                        ActiveTab::Details => {
                            if let Some(insp) = &self.inspection {
                                let (status_val, status_sub) = if insp.is_locked {
                                    ("已加密锁定", "AES-256-GCM 强保护模式")
                                } else {
                                    ("未锁定 (明文)", "可正常读写与编辑")
                                };

                                let (item_count, item_sub, total_size) = if insp.is_locked {
                                    (
                                        format!("{} 个加密块", insp.encrypted_files.len()),
                                        "文件名与结构已完全混淆",
                                        format_bytes(insp.total_encrypted_bytes),
                                    )
                                } else {
                                    let total_items = insp.total_plain_files + insp.total_plain_dirs;
                                    (
                                        format!("{} 项 ({} 文件, {} 目录)", total_items, insp.total_plain_files, insp.total_plain_dirs),
                                        "包含所有递归子目录与文件",
                                        format_bytes(insp.total_plain_bytes),
                                    )
                                };

                                let avail_w = ui.available_width();
                                let spacing = 10.0;
                                let card_w = ((avail_w - spacing) / 2.0).floor().max(160.0);

                                if avail_w < 440.0 {
                                    metric_card(ui, "🛡️", "防护状态", status_val, status_sub, avail_w);
                                    ui.add_space(8.0);
                                    metric_card(ui, "🔐", "加密算法", "AES-256-GCM", "Argon2id 内存防爆破", avail_w);
                                    ui.add_space(8.0);
                                    metric_card(ui, "📦", "存储统计", &item_count, item_sub, avail_w);
                                    ui.add_space(8.0);
                                    metric_card(ui, "💾", "占用空间", &total_size, "本地磁盘占用体积", avail_w);
                                } else {
                                    ui.horizontal(|ui| {
                                        ui.spacing_mut().item_spacing.x = spacing;
                                        metric_card(ui, "🛡️", "防护状态", status_val, status_sub, card_w);
                                        metric_card(ui, "🔐", "加密算法", "AES-256-GCM", "Argon2id 内存防爆破", card_w);
                                    });
                                    ui.add_space(10.0);
                                    ui.horizontal(|ui| {
                                        ui.spacing_mut().item_spacing.x = spacing;
                                        metric_card(ui, "📦", "存储统计", &item_count, item_sub, card_w);
                                        metric_card(ui, "💾", "占用空间", &total_size, "本地磁盘占用体积", card_w);
                                    });
                                }

                                ui.add_space(12.0);

                                // Security Spec Summary Box
                                egui::Frame::default()
                                    .fill(egui::Color32::from_rgb(18, 23, 33))
                                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(38, 48, 68)))
                                    .corner_radius(egui::CornerRadius::same(7))
                                    .inner_margin(egui::Margin::symmetric(14, 10))
                                    .show(ui, |ui| {
                                        ui.set_width(ui.available_width());
                                        ui.allocate_ui_with_layout(
                                            egui::vec2(ui.available_width(), 20.0),
                                            egui::Layout::left_to_right(egui::Align::Center),
                                            |ui| {
                                                ui.label(
                                                    egui::RichText::new("⚙️  保险箱安全规格与保护机制")
                                                        .strong()
                                                        .size(12.5)
                                                        .color(egui::Color32::from_rgb(220, 235, 255)),
                                                );
                                            },
                                        );
                                        ui.add_space(6.0);
                                        ui.separator();
                                        ui.add_space(6.0);

                                        let spec_line = |ui: &mut egui::Ui, key: &str, val: &str, note: &str| {
                                            ui.allocate_ui_with_layout(
                                                egui::vec2(ui.available_width(), 19.0),
                                                egui::Layout::left_to_right(egui::Align::Center),
                                                |ui| {
                                                    ui.label(egui::RichText::new(key).size(11.5).color(egui::Color32::from_rgb(140, 155, 180)));
                                                    ui.add_space(4.0);
                                                    ui.label(egui::RichText::new(val).size(11.5).strong().color(egui::Color32::from_rgb(220, 235, 255)));
                                                    ui.add_space(4.0);
                                                    ui.label(egui::RichText::new(note).size(10.5).color(egui::Color32::from_rgb(115, 130, 155)));
                                                },
                                            );
                                            ui.add_space(2.0);
                                        };

                                        spec_line(ui, "核心加密通道:", "AES-256-GCM (256-bit)", "· 硬件指令集高吞吐加速");
                                        spec_line(ui, "密钥派生算法:", "Argon2id (m_cost=64MB, t=3)", "· 抵御GPU与专用芯片暴力破解");
                                        spec_line(ui, "完整性防篡改:", "Poly1305 MAC 128位认证标签", "· 杜绝数据污染与静默损坏");
                                        spec_line(ui, "双份冗余镜像:", ".vault_meta 自动双写备份", "· 防止元数据意外丢失");
                                        spec_line(ui, "推荐存储环境:", "BitLocker / FileVault / LUKS", "· 配合全盘加密彻底杜绝SSD底层磨损残留");
                                    });
                            }
                        }
                    }
                });
        } else {
            // A single file is selected (encrypted .enc or plain file)
            let is_enc_file = self.selected_path.extension().and_then(|s| s.to_str()) == Some("enc")
                || self.selected_path.parent().map(|p| p.ends_with(".vault_data")).unwrap_or(false);
            let file_size = std::fs::metadata(&self.selected_path).map(|m| m.len()).unwrap_or(0);
            let parent_name = parent_vault.as_ref().map(|p| p.name.as_str()).unwrap_or("受保护目录");

            // Header Hero Card for File
            egui::Frame::default()
                .fill(egui::Color32::from_rgb(22, 28, 40))
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(42, 54, 76)))
                .corner_radius(egui::CornerRadius::same(8))
                .inner_margin(egui::Margin::symmetric(14, 10))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    let file_icon = if is_enc_file { "🔒" } else { "📄" };

                    ui.vertical(|ui| {
                        // Row 1: File icon + Name + Status Pill
                        ui.allocate_ui_with_layout(
                            egui::vec2(ui.available_width(), 26.0),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.label(egui::RichText::new(file_icon).size(18.0));
                                ui.add_space(4.0);
                                let file_name_resp = ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(&self.selected_name)
                                            .size(16.5)
                                            .strong()
                                            .color(egui::Color32::WHITE),
                                    )
                                    .sense(egui::Sense::click()),
                                );
                                if file_name_resp.double_clicked() {
                                    open_file_with_default_app(&self.selected_path);
                                }
                                file_name_resp.on_hover_text("双击使用系统默认程序打开此文件");
                                ui.add_space(8.0);
                                if is_enc_file {
                                    render_badge_pill(
                                        ui,
                                        "🔒",
                                        "密文数据块 (AES-256-GCM)",
                                        egui::Color32::from_rgb(12, 42, 28),
                                        egui::Stroke::new(1.0, egui::Color32::from_rgb(16, 185, 129)),
                                        egui::Color32::from_rgb(230, 255, 245),
                                        22.0,
                                        false,
                                    );
                                } else {
                                    render_badge_pill(
                                        ui,
                                        "📄",
                                        "明文文件 (未锁定)",
                                        egui::Color32::from_rgb(48, 34, 10),
                                        egui::Stroke::new(1.0, egui::Color32::from_rgb(245, 158, 11)),
                                        egui::Color32::from_rgb(255, 246, 214),
                                        22.0,
                                        false,
                                    );
                                }
                            },
                        );

                        ui.add_space(6.0);

                        // Row 2: Monospace path (left) + Action buttons (right)
                        ui.allocate_ui_with_layout(
                            egui::vec2(ui.available_width(), 26.0),
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                if !is_enc_file {
                                    if icon_text_button(
                                        ui,
                                        true,
                                        "↗",
                                        "打开所在目录",
                                        egui::Color32::from_rgb(28, 36, 50),
                                        egui::Stroke::new(1.0, egui::Color32::from_rgb(48, 62, 86)),
                                        egui::Color32::from_rgb(200, 215, 235),
                                        egui::vec2(100.0, 24.0),
                                        4.0,
                                    )
                                    .on_hover_text("在系统文件管理器中定位该文件")
                                    .clicked()
                                    {
                                        if let Some(parent) = self.selected_path.parent() {
                                            open_in_file_manager(parent);
                                        }
                                    }

                                    ui.add_space(6.0);

                                    if icon_text_button(
                                        ui,
                                        true,
                                        "⚡",
                                        "打开文件",
                                        egui::Color32::from_rgb(28, 48, 75),
                                        egui::Stroke::new(1.0, egui::Color32::from_rgb(50, 95, 160)),
                                        egui::Color32::from_rgb(220, 235, 255),
                                        egui::vec2(86.0, 24.0),
                                        4.0,
                                    )
                                    .on_hover_text("使用系统默认程序打开此文件")
                                    .clicked()
                                    {
                                        open_file_with_default_app(&self.selected_path);
                                    }

                                    ui.add_space(6.0);
                                }

                                if icon_text_button(
                                    ui,
                                    true,
                                    "📋",
                                    "复制路径",
                                    egui::Color32::from_rgb(28, 36, 50),
                                    egui::Stroke::new(1.0, egui::Color32::from_rgb(48, 62, 86)),
                                    egui::Color32::from_rgb(200, 215, 235),
                                    egui::vec2(80.0, 24.0),
                                    4.0,
                                )
                                .on_hover_text("复制当前文件完整路径到剪贴板")
                                .clicked()
                                {
                                    ui.ctx().copy_text(self.selected_path.to_string_lossy().to_string());
                                    self.status_message = Some(("已将文件路径复制到剪贴板".into(), false));
                                }

                                if let Some(parent) = &parent_vault {
                                    ui.add_space(6.0);
                                    if icon_text_button(
                                        ui,
                                        true,
                                        "📁",
                                        &format!("所属保险箱: {}", parent.name),
                                        egui::Color32::from_rgb(32, 45, 66),
                                        egui::Stroke::new(1.0, egui::Color32::from_rgb(55, 80, 115)),
                                        egui::Color32::from_rgb(180, 210, 255),
                                        egui::vec2(0.0, 24.0),
                                        4.0,
                                    )
                                    .on_hover_text("切换选中该文件所属的保险箱文件夹")
                                    .clicked()
                                    {
                                        return_to_parent = Some((parent.path.clone(), parent.name.clone(), self.selected_index));
                                    }
                                }

                                ui.add_space(8.0);

                                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(self.selected_path.to_string_lossy())
                                                .monospace()
                                                .size(11.5)
                                                .color(egui::Color32::from_rgb(155, 175, 205)),
                                        )
                                        .truncate(),
                                    )
                                    .on_hover_text(self.selected_path.to_string_lossy());
                                });
                            },
                        );
                    });
                });

            ui.add_space(8.0);

            // Content Card Container for File
            egui::Frame::default()
                .fill(egui::Color32::from_rgb(22, 28, 40))
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(42, 54, 76)))
                .corner_radius(egui::CornerRadius::same(8))
                .inner_margin(egui::Margin::symmetric(20, 16))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    if is_enc_file {
                        ui.allocate_ui_with_layout(
                            egui::vec2(ui.available_width(), 24.0),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.label(
                                    egui::RichText::new(format!(
                                        "🔒  该文件为密文存储块，属于受保护保险箱【{}】。",
                                        parent_name
                                    ))
                                    .size(13.0)
                                    .strong()
                                    .color(egui::Color32::from_rgb(52, 211, 153)),
                                );
                            },
                        );
                        ui.add_space(4.0);
                        ui.label(
                            egui::RichText::new(format!(
                                "数据块大小: {} · 加密算法: AES-256-GCM + Argon2id · 原始文件名已进行安全混淆。",
                                format_bytes(file_size)
                            ))
                            .size(11.5)
                            .color(egui::Color32::from_rgb(140, 160, 190)),
                        );

                        ui.add_space(14.0);
                        ui.separator();
                        ui.add_space(12.0);

                        ui.label(
                            egui::RichText::new(format!(
                                "如需查看或还原该文件，请在此输入所属保险箱【{}】的解密密码执行还原：",
                                parent_name
                            ))
                            .size(13.0)
                            .strong()
                            .color(egui::Color32::WHITE),
                        );
                        ui.add_space(10.0);

                        if let Some(hint) = self
                            .inspection
                            .as_ref()
                            .and_then(|i| i.password_hint.as_deref())
                            .filter(|h| !h.trim().is_empty())
                        {
                            egui::Frame::default()
                                .fill(egui::Color32::from_rgb(18, 38, 62))
                                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(59, 130, 246)))
                                .corner_radius(egui::CornerRadius::same(6))
                                .inner_margin(egui::Margin::symmetric(12, 8))
                                .show(ui, |ui| {
                                    ui.allocate_ui_with_layout(
                                        egui::vec2(ui.available_width(), 20.0),
                                        egui::Layout::left_to_right(egui::Align::Center),
                                        |ui| {
                                            ui.label(
                                                egui::RichText::new("💡 所属保险箱密码提示：")
                                                    .size(13.0)
                                                    .strong()
                                                    .color(egui::Color32::from_rgb(147, 197, 253)),
                                            );
                                            ui.label(
                                                egui::RichText::new(hint)
                                                    .size(13.0)
                                                    .strong()
                                                    .color(egui::Color32::WHITE),
                                            );
                                        },
                                    );
                                });
                            ui.add_space(8.0);
                        }

                        egui::Grid::new("file_unlock_grid").num_columns(2).spacing([12.0, 12.0]).show(ui, |ui| {
                            ui.label(egui::RichText::new("输入解密密码:").size(13.0));
                            ui.add_enabled(
                                !self.is_busy,
                                bordered_text_edit(
                                    &mut self.password,
                                    !self.show_password,
                                    260.0,
                                    "请输入所属保险箱解密密码 (支持中文)",
                                ),
                            );
                            ui.end_row();
                        });

                        ui.add_space(6.0);
                        ui.checkbox(&mut self.show_password, "显示明文密码");
                        ui.add_space(4.0);
                        egui::Frame::default()
                            .fill(egui::Color32::from_rgb(18, 28, 44))
                            .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(45, 85, 140)))
                            .corner_radius(egui::CornerRadius::same(6))
                            .inner_margin(egui::Margin::symmetric(10, 6))
                            .show(ui, |ui| {
                                ui.label(
                                    egui::RichText::new("💡 解密提示：请输入所属保险箱加密时设置的原始密码（支持中文输入）。验证错误不会解密，多次尝试不会损坏已有密文数据。")
                                        .size(11.5)
                                        .color(egui::Color32::from_rgb(190, 220, 255)),
                                );
                            });
                        ui.add_space(10.0);

                        if primary_action_button(
                            ui,
                            !self.is_busy,
                            "🔓",
                            &format!("解密还原所属保险箱【{}】", parent_name),
                            egui::Color32::from_rgb(217, 119, 6),
                        )
                        .clicked()
                        {
                            if self.password.is_empty() {
                                self.status_message = Some(("请输入解密密码".into(), true));
                            } else if let Some(parent) = &parent_vault {
                                let parent_path = parent.path.clone();
                                self.start_unlock_task(&parent_path);
                            }
                        }
                    } else {
                        // Plain file
                        ui.allocate_ui_with_layout(
                            egui::vec2(ui.available_width(), 24.0),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.label(
                                    egui::RichText::new(format!(
                                        "📄  该文件当前处于明文状态，位于受保护文件夹【{}】中。",
                                        parent_name
                                    ))
                                    .size(13.0)
                                    .strong()
                                    .color(egui::Color32::from_rgb(255, 235, 170)),
                                );
                            },
                        );
                        ui.add_space(4.0);
                        ui.label(
                            egui::RichText::new(format!(
                                "文件大小: {} · 状态: 明文未锁定 (可正常读写与运行)。",
                                format_bytes(file_size)
                            ))
                            .size(11.5)
                            .color(egui::Color32::from_rgb(140, 160, 190)),
                        );

                        ui.add_space(14.0);
                        ui.separator();
                        ui.add_space(12.0);

                        if let Some(parent) = &parent_vault {
                            if vault::is_locked(&parent.path) {
                                self.ui_append_panel(ui, &parent.path);
                                return;
                            }
                        }

                        ui.label(
                            egui::RichText::new(format!(
                                "为所属文件夹【{}】设置加密保护密钥并执行原地加密锁定：",
                                parent_name
                            ))
                            .size(13.0)
                            .strong()
                            .color(egui::Color32::WHITE),
                        );
                        ui.add_space(10.0);

                        egui::Grid::new("file_lock_grid").num_columns(2).spacing([12.0, 12.0]).show(ui, |ui| {
                            ui.label(egui::RichText::new("设置新密码:").size(13.0));
                            ui.allocate_ui_with_layout(
                                egui::vec2(ui.available_width(), 32.0),
                                egui::Layout::left_to_right(egui::Align::Center),
                                |ui| {
                                    ui.add_enabled(
                                        !self.is_busy,
                                        bordered_text_edit(
                                            &mut self.password,
                                            !self.show_password,
                                            260.0,
                                            "请输入加密密码 (支持中文)",
                                        ),
                                    );
                                    ui.add_space(4.0);
                                    if icon_text_button(
                                        ui,
                                        !self.is_busy,
                                        "🎲",
                                        "随机生成 64 位密码",
                                        egui::Color32::from_rgb(32, 42, 60),
                                        egui::Stroke::new(1.0, egui::Color32::from_rgb(55, 75, 108)),
                                        egui::Color32::from_rgb(215, 230, 255),
                                        egui::vec2(165.0, 32.0),
                                        6.0,
                                    )
                                    .on_hover_text("一键生成 64 位高熵随机密码，自动填入并复制到剪贴板")
                                    .clicked()
                                    {
                                        let gen = generate_random_64_char_password();
                                        ui.ctx().copy_text(gen.clone());
                                        self.password = gen.clone();
                                        self.confirm_password = gen;
                                        self.show_password = true;
                                        self.status_message = Some(("已生成 64 位随机密码，并自动填入与复制到剪贴板！".into(), false));
                                    }
                                },
                            );
                            ui.end_row();

                            ui.label(egui::RichText::new("确认新密码:").size(13.0));
                            ui.add_enabled(
                                !self.is_busy,
                                bordered_text_edit(
                                    &mut self.confirm_password,
                                    !self.show_password,
                                    260.0,
                                    "请再次输入密码以确认",
                                ),
                            );
                            ui.end_row();

                            ui.label(egui::RichText::new("密码提示 (选填):").size(13.0));
                            ui.add_enabled(
                                !self.is_busy,
                                bordered_text_edit(
                                    &mut self.password_hint,
                                    false,
                                    260.0,
                                    "用于帮自己回忆密码，如：老家门牌号",
                                ),
                            );
                            ui.end_row();
                        });

                        ui.add_space(6.0);
                        ui.checkbox(&mut self.show_password, "显示明文密码");
                        ui.add_space(4.0);
                        egui::Frame::default()
                            .fill(egui::Color32::from_rgb(36, 28, 12))
                            .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(180, 120, 20)))
                            .corner_radius(egui::CornerRadius::same(6))
                            .inner_margin(egui::Margin::symmetric(10, 6))
                            .show(ui, |ui| {
                                ui.label(
                                    egui::RichText::new("💡 密码安全提示：密码支持中文字符、字母、数字及各类特殊符号。采用零知识高强物理级原地加密，无后门与密码找回机制，请务必妥善记录并牢记密码！")
                                        .size(11.5)
                                        .color(egui::Color32::from_rgb(255, 220, 140)),
                                );
                            });
                        ui.add_space(10.0);

                        if primary_action_button(
                            ui,
                            !self.is_busy,
                            "🔒",
                            &format!("加密锁定所属文件夹【{}】", parent_name),
                            egui::Color32::from_rgb(16, 149, 90),
                        )
                        .clicked()
                        {
                            if self.password.is_empty() {
                                self.status_message = Some(("密码不能为空，请输入密码或使用随机生成按钮".into(), true));
                            } else if self.password != self.confirm_password {
                                self.status_message = Some(("两次输入的密码不一致，请重新输入".into(), true));
                            } else if let Some(parent) = &parent_vault {
                                let parent_path = parent.path.clone();
                                self.start_lock_task(&parent_path);
                            }
                        }

                        ui.add_space(8.0);
                        egui::Frame::default()
                            .fill(egui::Color32::from_rgb(18, 26, 38))
                            .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(45, 60, 85)))
                            .corner_radius(egui::CornerRadius::same(6))
                            .inner_margin(egui::Margin::symmetric(10, 8))
                            .show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.label(
                                    egui::RichText::new("💡 安全声明：强烈建议在已开启全盘加密（Windows BitLocker、macOS FileVault 或 Linux LUKS）的磁盘环境中使用。固态硬盘（SSD）的磨损均衡机制可能导致粉碎前的底层旧闪存块在物理芯片级残留；配合系统全盘加密可彻底阻断任何硬件取证恢复。")
                                        .size(11.0)
                                        .color(egui::Color32::from_rgb(160, 185, 215)),
                                );
                            });
                    }
                });
        }

        ui.add_space(10.0);

        // Real-time progress cards & status messages
        if let Some(active) = &self.active_progress {
            self.ui_active_progress_card(ui, active);
            ui.add_space(8.0);
        } else if let Some(binfo) = &self.batch_running_info {
            self.ui_batch_progress_card(ui, binfo);
            ui.add_space(8.0);
        } else if self.is_busy {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(
                    egui::RichText::new(&self.progress_text)
                        .size(13.0)
                        .color(egui::Color32::from_rgb(147, 197, 253)),
                );
            });
            ui.add_space(8.0);
        }

        if self.status_message.is_some() {
            status_banner(ui, &mut self.status_message);
        }

        if let Some((target_path, target_name, parent_idx)) = return_to_parent {
            self.select_target(target_path, target_name, true, parent_idx);
        }
    }

    // ── Requirement 3: Modal Dialog on App Close ──

    fn ui_exit_dialog(&mut self, ui: &mut egui::Ui) {
        let unlocked = self.get_unlocked_vaults();

        egui::Window::new("⚠️ 退出安全保护确认")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .frame(
                egui::Frame::default()
                    .fill(egui::Color32::from_rgb(22, 28, 40))
                    .stroke(egui::Stroke::new(1.2, egui::Color32::from_rgb(60, 75, 105)))
                    .corner_radius(egui::CornerRadius::same(10))
                    .inner_margin(egui::Margin::symmetric(20, 16)),
            )
            .show(ui.ctx(), |ui| {
                ui.set_width(460.0);
                ui.add_space(4.0);

                ui.allocate_ui_with_layout(
                    egui::vec2(ui.available_width(), 24.0),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        ui.label(
                            egui::RichText::new("⚠️  检测到以下文件夹目前处于【已解密 / 明文】状态：")
                                .color(egui::Color32::from_rgb(255, 235, 170))
                                .strong()
                                .size(13.5),
                        );
                    },
                );
                ui.add_space(6.0);

                egui::Frame::default()
                    .fill(egui::Color32::from_rgb(16, 21, 31))
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(38, 48, 68)))
                    .corner_radius(egui::CornerRadius::same(6))
                    .inner_margin(egui::Margin::symmetric(12, 8))
                    .show(ui, |ui| {
                        for p in &unlocked {
                            ui.allocate_ui_with_layout(
                                egui::vec2(ui.available_width(), 18.0),
                                egui::Layout::left_to_right(egui::Align::Center),
                                |ui| {
                                    ui.label(
                                        egui::RichText::new(format!("🔓  {}", p.to_string_lossy()))
                                            .monospace()
                                            .size(11.0)
                                            .color(egui::Color32::from_rgb(200, 215, 235)),
                                    );
                                },
                            );
                        }
                    });

                ui.add_space(10.0);
                ui.label(
                    egui::RichText::new("为了保障您的文件隐私安全，建议在关闭软件前将其重新加密锁定。")
                        .size(12.0)
                        .color(egui::Color32::from_rgb(170, 185, 210)),
                );
                ui.add_space(2.0);
                ui.label(egui::RichText::new("请输入新的加密密钥（支持中文密码）：").strong().size(13.0));
                ui.add_space(8.0);

                egui::Grid::new("exit_pw_grid").num_columns(2).spacing([10.0, 10.0]).show(ui, |ui| {
                    ui.label(egui::RichText::new("新加密密钥:").size(13.0));
                    ui.allocate_ui_with_layout(
                        egui::vec2(ui.available_width(), 32.0),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| {
                            ui.add_enabled(
                                !self.is_exit_encrypting,
                                bordered_text_edit(
                                    &mut self.exit_password,
                                    !self.exit_show_password,
                                    220.0,
                                    "请输入统一加密密钥 (支持中文)",
                                ),
                            );
                            ui.add_space(4.0);
                            if icon_text_button(
                                ui,
                                !self.is_exit_encrypting,
                                "🎲",
                                "随机 64 位",
                                egui::Color32::from_rgb(32, 42, 60),
                                egui::Stroke::new(1.0, egui::Color32::from_rgb(55, 75, 108)),
                                egui::Color32::from_rgb(215, 230, 255),
                                egui::vec2(105.0, 32.0),
                                6.0,
                            )
                            .on_hover_text("一键生成 64 位高熵随机密钥并复制到剪贴板")
                            .clicked()
                            {
                                let gen = generate_random_64_char_password();
                                ui.ctx().copy_text(gen.clone());
                                self.exit_password = gen.clone();
                                self.exit_confirm_password = gen;
                                self.exit_show_password = true;
                                self.exit_error = Some("✅ 已生成 64 位随机密钥并自动复制到剪贴板！".into());
                            }
                        },
                    );
                    ui.end_row();

                    ui.label(egui::RichText::new("确认新密钥:").size(13.0));
                    ui.add_enabled(
                        !self.is_exit_encrypting,
                        bordered_text_edit(
                            &mut self.exit_confirm_password,
                            !self.exit_show_password,
                            220.0,
                            "请再次输入密钥以确认",
                        ),
                    );
                    ui.end_row();

                    ui.label(egui::RichText::new("密码提示 (选填):").size(13.0));
                    ui.add_enabled(
                        !self.is_exit_encrypting,
                        bordered_text_edit(
                            &mut self.exit_password_hint,
                            false,
                            220.0,
                            "如：统一备忘线索",
                        ),
                    );
                    ui.end_row();
                });

                ui.add_space(6.0);
                ui.checkbox(&mut self.exit_show_password, "显示明文密码");
                ui.add_space(4.0);
                egui::Frame::default()
                    .fill(egui::Color32::from_rgb(36, 28, 12))
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(180, 120, 20)))
                    .corner_radius(egui::CornerRadius::same(6))
                    .inner_margin(egui::Margin::symmetric(10, 6))
                    .show(ui, |ui| {
                        ui.label(
                            egui::RichText::new("💡 退出加密提示：将为所有明文文件夹统一设置此加密密钥（支持中文密码）。采用零知识原地加密，无密码找回机制，请务必妥善记录！")
                                .size(11.5)
                                .color(egui::Color32::from_rgb(255, 220, 140)),
                        );
                    });

                if let Some(err) = &self.exit_error {
                    ui.add_space(6.0);
                    let is_ok = err.starts_with('✅');
                    let (icon, color) = if is_ok {
                        ("✅", egui::Color32::from_rgb(52, 211, 153))
                    } else {
                        ("❌", egui::Color32::from_rgb(239, 68, 68))
                    };
                    let clean_text = err.trim_start_matches('✅').trim_start_matches('❌').trim();
                    egui::Frame::default()
                        .fill(if is_ok { egui::Color32::from_rgb(12, 36, 24) } else { egui::Color32::from_rgb(42, 16, 20) })
                        .stroke(egui::Stroke::new(1.0, if is_ok { egui::Color32::from_rgb(16, 185, 129) } else { egui::Color32::from_rgb(239, 68, 68) }))
                        .corner_radius(egui::CornerRadius::same(5))
                        .inner_margin(egui::Margin::symmetric(10, 6))
                        .show(ui, |ui| {
                            let label = egui::Label::new(
                                egui::RichText::new(format!("{}  {}", icon, clean_text))
                                    .size(12.0)
                                    .color(color),
                            )
                            .wrap_mode(egui::TextWrapMode::Wrap)
                            .selectable(true);
                            ui.add(label);
                        });
                }

                ui.add_space(14.0);

                if self.is_exit_encrypting {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(
                            egui::RichText::new("正在重新加密锁定中，完成后将自动退出...")
                                .size(13.0)
                                .color(egui::Color32::from_rgb(147, 197, 253)),
                        );
                    });
                } else {
                    ui.allocate_ui_with_layout(
                        egui::vec2(ui.available_width(), 32.0),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| {
                            if icon_text_button(
                                ui,
                                true,
                                "🔒",
                                "立即加密并退出",
                                egui::Color32::from_rgb(16, 149, 90),
                                egui::Stroke::NONE,
                                egui::Color32::WHITE,
                                egui::vec2(145.0, 32.0),
                                6.0,
                            )
                            .clicked()
                            {
                                if self.exit_password.is_empty() {
                                    self.exit_error = Some("密码不能为空".into());
                                } else if self.exit_password != self.exit_confirm_password {
                                    self.exit_error = Some("两次输入的密码不一致".into());
                                } else {
                                    self.is_exit_encrypting = true;
                                    self.exit_error = None;
                                    let exit_pwd = std::mem::take(&mut self.exit_password);
                                    self.exit_confirm_password.clear();
                                    self.start_exit_encrypt_task(unlocked, exit_pwd);
                                }
                            }

                            if icon_text_button(
                                ui,
                                true,
                                "⚠️",
                                "直接退出 (保持解密)",
                                egui::Color32::from_rgb(34, 43, 60),
                                egui::Stroke::new(1.0, egui::Color32::from_rgb(60, 75, 105)),
                                egui::Color32::from_rgb(230, 180, 80),
                                egui::vec2(155.0, 32.0),
                                6.0,
                            )
                            .clicked()
                            {
                                self.exit_password.clear();
                                self.exit_confirm_password.clear();
                                self.bypass_exit_check = true;
                                ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                            }

                            if icon_text_button(
                                ui,
                                true,
                                "❌",
                                "取消",
                                egui::Color32::from_rgb(34, 43, 60),
                                egui::Stroke::new(1.0, egui::Color32::from_rgb(55, 70, 95)),
                                egui::Color32::from_rgb(200, 215, 240),
                                egui::vec2(76.0, 32.0),
                                6.0,
                            )
                            .clicked()
                            {
                                self.exit_password.clear();
                                self.exit_confirm_password.clear();
                                self.exit_error = None;
                                self.show_exit_dialog = false;
                            }
                        },
                    );
                }
                ui.add_space(2.0);
            });
    }
}

// ── Background Tasks ──

impl SecureVaultApp {
    fn ui_append_panel(&mut self, ui: &mut egui::Ui, path: &Path) {
        ui.label(egui::RichText::new("继续加密新增文件").size(14.0).strong());
        ui.add_space(6.0);
        ui.label("将新文件放入此文件夹后，输入原密码继续加密。已有密文保持不变，无需先解密。");
        ui.label(egui::RichText::new("新增文件在点击并成功完成前仍是明文，请勿在操作期间改动文件或目录。")
            .color(egui::Color32::from_rgb(255, 235, 170)));
        ui.label("如果新文件与已有加密文件的相对路径冲突，本次操作会停止，请先重命名或移走冲突的新文件。");
        ui.add_space(10.0);
        egui::Grid::new("append_grid").num_columns(2).spacing([12.0, 12.0]).show(ui, |ui| {
            ui.label(egui::RichText::new("输入原密码:").size(13.0));
            ui.add_enabled(
                !self.is_busy,
                bordered_text_edit(
                    &mut self.password,
                    !self.show_password,
                    260.0,
                    "请输入该保险箱原加密密码 (支持中文)",
                ),
            );
            ui.end_row();
        });
        ui.add_space(6.0);
        ui.add_enabled(!self.is_busy, egui::Checkbox::new(&mut self.show_password, "显示明文密码"));
        ui.add_space(4.0);
        egui::Frame::default()
            .fill(egui::Color32::from_rgb(18, 28, 44))
            .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(45, 85, 140)))
            .corner_radius(egui::CornerRadius::same(6))
            .inner_margin(egui::Margin::symmetric(10, 6))
            .show(ui, |ui| {
                ui.label(
                    egui::RichText::new("💡 增量加密提示：请输入该保险箱原加密密码（支持中文输入）。验证通过后仅对本次新增的文件与目录执行原地加密。")
                        .size(11.5)
                        .color(egui::Color32::from_rgb(190, 220, 255)),
                );
            });
        ui.add_space(10.0);
        if primary_action_button(ui, !self.is_busy, "🔒", "继续加密", egui::Color32::from_rgb(16, 149, 90)).clicked() {
            if self.password.is_empty() {
                self.status_message = Some(("请输入此文件夹的原密码".into(), true));
            } else {
                self.start_append_task(path);
            }
        }
    }

    fn start_append_task(&mut self, path: &Path) {
        use zeroize::{Zeroize, Zeroizing};

        let path = path.to_path_buf();
        let password = Zeroizing::new(std::mem::take(&mut self.password));
        self.confirm_password.zeroize();
        self.show_password = false;
        let tx = self.tx.clone();
        self.is_busy = true;
        self.progress_text = "正在验证原密码并加密新增文件...".into();
        self.status_message = None;

        thread::spawn(move || {
            let result = vault::append(&path, &password);
            drop(password);
            let message = match result {
                Ok(report) if report.is_complete() => {
                    if report.added == 0 {
                        VaultTaskMsg::Success("未新增文件；空目录已同步，已有密文保持不变。".into())
                    } else {
                        VaultTaskMsg::Success(format!("✅ 已继续加密 {} 个新增文件，已有密文保持不变。", report.added))
                    }
                }
                Ok(report) => {
                    let skipped_list: Vec<String> = report
                        .skipped
                        .iter()
                        .map(|(path, err)| format!("  • {} — {}", path.display(), err))
                        .collect();
                    VaultTaskMsg::Success(format!(
                        "⚠️ 增量加密部分完成：已加密 {} 个文件，{} 个文件因被占用或无权限而跳过。\n跳过文件：\n{}\n💡 占用解除后可再次点击【继续加密】。",
                        report.added,
                        report.skipped.len(),
                        skipped_list.join("\n")
                    ))
                }
                Err(error) => VaultTaskMsg::Error(format!("{:#}", error)),
            };
            let _ = tx.send(message);
        });
    }

    fn open_batch_dialog(&mut self, mode: BatchMode) {
        let mut selected = HashSet::new();
        for v in &self.tracked_vaults {
            if v.path.exists() {
                let is_locked = vault::is_locked(&v.path);
                if mode == BatchMode::Encrypt && !is_locked {
                    selected.insert(v.path.clone());
                } else if mode == BatchMode::Decrypt && is_locked {
                    selected.insert(v.path.clone());
                }
            }
        }
        self.batch_dialog = Some(BatchDialogState {
            mode,
            selected_paths: selected,
            password: String::new(),
            confirm_password: String::new(),
            password_hint: String::new(),
            show_password: false,
            error: None,
        });
    }

    fn ui_batch_dialog(&mut self, ui: &mut egui::Ui) {
        let mut batch = match &self.batch_dialog {
            Some(b) => b.clone(),
            None => return,
        };

        let is_encrypt = batch.mode == BatchMode::Encrypt;
        let (title, action_name, action_color) = if is_encrypt {
            ("🔒 批量加密项目", "立即开始批量加密", egui::Color32::from_rgb(16, 149, 90))
        } else {
            ("🔓 批量解密项目", "立即开始批量解密", egui::Color32::from_rgb(217, 119, 6))
        };

        let candidate_vaults: Vec<TrackedVault> = self.tracked_vaults
            .iter()
            .filter(|v| {
                if !v.path.exists() {
                    return false;
                }
                let locked = vault::is_locked(&v.path);
                if is_encrypt { !locked } else { locked }
            })
            .cloned()
            .collect();

        let mut close_dialog = false;
        let mut start_task_args: Option<(BatchMode, Vec<TrackedVault>, String, String)> = None;

        egui::Window::new(title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .frame(
                egui::Frame::default()
                    .fill(egui::Color32::from_rgb(22, 28, 40))
                    .stroke(egui::Stroke::new(1.2, egui::Color32::from_rgb(60, 75, 105)))
                    .corner_radius(egui::CornerRadius::same(10))
                    .inner_margin(egui::Margin::symmetric(20, 16)),
            )
            .show(ui.ctx(), |ui| {
                ui.set_width(480.0);
                ui.add_space(2.0);

                ui.allocate_ui_with_layout(
                    egui::vec2(ui.available_width(), 24.0),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        let desc = if is_encrypt {
                            "请勾选需要进行批量加密的项目（默认已全选）："
                        } else {
                            "请勾选需要进行批量解密的项目（默认已全选）："
                        };
                        ui.label(
                            egui::RichText::new(desc)
                                .size(13.0)
                                .strong()
                                .color(egui::Color32::from_rgb(220, 235, 255)),
                        );

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if icon_text_button(
                                ui,
                                true,
                                "☐",
                                "全不选",
                                egui::Color32::from_rgb(30, 38, 54),
                                egui::Stroke::new(1.0, egui::Color32::from_rgb(50, 65, 90)),
                                egui::Color32::from_rgb(180, 195, 220),
                                egui::vec2(65.0, 22.0),
                                4.0,
                            )
                            .clicked()
                            {
                                batch.selected_paths.clear();
                            }

                            ui.add_space(4.0);

                            if icon_text_button(
                                ui,
                                true,
                                "☑",
                                "全选",
                                egui::Color32::from_rgb(30, 38, 54),
                                egui::Stroke::new(1.0, egui::Color32::from_rgb(50, 65, 90)),
                                egui::Color32::from_rgb(180, 195, 220),
                                egui::vec2(55.0, 22.0),
                                4.0,
                            )
                            .clicked()
                            {
                                for v in &candidate_vaults {
                                    batch.selected_paths.insert(v.path.clone());
                                }
                            }
                        });
                    },
                );

                ui.add_space(8.0);

                egui::Frame::default()
                    .fill(egui::Color32::from_rgb(16, 21, 31))
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(38, 48, 68)))
                    .corner_radius(egui::CornerRadius::same(6))
                    .inner_margin(egui::Margin::symmetric(12, 8))
                    .show(ui, |ui| {
                        if candidate_vaults.is_empty() {
                            ui.label(egui::RichText::new("没有找到符合条件的项目").weak().size(11.5));
                        } else {
                            egui::ScrollArea::vertical()
                                .max_height(140.0)
                                .show(ui, |ui| {
                                    for v in &candidate_vaults {
                                        let mut checked = batch.selected_paths.contains(&v.path);
                                        ui.allocate_ui_with_layout(
                                            egui::vec2(ui.available_width(), 22.0),
                                            egui::Layout::left_to_right(egui::Align::Center),
                                            |ui| {
                                                if ui.checkbox(&mut checked, "").changed() {
                                                    if checked {
                                                        batch.selected_paths.insert(v.path.clone());
                                                    } else {
                                                        batch.selected_paths.remove(&v.path);
                                                    }
                                                }
                                                ui.label(
                                                    egui::RichText::new(&v.name)
                                                        .size(12.0)
                                                        .strong()
                                                        .color(if checked { egui::Color32::WHITE } else { egui::Color32::from_rgb(140, 155, 180) }),
                                                );
                                                ui.add_space(6.0);
                                                ui.add(
                                                    egui::Label::new(
                                                        egui::RichText::new(v.path.to_string_lossy())
                                                            .size(10.5)
                                                            .monospace()
                                                            .color(egui::Color32::from_rgb(115, 130, 155)),
                                                    )
                                                    .truncate(),
                                                );
                                            },
                                        );
                                    }
                                });
                        }
                    });

                ui.add_space(10.0);

                let pwd_label = if is_encrypt {
                    "设置加密密钥（将统一应用于所选项目）："
                } else {
                    "输入解密密钥（将统一应用于所选项目）："
                };
                ui.label(egui::RichText::new(pwd_label).size(12.5).strong().color(egui::Color32::from_rgb(220, 235, 255)));
                ui.add_space(6.0);

                if !is_encrypt {
                    let mut hint_lines = Vec::new();
                    for p in &batch.selected_paths {
                        if let Ok((m, _)) = vault::read_vault_meta(p) {
                            if let Some(h) = m.password_hint.filter(|h| !h.trim().is_empty()) {
                                let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "文件夹".into());
                                hint_lines.push((name, h));
                            }
                        }
                    }
                    if !hint_lines.is_empty() {
                        egui::Frame::default()
                            .fill(egui::Color32::from_rgb(18, 38, 62))
                            .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(59, 130, 246)))
                            .corner_radius(egui::CornerRadius::same(6))
                            .inner_margin(egui::Margin::symmetric(10, 8))
                            .show(ui, |ui| {
                                for (name, hint) in hint_lines {
                                    ui.horizontal(|ui| {
                                        ui.label(
                                            egui::RichText::new(format!("💡 【{}】密码提示:", name))
                                                .size(12.0)
                                                .strong()
                                                .color(egui::Color32::from_rgb(147, 197, 253)),
                                        );
                                        ui.label(
                                            egui::RichText::new(hint)
                                                .size(12.0)
                                                .strong()
                                                .color(egui::Color32::WHITE),
                                        );
                                    });
                                }
                            });
                        ui.add_space(8.0);
                    }
                }

                egui::Grid::new("batch_pw_grid").num_columns(2).spacing([10.0, 10.0]).show(ui, |ui| {
                    ui.label(egui::RichText::new(if is_encrypt { "设置新密钥:" } else { "输入密钥:" }).size(12.5));
                    ui.allocate_ui_with_layout(
                        egui::vec2(ui.available_width(), 32.0),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| {
                            let hint = if is_encrypt {
                                "请输入统一加密密钥 (支持中文)"
                            } else {
                                "请输入批量解密密钥 (支持中文)"
                            };
                            ui.add(bordered_text_edit(&mut batch.password, !batch.show_password, 220.0, hint));
                            if is_encrypt {
                                ui.add_space(4.0);
                                if icon_text_button(
                                    ui,
                                    true,
                                    "🎲",
                                    "随机 64 位",
                                    egui::Color32::from_rgb(32, 42, 60),
                                    egui::Stroke::new(1.0, egui::Color32::from_rgb(55, 75, 108)),
                                    egui::Color32::from_rgb(215, 230, 255),
                                    egui::vec2(100.0, 32.0),
                                    5.0,
                                )
                                .on_hover_text("一键生成 64 位高熵随机密钥并复制到剪贴板")
                                .clicked()
                                {
                                    let gen = generate_random_64_char_password();
                                    ui.ctx().copy_text(gen.clone());
                                    batch.password = gen.clone();
                                    batch.confirm_password = gen;
                                    batch.show_password = true;
                                }
                            }
                        },
                    );
                    ui.end_row();

                    if is_encrypt {
                        ui.label(egui::RichText::new("确认新密钥:").size(12.5));
                        ui.add(bordered_text_edit(&mut batch.confirm_password, !batch.show_password, 220.0, "请再次输入密钥以确认"));
                        ui.end_row();

                        ui.label(egui::RichText::new("密码提示 (选填):").size(12.5));
                        ui.add(bordered_text_edit(&mut batch.password_hint, false, 220.0, "如：统一备忘线索"));
                        ui.end_row();
                    }
                });

                ui.add_space(4.0);
                ui.checkbox(&mut batch.show_password, "显示明文密码");
                ui.add_space(4.0);
                if is_encrypt {
                    egui::Frame::default()
                        .fill(egui::Color32::from_rgb(36, 28, 12))
                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(180, 120, 20)))
                        .corner_radius(egui::CornerRadius::same(6))
                        .inner_margin(egui::Margin::symmetric(10, 6))
                        .show(ui, |ui| {
                            ui.label(
                                egui::RichText::new("💡 批量加密提示：所选的全部文件夹将统一使用此密码原地加密锁定（支持中文）。采用零知识保护，无找回机制，请务必牢记！")
                                    .size(11.5)
                                    .color(egui::Color32::from_rgb(255, 220, 140)),
                            );
                        });
                } else {
                    egui::Frame::default()
                        .fill(egui::Color32::from_rgb(18, 28, 44))
                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(45, 85, 140)))
                        .corner_radius(egui::CornerRadius::same(6))
                        .inner_margin(egui::Margin::symmetric(10, 6))
                        .show(ui, |ui| {
                            ui.label(
                                egui::RichText::new("💡 批量解密提示：将使用此密码尝试对所选保险箱批量解密还原（支持中文）。若密码不匹配则会自动跳过，不影响数据安全。")
                                    .size(11.5)
                                    .color(egui::Color32::from_rgb(190, 220, 255)),
                            );
                        });
                }

                if let Some(err) = &batch.error {
                    ui.add_space(6.0);
                    egui::Frame::default()
                        .fill(egui::Color32::from_rgb(46, 18, 22))
                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(239, 68, 68)))
                        .corner_radius(egui::CornerRadius::same(5))
                        .inner_margin(egui::Margin::symmetric(10, 6))
                        .show(ui, |ui| {
                            ui.colored_label(egui::Color32::from_rgb(255, 180, 180), format!("❌  {}", err));
                        });
                }

                ui.add_space(14.0);

                let selected_count = batch.selected_paths.len();
                ui.allocate_ui_with_layout(
                    egui::vec2(ui.available_width(), 32.0),
                    egui::Layout::right_to_left(egui::Align::Center),
                    |ui| {
                        if icon_text_button(
                            ui,
                            selected_count > 0,
                            if is_encrypt { "🔒" } else { "🔓" },
                            &format!("{} ({})", action_name, selected_count),
                            action_color,
                            egui::Stroke::NONE,
                            egui::Color32::WHITE,
                            egui::vec2(165.0, 32.0),
                            6.0,
                        )
                        .clicked()
                        {
                            if batch.selected_paths.is_empty() {
                                batch.error = Some("请至少选择一个项目".into());
                            } else if batch.password.is_empty() {
                                batch.error = Some("密钥不能为空".into());
                            } else if is_encrypt && batch.password != batch.confirm_password {
                                batch.error = Some("两次输入的密钥不一致".into());
                            } else {
                                let selected_vaults: Vec<TrackedVault> = candidate_vaults
                                    .iter()
                                    .filter(|v| batch.selected_paths.contains(&v.path))
                                    .cloned()
                                    .collect();
                                start_task_args = Some((batch.mode, selected_vaults, batch.password.clone(), batch.password_hint.clone()));
                                close_dialog = true;
                            }
                        }

                        ui.add_space(8.0);

                        if icon_text_button(
                            ui,
                            true,
                            "❌",
                            "取消",
                            egui::Color32::from_rgb(34, 43, 60),
                            egui::Stroke::new(1.0, egui::Color32::from_rgb(55, 70, 95)),
                            egui::Color32::from_rgb(200, 215, 240),
                            egui::vec2(76.0, 32.0),
                            6.0,
                        )
                        .clicked()
                        {
                            close_dialog = true;
                        }
                    },
                );

                ui.add_space(2.0);
            });

        if close_dialog {
            self.batch_dialog = None;
        } else {
            self.batch_dialog = Some(batch);
        }

        if let Some((mode, vaults, pwd, hint)) = start_task_args {
            self.start_batch_task(mode, vaults, pwd, hint);
        }
    }

    fn ui_active_progress_card(&self, ui: &mut egui::Ui, active: &ActiveProgressState) {
        let (icon, title, color, bar_color) = if active.is_decrypt {
            ("🔓", "正在实时解密还原...", egui::Color32::from_rgb(217, 119, 6), egui::Color32::from_rgb(245, 158, 11))
        } else {
            ("🔒", "正在实时加密锁定...", egui::Color32::from_rgb(16, 185, 129), egui::Color32::from_rgb(16, 185, 129))
        };

        egui::Frame::default()
            .fill(egui::Color32::from_rgb(20, 26, 38))
            .stroke(egui::Stroke::new(1.2, color))
            .corner_radius(egui::CornerRadius::same(8))
            .inner_margin(egui::Margin::symmetric(16, 12))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.allocate_ui_with_layout(
                    egui::vec2(ui.available_width(), 26.0),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        ui.spinner();
                        ui.add_space(4.0);
                        ui.label(
                            egui::RichText::new(format!("{}  {}", icon, title))
                                .size(14.0)
                                .strong()
                                .color(egui::Color32::WHITE),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let pct = if active.total > 0 {
                                (active.completed as f32 / active.total as f32) * 100.0
                            } else {
                                0.0
                            };
                            ui.label(
                                egui::RichText::new(format!("{:.1}%", pct))
                                    .size(14.0)
                                    .strong()
                                    .color(color),
                            );
                        });
                    },
                );

                ui.add_space(8.0);

                let progress_frac = if active.total > 0 {
                    (active.completed as f32 / active.total as f32).clamp(0.0, 1.0)
                } else {
                    0.0
                };
                let pbar = egui::ProgressBar::new(progress_frac)
                    .show_percentage()
                    .fill(bar_color)
                    .animate(true);
                ui.add(pbar);

                ui.add_space(8.0);

                ui.allocate_ui_with_layout(
                    egui::vec2(ui.available_width(), 20.0),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        let action_noun = if active.is_decrypt { "已解密" } else { "已加密" };
                        ui.label(
                            egui::RichText::new(format!("{}: {} / {} 个文件", action_noun, active.completed, active.total))
                                .size(12.5)
                                .strong()
                                .color(egui::Color32::from_rgb(225, 235, 255)),
                        );
                        if active.total_bytes_done > 0 {
                            ui.add_space(10.0);
                            ui.label(
                                egui::RichText::new(format!("累计处理: {}", format_bytes(active.total_bytes_done)))
                                    .size(11.5)
                                    .color(egui::Color32::from_rgb(147, 197, 253)),
                            );
                        }
                    },
                );

                if !active.current_file.is_empty() {
                    ui.add_space(4.0);
                    ui.allocate_ui_with_layout(
                        egui::vec2(ui.available_width(), 18.0),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| {
                            ui.label(egui::RichText::new("当前文件:").size(11.0).weak());
                            ui.add_space(4.0);
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(&active.current_file)
                                        .size(11.0)
                                        .monospace()
                                        .color(egui::Color32::from_rgb(180, 210, 245)),
                                )
                                .truncate(),
                            );
                        },
                    );
                }

                if !active.recent_files.is_empty() {
                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(4.0);
                    let list_title = if active.is_decrypt {
                        format!("⚡ 实时解密文件清单 (已还原 {} 个文件):", active.recent_files.len())
                    } else {
                        format!("⚡ 实时加密文件清单 (已加密 {} 个文件):", active.recent_files.len())
                    };
                    ui.label(
                        egui::RichText::new(list_title)
                            .size(11.5)
                            .strong()
                            .color(if active.is_decrypt { egui::Color32::from_rgb(245, 158, 11) } else { egui::Color32::from_rgb(52, 211, 153) }),
                    );
                    ui.add_space(4.0);

                    egui::Frame::default()
                        .fill(egui::Color32::from_rgb(14, 18, 26))
                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(32, 42, 60)))
                        .corner_radius(egui::CornerRadius::same(5))
                        .inner_margin(egui::Margin::symmetric(10, 6))
                        .show(ui, |ui| {
                            egui::ScrollArea::vertical()
                                .max_height(130.0)
                                .stick_to_bottom(true)
                                .show(ui, |ui| {
                                    for (fname, fsize) in active.recent_files.iter().rev() {
                                        ui.allocate_ui_with_layout(
                                            egui::vec2(ui.available_width(), 18.0),
                                            egui::Layout::left_to_right(egui::Align::Center),
                                            |ui| {
                                                let check_color = if active.is_decrypt {
                                                    egui::Color32::from_rgb(245, 158, 11)
                                                } else {
                                                    egui::Color32::from_rgb(52, 211, 153)
                                                };
                                                ui.colored_label(check_color, "✓");
                                                ui.add_space(4.0);
                                                ui.add(
                                                    egui::Label::new(
                                                        egui::RichText::new(fname)
                                                            .size(10.5)
                                                            .monospace()
                                                            .color(egui::Color32::from_rgb(205, 220, 240)),
                                                    )
                                                    .truncate(),
                                                );
                                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                    ui.label(
                                                        egui::RichText::new(format_bytes(*fsize))
                                                            .size(10.0)
                                                            .weak(),
                                                    );
                                                });
                                            },
                                        );
                                    }
                                });
                        });
                }
            });
    }

    fn ui_batch_progress_card(&self, ui: &mut egui::Ui, binfo: &BatchProgressInfo) {
        let action = if binfo.is_encrypt { "批量加密锁定" } else { "批量解密还原" };
        let action_color = if binfo.is_encrypt {
            egui::Color32::from_rgb(16, 185, 129)
        } else {
            egui::Color32::from_rgb(217, 119, 6)
        };

        egui::Frame::default()
            .fill(egui::Color32::from_rgb(20, 26, 38))
            .stroke(egui::Stroke::new(1.2, action_color))
            .corner_radius(egui::CornerRadius::same(8))
            .inner_margin(egui::Margin::symmetric(16, 12))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.allocate_ui_with_layout(
                    egui::vec2(ui.available_width(), 26.0),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        ui.spinner();
                        ui.add_space(4.0);
                        ui.label(
                            egui::RichText::new(format!("🔄  正在执行{}...", action))
                                .size(14.0)
                                .strong()
                                .color(egui::Color32::WHITE),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(
                                egui::RichText::new(format!("第 {} / {} 个项目", binfo.current_folder_index + 1, binfo.total_folders))
                                    .size(13.0)
                                    .strong()
                                    .color(action_color),
                            );
                        });
                    },
                );

                ui.add_space(8.0);

                let overall_frac = if binfo.total_folders > 0 {
                    (binfo.current_folder_index as f32 / binfo.total_folders as f32).clamp(0.0, 1.0)
                } else {
                    0.0
                };
                let pbar = egui::ProgressBar::new(overall_frac)
                    .show_percentage()
                    .fill(action_color)
                    .animate(true);
                ui.add(pbar);

                ui.add_space(8.0);

                ui.allocate_ui_with_layout(
                    egui::vec2(ui.available_width(), 20.0),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        ui.label(egui::RichText::new("正在处理项目:").size(12.0).weak());
                        ui.add_space(4.0);
                        ui.label(
                            egui::RichText::new(&binfo.folder_name)
                                .size(13.0)
                                .strong()
                                .color(egui::Color32::WHITE),
                        );
                        if binfo.folder_total > 0 {
                            ui.add_space(8.0);
                            let pct = (binfo.folder_completed as f32 / binfo.folder_total as f32) * 100.0;
                            ui.label(
                                egui::RichText::new(format!("(文件进度: {} / {} · {:.1}%)", binfo.folder_completed, binfo.folder_total, pct))
                                    .size(11.5)
                                    .color(egui::Color32::from_rgb(147, 197, 253)),
                            );
                        }
                    },
                );

                if !binfo.current_file.is_empty() {
                    ui.add_space(4.0);
                    ui.allocate_ui_with_layout(
                        egui::vec2(ui.available_width(), 18.0),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| {
                            ui.label(egui::RichText::new("当前文件:").size(11.0).weak());
                            ui.add_space(4.0);
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(&binfo.current_file)
                                        .size(11.0)
                                        .monospace()
                                        .color(egui::Color32::from_rgb(180, 210, 245)),
                                )
                                .truncate(),
                            );
                            if binfo.file_size > 0 {
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    ui.label(
                                        egui::RichText::new(format_bytes(binfo.file_size))
                                            .size(10.5)
                                            .weak(),
                                    );
                                });
                            }
                        },
                    );
                }
            });
    }

    fn start_lock_task(&mut self, path: &Path) {
        let path = path.to_path_buf();
        let password = std::mem::take(&mut self.password);
        self.confirm_password.clear();
        let hint = std::mem::take(&mut self.password_hint);
        let tx = self.tx.clone();

        self.is_busy = true;
        self.progress_text = "正在派生密钥并加密所有文件 (Argon2id + AES-256-GCM)...".into();
        self.status_message = None;

        // Remove from session unlocked set
        self.unlocked_during_session.remove(&path);

        let target_path = path.clone();
        self.active_progress = Some(ActiveProgressState {
            folder: path.clone(),
            is_decrypt: false,
            completed: 0,
            total: 0,
            current_file: String::new(),
            recent_files: Vec::new(),
            total_bytes_done: 0,
        });

        thread::spawn(move || {
            use zeroize::Zeroize;
            let mut password = password;
            let tx_mutex = std::sync::Arc::new(std::sync::Mutex::new(tx));
            let tx_prog = tx_mutex.clone();
            let folder_prog = target_path.clone();

            let hint_opt = if hint.trim().is_empty() { None } else { Some(hint.as_str()) };
            let res = vault::lock_with_hint_and_progress(&target_path, &password, hint_opt, move |completed, total, current_file, file_size| {
                if let Ok(tx) = tx_prog.lock() {
                    let _ = tx.send(VaultTaskMsg::EncryptProgress(EncryptProgressInfo {
                        folder: folder_prog.clone(),
                        completed,
                        total,
                        current_file: current_file.to_string(),
                        file_size,
                    }));
                }
            });

            password.zeroize();
            if let Ok(tx) = tx_mutex.lock() {
                match res {
                    Ok(report) => {
                        if report.is_complete() {
                            let _ = tx.send(VaultTaskMsg::Success("✅ 文件夹已成功加密锁定！".into()));
                        } else {
                            let skipped_list: Vec<String> = report
                                .skipped_files
                                .iter()
                                .map(|(path, err)| format!("  • {} — {}", path.display(), err))
                                .collect();
                            let _ = tx.send(VaultTaskMsg::Success(format!(
                                "⚠️ 部分加密完成：{} 个文件已加密保护，{} 个文件因被占用或无权限而跳过。\n跳过文件：\n{}\n💡 未加密的文件仍保留为明文。当文件占用解除后，可点击【继续加密】完成剩余文件的加密。",
                                report.encrypted_files,
                                report.skipped_files.len(),
                                skipped_list.join("\n")
                            )));
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(VaultTaskMsg::Error(e.to_string()));
                    }
                }
            };
        });
    }

    fn start_unlock_task(&mut self, path: &Path) {
        let path = path.to_path_buf();
        let password = std::mem::take(&mut self.password);
        self.confirm_password.clear();
        let tx = self.tx.clone();

        self.is_busy = true;
        self.progress_text = "正在验证密码并解密还原文件夹...".into();
        self.status_message = None;

        // Add to session unlocked set
        self.unlocked_during_session.insert(path.clone());

        let target_path = path.clone();
        self.active_progress = Some(ActiveProgressState {
            folder: path.clone(),
            is_decrypt: true,
            completed: 0,
            total: 0,
            current_file: String::new(),
            recent_files: Vec::new(),
            total_bytes_done: 0,
        });

        thread::spawn(move || {
            use zeroize::Zeroize;
            let mut password = password;
            let tx_mutex = std::sync::Arc::new(std::sync::Mutex::new(tx));
            let tx_prog = tx_mutex.clone();
            let folder_prog = target_path.clone();

            let res = vault::unlock_with_progress(&target_path, &password, move |completed, total, current_file, file_size| {
                if let Ok(tx) = tx_prog.lock() {
                    let _ = tx.send(VaultTaskMsg::DecryptProgress(DecryptProgressInfo {
                        folder: folder_prog.clone(),
                        completed,
                        total,
                        current_file: current_file.to_string(),
                        file_size,
                    }));
                }
            });

            password.zeroize();
            if let Ok(tx) = tx_mutex.lock() {
                match res {
                    Ok(report) => {
                        if report.is_complete() {
                            let _ = tx.send(VaultTaskMsg::Success(
                                format!("✅ 文件夹已成功解密还原！共恢复 {} 个文件。", report.restored.len())
                            ));
                        } else {
                            let failed_list: Vec<String> = report.failed.iter()
                                .map(|(path, err)| format!("  • {} — {}", path, err))
                                .collect();
                            let _ = tx.send(VaultTaskMsg::Success(
                                format!(
                                    "⚠️ 部分解密完成：{} 个文件成功恢复，{} 个文件解密失败。\n失败文件：\n{}\n💡 加密数据已保留，可修复后重试。",
                                    report.restored.len(),
                                    report.failed.len(),
                                    failed_list.join("\n")
                                )
                            ));
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(VaultTaskMsg::Error(e.to_string()));
                    }
                }
            };
        });
    }

    fn start_batch_task(&mut self, mode: BatchMode, folders: Vec<TrackedVault>, password: String, hint: String) {
        self.is_busy = true;
        self.status_message = None;
        let is_encrypt = mode == BatchMode::Encrypt;
        let action = if is_encrypt { "加密" } else { "解密" };
        self.progress_text = format!("正在准备批量{}...", action);
        self.batch_running_info = Some(BatchProgressInfo {
            current_folder_index: 0,
            total_folders: folders.len(),
            folder_name: folders.first().map(|f| f.name.clone()).unwrap_or_default(),
            folder_path: folders.first().map(|f| f.path.clone()).unwrap_or_default(),
            is_encrypt,
            folder_completed: 0,
            folder_total: 0,
            current_file: String::new(),
            file_size: 0,
        });

        let tx = self.tx.clone();
        thread::spawn(move || {
            use zeroize::Zeroize;
            let mut password = password;
            let total = folders.len();
            let mut success_count = 0;
            let mut fail_count = 0;
            let tx_mutex = std::sync::Arc::new(std::sync::Mutex::new(tx));

            for (idx, vault_item) in folders.iter().enumerate() {
                let folder_path = vault_item.path.clone();
                let folder_name = vault_item.name.clone();

                if let Ok(tx) = tx_mutex.lock() {
                    let _ = tx.send(VaultTaskMsg::BatchProgress(BatchProgressInfo {
                        current_folder_index: idx,
                        total_folders: total,
                        folder_name: folder_name.clone(),
                        folder_path: folder_path.clone(),
                        is_encrypt,
                        folder_completed: 0,
                        folder_total: 0,
                        current_file: String::new(),
                        file_size: 0,
                    }));
                }

                let tx_prog = tx_mutex.clone();
                let f_name = folder_name.clone();
                let f_path = folder_path.clone();

                let res: Result<(), anyhow::Error> = if is_encrypt {
                    let hint_opt = if hint.trim().is_empty() { None } else { Some(hint.as_str()) };
                    vault::lock_with_hint_and_progress(&folder_path, &password, hint_opt, move |completed, ftotal, file_path, file_size| {
                        if let Ok(tx) = tx_prog.lock() {
                            let _ = tx.send(VaultTaskMsg::BatchProgress(BatchProgressInfo {
                                current_folder_index: idx,
                                total_folders: total,
                                folder_name: f_name.clone(),
                                folder_path: f_path.clone(),
                                is_encrypt: true,
                                folder_completed: completed,
                                folder_total: ftotal,
                                current_file: file_path.to_string(),
                                file_size,
                            }));
                        }
                    }).map(|_report| ())
                } else {
                    vault::unlock_with_progress(&folder_path, &password, move |completed, ftotal, file_path, file_size| {
                        if let Ok(tx) = tx_prog.lock() {
                            let _ = tx.send(VaultTaskMsg::BatchProgress(BatchProgressInfo {
                                current_folder_index: idx,
                                total_folders: total,
                                folder_name: f_name.clone(),
                                folder_path: f_path.clone(),
                                is_encrypt: false,
                                folder_completed: completed,
                                folder_total: ftotal,
                                current_file: file_path.to_string(),
                                file_size,
                            }));
                        }
                    }).map(|_report| ())
                };

                let res_for_msg = match res {
                    Ok(_) => {
                        success_count += 1;
                        Ok(())
                    }
                    Err(e) => {
                        fail_count += 1;
                        Err(e.to_string())
                    }
                };

                if let Ok(tx) = tx_mutex.lock() {
                    let _ = tx.send(VaultTaskMsg::BatchFolderCompleted {
                        folder: folder_path,
                        is_encrypt,
                        result: res_for_msg,
                    });
                }
            }

            password.zeroize();
            if let Ok(tx) = tx_mutex.lock() {
                let _ = tx.send(VaultTaskMsg::BatchAllCompleted {
                    total,
                    success_count,
                    fail_count,
                    is_encrypt,
                });
            };
        });
    }


    fn start_exit_encrypt_task(&mut self, folders: Vec<PathBuf>, mut password: String) {
        let hint = std::mem::take(&mut self.exit_password_hint);
        let tx = self.tx.clone();
        thread::spawn(move || {
            use zeroize::Zeroize;
            let hint_opt = if hint.trim().is_empty() { None } else { Some(hint.as_str()) };
            for folder in folders {
                if folder.exists() && !vault::is_locked(&folder) {
                    if let Err(e) = vault::lock_with_hint_and_progress(&folder, &password, hint_opt, |_, _, _, _| {}) {
                        password.zeroize();
                        let _ = tx.send(VaultTaskMsg::ExitEncryptComplete(Err(format!(
                            "加密 {} 失败: {}",
                            folder.display(),
                            e
                        ))));
                        return;
                    }
                }
            }
            password.zeroize();
            let _ = tx.send(VaultTaskMsg::ExitEncryptComplete(Ok(())));
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_font_galley() {
        let ctx = egui::Context::default();
        setup_chinese_fonts(&ctx);

        let raw_input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(600.0, 600.0))),
            ..Default::default()
        };
        let mut output = ctx.run_ui(raw_input, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let mut status = Some((
                    "失败: Cannot lock folder: file 'C:\\Users\\rock\\workspace\\gemini\\sms-pod-apply\\.git\\objects\\01\\615b2375f11f04803db64effcbfcb40af61863' cannot be opened for writing (possibly in use by another program): 拒绝访问。 (os error 5)".into(),
                    true
                ));
                status_banner(ui, &mut status);
                assert!(status.is_some());
            });
        });
        output.textures_delta.clear();
    }

    #[test]
    fn test_load_system_font() {
        let candidate_paths = [
            // Windows
            "C:\\Windows\\Fonts\\msyh.ttc",
            "C:\\Windows\\Fonts\\simhei.ttf",
            // macOS
            "/System/Library/Fonts/PingFang.ttc",
            "/System/Library/Fonts/STHeiti Light.ttc",
            "/Library/Fonts/Arial Unicode.ttf",
            "/System/Library/Fonts/Supplemental/Songti.ttc",
        ];
        let mut loaded = false;
        for path in candidate_paths {
            if Path::new(path).exists() {
                let bytes = std::fs::read(path).unwrap();
                let _font_data = egui::FontData::from_owned(bytes);
                loaded = true;
                break;
            }
        }
        assert!(loaded);
    }

    #[test]
    fn test_recursive_plain_dir_tree() {
        let root = std::env::temp_dir().join("securevault_test_tree");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        // Create structure:
        // root/
        //   sub1/
        //     file1.txt
        //     nested/
        //       file2.txt
        //   sub2/ (empty)
        //   root_file.txt
        let sub1 = root.join("sub1");
        let nested = sub1.join("nested");
        let sub2 = root.join("sub2");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::create_dir_all(&sub2).unwrap();
        std::fs::write(sub1.join("file1.txt"), b"hello").unwrap();
        std::fs::write(nested.join("file2.txt"), b"world!").unwrap();
        std::fs::write(root.join("root_file.txt"), b"top").unwrap();

        let tree = scan_plain_dir_tree(&root);
        let (files, dirs) = count_tree_items(&tree);
        assert_eq!(files, 3);
        assert_eq!(dirs, 3); // sub1, nested, sub2

        let total_size = sum_tree_size(&tree);
        assert_eq!(total_size, 5 + 6 + 3);

        // Verify sub1 has children
        let sub1_node = tree.iter().find(|n| n.name == "sub1").expect("sub1 node exists");
        assert!(sub1_node.is_dir);
        assert_eq!(sub1_node.children.len(), 2); // file1.txt, nested

        // Test collect_all_folder_paths
        let vaults = vec![TrackedVault {
            name: "test".into(),
            path: root.clone(),
        }];
        let all_paths = collect_all_folder_paths(&vaults);
        assert!(all_paths.contains(&root));
        assert!(all_paths.contains(&sub1));
        assert!(all_paths.contains(&nested));
        assert!(all_paths.contains(&sub2));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_open_with_default_app_signature() {
        let path = std::env::temp_dir();
        // Test that open_with_default_app and open_in_file_manager execute without panicking on valid paths
        open_with_default_app(&path);
        open_in_file_manager(&path);

        let non_existent_file = std::env::temp_dir().join("securevault_non_existent_test_file.txt");
        open_file_with_default_app(&non_existent_file);
    }
}
