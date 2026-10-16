use egui::{Color32, FontId, Stroke, TextStyle};

pub const ACCENT: Color32 = Color32::from_rgb(31, 87, 163);
pub const SIDEBAR: Color32 = Color32::from_rgb(24, 36, 53);
pub const TEXT: Color32 = Color32::from_rgb(30, 41, 59);
pub const MUTED: Color32 = Color32::from_rgb(71, 85, 105);
pub const SUCCESS: Color32 = Color32::from_rgb(21, 112, 68);
pub const WARNING: Color32 = Color32::from_rgb(146, 79, 0);
pub const ERROR: Color32 = Color32::from_rgb(180, 35, 45);

pub fn apply(ctx: &egui::Context) {
    // egui 0.31.1 style API: https://docs.rs/egui/0.31.1/egui/struct.Style.html
    ctx.set_theme(egui::ThemePreference::Light);
    let mut style = (*ctx.style()).clone();
    style.visuals = egui::Visuals::light();
    style.visuals.panel_fill = Color32::from_rgb(245, 247, 250);
    style.visuals.window_fill = Color32::WHITE;
    style.visuals.faint_bg_color = Color32::from_rgb(237, 242, 248);
    style.visuals.extreme_bg_color = Color32::WHITE;
    style.visuals.selection.bg_fill = Color32::from_rgb(218, 233, 252);
    style.visuals.selection.stroke = Stroke::new(1.0, ACCENT);
    style.visuals.hyperlink_color = ACCENT;
    style.visuals.warn_fg_color = WARNING;
    style.visuals.error_fg_color = ERROR;
    style.visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT);
    style.visuals.widgets.noninteractive.bg_stroke =
        Stroke::new(1.0, Color32::from_rgb(218, 225, 234));
    style.visuals.widgets.inactive.bg_fill = Color32::from_rgb(242, 245, 249);
    style.visuals.widgets.inactive.weak_bg_fill = Color32::from_rgb(234, 239, 246);
    style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, Color32::from_rgb(130, 146, 170));
    style.visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT);
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(225, 237, 251);
    style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, ACCENT);
    style.visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, TEXT);
    style.visuals.widgets.active.bg_fill = Color32::from_rgb(211, 227, 247);
    style.visuals.widgets.active.fg_stroke = Stroke::new(1.0, TEXT);
    style.spacing.item_spacing = egui::vec2(10.0, 8.0);
    style.spacing.button_padding = egui::vec2(10.0, 7.0);
    style.spacing.interact_size.y = 32.0;
    style.spacing.scroll = egui::style::ScrollStyle::solid();
    style.spacing.scroll.bar_width = 9.0;
    style.spacing.scroll.foreground_color = true;
    style.spacing.scroll.dormant_handle_opacity = 0.6;
    style.spacing.scroll.dormant_background_opacity = 0.12;
    style
        .text_styles
        .insert(TextStyle::Body, FontId::proportional(16.0));
    style
        .text_styles
        .insert(TextStyle::Button, FontId::proportional(15.0));
    style
        .text_styles
        .insert(TextStyle::Heading, FontId::proportional(22.0));
    style
        .text_styles
        .insert(TextStyle::Small, FontId::proportional(13.0));
    style
        .text_styles
        .insert(TextStyle::Monospace, FontId::monospace(14.5));
    ctx.set_style(style);
}

pub fn card(ui: &egui::Ui) -> egui::Frame {
    egui::Frame::group(ui.style())
        .fill(Color32::WHITE)
        .corner_radius(8)
        .inner_margin(12)
}
