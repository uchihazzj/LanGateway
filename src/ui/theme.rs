use egui::{Color32, FontId, Stroke, TextStyle};

pub const ACCENT: Color32 = Color32::from_rgb(36, 99, 177);
pub const SIDEBAR: Color32 = Color32::from_rgb(24, 36, 53);

pub fn apply(ctx: &egui::Context) {
    // egui 0.31.1 style API: https://docs.rs/egui/0.31.1/egui/struct.Style.html
    let mut style = (*ctx.style()).clone();
    style.visuals = egui::Visuals::light();
    style.visuals.panel_fill = Color32::from_rgb(245, 247, 250);
    style.visuals.window_fill = Color32::WHITE;
    style.visuals.faint_bg_color = Color32::from_rgb(237, 242, 248);
    style.visuals.extreme_bg_color = Color32::WHITE;
    style.visuals.selection.bg_fill = Color32::from_rgb(218, 233, 252);
    style.visuals.selection.stroke = Stroke::new(1.0, ACCENT);
    style.visuals.hyperlink_color = ACCENT;
    style.visuals.widgets.noninteractive.bg_stroke =
        Stroke::new(1.0, Color32::from_rgb(218, 225, 234));
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(225, 237, 251);
    style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, ACCENT);
    style.spacing.item_spacing = egui::vec2(10.0, 8.0);
    style.spacing.button_padding = egui::vec2(12.0, 7.0);
    style.spacing.interact_size.y = 30.0;
    style
        .text_styles
        .insert(TextStyle::Body, FontId::proportional(14.0));
    style
        .text_styles
        .insert(TextStyle::Button, FontId::proportional(14.0));
    style
        .text_styles
        .insert(TextStyle::Heading, FontId::proportional(23.0));
    style
        .text_styles
        .insert(TextStyle::Monospace, FontId::monospace(13.0));
    ctx.set_style(style);
}
