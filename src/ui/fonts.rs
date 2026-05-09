use egui::{FontData, FontDefinitions, FontFamily};
use std::path::Path;

/// Try to load a CJK font from Windows system directory.
/// Returns true if a font was successfully loaded and registered.
pub fn setup_fonts(ctx: &egui::Context) -> bool {
    let font_paths = [
        r"C:\Windows\Fonts\msyh.ttc",
        r"C:\Windows\Fonts\simhei.ttf",
        r"C:\Windows\Fonts\simsun.ttc",
        r"C:\Windows\Fonts\msjh.ttc",
        r"C:\Windows\Fonts\yugothm.ttc",
        r"C:\Windows\Fonts\malgun.ttf",
    ];

    let font_bytes = font_paths.iter().find_map(|p| {
        let path = Path::new(p);
        if path.exists() {
            std::fs::read(path).ok()
        } else {
            None
        }
    });

    let Some(bytes) = font_bytes else {
        return false;
    };

    let mut fonts = FontDefinitions::default();
    let font_data = FontData::from_owned(bytes);

    fonts
        .font_data
        .insert("cjk".to_string(), std::sync::Arc::new(font_data));

    fonts
        .families
        .get_mut(&FontFamily::Proportional)
        .unwrap()
        .insert(0, "cjk".to_string());

    fonts
        .families
        .get_mut(&FontFamily::Monospace)
        .unwrap()
        .insert(0, "cjk".to_string());

    ctx.set_fonts(fonts);
    true
}
