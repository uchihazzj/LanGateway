#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod core;
mod i18n;
mod service;
mod storage;
mod system;
mod ui;

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([860.0, 600.0]),
        ..Default::default()
    };

    eframe::run_native(
        "LanGateway",
        options,
        Box::new(|cc| Ok(Box::new(app::LanGatewayApp::new(cc)))),
    )
}
