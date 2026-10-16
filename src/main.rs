#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod core;
mod i18n;
mod service;
mod storage;
mod system;
mod ui;

fn main() -> Result<(), eframe::Error> {
    // Capture/clear update environment before any UI or worker threads exist.
    let startup_ready = match service::update::StartupReady::capture() {
        Ok(ticket) => ticket,
        Err(error) => {
            system::logger::log_to_file(&format!("Update startup acknowledgement failed: {error}"));
            None
        }
    };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1060.0, 740.0])
            .with_min_inner_size([800.0, 560.0]),
        ..Default::default()
    };

    let result = eframe::run_native(
        "LanGateway",
        options,
        Box::new(move |cc| Ok(Box::new(app::LanGatewayApp::new(cc, startup_ready)))),
    );
    system::logger::flush(std::time::Duration::from_millis(500));
    result
}
