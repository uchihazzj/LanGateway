use crate::core::model::{DashboardInfo, RefreshState};
use crate::i18n::I18n;
use crate::system::privilege;

pub struct DashboardPanel {
    pub elevation_error: Option<String>,
}

impl DashboardPanel {
    pub fn new() -> Self {
        Self {
            elevation_error: None,
        }
    }

    pub fn show(&mut self, ui: &mut egui::Ui, info: &DashboardInfo, i18n: &I18n) -> bool {
        let mut need_refresh = false;
        ui.heading(i18n.text("dashboard.title"));

        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_min_width(400.0);
            egui::Grid::new("dashboard_grid")
                .num_columns(2)
                .spacing([20.0, 8.0])
                .striped(true)
                .show(ui, |ui| {
                    ui.label(format!("{}:", i18n.text("dashboard.hostname")));
                    ui.label(&info.hostname);
                    ui.end_row();

                    ui.label(format!("{}:", i18n.text("dashboard.gateway_ip")));
                    if info.gateway_ip.is_empty() {
                        ui.strong(i18n.text("status.no_usable_ipv4"));
                    } else {
                        ui.strong(&info.gateway_ip);
                    }
                    ui.end_row();

                    ui.label(format!("{}:", i18n.text("dashboard.detected_ipv4")));
                    ui.label(info.local_ipv4.join(", "));
                    ui.end_row();

                    ui.label(format!("{}:", i18n.text("dashboard.active_interface")));
                    ui.label(&info.active_interface);
                    ui.end_row();

                    ui.label(format!("{}:", i18n.text("dashboard.administrator")));
                    ui.label(if info.is_admin {
                        i18n.text("status.admin_yes")
                    } else {
                        i18n.text("status.admin_no")
                    });
                    ui.end_row();

                    ui.label(format!("{}:", i18n.text("dashboard.portproxy_rules")));
                    ui.label(info.rule_count.to_string());
                    ui.end_row();
                });
        });

        ui.add_space(12.0);

        if !info.is_admin {
            ui.colored_label(
                egui::Color32::from_rgb(200, 160, 0),
                i18n.text("dashboard.read_only_hint"),
            );
            ui.add_space(8.0);
        }

        ui.heading(i18n.text("dashboard.quick_actions"));

        ui.horizontal(|ui| {
            let is_refreshing = matches!(info.refresh_state, RefreshState::Refreshing);
            let btn_text = if is_refreshing {
                "  ...  "
            } else {
                i18n.text("dashboard.refresh_status")
            };
            if ui
                .add_enabled(!is_refreshing, egui::Button::new(btn_text))
                .clicked()
            {
                need_refresh = true;
            }

            if !info.is_admin && ui.button(i18n.text("dashboard.restart_as_admin")).clicked() {
                if let Err(e) = privilege::restart_as_admin() {
                    self.elevation_error = Some(e);
                }
            }
        });

        if let Some(ref err) = self.elevation_error {
            ui.add_space(4.0);
            ui.colored_label(
                egui::Color32::from_rgb(220, 80, 60),
                format!("{}: {}", i18n.text("dashboard.elevation_failed"), err),
            );
        }

        ui.add_space(4.0);
        match &info.refresh_state {
            RefreshState::Refreshing => {
                ui.label("Refreshing...");
            }
            RefreshState::Done { error, .. } => {
                if let Some(err) = error {
                    ui.colored_label(
                        egui::Color32::from_rgb(220, 80, 60),
                        format!("Refresh failed: {}", err),
                    );
                }
            }
        }

        if info.rule_count == 0 {
            ui.add_space(4.0);
            ui.label(i18n.text("dashboard.add_rule_hint"));
        }

        need_refresh
    }
}
