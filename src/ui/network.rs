use crate::core::model::DashboardInfo;
use crate::i18n::I18n;
use crate::service::diagnostics;
use crate::service::mdns::MdnsStatus;
use crate::storage::config::Config;
use crate::system::{firewall, network};
use std::path::Path;

pub struct NetworkPanel {
    diagnostic_status: String,
}

impl NetworkPanel {
    pub fn new() -> Self {
        Self {
            diagnostic_status: String::new(),
        }
    }

    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        info: &DashboardInfo,
        config: &Config,
        config_path: &Path,
        proxy_entries: &[crate::core::model::PortproxyEntry],
        preflight: Vec<String>,
        mdns_status: &MdnsStatus,
        i18n: &I18n,
    ) {
        ui.heading(i18n.text("network.title"));

        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.strong(i18n.text("network.summary"));
                egui::Grid::new("network_summary_grid")
                    .num_columns(2)
                    .spacing([16.0, 6.0])
                    .show(ui, |ui| {
                        ui.label(i18n.text("dashboard.gateway_ip"));
                        ui.strong(if info.gateway_ip.is_empty() {
                            i18n.text("status.no_usable_ipv4")
                        } else {
                            &info.gateway_ip
                        });
                        ui.end_row();

                        ui.label(i18n.text("dashboard.active_interface"));
                        ui.label(&info.active_interface);
                        ui.end_row();

                        ui.label("IPv4");
                        ui.label(if info.local_ipv4.is_empty() {
                            "-".into()
                        } else {
                            info.local_ipv4.join(", ")
                        });
                        ui.end_row();

                        ui.label("IPv6");
                        ui.label(if info.local_ipv6.is_empty() {
                            "-".into()
                        } else {
                            info.local_ipv6.join(", ")
                        });
                        ui.end_row();

                        ui.label("mDNS");
                        ui.label(mdns_status.to_string());
                        ui.end_row();
                    });
            });

            ui.add_space(10.0);
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.strong(i18n.text("network.adapters"));
                if info.interfaces.is_empty() {
                    ui.label(i18n.text("status.no_adapters"));
                }
                egui::Grid::new("network_adapter_grid")
                    .num_columns(6)
                    .spacing([10.0, 4.0])
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong(i18n.text("status.interface"));
                        ui.strong("IPv4");
                        ui.strong("IPv6");
                        ui.strong("MAC");
                        ui.strong(i18n.text("network.priority"));
                        ui.strong(i18n.text("network.flags"));
                        ui.end_row();

                        for iface in &info.interfaces {
                            ui.label(&iface.name);
                            ui.label(if iface.ipv4.is_empty() {
                                "-"
                            } else {
                                &iface.ipv4
                            });
                            ui.label(if iface.ipv6.is_empty() {
                                "-".into()
                            } else {
                                iface.ipv6.join(", ")
                            });
                            ui.label(if iface.mac.is_empty() {
                                "-"
                            } else {
                                &iface.mac
                            });
                            ui.label(network::gateway_ip_priority(&iface.ipv4).to_string());
                            let mut flags = Vec::new();
                            if iface.is_virtual {
                                flags.push(i18n.text("settings.suspected_virtual"));
                            }
                            if network::is_apipa_ipv4(&iface.ipv4) {
                                flags.push(i18n.text("settings.apipa_warning"));
                            }
                            ui.label(if flags.is_empty() {
                                "-".into()
                            } else {
                                flags.join(", ")
                            });
                            ui.end_row();
                        }
                    });
            });

            ui.add_space(10.0);
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.strong(i18n.text("network.preflight"));
                if preflight.is_empty() {
                    ui.colored_label(
                        egui::Color32::from_rgb(0, 160, 90),
                        i18n.text("network.preflight_ok"),
                    );
                } else {
                    for item in preflight {
                        ui.colored_label(egui::Color32::from_rgb(200, 160, 0), item);
                    }
                }
            });

            ui.add_space(10.0);
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.strong(i18n.text("network.firewall"));
                for rule in &config.rules {
                    if rule.firewall_managed {
                        let name = firewall::tcp_rule_name(rule);
                        let status = firewall::query_rule(&name);
                        ui.label(format!("{}: exists={}", status.name, status.exists));
                    }
                }
                let status = firewall::query_rule(firewall::MDNS_FIREWALL_RULE);
                ui.label(format!("{}: exists={}", status.name, status.exists));
            });

            ui.add_space(10.0);
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.strong(i18n.text("network.diagnostics"));
                if ui.button(i18n.text("network.export_diagnostics")).clicked() {
                    let report = diagnostics::build_report(
                        config,
                        config_path,
                        info,
                        proxy_entries,
                        mdns_status,
                    );
                    match diagnostics::save_report(&report) {
                        Ok(path) => {
                            self.diagnostic_status = format!(
                                "{}: {}",
                                i18n.text("network.diagnostics_saved"),
                                path.display()
                            );
                        }
                        Err(e) => self.diagnostic_status = e,
                    }
                }
                if !self.diagnostic_status.is_empty() {
                    ui.label(&self.diagnostic_status);
                }
            });
        });
    }
}
