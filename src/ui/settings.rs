use crate::core::model::{DashboardInfo, InterfaceInfo, Language};
use crate::i18n::I18n;
use crate::service::mdns::MdnsStatus;
use crate::system::network;

pub struct SettingsPanel {
    pub mdns_enabled: bool,
    pub mdns_hostname: String,
    pub preferred_gateway_ip: String,
    pub interfaces: Vec<InterfaceInfo>,
    pub config_path: std::path::PathBuf,
    pub mdns_status: MdnsStatus,
    pub mdns_retry_requested: bool,
}

impl SettingsPanel {
    pub fn show(&mut self, ui: &mut egui::Ui, info: &DashboardInfo, i18n: &mut I18n) {
        ui.heading(i18n.text("settings.title"));

        egui::ScrollArea::vertical().show(ui, |ui| {
            self.show_language(ui, i18n);
            self.show_preferred_ip(ui, info, i18n);
            self.show_adapter_list(ui, info, i18n);
            self.show_mdns(ui, info, i18n);
            self.show_firewall_notes(ui, i18n);
            self.show_config(ui, i18n);
            ui.add_space(24.0);
        });
    }

    fn show_language(&mut self, ui: &mut egui::Ui, i18n: &mut I18n) {
        ui.add_space(4.0);
        ui.strong(i18n.text("settings.language"));
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.horizontal(|ui| {
                let current = i18n.language();
                let zh_selected = current == Language::ZhCn;
                let en_selected = current == Language::EnUs;

                if ui.selectable_label(zh_selected, "简体中文").clicked() && !zh_selected {
                    i18n.set_language(Language::ZhCn);
                }
                if ui.selectable_label(en_selected, "English").clicked() && !en_selected {
                    i18n.set_language(Language::EnUs);
                }
            });
        });
    }

    fn show_preferred_ip(&mut self, ui: &mut egui::Ui, info: &DashboardInfo, i18n: &I18n) {
        section_gap(ui);
        ui.strong(i18n.text("settings.preferred_gateway_ip"));
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.radio_value(
                &mut self.preferred_gateway_ip,
                "auto".to_string(),
                i18n.text("settings.auto_select"),
            );

            let ips: Vec<String> = if !info.local_ipv4.is_empty() {
                info.local_ipv4.clone()
            } else {
                self.interfaces
                    .iter()
                    .map(|i| i.ipv4.clone())
                    .filter(|ip| network::is_usable_gateway_ipv4(ip))
                    .collect()
            };

            for ip in &ips {
                let iface = info.interfaces.iter().find(|i| &i.ipv4 == ip);
                let label = if let Some(iface) = iface {
                    if iface.is_virtual {
                        format!(
                            "{} - {} [{}]",
                            ip,
                            iface.name,
                            i18n.text("settings.suspected_virtual")
                        )
                    } else {
                        format!("{} - {}", ip, iface.name)
                    }
                } else {
                    ip.clone()
                };
                ui.radio_value(&mut self.preferred_gateway_ip, ip.clone(), label);
            }
        });
    }

    fn show_adapter_list(&self, ui: &mut egui::Ui, info: &DashboardInfo, i18n: &I18n) {
        section_gap(ui);
        ui.strong(i18n.text("settings.adapter_list"));
        egui::Frame::group(ui.style()).show(ui, |ui| {
            for iface in &info.interfaces {
                let vtag = if iface.is_virtual {
                    format!(" [{}]", i18n.text("settings.suspected_virtual"))
                } else {
                    String::new()
                };
                let apipa_tag = if network::is_apipa_ipv4(&iface.ipv4) {
                    format!(" [{}]", i18n.text("settings.apipa_warning"))
                } else {
                    String::new()
                };
                let ipv6 = if iface.ipv6.is_empty() {
                    "-".into()
                } else {
                    iface.ipv6.join(", ")
                };
                ui.label(format!(
                    "{} | IPv4: {} | IPv6: {} | MAC: {}{}{}",
                    iface.name, iface.ipv4, ipv6, iface.mac, vtag, apipa_tag
                ));
            }
            if info.interfaces.is_empty() {
                ui.label(i18n.text("status.no_adapters"));
            }
        });
    }

    fn show_mdns(&mut self, ui: &mut egui::Ui, info: &DashboardInfo, i18n: &I18n) {
        section_gap(ui);
        ui.strong(i18n.text("settings.mdns"));
        ui.colored_label(
            egui::Color32::from_rgb(200, 160, 0),
            i18n.text("settings.mdns_experimental"),
        );
        egui::Frame::group(ui.style()).show(ui, |ui| {
            let has_ip = !info.gateway_ip.is_empty();
            ui.add_enabled_ui(has_ip || self.mdns_enabled, |ui| {
                ui.checkbox(&mut self.mdns_enabled, i18n.text("settings.mdns_enable"));
            });
            if !has_ip {
                ui.colored_label(
                    egui::Color32::from_rgb(200, 160, 0),
                    i18n.text("settings.mdns_err_no_ip"),
                );
            }

            ui.add_space(4.0);
            match &self.mdns_status {
                MdnsStatus::Disabled => {}
                MdnsStatus::Starting => {
                    ui.spinner();
                }
                MdnsStatus::Running => {
                    ui.colored_label(egui::Color32::from_rgb(0, 180, 80), "Running");
                }
                MdnsStatus::Failed(err) => {
                    ui.colored_label(
                        egui::Color32::from_rgb(220, 80, 60),
                        format!("{}: {}", i18n.text("settings.mdns_err_failed"), err),
                    );
                    ui.add_space(4.0);
                    self.mdns_retry_requested |=
                        ui.button(i18n.text("settings.mdns_retry")).clicked();
                }
                MdnsStatus::Conflict(err) => {
                    ui.colored_label(
                        egui::Color32::from_rgb(220, 80, 60),
                        format!("{}: {}", i18n.text("settings.mdns_err_conflict"), err),
                    );
                }
                MdnsStatus::WaitingForIp => {
                    ui.colored_label(
                        egui::Color32::from_rgb(200, 160, 0),
                        i18n.text("settings.mdns_err_no_ip"),
                    );
                }
            }

            let hostname = crate::service::mdns::validate_mdns_hostname(&self.mdns_hostname)
                .unwrap_or_else(|_| {
                    if self.mdns_hostname.trim().is_empty() {
                        "gateway".into()
                    } else {
                        self.mdns_hostname.trim().into()
                    }
                });
            ui.label(format!(
                "{}: {}.local",
                i18n.text("settings.mdns_display"),
                hostname
            ));
            ui.label(format!(
                "{}: {}",
                i18n.text("settings.mdns_bound_ip"),
                if info.gateway_ip.is_empty() {
                    i18n.text("status.no_usable_ipv4")
                } else {
                    &info.gateway_ip
                }
            ));
            ui.label(format!(
                "{}: {}",
                i18n.text("settings.mdns_bound_iface"),
                &info.active_interface
            ));
            ui.add_space(4.0);
            ui.label(i18n.text("settings.mdns_desc"));
            ui.label(i18n.text("settings.mdns_campus_hint"));
            ui.label(i18n.text("settings.mdns_scope_hint"));
            ui.horizontal(|ui| {
                ui.label(format!("{}:", i18n.text("settings.desired_mdns")));
                ui.add(egui::TextEdit::singleline(&mut self.mdns_hostname).desired_width(150.0));
                ui.label(".local");
            });
            ui.add_space(6.0);
            ui.colored_label(
                egui::Color32::from_rgb(180, 160, 80),
                i18n.text("settings.mdns_port_note"),
            );
            ui.label(i18n.text("settings.mdns_firewall_hint"));
            ui.monospace(i18n.text("settings.mdns_firewall_cmd"));
        });
    }

    fn show_firewall_notes(&self, ui: &mut egui::Ui, i18n: &I18n) {
        section_gap(ui);
        ui.strong(i18n.text("settings.firewall"));
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.label(i18n.text("settings.fw_planned"));
            ui.add_space(4.0);
            ui.label(i18n.text("settings.fw_desc1"));
            ui.label(i18n.text("settings.fw_desc2"));
            ui.add_space(4.0);
            ui.label(i18n.text("settings.fw_manual"));
            ui.monospace("netsh advfirewall firewall add rule name=\"LanGateway-<rule-id>\" dir=in action=allow protocol=TCP localport=<port>");
        });
    }

    fn show_config(&self, ui: &mut egui::Ui, i18n: &I18n) {
        section_gap(ui);
        ui.strong(i18n.text("settings.config"));
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.label(format!(
                "{}: {}",
                i18n.text("settings.config_file"),
                self.config_path.display()
            ));
            ui.label(i18n.text("settings.config_format"));
            ui.label(i18n.text("settings.config_desc"));
        });
    }
}

fn section_gap(ui: &mut egui::Ui) {
    ui.add_space(12.0);
    ui.separator();
    ui.add_space(8.0);
}
