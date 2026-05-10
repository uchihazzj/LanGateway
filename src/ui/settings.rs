use crate::core::model::{DashboardInfo, InterfaceInfo, Language};
use crate::i18n::I18n;
use crate::system::network;

pub struct SettingsPanel {
    pub mdns_hostname: String,
    pub preferred_gateway_ip: String,
    pub interfaces: Vec<InterfaceInfo>,
    pub config_path: std::path::PathBuf,
}

impl SettingsPanel {
    pub fn new() -> Self {
        Self {
            mdns_hostname: "gateway".into(),
            preferred_gateway_ip: "auto".into(),
            interfaces: Vec::new(),
            config_path: std::path::PathBuf::from("C:\\ProgramData\\LanGateway\\config.toml"),
        }
    }

    pub fn show(&mut self, ui: &mut egui::Ui, info: &DashboardInfo, i18n: &mut I18n) {
        ui.heading(i18n.text("settings.title"));

        egui::ScrollArea::vertical().show(ui, |ui| {
        // Language selector
        ui.add_space(4.0);
        ui.strong(i18n.text("settings.language"));
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.horizontal(|ui| {
                let current = i18n.language();
                let zh_selected = current == Language::ZhCn;
                let en_selected = current == Language::EnUs;

                if ui
                    .selectable_label(zh_selected, "简体中文")
                    .clicked()
                    && !zh_selected
                {
                    i18n.set_language(Language::ZhCn);
                }
                if ui
                    .selectable_label(en_selected, "English")
                    .clicked()
                    && !en_selected
                {
                    i18n.set_language(Language::EnUs);
                }
            });
        });

        ui.add_space(12.0);
        ui.separator();
        ui.add_space(8.0);

        // Preferred Gateway IP
        ui.strong(i18n.text("settings.preferred_gateway_ip"));
        egui::Frame::group(ui.style()).show(ui, |ui| {
            // Auto option
            let _is_auto = self.preferred_gateway_ip == "auto";
            ui.radio_value(
                &mut self.preferred_gateway_ip,
                "auto".to_string(),
                i18n.text("settings.auto_select"),
            )
            .clicked();

            // List detected IPs — only usable gateway IPs
            let ips: Vec<String> = if !info.local_ipv4.is_empty() {
                info.local_ipv4.clone()
            } else {
                self.interfaces.iter().map(|i| i.ipv4.clone())
                    .filter(|ip| network::is_usable_gateway_ipv4(ip))
                    .collect()
            };

            for ip in &ips {
                let iface = info
                    .interfaces
                    .iter()
                    .find(|i| &i.ipv4 == ip);
                let label = if let Some(iface) = iface {
                    if iface.is_virtual {
                        format!("{} — {} [{}]",
                            ip,
                            iface.name,
                            i18n.text("settings.suspected_virtual"))
                    } else {
                        format!("{} — {}", ip, iface.name)
                    }
                } else {
                    ip.clone()
                };
                if ui
                    .radio_value(&mut self.preferred_gateway_ip, ip.clone(), &label)
                    .clicked()
                {}
            }
        });

        ui.add_space(12.0);
        ui.separator();
        ui.add_space(8.0);

        // Adapter list
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
                ui.label(format!(
                    "{}  |  IPv4: {}  |  MAC: {}{}{}",
                    iface.name, iface.ipv4, iface.mac, vtag, apipa_tag
                ));
            }
            if info.interfaces.is_empty() {
                ui.label(i18n.text("status.no_adapters"));
            }
        });

        ui.add_space(12.0);
        ui.separator();
        ui.add_space(8.0);

        // mDNS section
        ui.strong(i18n.text("settings.mdns"));
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.label(format!(
                "{}: {}.local",
                i18n.text("settings.current_mdns"),
                info.hostname
            ));
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(format!("{}:", i18n.text("settings.desired_mdns")));
                ui.add(
                    egui::TextEdit::singleline(&mut self.mdns_hostname).desired_width(150.0),
                );
                ui.label(".local");
            });
            ui.add_space(4.0);
            ui.label(i18n.text("settings.mdns_planned"));
            ui.label(i18n.text("settings.mdns_desc"));
        });

        ui.add_space(12.0);
        ui.separator();
        ui.add_space(8.0);

        // Firewall section
        ui.strong(i18n.text("settings.firewall"));
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.label(i18n.text("settings.fw_planned"));
            ui.add_space(4.0);
            ui.label(i18n.text("settings.fw_desc1"));
            ui.label(i18n.text("settings.fw_desc2"));
            ui.add_space(4.0);
            ui.label(i18n.text("settings.fw_manual"));
            ui.monospace("netsh advfirewall firewall add rule name=\"LanGateway-<port>\" dir=in action=allow protocol=TCP localport=<port>");
        });

        ui.add_space(12.0);
        ui.separator();
        ui.add_space(8.0);

        // Config section
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

            ui.add_space(24.0);
        }); // ScrollArea
    }
}
