use crate::core::model::DashboardInfo;
use crate::i18n::I18n;
use crate::service::diagnostics;
use crate::service::mdns::MdnsStatus;
use crate::storage::config::Config;
use crate::system::{firewall, network};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const FIREWALL_REFRESH_INTERVAL: Duration = Duration::from_secs(10);

pub struct NetworkPanel {
    diagnostic_status: String,
    diagnostic_result: Option<std::sync::mpsc::Receiver<Result<std::path::PathBuf, String>>>,
    firewall_statuses: Vec<firewall::FirewallRuleStatus>,
    firewall_signature: String,
    firewall_refreshing: bool,
    last_firewall_refresh: Option<Instant>,
    firewall_pending: Arc<Mutex<Option<FirewallRefreshResult>>>,
}

type FirewallRefreshResult = (String, Vec<firewall::FirewallRuleStatus>);

impl NetworkPanel {
    pub fn new() -> Self {
        Self {
            diagnostic_status: String::new(),
            diagnostic_result: None,
            firewall_statuses: Vec::new(),
            firewall_signature: String::new(),
            firewall_refreshing: false,
            last_firewall_refresh: None,
            firewall_pending: Arc::new(Mutex::new(None)),
        }
    }

    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        info: &DashboardInfo,
        config: &Config,
        config_path: &Path,
        proxy_entries: &[crate::core::model::PortproxyEntry],
        preflight: &[String],
        mdns_status: &MdnsStatus,
        i18n: &I18n,
    ) {
        self.apply_firewall_result();
        self.apply_diagnostic_result(i18n);

        ui.heading(i18n.text("network.title"));

        egui::ScrollArea::vertical().show(ui, |ui| {
            crate::ui::theme::card(ui).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.strong(i18n.text("network.summary"));
                egui::Grid::new("network_summary_grid")
                    .num_columns(2)
                    .min_row_height(22.0)
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
                        ui.label(match mdns_status {
                            MdnsStatus::Disabled => i18n.text("status.disabled").to_owned(),
                            MdnsStatus::Starting => i18n.text("status.starting").to_owned(),
                            MdnsStatus::Running => i18n.text("status.running").to_owned(),
                            MdnsStatus::RunningWithWarning(_) => format!(
                                "{} ({})",
                                i18n.text("status.running"),
                                i18n.text("settings.mdns_firewall_warning")
                            ),
                            MdnsStatus::WaitingForIp => {
                                i18n.text("settings.mdns_err_no_ip").to_owned()
                            }
                            MdnsStatus::Failed(error) => {
                                format!("{}: {error}", i18n.text("settings.mdns_err_failed"))
                            }
                            MdnsStatus::Conflict(error) => {
                                format!("{}: {error}", i18n.text("settings.mdns_err_conflict"))
                            }
                        });
                        ui.end_row();
                    });
            });

            ui.add_space(10.0);
            crate::ui::theme::card(ui).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.strong(i18n.text("network.adapters"));
                if info.interfaces.is_empty() {
                    ui.label(i18n.text("status.no_adapters"));
                }
                egui::ScrollArea::horizontal()
                    .id_salt("network_adapters_scroll")
                    .show(ui, |ui| {
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
            });

            ui.add_space(10.0);
            crate::ui::theme::card(ui).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.strong(i18n.text("network.preflight"));
                if preflight.is_empty() {
                    ui.colored_label(crate::ui::theme::SUCCESS, i18n.text("network.preflight_ok"));
                } else {
                    for item in preflight {
                        ui.colored_label(crate::ui::theme::WARNING, item);
                    }
                }
            });

            ui.add_space(10.0);
            crate::ui::theme::card(ui).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.strong(i18n.text("network.firewall"));
                let firewall_names = Self::firewall_rule_names(config);
                self.ensure_firewall_refresh(firewall_names);
                if self.firewall_refreshing {
                    ui.label(i18n.text("network.firewall_refreshing"));
                    ui.ctx().request_repaint_after(Duration::from_millis(200));
                }
                for status in &self.firewall_statuses {
                    if let Some(error) = &status.error {
                        ui.colored_label(
                            crate::ui::theme::WARNING,
                            format!(
                                "{}: {}",
                                status.name,
                                i18n.text("network.firewall_query_failed")
                            ),
                        )
                        .on_hover_text(error);
                        continue;
                    }
                    ui.label(format!(
                        "{}: {}",
                        status.name,
                        i18n.text(if status.exists {
                            "network.firewall_present"
                        } else {
                            "network.firewall_missing"
                        })
                    ));
                }
            });

            ui.add_space(10.0);
            crate::ui::theme::card(ui).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.strong(i18n.text("network.diagnostics"));
                if ui
                    .add_enabled(
                        self.diagnostic_result.is_none(),
                        egui::Button::new(i18n.text("network.export_diagnostics")),
                    )
                    .clicked()
                {
                    let config = config.clone();
                    let config_path = config_path.to_path_buf();
                    let info = info.clone();
                    let proxy_entries = proxy_entries.to_vec();
                    let mdns_status = mdns_status.clone();
                    let (tx, rx) = std::sync::mpsc::channel();
                    self.diagnostic_result = Some(rx);
                    self.diagnostic_status.clear();
                    std::thread::spawn(move || {
                        let report = diagnostics::build_report(
                            &config,
                            &config_path,
                            &info,
                            &proxy_entries,
                            &mdns_status,
                        );
                        let _ = tx.send(diagnostics::save_report(&report));
                    });
                }
                if self.diagnostic_result.is_some() {
                    ui.spinner();
                    ui.ctx().request_repaint_after(Duration::from_millis(150));
                }
                if !self.diagnostic_status.is_empty() {
                    ui.label(&self.diagnostic_status);
                }
            });
        });
    }

    fn apply_diagnostic_result(&mut self, i18n: &I18n) {
        let Some(rx) = &self.diagnostic_result else {
            return;
        };
        self.diagnostic_status = match rx.try_recv() {
            Ok(Ok(path)) => format!(
                "{}: {}",
                i18n.text("network.diagnostics_saved"),
                path.display()
            ),
            Ok(Err(e)) => e,
            Err(std::sync::mpsc::TryRecvError::Empty) => return,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                i18n.text("rules.operation_failed").into()
            }
        };
        self.diagnostic_result = None;
    }

    fn firewall_rule_names(config: &Config) -> Vec<String> {
        let mut names = Vec::new();
        for rule in &config.rules {
            if rule.firewall_managed {
                let name = firewall::tcp_rule_name(rule);
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }
        if !names
            .iter()
            .any(|name| name == firewall::MDNS_FIREWALL_RULE)
        {
            names.push(firewall::MDNS_FIREWALL_RULE.to_string());
        }
        names
    }

    fn firewall_signature(names: &[String]) -> String {
        names.join("\n")
    }

    fn apply_firewall_result(&mut self) {
        let result = self
            .firewall_pending
            .lock()
            .ok()
            .and_then(|mut pending| pending.take());

        if let Some((signature, statuses)) = result {
            self.firewall_signature = signature;
            self.firewall_statuses = statuses;
            self.firewall_refreshing = false;
            self.last_firewall_refresh = Some(Instant::now());
        }
    }

    fn ensure_firewall_refresh(&mut self, names: Vec<String>) {
        let signature = Self::firewall_signature(&names);
        let stale = self
            .last_firewall_refresh
            .map(|last| last.elapsed() >= FIREWALL_REFRESH_INTERVAL)
            .unwrap_or(true);
        if self.firewall_refreshing || (signature == self.firewall_signature && !stale) {
            return;
        }

        self.firewall_refreshing = true;
        let pending = Arc::clone(&self.firewall_pending);
        std::thread::spawn(move || {
            let statuses = names
                .into_iter()
                .map(|name| firewall::query_rule(&name))
                .collect();
            if let Ok(mut pending) = pending.lock() {
                *pending = Some((signature, statuses));
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::model::{ForwardRule, ProxyMode, ProxyProtocol};

    fn make_rule(id: &str, firewall_managed: bool) -> ForwardRule {
        ForwardRule {
            id: id.into(),
            name: id.into(),
            notes: String::new(),
            listen_address: "0.0.0.0".into(),
            listen_port: 8080,
            connect_address: "127.0.0.1".into(),
            connect_port: 80,
            managed: true,
            protocol: ProxyProtocol::Tcp,
            proxy_mode: ProxyMode::V4ToV4,
            enabled: true,
            firewall_managed,
            mdns_publish: false,
            tags: vec![],
        }
    }

    #[test]
    fn firewall_rule_names_include_mdns() {
        let config = Config::default();
        assert_eq!(
            NetworkPanel::firewall_rule_names(&config),
            vec![firewall::MDNS_FIREWALL_RULE.to_string()]
        );
    }

    #[test]
    fn firewall_rule_names_skip_unmanaged_and_deduplicate() {
        let mut config = Config::default();
        config.rules = vec![
            make_rule("web", true),
            make_rule("web", true),
            make_rule("disabled-fw", false),
        ];

        let names = NetworkPanel::firewall_rule_names(&config);
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"LanGateway-web".to_string()));
        assert!(names.contains(&firewall::MDNS_FIREWALL_RULE.to_string()));
    }

    #[test]
    fn firewall_signature_is_stable() {
        let names = vec!["LanGateway-a".to_string(), "LanGateway-mDNS".to_string()];
        assert_eq!(
            NetworkPanel::firewall_signature(&names),
            "LanGateway-a\nLanGateway-mDNS"
        );
    }
}
