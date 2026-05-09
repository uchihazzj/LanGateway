use std::sync::{Arc, Mutex};

use crate::core::model::{DashboardInfo, Language, RefreshState};
use crate::i18n::I18n;
use crate::storage::config::Config;
use crate::system::{logger, network, portproxy, privilege};
use crate::ui::{dashboard::DashboardPanel, fonts, rules::RulesPanel, settings::SettingsPanel};

#[derive(PartialEq)]
enum Tab {
    Dashboard,
    Rules,
    Settings,
}

pub struct LanGatewayApp {
    tab: Tab,
    dashboard: DashboardPanel,
    rules_panel: RulesPanel,
    settings_panel: SettingsPanel,
    dashboard_info: DashboardInfo,
    config_path: std::path::PathBuf,
    i18n: I18n,
    config: Config,
    refresh_pending: Arc<Mutex<Option<DashboardInfo>>>,
}

impl LanGatewayApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        logger::log_to_file("=== LanGateway started ===");

        let config_path = Config::config_path();
        let config = Config::load(&config_path).unwrap_or_default();
        let language = config.language;
        logger::log_to_file(&format!("Config loaded, language: {:?}", language));

        let font_ok = fonts::setup_fonts(&cc.egui_ctx);
        if !font_ok {
            logger::log_to_file("WARNING: Failed to load CJK font, Chinese text may not display correctly");
        } else {
            logger::log_to_file("CJK font loaded successfully");
        }

        let info = Self::build_dashboard_info(&config);

        Self {
            tab: Tab::Dashboard,
            dashboard: DashboardPanel::new(),
            rules_panel: RulesPanel::new(config.clone(), config_path.clone(), info.is_admin),
            settings_panel: SettingsPanel {
                mdns_hostname: config.mdns_hostname.clone(),
                preferred_gateway_ip: config.preferred_gateway_ip.clone(),
                interfaces: info.interfaces.clone(),
            },
            dashboard_info: info,
            config_path,
            i18n: I18n::new(language),
            config,
            refresh_pending: Arc::new(Mutex::new(None)),
        }
    }

    fn build_dashboard_info(config: &Config) -> DashboardInfo {
        let is_admin = privilege::is_admin();
        let hostname = network::get_hostname().unwrap_or_else(|| "unknown".into());
        let interfaces = network::get_active_interfaces();
        let ipv4s = network::ipv4_addresses_from(&interfaces);
        let proxy_entries = portproxy::show_all().unwrap_or_default();

        let gateway_ip = network::select_preferred_ip(
            &ipv4s,
            &config.preferred_gateway_ip,
            &interfaces,
        );
        let active_interface = network::get_interface_for_ip(&gateway_ip, &interfaces).to_string();

        logger::log_to_file(&format!(
            "Hostname: {}, Gateway IP: {}, IPs: {:?}, Admin: {}, Rules: {}",
            hostname, gateway_ip, ipv4s, is_admin, proxy_entries.len()
        ));

        DashboardInfo {
            hostname,
            local_ipv4: ipv4s,
            active_interface,
            is_admin,
            rule_count: proxy_entries.len(),
            gateway_ip,
            interfaces,
            refresh_state: RefreshState::Idle,
        }
    }

    fn start_background_refresh(&mut self) {
        if matches!(self.dashboard_info.refresh_state, RefreshState::Refreshing) {
            return;
        }
        self.dashboard_info.refresh_state = RefreshState::Refreshing;

        let config = self.config.clone();
        let pending = self.refresh_pending.clone();

        std::thread::spawn(move || {
            let info = Self::build_dashboard_info(&config);
            if let Ok(mut guard) = pending.lock() {
                *guard = Some(info);
            }
        });
    }

    fn try_apply_refresh(&mut self) {
        if let Ok(mut guard) = self.refresh_pending.lock() {
            if let Some(mut info) = guard.take() {
                // If old state had interfaces but new state is empty, retain old network data
                if info.interfaces.is_empty() && !self.dashboard_info.interfaces.is_empty() {
                    logger::log_to_file("WARNING: refresh returned empty interfaces, retaining old network state");
                    info.interfaces = self.dashboard_info.interfaces.clone();
                    info.local_ipv4 = self.dashboard_info.local_ipv4.clone();
                    info.gateway_ip = self.dashboard_info.gateway_ip.clone();
                    info.active_interface = self.dashboard_info.active_interface.clone();
                    info.refresh_state = RefreshState::Done {
                        at: std::time::Instant::now(),
                        error: Some("Network detection failed, showing cached data".into()),
                    };
                } else {
                    info.refresh_state = RefreshState::Done {
                        at: std::time::Instant::now(),
                        error: None,
                    };
                }
                self.dashboard_info = info;
                self.rules_panel.is_admin = self.dashboard_info.is_admin;
                self.rules_panel.refresh_proxy();
                self.dashboard_info.rule_count = self.rules_panel.proxy_entries.len();
                self.settings_panel.interfaces = self.dashboard_info.interfaces.clone();
            }
        }
    }

    fn recompute_gateway_ip_from_ui(&mut self) {
        let ips = network::ipv4_addresses_from(&self.dashboard_info.interfaces);
        let preferred = &self.config.preferred_gateway_ip;
        self.dashboard_info.gateway_ip =
            network::select_preferred_ip(&ips, preferred, &self.dashboard_info.interfaces);
        self.dashboard_info.active_interface =
            network::get_interface_for_ip(&self.dashboard_info.gateway_ip, &self.dashboard_info.interfaces).to_string();
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            ui.heading(self.i18n.text("app.title"));
            ui.separator();

            ui.selectable_value(&mut self.tab, Tab::Dashboard, self.i18n.text("tab.dashboard"));
            ui.selectable_value(&mut self.tab, Tab::Rules, self.i18n.text("tab.forward_rules"));
            ui.selectable_value(&mut self.tab, Tab::Settings, self.i18n.text("tab.settings"));
        });
    }

    fn on_language_changed(&mut self, new_lang: Language) {
        self.i18n.set_language(new_lang);
        self.config.language = new_lang;
        self.rules_panel.config.language = new_lang;
        let _ = self.config.save(&self.config_path);
        logger::log_to_file(&format!("Language changed to {:?}", new_lang));
    }

    fn save_config_deferred(&mut self) {
        if self.config.preferred_gateway_ip != self.settings_panel.preferred_gateway_ip {
            self.config.preferred_gateway_ip = self.settings_panel.preferred_gateway_ip.clone();
            self.rules_panel.config.preferred_gateway_ip = self.settings_panel.preferred_gateway_ip.clone();
            let _ = self.config.save(&self.config_path);
        }
        if self.config.mdns_hostname != self.settings_panel.mdns_hostname {
            self.config.mdns_hostname = self.settings_panel.mdns_hostname.clone();
            self.rules_panel.config.mdns_hostname = self.settings_panel.mdns_hostname.clone();
            let _ = self.config.save(&self.config_path);
        }
    }
}

impl eframe::App for LanGatewayApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Check for background refresh completion
        self.try_apply_refresh();

        egui::SidePanel::left("sidebar")
            .min_width(160.0)
            .resizable(false)
            .show(ctx, |ui| {
                self.sidebar(ui);
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            match self.tab {
                Tab::Dashboard => {
                    if self.dashboard.show(ui, &self.dashboard_info, &self.i18n) {
                        self.start_background_refresh();
                    }
                }
                Tab::Rules => {
                    self.rules_panel.show(ui, &self.i18n);
                }
                Tab::Settings => {
                    let prev_lang = self.i18n.language();
                    let prev_ip = self.settings_panel.preferred_gateway_ip.clone();
                    self.settings_panel
                        .show(ui, &self.dashboard_info, &mut self.i18n);
                    if self.i18n.language() != prev_lang {
                        self.on_language_changed(self.i18n.language());
                    }
                    if self.settings_panel.preferred_gateway_ip != prev_ip {
                        self.save_config_deferred();
                        // Lightweight recompute — no system commands
                        self.recompute_gateway_ip_from_ui();
                    }
                }
            }
        });

        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let i = &self.i18n;
                let admin_key = if self.dashboard_info.is_admin {
                    "status.admin_yes"
                } else {
                    "status.admin_no"
                };
                let gateway_display = if self.dashboard_info.gateway_ip.is_empty() {
                    i.text("status.no_usable_ipv4")
                } else {
                    &self.dashboard_info.gateway_ip
                };
                ui.label(format!(
                    "{} | {}: {} | {}: {} | {}: {}",
                    i.text(admin_key),
                    i.text("status.ip"),
                    gateway_display,
                    i.text("status.rules"),
                    self.dashboard_info.rule_count,
                    i.text("status.interface"),
                    self.dashboard_info.active_interface,
                ));
            });
        });

        // Only request repaint while background refresh is in progress
        if matches!(self.dashboard_info.refresh_state, RefreshState::Refreshing) {
            ctx.request_repaint_after(std::time::Duration::from_millis(150));
        }
    }
}
