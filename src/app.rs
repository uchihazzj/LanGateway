use std::sync::{Arc, Mutex};

use crate::core::model::{DashboardInfo, Language, PortproxyEntry, RefreshState};
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

/// Bundled result from a single background refresh: network info + portproxy entries.
struct RefreshResult {
    info: DashboardInfo,
    proxy_entries: Vec<PortproxyEntry>,
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
    refresh_pending: Arc<Mutex<Option<RefreshResult>>>,
    initial_refresh_done: bool,
    initial_health_started: bool,
}

impl LanGatewayApp {
    /// Two-phase init: fast setup first, then background thread for heavy lifting.
    /// This ensures the first frame renders quickly with a "refreshing" placeholder.
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        logger::log_to_file("=== LanGateway started ===");

        // Load config from C:\ProgramData\LanGateway\config.toml
        // Auto-migrates from exe-adjacent config.toml if present
        let (config, config_path) = match Config::load_or_migrate() {
            Ok((cfg, migration_msg)) => {
                let path = Config::config_path().unwrap_or_else(|_| {
                    std::path::PathBuf::from("C:\\ProgramData\\LanGateway\\config.toml")
                });
                logger::log_to_file(&format!(
                    "Config path: {}, language: {:?}",
                    path.display(),
                    cfg.language
                ));
                if let Some(msg) = migration_msg {
                    logger::log_to_file(&msg);
                }
                (cfg, path)
            }
            Err(e) => {
                logger::log_to_file(&format!("Config load failed: {}, using defaults", e));
                let path = Config::config_path().unwrap_or_else(|_| {
                    std::path::PathBuf::from("C:\\ProgramData\\LanGateway\\config.toml")
                });
                (Config::default(), path)
            }
        };
        let language = config.language;

        let font_ok = fonts::setup_fonts(&cc.egui_ctx);
        if !font_ok {
            logger::log_to_file(
                "WARNING: Failed to load CJK font, Chinese text may not display correctly",
            );
        } else {
            logger::log_to_file("CJK font loaded successfully");
        }

        // Fast: admin check (net session, cached by OS, ~0ms when warm)
        let is_admin = privilege::is_admin();

        // Placeholder info — background thread will replace it
        let placeholder_info = DashboardInfo {
            hostname: String::new(),
            local_ipv4: vec![],
            active_interface: String::new(),
            is_admin,
            rule_count: 0,
            gateway_ip: String::new(),
            interfaces: vec![],
            refresh_state: RefreshState::Refreshing,
        };

        let rules_panel = RulesPanel::new(config.clone(), config_path.clone(), is_admin);
        let settings_panel = SettingsPanel {
            mdns_hostname: config.mdns_hostname.clone(),
            preferred_gateway_ip: config.preferred_gateway_ip.clone(),
            interfaces: vec![],
            config_path: config_path.clone(),
        };

        let refresh_pending: Arc<Mutex<Option<RefreshResult>>> = Arc::new(Mutex::new(None));

        // Spawn background thread for initial refresh (hostname + PowerShell + netsh)
        let cfg = config.clone();
        let pending = refresh_pending.clone();
        std::thread::spawn(move || {
            let result = Self::build_dashboard_info(&cfg);
            if let Ok(mut guard) = pending.lock() {
                *guard = Some(result);
            }
        });

        Self {
            tab: Tab::Dashboard,
            dashboard: DashboardPanel::new(),
            rules_panel,
            settings_panel,
            dashboard_info: placeholder_info,
            config_path,
            i18n: I18n::new(language),
            config,
            refresh_pending,
            initial_refresh_done: false,
            initial_health_started: false,
        }
    }

    /// Heavy operations: hostname, PowerShell network detection, netsh portproxy show all.
    /// Runs on background thread only. Returns both network info and proxy entries in one call.
    fn build_dashboard_info(config: &Config) -> RefreshResult {
        let is_admin = privilege::is_admin();
        let hostname = network::get_hostname().unwrap_or_else(|| "unknown".into());
        let interfaces = network::get_active_interfaces();
        let ipv4s = network::ipv4_addresses_from(&interfaces);
        let usable_ipv4s = network::usable_gateway_ipv4_addresses(&interfaces);
        let proxy_entries = portproxy::show_all().unwrap_or_else(|e| {
            logger::log_to_file(&format!("Background refresh: netsh show all failed: {}", e));
            vec![]
        });

        let gateway_ip =
            network::select_preferred_ip(&ipv4s, &config.preferred_gateway_ip, &interfaces);
        let active_interface = network::get_interface_for_ip(&gateway_ip, &interfaces).to_string();

        logger::log_to_file(&format!(
            "Hostname: {}, Gateway IP: {}, IPs: {:?}, Admin: {}, Rules: {}",
            hostname,
            gateway_ip,
            ipv4s,
            is_admin,
            proxy_entries.len()
        ));

        RefreshResult {
            info: DashboardInfo {
                hostname,
                local_ipv4: usable_ipv4s,
                active_interface,
                is_admin,
                rule_count: proxy_entries.len(),
                gateway_ip,
                interfaces,
                refresh_state: RefreshState::Done {
                    at: std::time::Instant::now(),
                    error: None,
                },
            },
            proxy_entries,
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
            let result = Self::build_dashboard_info(&config);
            if let Ok(mut guard) = pending.lock() {
                *guard = Some(result);
            }
        });
    }

    /// Apply completed background refresh. Returns true if this was the initial refresh.
    fn try_apply_refresh(&mut self) -> bool {
        let mut was_initial = false;
        if let Ok(mut guard) = self.refresh_pending.lock() {
            if let Some(result) = guard.take() {
                let mut info = result.info;
                // If old state had interfaces but new state is empty, retain old network data
                if info.interfaces.is_empty() && !self.dashboard_info.interfaces.is_empty() {
                    logger::log_to_file(
                        "WARNING: refresh returned empty interfaces, retaining old network state",
                    );
                    info.interfaces = self.dashboard_info.interfaces.clone();
                    info.local_ipv4 = self.dashboard_info.local_ipv4.clone();
                    info.gateway_ip = self.dashboard_info.gateway_ip.clone();
                    info.active_interface = self.dashboard_info.active_interface.clone();
                    info.refresh_state = RefreshState::Done {
                        at: std::time::Instant::now(),
                        error: Some("Network detection failed, showing cached data".into()),
                    };
                }
                self.dashboard_info = info;
                self.rules_panel.apply_proxy_entries(result.proxy_entries);
                self.rules_panel.is_admin = self.dashboard_info.is_admin;
                self.dashboard_info.rule_count = self.rules_panel.proxy_entries.len();
                self.settings_panel.interfaces = self.dashboard_info.interfaces.clone();
                was_initial = !self.initial_refresh_done;
                self.initial_refresh_done = true;
            }
        }
        was_initial
    }

    fn recompute_gateway_ip_from_ui(&mut self) {
        let ips = network::ipv4_addresses_from(&self.dashboard_info.interfaces);
        let preferred = &self.config.preferred_gateway_ip;
        self.dashboard_info.gateway_ip =
            network::select_preferred_ip(&ips, preferred, &self.dashboard_info.interfaces);
        self.dashboard_info.active_interface = network::get_interface_for_ip(
            &self.dashboard_info.gateway_ip,
            &self.dashboard_info.interfaces,
        )
        .to_string();
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            ui.heading(self.i18n.text("app.title"));
            ui.separator();

            ui.selectable_value(
                &mut self.tab,
                Tab::Dashboard,
                self.i18n.text("tab.dashboard"),
            );
            ui.selectable_value(
                &mut self.tab,
                Tab::Rules,
                self.i18n.text("tab.forward_rules"),
            );
            ui.selectable_value(&mut self.tab, Tab::Settings, self.i18n.text("tab.settings"));
        });
    }

    fn on_language_changed(&mut self, new_lang: Language) {
        self.i18n.set_language(new_lang);
        self.config.language = new_lang;
        self.rules_panel.config.language = new_lang;
        if let Err(e) = self.config.save(&self.config_path) {
            logger::log_to_file(&format!(
                "Failed to save config after language change: {}",
                e
            ));
        }
        logger::log_to_file(&format!("Language changed to {:?}", new_lang));
    }

    fn save_config_deferred(&mut self) {
        if self.config.preferred_gateway_ip != self.settings_panel.preferred_gateway_ip {
            self.config.preferred_gateway_ip = self.settings_panel.preferred_gateway_ip.clone();
            self.rules_panel.config.preferred_gateway_ip =
                self.settings_panel.preferred_gateway_ip.clone();
            if let Err(e) = self.config.save(&self.config_path) {
                logger::log_to_file(&format!(
                    "Failed to save config after gateway IP change: {}",
                    e
                ));
            }
        }
        if self.config.mdns_hostname != self.settings_panel.mdns_hostname {
            self.config.mdns_hostname = self.settings_panel.mdns_hostname.clone();
            self.rules_panel.config.mdns_hostname = self.settings_panel.mdns_hostname.clone();
            if let Err(e) = self.config.save(&self.config_path) {
                logger::log_to_file(&format!(
                    "Failed to save config after mDNS hostname change: {}",
                    e
                ));
            }
        }
    }
}

impl eframe::App for LanGatewayApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Check for background refresh completion
        self.try_apply_refresh();

        // Always consume health check results (not just when on Rules tab)
        self.rules_panel.apply_health_results();

        // After initial refresh completes, auto-start health check once
        if self.initial_refresh_done
            && !self.initial_health_started
            && !self.rules_panel.health_check_running
        {
            self.initial_health_started = true;
            self.rules_panel.run_health_checks_background();
        }

        egui::SidePanel::left("sidebar")
            .min_width(160.0)
            .resizable(false)
            .show(ctx, |ui| {
                self.sidebar(ui);
            });

        // TopBottomPanel must render before CentralPanel so it reserves space first
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let i = &self.i18n;
                let admin_key = if self.dashboard_info.is_admin {
                    "status.admin_yes"
                } else {
                    "status.admin_no"
                };
                let gateway_display =
                    if matches!(self.dashboard_info.refresh_state, RefreshState::Refreshing) {
                        i.text("status.initializing")
                    } else if self.dashboard_info.gateway_ip.is_empty() {
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

        // CentralPanel fills remaining space after SidePanel and TopBottomPanel
        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
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
                    self.recompute_gateway_ip_from_ui();
                }
            }
        });

        // Request repaint while background refresh or health check is running
        let needs_repaint = matches!(self.dashboard_info.refresh_state, RefreshState::Refreshing)
            || self.rules_panel.health_check_running;
        if needs_repaint {
            ctx.request_repaint_after(std::time::Duration::from_millis(150));
        }
    }
}
