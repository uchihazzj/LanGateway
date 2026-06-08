use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::core::model::{DashboardInfo, Language, PortproxyEntry, RefreshState};
use crate::i18n::I18n;
use crate::service::mdns::{self, MdnsConfigSnapshot, MdnsHandle};
use crate::service::state::{AppState, OperationState, SharedState};
use crate::service::update::{self, UpdateStatus};
use crate::storage::config::Config;
use crate::system::{firewall, logger, network, portproxy, privilege};
use crate::ui::{
    dashboard::DashboardPanel, fonts, network::NetworkPanel, rules::RulesPanel,
    settings::SettingsPanel,
};

#[derive(PartialEq)]
enum Tab {
    Dashboard,
    Rules,
    Network,
    Settings,
}

/// Bundled result from a background refresh stage.
struct RefreshResult {
    info: DashboardInfo,
    proxy_entries: Option<Vec<PortproxyEntry>>,
    complete: bool,
}

pub struct LanGatewayApp {
    tab: Tab,
    dashboard: DashboardPanel,
    rules_panel: RulesPanel,
    network_panel: NetworkPanel,
    settings_panel: SettingsPanel,
    state: SharedState,
    dashboard_info: DashboardInfo,
    config_path: std::path::PathBuf,
    i18n: I18n,
    config: Config,
    refresh_pending: Arc<Mutex<VecDeque<RefreshResult>>>,
    update_status: Arc<Mutex<UpdateStatus>>,
    mdns_handle: Option<MdnsHandle>,
    last_mdns_snapshot: MdnsConfigSnapshot,
    last_mdns_failure: Option<String>,
    initial_refresh_done: bool,
    initial_health_started: bool,
    initial_update_check_done: bool,
    last_mdns_auto_refresh: Instant,
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
            hostname: config.mdns_hostname.trim_end_matches(".local").to_string(),
            local_ipv4: vec![],
            local_ipv6: vec![],
            active_interface: String::new(),
            is_admin,
            rule_count: config.rules.iter().filter(|r| r.enabled).count(),
            gateway_ip: String::new(),
            interfaces: vec![],
            refresh_state: RefreshState::Refreshing { stage: "startup" },
        };

        let rules_panel = RulesPanel::new(config.clone(), config_path.clone(), is_admin);
        let settings_panel = SettingsPanel {
            mdns_enabled: config.mdns_enabled,
            mdns_hostname: config.mdns_hostname.clone(),
            preferred_gateway_ip: config.preferred_gateway_ip.clone(),
            interfaces: vec![],
            config_path: config_path.clone(),
            mdns_status: mdns::MdnsStatus::Disabled,
            mdns_retry_requested: false,
        };

        let refresh_pending: Arc<Mutex<VecDeque<RefreshResult>>> =
            Arc::new(Mutex::new(VecDeque::new()));

        Self::spawn_refresh_workers(config.clone(), refresh_pending.clone());

        let state = Arc::new(Mutex::new(AppState::new(
            config.clone(),
            config_path.clone(),
            placeholder_info.clone(),
        )));

        Self {
            tab: Tab::Dashboard,
            dashboard: DashboardPanel::new(),
            rules_panel,
            network_panel: NetworkPanel::new(),
            settings_panel,
            state,
            dashboard_info: placeholder_info,
            config_path,
            i18n: I18n::new(language),
            config,
            refresh_pending,
            update_status: Arc::new(Mutex::new(UpdateStatus::Idle)),
            mdns_handle: None,
            last_mdns_snapshot: MdnsConfigSnapshot {
                enabled: false,
                hostname: String::new(),
                gateway_ip: String::new(),
            },
            last_mdns_failure: None,
            initial_refresh_done: false,
            initial_health_started: false,
            initial_update_check_done: false,
            last_mdns_auto_refresh: Instant::now(),
        }
    }

    fn spawn_refresh_workers(config: Config, pending: Arc<Mutex<VecDeque<RefreshResult>>>) {
        let quick_cfg = config.clone();
        let quick_pending = pending.clone();
        std::thread::spawn(move || {
            Self::push_refresh_result(&quick_pending, Self::build_quick_dashboard_info(&quick_cfg));
        });

        std::thread::spawn(move || {
            Self::push_refresh_result(&pending, Self::build_full_dashboard_info(&config));
        });
    }

    fn push_refresh_result(pending: &Arc<Mutex<VecDeque<RefreshResult>>>, result: RefreshResult) {
        if let Ok(mut guard) = pending.lock() {
            guard.push_back(result);
        }
    }

    /// Fast startup stage: hostname, plain ipconfig IPv4, and v4tov4 PortProxy.
    fn build_quick_dashboard_info(config: &Config) -> RefreshResult {
        let is_admin = privilege::is_admin();
        let hostname = network::get_hostname().unwrap_or_else(|| "unknown".into());
        let interfaces = network::get_quick_interfaces();
        let ipv4s = network::ipv4_addresses_from(&interfaces);
        let usable_ipv4s = network::usable_gateway_ipv4_addresses(&interfaces);
        let proxy_entries = portproxy::show_v4tov4().unwrap_or_else(|e| {
            logger::log_to_file(&format!("Quick refresh: netsh v4tov4 failed: {}", e));
            vec![]
        });
        let gateway_ip =
            network::select_preferred_ip(&ipv4s, &config.preferred_gateway_ip, &interfaces);
        let active_interface = network::get_interface_for_ip(&gateway_ip, &interfaces).to_string();

        RefreshResult {
            info: DashboardInfo {
                hostname,
                local_ipv4: usable_ipv4s,
                local_ipv6: Vec::new(),
                active_interface,
                is_admin,
                rule_count: proxy_entries.len(),
                gateway_ip,
                interfaces,
                refresh_state: RefreshState::Refreshing { stage: "details" },
            },
            proxy_entries: Some(proxy_entries),
            complete: false,
        }
    }

    /// Heavy stage: PowerShell network details and all PortProxy modes.
    fn build_full_dashboard_info(config: &Config) -> RefreshResult {
        let is_admin = privilege::is_admin();
        let hostname = network::get_hostname().unwrap_or_else(|| "unknown".into());
        let interfaces = network::get_active_interfaces();
        let ipv4s = network::ipv4_addresses_from(&interfaces);
        let ipv6s = network::ipv6_addresses_from(&interfaces);
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
                local_ipv6: ipv6s,
                active_interface,
                is_admin,
                rule_count: proxy_entries.len(),
                gateway_ip,
                interfaces,
                refresh_state: RefreshState::Done { error: None },
            },
            proxy_entries: Some(proxy_entries),
            complete: true,
        }
    }

    fn start_background_refresh(&mut self) {
        if matches!(
            self.dashboard_info.refresh_state,
            RefreshState::Refreshing { .. }
        ) {
            return;
        }
        self.dashboard_info.refresh_state = RefreshState::Refreshing { stage: "refresh" };
        if let Ok(mut state) = self.state.lock() {
            state.operation = OperationState::Refreshing;
            state.add_log("Refresh started");
        }

        Self::spawn_refresh_workers(self.effective_config(), self.refresh_pending.clone());
    }

    /// Apply completed background refresh. Returns true if this was the initial refresh.
    fn try_apply_refresh(&mut self) -> bool {
        let mut was_initial = false;
        let mut results = Vec::new();
        if let Ok(mut guard) = self.refresh_pending.lock() {
            while let Some(result) = guard.pop_front() {
                results.push(result);
            }
        }

        for result in results {
            let mut info = result.info;
            // If old state had interfaces but new state is empty, retain old network data
            if info.interfaces.is_empty() && !self.dashboard_info.interfaces.is_empty() {
                logger::log_to_file(
                    "WARNING: refresh returned empty interfaces, retaining old network state",
                );
                info.interfaces = self.dashboard_info.interfaces.clone();
                info.local_ipv4 = self.dashboard_info.local_ipv4.clone();
                info.local_ipv6 = self.dashboard_info.local_ipv6.clone();
                info.gateway_ip = self.dashboard_info.gateway_ip.clone();
                info.active_interface = self.dashboard_info.active_interface.clone();
                if result.complete {
                    info.refresh_state = RefreshState::Done {
                        error: Some("Network detection failed, showing cached data".into()),
                    };
                }
            }
            self.dashboard_info = info;
            if let Some(proxy_entries) = result.proxy_entries {
                self.rules_panel.apply_proxy_entries(proxy_entries);
            }
            self.rules_panel.is_admin = self.dashboard_info.is_admin;
            self.dashboard_info.rule_count = self.rules_panel.proxy_entries.len();
            self.settings_panel.interfaces = self.dashboard_info.interfaces.clone();
            let effective_config = self.effective_config();
            if let Ok(mut state) = self.state.lock() {
                state.dashboard = self.dashboard_info.clone();
                state.config = effective_config;
                state.proxy_entries = self.rules_panel.proxy_entries.clone();
                if result.complete {
                    state.operation = OperationState::Idle;
                    state.add_log("Refresh completed");
                } else {
                    state.operation = OperationState::Refreshing;
                    state.add_log("Fast startup data ready");
                }
            }
            if result.complete {
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

    fn sync_mdns_state(&mut self) {
        self.sync_mdns_state_impl(false);
    }

    fn maybe_refresh_for_mdns(&mut self) {
        if !self.settings_panel.mdns_enabled || !self.initial_refresh_done {
            return;
        }
        if matches!(
            self.dashboard_info.refresh_state,
            RefreshState::Refreshing { .. }
        ) {
            return;
        }
        if self.last_mdns_auto_refresh.elapsed() < Duration::from_secs(30) {
            return;
        }
        self.last_mdns_auto_refresh = Instant::now();
        logger::log_to_file("mDNS: scheduled network refresh for dynamic IP tracking");
        self.start_background_refresh();
    }

    fn sync_mdns_state_impl(&mut self, force: bool) {
        // Validate hostname first; fall back to "gateway" if empty
        let raw = if self.settings_panel.mdns_hostname.is_empty() {
            "gateway"
        } else {
            &self.settings_panel.mdns_hostname
        };
        let hostname = match mdns::validate_mdns_hostname(raw) {
            Ok(h) => h,
            Err(e) => {
                logger::log_to_file(&format!("mDNS: hostname validation failed: {}", e));
                self.settings_panel.mdns_status =
                    mdns::MdnsStatus::Failed(format!("Invalid hostname: {}", e));
                if let Some(h) = self.mdns_handle.take() {
                    h.shutdown();
                }
                return;
            }
        };

        let snapshot = MdnsConfigSnapshot {
            enabled: self.settings_panel.mdns_enabled,
            hostname,
            gateway_ip: self.dashboard_info.gateway_ip.clone(),
        };

        if !force && !self.last_mdns_snapshot.needs_restart(&snapshot) {
            // Snapshot unchanged: if we already failed, keep showing the error
            // rather than retrying every frame.
            if let Some(ref err) = self.last_mdns_failure {
                self.settings_panel.mdns_status = mdns::MdnsStatus::Failed(err.clone());
            }
            return;
        }

        // Snapshot changed (or forced retry) — clear previous failure.
        self.last_mdns_failure = None;
        self.last_mdns_snapshot = snapshot.clone();

        if !snapshot.enabled {
            self.settings_panel.mdns_status = mdns::MdnsStatus::Disabled;
            if let Some(h) = self.mdns_handle.take() {
                h.shutdown();
            }
            return;
        }

        if snapshot.gateway_ip.is_empty() {
            self.settings_panel.mdns_status = mdns::MdnsStatus::WaitingForIp;
            if let Some(h) = self.mdns_handle.take() {
                h.shutdown();
            }
            return;
        }

        match MdnsHandle::start(&snapshot.hostname, &snapshot.gateway_ip) {
            Ok(handle) => {
                if let Err(e) = firewall::ensure_mdns_rule() {
                    logger::log_to_file(&format!("mDNS firewall rule setup failed: {}", e));
                }
                self.last_mdns_failure = None;
                self.settings_panel.mdns_status = mdns::MdnsStatus::Running;
                self.mdns_handle = Some(handle);
            }
            Err(e) => {
                logger::log_to_file(&format!("mDNS: start failed: {}", e));
                self.last_mdns_failure = Some(e.clone());
                self.settings_panel.mdns_status = mdns::MdnsStatus::Failed(e);
                self.mdns_handle = None;
            }
        }
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
            ui.selectable_value(&mut self.tab, Tab::Network, self.i18n.text("tab.network"));
            ui.selectable_value(&mut self.tab, Tab::Settings, self.i18n.text("tab.settings"));
        });
    }

    fn effective_config(&self) -> Config {
        let mut config = self.config.clone();
        config.rules = self.rules_panel.config.rules.clone();
        config.normalize();
        config
    }

    fn sync_rules_into_config(&mut self) {
        self.config.rules = self.rules_panel.config.rules.clone();
        self.config.normalize();
    }

    fn on_language_changed(&mut self, new_lang: Language) {
        self.i18n.set_language(new_lang);
        self.config.language = new_lang;
        self.rules_panel.config.language = new_lang;
        self.sync_rules_into_config();
        if let Err(e) = self.config.save(&self.config_path) {
            logger::log_to_file(&format!(
                "Failed to save config after language change: {}",
                e
            ));
        }
        if let Ok(mut state) = self.state.lock() {
            state.config = self.effective_config();
            state.add_log(format!("Language changed to {:?}", new_lang));
        }
        logger::log_to_file(&format!("Language changed to {:?}", new_lang));
    }

    fn save_config_deferred(&mut self) {
        let mut changed = false;
        if self.config.preferred_gateway_ip != self.settings_panel.preferred_gateway_ip {
            self.config.preferred_gateway_ip = self.settings_panel.preferred_gateway_ip.clone();
            self.rules_panel.config.preferred_gateway_ip =
                self.settings_panel.preferred_gateway_ip.clone();
            changed = true;
        }
        if self.config.mdns_hostname != self.settings_panel.mdns_hostname {
            self.config.mdns_hostname = self.settings_panel.mdns_hostname.clone();
            self.rules_panel.config.mdns_hostname = self.settings_panel.mdns_hostname.clone();
            changed = true;
        }
        if self.config.mdns_enabled != self.settings_panel.mdns_enabled {
            self.config.mdns_enabled = self.settings_panel.mdns_enabled;
            self.rules_panel.config.mdns_enabled = self.settings_panel.mdns_enabled;
            changed = true;
        }
        if changed {
            self.sync_rules_into_config();
            if let Err(e) = self.config.save(&self.config_path) {
                logger::log_to_file(&format!("Failed to save config: {}", e));
            }
            if let Ok(mut state) = self.state.lock() {
                state.config = self.effective_config();
                state.add_log("Settings saved");
            }
        }
    }

    fn start_update_check(&mut self) {
        let status = self.update_status.clone();
        {
            let mut s = status.lock().unwrap();
            if s.is_busy() {
                return;
            }
            *s = UpdateStatus::Checking;
        }
        if let Ok(mut state) = self.state.lock() {
            state.update_status = UpdateStatus::Checking;
            state.add_log("Update check started");
        }

        std::thread::spawn(move || {
            let result = update::check_update();
            let mut s = status.lock().unwrap();
            match result {
                Ok(Some((latest, release_url, download_url))) => {
                    *s = UpdateStatus::Available {
                        latest,
                        release_url,
                        download_url,
                    };
                }
                Ok(None) => {
                    *s = UpdateStatus::UpToDate;
                }
                Err(e) => {
                    *s = UpdateStatus::Failed(e);
                }
            }
        });
    }

    fn start_update_download(&mut self) {
        let (download_url, latest_version) = {
            let s = self.update_status.lock().unwrap();
            match &*s {
                UpdateStatus::Available {
                    download_url,
                    latest,
                    ..
                } => (download_url.clone(), latest.clone()),
                _ => return,
            }
        };

        let status = self.update_status.clone();
        {
            let mut s = status.lock().unwrap();
            *s = UpdateStatus::Downloading;
        }
        if let Ok(mut state) = self.state.lock() {
            state.update_status = UpdateStatus::Downloading;
            state.add_log("Update download started");
        }

        let config_to_save = self.effective_config();
        let config_path = self.config_path.clone();
        std::thread::spawn(move || {
            // Save config and update status — keep the lock scope minimal
            {
                let mut s = status.lock().unwrap();
                if let Err(e) = config_to_save.save(&config_path) {
                    logger::log_to_file(&format!("Failed to save config before update: {}", e));
                }
                logger::log_to_file(&format!(
                    "Starting update download: {} -> {}",
                    download_url, latest_version
                ));
                *s = UpdateStatus::PreparingUpdate;
            } // Lock released — download must NOT hold the Mutex

            match update::perform_update(&download_url, &latest_version) {
                Ok(()) => {
                    // process::exit called inside perform_update;
                    // if we ever reach here, update status briefly
                    if let Ok(mut s) = status.lock() {
                        *s = UpdateStatus::Restarting;
                    }
                }
                Err(e) => {
                    logger::log_to_file(&format!("Update failed: {}", e));
                    if let Ok(mut s) = status.lock() {
                        *s = UpdateStatus::Failed(e);
                    }
                }
            }
        });
    }

    fn get_update_status(&self) -> UpdateStatus {
        self.update_status.lock().unwrap().clone()
    }
}

impl eframe::App for LanGatewayApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Check for background refresh completion
        self.try_apply_refresh();
        self.sync_mdns_state();
        self.maybe_refresh_for_mdns();

        // Always consume health check results (not just when on Rules tab)
        self.rules_panel.apply_health_results();
        let effective_config = self.effective_config();
        if let Ok(mut state) = self.state.lock() {
            state.config = effective_config;
            state.dashboard = self.dashboard_info.clone();
            state.proxy_entries = self.rules_panel.proxy_entries.clone();
            state.health_map = self.rules_panel.health_map.clone();
            state.orphan_health = self.rules_panel.orphan_health.clone();
            state.mdns_status = self.settings_panel.mdns_status.clone();
            state.update_status = self.get_update_status();
            if self.rules_panel.health_check_running {
                state.operation = OperationState::CheckingHealth;
            } else if !matches!(state.operation, OperationState::Refreshing) {
                state.operation = OperationState::Idle;
            }
        }

        // After initial refresh completes, auto-start health check once
        if self.initial_refresh_done
            && !self.initial_health_started
            && !self.rules_panel.health_check_running
        {
            self.initial_health_started = true;
            self.rules_panel.run_health_checks_background();
        }

        // After initial refresh completes, auto-check for updates once
        if self.initial_refresh_done && !self.initial_update_check_done {
            self.initial_update_check_done = true;
            self.start_update_check();
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
                let (op_label, op_busy, cfg_path) = self
                    .state
                    .lock()
                    .map(|s| {
                        (
                            format!("{:?}", s.operation),
                            s.operation.is_busy(),
                            s.config_path.display().to_string(),
                        )
                    })
                    .unwrap_or_else(|_| ("StateUnavailable".into(), false, String::new()));
                let admin_key = if self.dashboard_info.is_admin {
                    "status.admin_yes"
                } else {
                    "status.admin_no"
                };
                let gateway_display = if matches!(
                    self.dashboard_info.refresh_state,
                    RefreshState::Refreshing { .. }
                ) {
                    i.text("status.initializing")
                } else if self.dashboard_info.gateway_ip.is_empty() {
                    i.text("status.no_usable_ipv4")
                } else {
                    &self.dashboard_info.gateway_ip
                };
                ui.label(format!(
                    "{} | {}: {} | {}: {} | {}: {} | {}{}",
                    i.text(admin_key),
                    i.text("status.ip"),
                    gateway_display,
                    i.text("status.rules"),
                    self.dashboard_info.rule_count,
                    i.text("status.interface"),
                    self.dashboard_info.active_interface,
                    if op_busy { "*" } else { "" },
                    op_label,
                ))
                .on_hover_text(cfg_path);
            });
        });

        // CentralPanel fills remaining space after SidePanel and TopBottomPanel
        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Dashboard => {
                let update_status = self.get_update_status();
                let mut check_update = false;
                let mut download_update = false;
                if self.dashboard.show(
                    ui,
                    &self.dashboard_info,
                    &self.i18n,
                    &update_status,
                    &mut check_update,
                    &mut download_update,
                ) {
                    self.start_background_refresh();
                }
                if check_update {
                    self.start_update_check();
                }
                if download_update {
                    self.start_update_download();
                }
            }
            Tab::Rules => {
                self.rules_panel.show(ui, &self.i18n);
            }
            Tab::Network => {
                let effective_config = self.effective_config();
                self.network_panel.show(
                    ui,
                    &self.dashboard_info,
                    &effective_config,
                    &self.config_path,
                    &self.rules_panel.proxy_entries,
                    self.rules_panel.last_preflight.clone(),
                    &self.settings_panel.mdns_status,
                    &self.i18n,
                );
            }
            Tab::Settings => {
                let prev_lang = self.i18n.language();
                let prev_ip = self.settings_panel.preferred_gateway_ip.clone();
                let prev_mdns_enabled = self.settings_panel.mdns_enabled;
                let prev_mdns_hostname = self.settings_panel.mdns_hostname.clone();
                self.settings_panel
                    .show(ui, &self.dashboard_info, &mut self.i18n);
                if self.i18n.language() != prev_lang {
                    self.on_language_changed(self.i18n.language());
                }
                let settings_changed = self.settings_panel.preferred_gateway_ip != prev_ip
                    || self.settings_panel.mdns_enabled != prev_mdns_enabled
                    || self.settings_panel.mdns_hostname != prev_mdns_hostname;
                if settings_changed {
                    self.save_config_deferred();
                    if self.settings_panel.preferred_gateway_ip != prev_ip {
                        self.recompute_gateway_ip_from_ui();
                    }
                    self.sync_mdns_state();
                }
                // Handle Retry mDNS button — force restart regardless of snapshot
                if self.settings_panel.mdns_retry_requested {
                    self.settings_panel.mdns_retry_requested = false;
                    self.last_mdns_failure = None;
                    self.sync_mdns_state_impl(true);
                }
            }
        });

        // Request repaint while background refresh, health check, or update is running
        let needs_repaint = matches!(
            self.dashboard_info.refresh_state,
            RefreshState::Refreshing { .. }
        ) || self.rules_panel.health_check_running
            || self.get_update_status().is_busy();
        if needs_repaint {
            ctx.request_repaint_after(std::time::Duration::from_millis(150));
        }
    }
}
