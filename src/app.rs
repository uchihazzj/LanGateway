use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::core::model::{DashboardInfo, Language, PortproxyEntry, RefreshState};
use crate::i18n::I18n;
use crate::service::mdns::{self, MdnsConfigSnapshot, MdnsController};
use crate::service::state::{AppState, OperationState, SharedState};
use crate::service::update::{self, UpdateStatus};
use crate::storage::config::Config;
use crate::system::{logger, network, portproxy, privilege};
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
    generation: u64,
    rules_generation: u64,
    info: DashboardInfo,
    proxy_entries: Option<Vec<PortproxyEntry>>,
    complete: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum RefreshKind {
    Startup,
    Manual,
    Network,
}

fn should_apply_refresh(generation: u64, state: &RefreshState, result: &RefreshResult) -> bool {
    result.generation == generation
        && (result.complete || matches!(state, RefreshState::Refreshing { .. }))
}

fn merge_quick_entries(
    mut quick: Vec<PortproxyEntry>,
    previous: &[PortproxyEntry],
) -> Vec<PortproxyEntry> {
    quick.extend(
        previous
            .iter()
            .filter(|entry| entry.proxy_mode != crate::core::model::ProxyMode::V4ToV4)
            .cloned(),
    );
    quick
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
    update_result: Option<std::sync::mpsc::Receiver<Result<update::PreparedUpdate, String>>>,
    startup_ready: Option<update::StartupReady>,
    mdns_controller: MdnsController,
    last_mdns_snapshot: MdnsConfigSnapshot,
    refresh_generation: u64,
    config_load_error: Option<String>,
    close_after_operation: bool,
    initial_refresh_done: bool,
    initial_health_started: bool,
    initial_update_check_done: bool,
    last_mdns_auto_refresh: Instant,
}

impl LanGatewayApp {
    /// Two-phase init: fast setup first, then background thread for heavy lifting.
    /// This ensures the first frame renders quickly with a "refreshing" placeholder.
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        startup_ready: Option<update::StartupReady>,
    ) -> Self {
        logger::log_to_file("=== LanGateway started ===");

        // Load config from C:\ProgramData\LanGateway\config.toml
        // Auto-migrates from exe-adjacent config.toml if present
        let (config, config_path, config_load_error) = match Config::load_or_migrate() {
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
                (cfg, path, None)
            }
            Err(e) => {
                logger::log_to_file(&format!("Config load failed: {}, using defaults", e));
                let path = Config::config_path().unwrap_or_else(|_| {
                    std::path::PathBuf::from("C:\\ProgramData\\LanGateway\\config.toml")
                });
                (Config::default(), path, Some(e))
            }
        };
        let language = config.language;
        crate::ui::theme::apply(&cc.egui_ctx);

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

        Self::spawn_refresh_workers(
            config.clone(),
            refresh_pending.clone(),
            0,
            rules_panel.snapshot_generation(),
            RefreshKind::Startup,
            cc.egui_ctx.clone(),
        );

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
            update_result: None,
            startup_ready,
            mdns_controller: MdnsController::new(),
            last_mdns_snapshot: MdnsConfigSnapshot {
                enabled: false,
                hostname: String::new(),
                gateway_ip: String::new(),
            },
            refresh_generation: 0,
            config_load_error,
            close_after_operation: false,
            initial_refresh_done: false,
            initial_health_started: false,
            initial_update_check_done: false,
            last_mdns_auto_refresh: Instant::now(),
        }
    }

    fn spawn_refresh_workers(
        config: Config,
        pending: Arc<Mutex<VecDeque<RefreshResult>>>,
        generation: u64,
        rules_generation: u64,
        kind: RefreshKind,
        ctx: egui::Context,
    ) {
        if kind == RefreshKind::Startup {
            let quick_cfg = config.clone();
            let quick_pending = pending.clone();
            let quick_ctx = ctx.clone();
            std::thread::spawn(move || {
                let mut result = Self::build_quick_dashboard_info(&quick_cfg);
                result.generation = generation;
                result.rules_generation = rules_generation;
                Self::push_refresh_result(&quick_pending, result);
                quick_ctx.request_repaint();
            });
        }

        std::thread::spawn(move || {
            let mut result = Self::build_full_dashboard_info(&config, kind != RefreshKind::Network);
            result.generation = generation;
            result.rules_generation = rules_generation;
            Self::push_refresh_result(&pending, result);
            ctx.request_repaint();
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
        let proxy_entries = portproxy::show_v4tov4()
            .map_err(|e| {
                logger::log_to_file(&format!("Quick refresh: netsh v4tov4 failed: {}", e));
            })
            .ok();
        let gateway_ip =
            network::select_preferred_ip(&ipv4s, &config.preferred_gateway_ip, &interfaces);
        let active_interface = network::get_interface_for_ip(&gateway_ip, &interfaces).to_string();

        RefreshResult {
            generation: 0,
            rules_generation: 0,
            info: DashboardInfo {
                hostname,
                local_ipv4: usable_ipv4s,
                local_ipv6: Vec::new(),
                active_interface,
                is_admin,
                rule_count: proxy_entries.as_ref().map_or(0, Vec::len),
                gateway_ip,
                interfaces,
                refresh_state: RefreshState::Refreshing { stage: "details" },
            },
            proxy_entries,
            complete: false,
        }
    }

    /// Heavy stage: PowerShell network details and all PortProxy modes.
    fn build_full_dashboard_info(config: &Config, refresh_rules: bool) -> RefreshResult {
        let is_admin = privilege::is_admin();
        let hostname = network::get_hostname().unwrap_or_else(|| "unknown".into());
        let interfaces = network::get_active_interfaces();
        let ipv4s = network::ipv4_addresses_from(&interfaces);
        let ipv6s = network::ipv6_addresses_from(&interfaces);
        let usable_ipv4s = network::usable_gateway_ipv4_addresses(&interfaces);
        let (proxy_entries, proxy_error) = if !refresh_rules {
            (None, None)
        } else {
            match portproxy::show_all() {
                Ok(entries) => (Some(entries), None),
                Err(e) => {
                    logger::log_to_file(&format!(
                        "Background refresh: netsh show all failed: {}",
                        e
                    ));
                    (None, Some(e))
                }
            }
        };

        let gateway_ip =
            network::select_preferred_ip(&ipv4s, &config.preferred_gateway_ip, &interfaces);
        let active_interface = network::get_interface_for_ip(&gateway_ip, &interfaces).to_string();

        logger::log_to_file(&format!(
            "Hostname: {}, Gateway IP: {}, IPs: {:?}, Admin: {}, Rules: {}",
            hostname,
            gateway_ip,
            ipv4s,
            is_admin,
            proxy_entries.as_ref().map_or(0, Vec::len)
        ));

        RefreshResult {
            generation: 0,
            rules_generation: 0,
            info: DashboardInfo {
                hostname,
                local_ipv4: usable_ipv4s,
                local_ipv6: ipv6s,
                active_interface,
                is_admin,
                rule_count: proxy_entries.as_ref().map_or(0, Vec::len),
                gateway_ip,
                interfaces,
                refresh_state: RefreshState::Done { error: proxy_error },
            },
            proxy_entries,
            complete: true,
        }
    }

    fn start_background_refresh(&mut self, ctx: &egui::Context, kind: RefreshKind) {
        if self.rules_panel.is_busy() {
            return;
        }
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

        self.refresh_generation += 1;
        Self::spawn_refresh_workers(
            self.effective_config(),
            self.refresh_pending.clone(),
            self.refresh_generation,
            self.rules_panel.snapshot_generation(),
            kind,
            ctx.clone(),
        );
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
            if !should_apply_refresh(
                self.refresh_generation,
                &self.dashboard_info.refresh_state,
                &result,
            ) {
                continue;
            }
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
                    if let RefreshState::Done { error } = &mut info.refresh_state {
                        let cached = "Network detection failed, showing cached data";
                        *error =
                            Some(error.as_ref().map_or_else(
                                || cached.to_string(),
                                |e| format!("{}; {}", e, cached),
                            ));
                    }
                }
            }
            self.dashboard_info = info;
            self.recompute_gateway_ip_from_ui();
            // A rule edit can finish while this read-only query is in flight.
            // Its newer Windows snapshot must not be replaced by the older read.
            if let Some(proxy_entries) = result
                .proxy_entries
                .filter(|_| self.rules_panel.can_apply_snapshot(result.rules_generation))
            {
                let proxy_entries = if result.complete {
                    proxy_entries
                } else {
                    merge_quick_entries(proxy_entries, &self.rules_panel.proxy_entries)
                };
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

    fn maybe_refresh_for_mdns(&mut self, ctx: &egui::Context) {
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
        self.start_background_refresh(ctx, RefreshKind::Network);
    }

    fn sync_mdns_state_impl(&mut self, force: bool) {
        while let Some((snapshot, status)) = self.mdns_controller.try_result() {
            if snapshot == self.last_mdns_snapshot {
                self.settings_panel.mdns_status = status;
            }
        }
        let raw = self.settings_panel.mdns_hostname.trim();
        let snapshot = MdnsConfigSnapshot {
            enabled: self.settings_panel.mdns_enabled,
            hostname: if raw.is_empty() {
                "gateway".into()
            } else {
                raw.into()
            },
            gateway_ip: self.dashboard_info.gateway_ip.clone(),
        };
        if !force && !self.last_mdns_snapshot.needs_restart(&snapshot) {
            return;
        }
        self.last_mdns_snapshot = snapshot.clone();
        self.settings_panel.mdns_status = match self.mdns_controller.configure(snapshot) {
            Ok(()) => mdns::MdnsStatus::Starting,
            Err(e) => mdns::MdnsStatus::Failed(e),
        };
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        ui.visuals_mut().override_text_color = Some(egui::Color32::from_rgb(229, 236, 246));
        ui.visuals_mut().selection.bg_fill = crate::ui::theme::ACCENT;
        ui.visuals_mut().selection.stroke = egui::Stroke::new(1.0, egui::Color32::WHITE);
        ui.vertical(|ui| {
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new(self.i18n.text("app.title"))
                    .size(22.0)
                    .strong()
                    .color(egui::Color32::WHITE),
            );
            ui.label(
                egui::RichText::new(self.i18n.text("app.subtitle"))
                    .size(13.0)
                    .color(egui::Color32::from_rgb(193, 207, 226)),
            );
            ui.add_space(24.0);
            for (tab, key) in [
                (Tab::Dashboard, "tab.dashboard"),
                (Tab::Rules, "tab.forward_rules"),
                (Tab::Network, "tab.network"),
                (Tab::Settings, "tab.settings"),
            ] {
                let button = egui::Button::new(
                    egui::RichText::new(self.i18n.text(key)).color(egui::Color32::WHITE),
                )
                .selected(self.tab == tab)
                .corner_radius(6)
                .stroke(egui::Stroke::NONE)
                .fill(if self.tab == tab {
                    crate::ui::theme::ACCENT
                } else {
                    crate::ui::theme::SIDEBAR
                });
                if ui.add_sized([ui.available_width(), 42.0], button).clicked() {
                    self.tab = tab;
                }
            }
            ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                ui.small(format!("v{}", env!("CARGO_PKG_VERSION")));
            });
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

    fn start_update_download(&mut self, ctx: &egui::Context) {
        if let Some(error) = &self.config_load_error {
            *self.update_status.lock().unwrap() =
                UpdateStatus::Failed(format!("Config could not be loaded: {}", error));
            return;
        }
        if self.rules_panel.is_busy() || self.update_result.is_some() {
            return;
        }
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
        let (sender, receiver) = std::sync::mpsc::channel();
        self.update_result = Some(receiver);
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            if let Err(e) = config_to_save.save(&config_path) {
                logger::log_to_file(&format!("Failed to save config before update: {}", e));
                let _ = sender.send(Err(e));
                ctx.request_repaint();
                return;
            }
            logger::log_to_file(&format!(
                "Starting update download: {} -> {}",
                download_url, latest_version
            ));

            let status_for_update = status.clone();
            let set_status = move |next_status| {
                if let Ok(mut s) = status_for_update.lock() {
                    *s = next_status;
                }
            };

            // A dropped receiver cancels an initialized helper through RAII.
            let _ = sender.send(update::perform_update(
                &download_url,
                &latest_version,
                set_status,
            ));
            ctx.request_repaint();
        });
    }

    fn apply_update_result(&mut self, ctx: &egui::Context) {
        let result = match self
            .update_result
            .as_ref()
            .map(|receiver| receiver.try_recv())
        {
            Some(Ok(result)) => result,
            Some(Err(std::sync::mpsc::TryRecvError::Empty)) | None => return,
            Some(Err(std::sync::mpsc::TryRecvError::Disconnected)) => {
                Err("Update worker disconnected before handoff".into())
            }
        };
        self.update_result = None;
        match result {
            Ok(prepared) => {
                prepared.commit();
                self.close_after_operation = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            Err(error) => {
                logger::log_to_file(&format!("Update failed: {error}"));
                *self.update_status.lock().unwrap() = UpdateStatus::Failed(error);
            }
        }
    }

    fn get_update_status(&self) -> UpdateStatus {
        self.update_status.lock().unwrap().clone()
    }
}

impl eframe::App for LanGatewayApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if ctx.input(|input| input.viewport().close_requested())
            && (self.rules_panel.is_busy() || self.update_result.is_some())
        {
            self.close_after_operation = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        }
        // Check for background refresh completion
        self.try_apply_refresh();
        self.rules_panel.apply_operation_results(&self.i18n);
        self.apply_update_result(ctx);
        self.dashboard_info.rule_count = self.rules_panel.proxy_entries.len();
        self.sync_mdns_state();
        self.maybe_refresh_for_mdns(ctx);

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
            state.operation = if self.rules_panel.is_busy() {
                OperationState::ApplyingRules
            } else if self.rules_panel.is_refreshing()
                || matches!(
                    self.dashboard_info.refresh_state,
                    RefreshState::Refreshing { .. }
                )
            {
                OperationState::Refreshing
            } else if self.rules_panel.health_check_running {
                OperationState::CheckingHealth
            } else {
                OperationState::Idle
            };
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
        let updating = matches!(
            self.get_update_status(),
            UpdateStatus::Downloading | UpdateStatus::PreparingUpdate | UpdateStatus::Restarting
        );
        self.rules_panel.operations_blocked = self.config_load_error.is_some() || updating;

        egui::SidePanel::left("sidebar")
            .exact_width(184.0)
            .resizable(false)
            .frame(
                egui::Frame::NONE
                    .fill(crate::ui::theme::SIDEBAR)
                    .inner_margin(16),
            )
            .show(ctx, |ui| {
                self.sidebar(ui);
            });

        // TopBottomPanel must render before CentralPanel so it reserves space first
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.style_mut()
                .text_styles
                .insert(egui::TextStyle::Body, egui::FontId::proportional(13.0));
            ui.horizontal_wrapped(|ui| {
                if let Some(error) = &self.config_load_error {
                    ui.colored_label(
                        crate::ui::theme::ERROR,
                        format!(
                            "{}: {}",
                            self.i18n.text("settings.config_load_failed"),
                            error
                        ),
                    );
                }
                let i = &self.i18n;
                let (op_label, op_busy, cfg_path) = self
                    .state
                    .lock()
                    .map(|s| {
                        (
                            i.text(match s.operation {
                                OperationState::Idle => "status.idle",
                                OperationState::Refreshing => "status.refreshing",
                                OperationState::CheckingHealth => "status.checking_health",
                                OperationState::ApplyingRules => "status.applying_rules",
                                OperationState::Failed(_) => "rules.operation_failed",
                            })
                            .to_string(),
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
                let gateway_display = if !self.dashboard_info.gateway_ip.is_empty() {
                    &self.dashboard_info.gateway_ip
                } else if matches!(
                    self.dashboard_info.refresh_state,
                    RefreshState::Refreshing { .. }
                ) {
                    i.text("status.initializing")
                } else {
                    i.text("status.no_usable_ipv4")
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
        let central_panel = egui::CentralPanel::default()
            .frame(egui::Frame::central_panel(&ctx.style()).inner_margin(18));
        central_panel.show(ctx, |ui| match self.tab {
            Tab::Dashboard => {
                let update_status = self.get_update_status();
                let mut check_update = false;
                let mut download_update = false;
                let refresh = egui::ScrollArea::vertical()
                    .id_salt("dashboard_page")
                    .show(ui, |ui| {
                        ui.add_enabled_ui(!self.rules_panel.is_busy(), |ui| {
                            self.dashboard.show(
                                ui,
                                &self.dashboard_info,
                                &self.i18n,
                                &update_status,
                                &mut check_update,
                                &mut download_update,
                            )
                        })
                        .inner
                    })
                    .inner;
                if refresh {
                    self.start_background_refresh(ctx, RefreshKind::Manual);
                }
                if check_update {
                    self.start_update_check();
                }
                if download_update {
                    self.start_update_download(ctx);
                }
            }
            Tab::Rules => {
                egui::ScrollArea::vertical()
                    .id_salt("rules_page")
                    .show(ui, |ui| {
                        self.rules_panel.show(ui, &self.i18n);
                    });
            }
            Tab::Network => {
                let effective_config = self.effective_config();
                self.network_panel.show(
                    ui,
                    &self.dashboard_info,
                    &effective_config,
                    &self.config_path,
                    &self.rules_panel.proxy_entries,
                    &self.rules_panel.last_preflight,
                    &self.settings_panel.mdns_status,
                    &self.i18n,
                );
            }
            Tab::Settings => {
                let prev_lang = self.i18n.language();
                let prev_ip = self.settings_panel.preferred_gateway_ip.clone();
                let prev_mdns_enabled = self.settings_panel.mdns_enabled;
                let prev_mdns_hostname = self.settings_panel.mdns_hostname.clone();
                ui.add_enabled_ui(
                    self.config_load_error.is_none() && !self.rules_panel.is_busy() && !updating,
                    |ui| {
                        self.settings_panel
                            .show(ui, &self.dashboard_info, &mut self.i18n);
                    },
                );
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
                    self.sync_mdns_state_impl(true);
                }
            }
        });

        // Request repaint while background refresh, health check, or update is running
        let needs_repaint = matches!(
            self.dashboard_info.refresh_state,
            RefreshState::Refreshing { .. }
        ) || self.rules_panel.health_check_running
            || self.rules_panel.is_refreshing()
            || self.rules_panel.is_busy()
            || matches!(self.settings_panel.mdns_status, mdns::MdnsStatus::Starting)
            || self.get_update_status().is_busy();
        if needs_repaint {
            ctx.request_repaint_after(std::time::Duration::from_millis(150));
        }
        if self.settings_panel.mdns_enabled {
            ctx.request_repaint_after(Duration::from_secs(1));
        }
        if self.close_after_operation && !self.rules_panel.is_busy() && self.update_result.is_none()
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        if self.config_load_error.is_none() {
            if let Some(ticket) = self.startup_ready.take() {
                if let Err(error) = ticket.acknowledge() {
                    logger::log_to_file(&format!(
                        "Cannot acknowledge updated application startup: {error}"
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refresh(generation: u64, complete: bool) -> RefreshResult {
        RefreshResult {
            generation,
            rules_generation: 0,
            complete,
            proxy_entries: None,
            info: DashboardInfo {
                hostname: "test-host".into(),
                local_ipv4: vec![],
                local_ipv6: vec![],
                active_interface: String::new(),
                is_admin: false,
                rule_count: 0,
                gateway_ip: String::new(),
                interfaces: vec![],
                refresh_state: if complete {
                    RefreshState::Done { error: None }
                } else {
                    RefreshState::Refreshing { stage: "details" }
                },
            },
        }
    }

    #[test]
    fn late_quick_results_cannot_overwrite_a_completed_full_refresh() {
        assert!(!should_apply_refresh(
            1,
            &RefreshState::Done { error: None },
            &refresh(1, false)
        ));
        assert!(should_apply_refresh(
            1,
            &RefreshState::Refreshing { stage: "startup" },
            &refresh(1, true)
        ));
    }

    #[test]
    fn results_from_a_previous_refresh_cannot_overwrite_a_newer_refresh() {
        let state = RefreshState::Refreshing { stage: "refresh" };
        assert!(!should_apply_refresh(2, &state, &refresh(1, true)));
        assert!(!should_apply_refresh(2, &state, &refresh(1, false)));
        assert!(should_apply_refresh(2, &state, &refresh(2, false)));
    }

    #[test]
    fn quick_refresh_keeps_other_proxy_modes_from_the_last_snapshot() {
        let ipv4 = PortproxyEntry {
            proxy_mode: crate::core::model::ProxyMode::V4ToV4,
            listen_address: "0.0.0.0".into(),
            listen_port: 8080,
            connect_address: "127.0.0.1".into(),
            connect_port: 80,
        };
        let mut ipv6 = ipv4.clone();
        ipv6.proxy_mode = crate::core::model::ProxyMode::V6ToV4;
        ipv6.listen_address = "::".into();
        assert_eq!(
            merge_quick_entries(vec![], &[ipv4, ipv6.clone()]),
            vec![ipv6]
        );
    }
}
