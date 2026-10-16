use crate::core::model::{
    ForwardRule, HealthStatus, OrphanKey, PortproxyEntry, ProxyMode, ProxyProtocol,
};
use crate::i18n::I18n;
use crate::service::rules::{self, RuleForm, RuleService};
use crate::storage::config::Config;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::Receiver;

pub struct HealthCheckResult {
    pub health_map: HashMap<usize, HealthStatus>,
    pub orphan_health: HashMap<OrphanKey, HealthStatus>,
    rules: Vec<ForwardRule>,
    proxy_entries: Vec<PortproxyEntry>,
}

enum RuleCompletion {
    Save(&'static str),
    Toggle(usize, bool),
    Delete(usize),
    Refresh,
    DeleteOrphan,
}

struct RuleOperationResult {
    config: Config,
    result: Result<Vec<PortproxyEntry>, String>,
    recovered_entries: Option<Vec<PortproxyEntry>>,
    completion: RuleCompletion,
}

pub struct RulesPanel {
    pub config: Config,
    pub service: RuleService,
    pub proxy_entries: Vec<PortproxyEntry>,
    pub health_map: HashMap<usize, HealthStatus>,
    pub orphan_health: HashMap<OrphanKey, HealthStatus>,
    pub status_message: String,
    pub last_preflight: Vec<String>,
    pub is_admin: bool,
    pub health_check_running: bool,
    pub health_result_rx: Option<Receiver<HealthCheckResult>>,
    operation_rx: Option<Receiver<RuleOperationResult>>,
    pub operations_blocked: bool,
    pub editing_rule_index: Option<usize>,
    pub add_listen_address: String,
    pub add_listen_port: String,
    pub add_connect_address: String,
    pub add_connect_port: String,
    pub add_name: String,
    pub add_notes: String,
    pub add_protocol: ProxyProtocol,
    pub add_proxy_mode: ProxyMode,
    pub add_enabled: bool,
    pub add_firewall_managed: bool,
    pub add_mdns_publish: bool,
    pub add_tags: String,
}

impl RulesPanel {
    pub fn new(mut config: Config, config_path: PathBuf, is_admin: bool) -> Self {
        config.normalize();
        Self {
            config,
            service: RuleService::new(config_path.clone()),
            proxy_entries: Vec::new(),
            health_map: HashMap::new(),
            orphan_health: HashMap::new(),
            status_message: String::new(),
            last_preflight: Vec::new(),
            is_admin,
            health_check_running: false,
            health_result_rx: None,
            operation_rx: None,
            operations_blocked: false,
            editing_rule_index: None,
            add_listen_address: "0.0.0.0".into(),
            add_listen_port: String::new(),
            add_connect_address: String::new(),
            add_connect_port: String::new(),
            add_name: String::new(),
            add_notes: String::new(),
            add_protocol: ProxyProtocol::Tcp,
            add_proxy_mode: ProxyMode::V4ToV4,
            add_enabled: true,
            add_firewall_managed: false,
            add_mdns_publish: false,
            add_tags: String::new(),
        }
    }

    pub fn apply_proxy_entries(&mut self, entries: Vec<PortproxyEntry>) {
        if self.proxy_entries == entries {
            self.update_preflight_notes();
            return;
        }
        self.proxy_entries = entries;
        self.health_map.clear();
        for i in 0..self.config.rules.len() {
            self.health_map.insert(i, HealthStatus::NotChecked);
        }
        self.orphan_health.clear();
        self.update_preflight_notes();
    }

    pub fn refresh_proxy(&mut self) {
        if let Err(e) = self.start_operation(
            |_, _| crate::system::portproxy::show_all(),
            RuleCompletion::Refresh,
        ) {
            self.status_message = e;
        }
    }

    pub fn is_busy(&self) -> bool {
        self.operation_rx.is_some()
    }

    fn start_operation(
        &mut self,
        task: impl FnOnce(&RuleService, &mut Config) -> Result<Vec<PortproxyEntry>, String>
            + Send
            + 'static,
        completion: RuleCompletion,
    ) -> Result<(), String> {
        if self.is_busy() || self.operations_blocked {
            return Err("Another operation is in progress; please wait".into());
        }
        let service = self.service.clone();
        let mut config = self.config.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        self.operation_rx = Some(rx);
        std::thread::spawn(move || {
            let result = task(&service, &mut config);
            let recovered_entries = if result.is_err() {
                crate::system::portproxy::show_all().ok()
            } else {
                None
            };
            let _ = tx.send(RuleOperationResult {
                config,
                result,
                recovered_entries,
                completion,
            });
        });
        Ok(())
    }

    pub fn apply_operation_results(&mut self, i18n: &I18n) {
        let Some(rx) = &self.operation_rx else { return };
        let result = match rx.try_recv() {
            Ok(result) => result,
            Err(std::sync::mpsc::TryRecvError::Empty) => return,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                self.operation_rx = None;
                self.status_message = i18n.text("rules.operation_failed").into();
                return;
            }
        };
        self.operation_rx = None;
        match result.result {
            Ok(entries) => {
                // Settings can be changed on another page; only the worker's
                // rules belong to this operation.
                let rules_changed = self.config.rules != result.config.rules;
                self.config.rules = result.config.rules;
                self.apply_proxy_entries(entries);
                if rules_changed {
                    self.health_map.clear();
                    self.orphan_health.clear();
                }
                self.status_message = match result.completion {
                    RuleCompletion::Save(key) => {
                        self.clear_form();
                        self.editing_rule_index = None;
                        i18n.text(key).into()
                    }
                    RuleCompletion::Toggle(index, enabled) => {
                        if self.editing_rule_index == Some(index) {
                            self.add_enabled = enabled;
                        }
                        i18n.text(if enabled {
                            "msg.rule_enabled"
                        } else {
                            "msg.rule_disabled"
                        })
                        .into()
                    }
                    RuleCompletion::Delete(index) => {
                        self.adjust_editing_after_delete(index);
                        String::new()
                    }
                    RuleCompletion::Refresh | RuleCompletion::DeleteOrphan => String::new(),
                };
            }
            Err(e) => {
                if let Some(entries) = result.recovered_entries {
                    self.apply_proxy_entries(entries);
                }
                self.status_message = format!("{}: {}", i18n.text("rules.operation_failed"), e);
            }
        }
    }

    fn adjust_editing_after_delete(&mut self, deleted: usize) {
        match self.editing_rule_index {
            Some(index) if index == deleted => {
                self.clear_form();
                self.editing_rule_index = None;
            }
            Some(index) if index > deleted => self.editing_rule_index = Some(index - 1),
            _ => {}
        }
    }

    pub fn run_health_checks_background(&mut self) {
        if self.health_check_running {
            return;
        }
        self.health_check_running = true;

        let rules = self.config.rules.clone();
        let proxy_entries = self.proxy_entries.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        self.health_result_rx = Some(rx);

        std::thread::spawn(move || {
            let (health_map, orphan_health) = rules::run_health_checks(&rules, &proxy_entries);
            let _ = tx.send(HealthCheckResult {
                health_map,
                orphan_health,
                rules,
                proxy_entries,
            });
        });
    }

    pub fn apply_health_results(&mut self) {
        if let Some(rx) = &self.health_result_rx {
            match rx.try_recv() {
                Ok(result) => {
                    if result.rules == self.config.rules
                        && result.proxy_entries == self.proxy_entries
                    {
                        self.health_map = result.health_map;
                        self.orphan_health = result.orphan_health;
                    }
                    self.health_check_running = false;
                    self.health_result_rx = None;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.health_check_running = false;
                    self.health_result_rx = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
    }

    pub fn orphan_entries(&self) -> Vec<&PortproxyEntry> {
        self.proxy_entries
            .iter()
            .filter(|e| {
                !self.config.rules.iter().any(|r| {
                    r.protocol == ProxyProtocol::Tcp
                        && r.proxy_mode == e.proxy_mode
                        && r.listen_address == e.listen_address
                        && r.listen_port == e.listen_port
                        && r.connect_address == e.connect_address
                        && r.connect_port == e.connect_port
                })
            })
            .collect()
    }

    pub fn add_rule(&mut self, i18n: &I18n) -> Result<(), String> {
        let form = self.parse_form(i18n)?;
        let admin = self.is_admin;
        self.start_operation(
            move |service, config| service.add_rule(config, form, admin),
            RuleCompletion::Save("msg.rule_added"),
        )
    }

    pub fn update_rule(&mut self, i18n: &I18n) -> Result<(), String> {
        let idx = self
            .editing_rule_index
            .ok_or_else(|| i18n.text("err.invalid_rule_index").to_string())?;
        let form = self.parse_form(i18n)?;
        let admin = self.is_admin;
        self.start_operation(
            move |service, config| service.update_rule(config, idx, form, admin),
            RuleCompletion::Save("msg.rule_updated"),
        )
    }

    pub fn toggle_rule_enabled(
        &mut self,
        index: usize,
        enabled: bool,
        i18n: &I18n,
    ) -> Result<(), String> {
        if index >= self.config.rules.len() {
            return Err(i18n.text("err.invalid_rule_index").to_string());
        }
        let admin = self.is_admin;
        self.start_operation(
            move |service, config| service.set_rule_enabled(config, index, enabled, admin),
            RuleCompletion::Toggle(index, enabled),
        )
    }

    pub fn adopt_orphan(&mut self, orphan_index: usize, i18n: &I18n) -> Result<(), String> {
        let orphans: Vec<PortproxyEntry> = self.orphan_entries().into_iter().cloned().collect();
        let entry = orphans
            .get(orphan_index)
            .ok_or_else(|| i18n.text("err.invalid_orphan_index").to_string())?;
        let key = OrphanKey::from_entry(entry);
        self.service.adopt_orphan(&mut self.config, entry)?;
        self.health_map
            .insert(self.config.rules.len() - 1, HealthStatus::NotChecked);
        self.orphan_health.remove(&key);
        self.update_preflight_notes();
        Ok(())
    }

    pub fn adopt_all_orphans(&mut self, _i18n: &I18n) -> Result<usize, String> {
        let count = self
            .service
            .adopt_all_orphans(&mut self.config, &self.proxy_entries)?;
        self.health_map.clear();
        for i in 0..self.config.rules.len() {
            self.health_map.insert(i, HealthStatus::NotChecked);
        }
        self.orphan_health.clear();
        self.update_preflight_notes();
        Ok(count)
    }

    pub fn delete_rule(&mut self, index: usize, i18n: &I18n) -> Result<(), String> {
        if index >= self.config.rules.len() {
            return Err(i18n.text("err.invalid_rule_index").to_string());
        }
        let admin = self.is_admin;
        self.start_operation(
            move |service, config| service.delete_rule(config, index, admin),
            RuleCompletion::Delete(index),
        )
    }

    pub fn delete_orphan(&mut self, orphan_index: usize, i18n: &I18n) -> Result<(), String> {
        let orphans: Vec<PortproxyEntry> = self.orphan_entries().into_iter().cloned().collect();
        let entry = orphans
            .get(orphan_index)
            .ok_or_else(|| i18n.text("err.invalid_orphan_index").to_string())?
            .clone();
        let admin = self.is_admin;
        self.start_operation(
            move |service, _| service.delete_orphan(&entry, admin),
            RuleCompletion::DeleteOrphan,
        )
    }

    pub fn show(&mut self, ui: &mut egui::Ui, i18n: &I18n) {
        self.apply_health_results();
        ui.heading(i18n.text("rules.title"));

        if !self.status_message.is_empty() {
            ui.horizontal_wrapped(|ui| {
                ui.label(&self.status_message);
                if ui.small_button("×").clicked() {
                    self.status_message.clear();
                }
            });
        }
        if self.is_busy() {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(i18n.text("rules.working"));
            });
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(100));
        }
        ui.add_enabled_ui(!self.is_busy() && !self.operations_blocked, |ui| {
            if !self.last_preflight.is_empty() {
                crate::ui::theme::card(ui).show(ui, |ui| {
                    ui.strong(i18n.text("rules.preflight"));
                    for item in &self.last_preflight {
                        ui.label(item);
                    }
                });
                ui.add_space(8.0);
            }

            ui.strong(i18n.text("rules.managed"));
            self.show_rules_table(ui, i18n);

            let orphans: Vec<PortproxyEntry> = self.orphan_entries().into_iter().cloned().collect();
            if !orphans.is_empty() {
                ui.add_space(12.0);
                ui.strong(i18n.text("rules.orphan"));
                self.show_orphan_table(ui, &orphans, i18n);
            }

            ui.add_space(12.0);
            ui.separator();
            ui.add_space(8.0);

            if self.editing_rule_index.is_some() {
                ui.heading(i18n.text("rules.edit_rule"));
            } else {
                ui.heading(i18n.text("rules.add_new"));
            }
            self.show_add_form(ui, i18n);

            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button(i18n.text("rules.refresh")).clicked() {
                    self.clear_form();
                    self.editing_rule_index = None;
                    self.refresh_proxy();
                }
                let label = if self.health_check_running {
                    "..."
                } else {
                    i18n.text("dashboard.run_health_check")
                };
                if ui
                    .add_enabled(!self.health_check_running, egui::Button::new(label))
                    .clicked()
                {
                    self.run_health_checks_background();
                }
            });
        });
    }

    fn show_rules_table(&mut self, ui: &mut egui::Ui, i18n: &I18n) {
        if self.config.rules.is_empty() {
            ui.label(i18n.text("rules.no_managed"));
            return;
        }

        let mut delete_idx = None;
        let mut edit_idx = None;
        let mut toggle_idx = None;

        egui::ScrollArea::horizontal()
            .id_salt("managed_rules_scroll")
            .show(ui, |ui| {
                crate::ui::theme::card(ui).show(ui, |ui| {
                    egui::Grid::new("rules_grid")
                        .num_columns(5)
                        .max_col_width(128.0)
                        .spacing([14.0, 10.0])
                        .min_row_height(44.0)
                        .striped(true)
                        .show(ui, |ui| {
                            for key in [
                                "col.name",
                                "col.listen_endpoint",
                                "col.target_endpoint",
                                "col.health",
                                "col.action",
                            ] {
                                ui.add(
                                    egui::Label::new(egui::RichText::new(i18n.text(key)).strong())
                                        .extend(),
                                );
                            }
                            ui.end_row();

                            for (i, rule) in self.config.rules.iter().enumerate() {
                                ui.vertical(|ui| {
                                    ui.set_width(120.0);
                                    let details = format!(
                                        "{}: {}\n{}: {}\n{}",
                                        i18n.text("col.flags"),
                                        rule_flags(rule),
                                        i18n.text("col.notes"),
                                        rule.notes,
                                        rule.tags.join(", "),
                                    );
                                    ui.add(
                                        egui::Label::new(egui::RichText::new(&rule.name).strong())
                                            .truncate(),
                                    )
                                    .on_hover_text(&details);
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(format!(
                                                "{} / {} · {}",
                                                rule.protocol.label(),
                                                rule.proxy_mode.label(),
                                                rule_flags(rule),
                                            ))
                                            .small()
                                            .color(crate::ui::theme::MUTED),
                                        )
                                        .truncate(),
                                    )
                                    .on_hover_text(details);
                                    if !rule.notes.is_empty() {
                                        ui.add(
                                            egui::Label::new(
                                                egui::RichText::new(&rule.notes)
                                                    .small()
                                                    .color(crate::ui::theme::MUTED),
                                            )
                                            .truncate(),
                                        )
                                        .on_hover_text(&rule.notes);
                                    }
                                });
                                ui.monospace(endpoint(&rule.listen_address, rule.listen_port));
                                ui.monospace(endpoint(&rule.connect_address, rule.connect_port));

                                let health =
                                    self.health_map.get(&i).unwrap_or(&HealthStatus::NotChecked);
                                ui.colored_label(
                                    health.color(),
                                    health.label(self.config.language),
                                )
                                .on_hover_text(health.detail());

                                ui.vertical(|ui| {
                                    ui.set_width(132.0);
                                    ui.spacing_mut().item_spacing.x = 6.0;
                                    ui.spacing_mut().button_padding = egui::vec2(7.0, 5.0);
                                    ui.horizontal(|ui| {
                                        let toggle_label = if rule.enabled {
                                            i18n.text("btn.disable")
                                        } else {
                                            i18n.text("btn.enable")
                                        };
                                        if ui
                                            .add_enabled(
                                                self.is_admin,
                                                egui::Button::new(toggle_label),
                                            )
                                            .clicked()
                                        {
                                            toggle_idx = Some((i, !rule.enabled));
                                        }
                                        if ui
                                            .add_enabled(
                                                self.is_admin,
                                                egui::Button::new(i18n.text("btn.edit")),
                                            )
                                            .clicked()
                                        {
                                            edit_idx = Some(i);
                                        }
                                    });
                                    if ui
                                        .add_enabled(
                                            self.is_admin,
                                            egui::Button::new(i18n.text("btn.delete")),
                                        )
                                        .clicked()
                                    {
                                        delete_idx = Some(i);
                                    }
                                });
                                ui.end_row();
                            }
                        });
                });
            });

        if let Some((i, enabled)) = toggle_idx {
            match self.toggle_rule_enabled(i, enabled, i18n) {
                Ok(()) => self.status_message = i18n.text("rules.working").into(),
                Err(e) => {
                    self.status_message = format!("{}: {}", i18n.text("msg.rule_add_failed"), e);
                }
            }
        }

        if let Some(i) = delete_idx {
            if let Err(e) = self.delete_rule(i, i18n) {
                self.status_message = format!("{}: {}", i18n.text("msg.rule_delete_failed"), e);
            }
        }

        if let Some(i) = edit_idx {
            self.load_rule_into_form(i);
        }
    }

    fn show_orphan_table(&mut self, ui: &mut egui::Ui, orphans: &[PortproxyEntry], i18n: &I18n) {
        let mut delete_idx = None;
        let mut adopt_idx = None;
        let mut adopt_all = false;

        ui.horizontal(|ui| {
            if ui.button(i18n.text("btn.adopt_all")).clicked() {
                adopt_all = true;
            }
        });
        ui.add_space(4.0);

        egui::ScrollArea::horizontal()
            .id_salt("orphan_rules_scroll")
            .show(ui, |ui| {
                crate::ui::theme::card(ui).show(ui, |ui| {
                    egui::Grid::new("orphan_grid")
                        .num_columns(5)
                        .max_col_width(128.0)
                        .spacing([14.0, 10.0])
                        .min_row_height(40.0)
                        .striped(true)
                        .show(ui, |ui| {
                            for key in [
                                "col.mode",
                                "col.listen_endpoint",
                                "col.target_endpoint",
                                "col.health",
                                "col.action",
                            ] {
                                ui.add(
                                    egui::Label::new(egui::RichText::new(i18n.text(key)).strong())
                                        .extend(),
                                );
                            }
                            ui.end_row();

                            for (i, entry) in orphans.iter().enumerate() {
                                ui.label(entry.proxy_mode.label());
                                ui.monospace(endpoint(&entry.listen_address, entry.listen_port));
                                ui.monospace(endpoint(&entry.connect_address, entry.connect_port));

                                let key = OrphanKey::from_entry(entry);
                                let status = self
                                    .orphan_health
                                    .get(&key)
                                    .unwrap_or(&HealthStatus::NotChecked);
                                ui.colored_label(
                                    status.color(),
                                    status.label(self.config.language),
                                )
                                .on_hover_text(status.detail());

                                ui.horizontal(|ui| {
                                    ui.set_width(154.0);
                                    if ui
                                        .add_enabled(
                                            self.is_admin,
                                            egui::Button::new(i18n.text("btn.delete")),
                                        )
                                        .clicked()
                                    {
                                        delete_idx = Some(i);
                                    }
                                    if ui.button(i18n.text("btn.adopt")).clicked() {
                                        adopt_idx = Some(i);
                                    }
                                });
                                ui.end_row();
                            }
                        });
                });
            });

        if let Some(i) = delete_idx {
            if let Err(e) = self.delete_orphan(i, i18n) {
                self.status_message = format!("{}: {}", i18n.text("msg.rule_delete_failed"), e);
            }
        }
        if let Some(i) = adopt_idx {
            match self.adopt_orphan(i, i18n) {
                Ok(()) => self.status_message = i18n.text("msg.orphan_adopted").into(),
                Err(e) => self.status_message = format!("{}: {}", i18n.text("msg.adopt_failed"), e),
            }
        }
        if adopt_all {
            match self.adopt_all_orphans(i18n) {
                Ok(count) if count > 0 => {
                    self.status_message = i18n
                        .text("msg.orphans_adopted")
                        .replace("{count}", &count.to_string());
                }
                Ok(_) => {}
                Err(e) => self.status_message = format!("{}: {}", i18n.text("msg.adopt_failed"), e),
            }
        }
    }

    fn show_add_form(&mut self, ui: &mut egui::Ui, i18n: &I18n) {
        let is_editing = self.editing_rule_index.is_some();

        crate::ui::theme::card(ui).show(ui, |ui| {
            egui::Grid::new("add_form")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.label(format!("{}:", i18n.text("form.protocol")));
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut self.add_protocol, ProxyProtocol::Tcp, "TCP");
                        ui.add_enabled(
                            false,
                            egui::RadioButton::new(self.add_protocol == ProxyProtocol::Udp, "UDP"),
                        )
                        .on_hover_text(i18n.text("rules.udp_note"));
                    });
                    ui.end_row();

                    ui.label(format!("{}:", i18n.text("form.proxy_mode")));
                    let previous_mode = self.add_proxy_mode;
                    egui::ComboBox::from_id_salt("proxy_mode_combo")
                        .selected_text(self.add_proxy_mode.label())
                        .show_ui(ui, |ui| {
                            for mode in ProxyMode::variants() {
                                ui.selectable_value(&mut self.add_proxy_mode, *mode, mode.label());
                            }
                        });
                    if self.add_proxy_mode != previous_mode
                        && self.add_listen_address == previous_mode.listen_any_address()
                    {
                        self.add_listen_address = self.add_proxy_mode.listen_any_address().into();
                    }
                    ui.end_row();

                    ui.label(format!("{}:", i18n.text("form.listen_addr")));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.add_listen_address)
                            .desired_width(220.0),
                    );
                    ui.end_row();

                    ui.label(format!("{}:", i18n.text("form.listen_port")));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.add_listen_port).desired_width(120.0),
                    );
                    ui.end_row();

                    ui.label(format!("{}:", i18n.text("form.connect_addr")));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.add_connect_address)
                            .desired_width(220.0),
                    );
                    ui.end_row();

                    ui.label(format!("{}:", i18n.text("form.connect_port")));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.add_connect_port).desired_width(120.0),
                    );
                    ui.end_row();

                    ui.label(format!("{}:", i18n.text("form.name_opt")));
                    ui.add(egui::TextEdit::singleline(&mut self.add_name).desired_width(220.0));
                    ui.end_row();

                    ui.label(format!("{}:", i18n.text("form.notes_opt")));
                    ui.add(egui::TextEdit::singleline(&mut self.add_notes).desired_width(220.0));
                    ui.end_row();

                    ui.label(format!("{}:", i18n.text("form.tags_opt")));
                    ui.add(egui::TextEdit::singleline(&mut self.add_tags).desired_width(220.0));
                    ui.end_row();
                });

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.add_enabled, i18n.text("form.enabled"));
                ui.checkbox(
                    &mut self.add_firewall_managed,
                    i18n.text("form.firewall_managed"),
                );
                ui.add_enabled(
                    false,
                    egui::Checkbox::new(&mut self.add_mdns_publish, i18n.text("form.mdns_publish")),
                )
                .on_hover_text(i18n.text("form.mdns_publish_note"));
            });

            if self.add_protocol == ProxyProtocol::Udp {
                ui.colored_label(crate::ui::theme::WARNING, i18n.text("rules.udp_note"));
            }

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if is_editing {
                    if ui
                        .add_enabled(
                            self.is_admin && self.add_protocol == ProxyProtocol::Tcp,
                            egui::Button::new(i18n.text("btn.update_rule")),
                        )
                        .clicked()
                    {
                        match self.update_rule(i18n) {
                            Ok(()) => self.status_message = i18n.text("rules.working").into(),
                            Err(e) => {
                                self.status_message =
                                    format!("{}: {}", i18n.text("msg.rule_add_failed"), e);
                            }
                        }
                    }
                    if ui.button(i18n.text("btn.cancel_edit")).clicked() {
                        self.clear_form();
                        self.editing_rule_index = None;
                    }
                } else if ui
                    .add_enabled(
                        self.is_admin && self.add_protocol == ProxyProtocol::Tcp,
                        egui::Button::new(i18n.text("btn.add_rule")),
                    )
                    .clicked()
                {
                    match self.add_rule(i18n) {
                        Ok(()) => self.status_message = i18n.text("rules.working").into(),
                        Err(e) => {
                            self.status_message =
                                format!("{}: {}", i18n.text("msg.rule_add_failed"), e);
                        }
                    }
                }
            });
            if !self.is_admin {
                ui.label(i18n.text("msg.admin_required"));
            }
        });
    }

    fn parse_form(&self, i18n: &I18n) -> Result<RuleForm, String> {
        let listen_port: u16 = self
            .add_listen_port
            .trim()
            .parse()
            .map_err(|_| i18n.text("err.invalid_listen_port").to_string())?;
        let connect_port: u16 = self
            .add_connect_port
            .trim()
            .parse()
            .map_err(|_| i18n.text("err.invalid_connect_port").to_string())?;
        if self.add_connect_address.trim().is_empty() {
            return Err(i18n.text("err.connect_addr_required").to_string());
        }
        Ok(RuleForm {
            id: self
                .editing_rule_index
                .and_then(|idx| self.config.rules.get(idx).map(|r| r.id.clone()))
                .unwrap_or_default(),
            name: self.add_name.clone(),
            notes: self.add_notes.clone(),
            listen_address: self.add_listen_address.clone(),
            listen_port,
            connect_address: self.add_connect_address.clone(),
            connect_port,
            protocol: self.add_protocol,
            proxy_mode: self.add_proxy_mode,
            enabled: self.add_enabled,
            firewall_managed: self.add_firewall_managed,
            mdns_publish: self.add_mdns_publish,
            tags: self
                .add_tags
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
        })
    }

    fn load_rule_into_form(&mut self, index: usize) {
        if let Some(rule) = self.config.rules.get(index) {
            self.add_listen_address = rule.listen_address.clone();
            self.add_listen_port = rule.listen_port.to_string();
            self.add_connect_address = rule.connect_address.clone();
            self.add_connect_port = rule.connect_port.to_string();
            self.add_name = rule.name.clone();
            self.add_notes = rule.notes.clone();
            self.add_protocol = rule.protocol;
            self.add_proxy_mode = rule.proxy_mode;
            self.add_enabled = rule.enabled;
            self.add_firewall_managed = rule.firewall_managed;
            self.add_mdns_publish = rule.mdns_publish;
            self.add_tags = rule.tags.join(", ");
            self.editing_rule_index = Some(index);
        }
    }

    fn clear_form(&mut self) {
        self.add_listen_address = "0.0.0.0".into();
        self.add_listen_port.clear();
        self.add_connect_address.clear();
        self.add_connect_port.clear();
        self.add_name.clear();
        self.add_notes.clear();
        self.add_protocol = ProxyProtocol::Tcp;
        self.add_proxy_mode = ProxyMode::V4ToV4;
        self.add_enabled = true;
        self.add_firewall_managed = false;
        self.add_mdns_publish = false;
        self.add_tags.clear();
    }

    fn update_preflight_notes(&mut self) {
        let mut notes = Vec::new();
        let expected = crate::system::portproxy::expected_entries(&self.config.rules);
        let diff = crate::system::portproxy::diff_rules(&expected, &self.proxy_entries);
        if !diff.is_empty() {
            notes.push(format!(
                "PortProxy sync diff: {} pending action(s)",
                diff.len()
            ));
        }
        let orphan_count = self.orphan_entries().len();
        if orphan_count > 0 {
            notes.push(format!("{} orphan rule(s) found in Windows", orphan_count));
        }
        let udp_count = self
            .config
            .rules
            .iter()
            .filter(|r| r.protocol == ProxyProtocol::Udp)
            .count();
        if udp_count > 0 {
            notes.push(format!(
                "{} UDP rule(s) are metadata only; Windows portproxy supports TCP",
                udp_count
            ));
        }
        self.last_preflight = notes;
    }
}

fn endpoint(address: &str, port: u16) -> String {
    if address.contains(':') {
        format!("[{address}]:{port}")
    } else {
        format!("{address}:{port}")
    }
}

fn rule_flags(rule: &ForwardRule) -> String {
    let mut flags = Vec::new();
    if rule.enabled {
        flags.push("on");
    } else {
        flags.push("off");
    }
    if rule.firewall_managed {
        flags.push("fw");
    }
    if rule.mdns_publish {
        flags.push("mdns");
    }
    if !rule.tags.is_empty() {
        flags.push("tag");
    }
    flags.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::model::{Language, PortproxyEntry};

    #[test]
    fn editing_an_adopted_rule_preserves_its_listen_address() {
        let mut panel = make_panel();
        panel.proxy_entries = vec![make_entry(
            ProxyMode::V4ToV4,
            "127.0.0.1",
            8080,
            "127.0.0.1",
            80,
        )];
        panel.adopt_orphan(0, &I18n::new(Language::EnUs)).unwrap();
        panel.load_rule_into_form(0);
        let form = panel.parse_form(&I18n::new(Language::EnUs)).unwrap();
        assert_eq!(form.listen_address, "127.0.0.1");
    }

    fn make_entry(
        mode: ProxyMode,
        listen_addr: &str,
        listen_port: u16,
        connect_addr: &str,
        connect_port: u16,
    ) -> PortproxyEntry {
        PortproxyEntry {
            proxy_mode: mode,
            listen_address: listen_addr.into(),
            listen_port,
            connect_address: connect_addr.into(),
            connect_port,
        }
    }

    fn make_panel() -> RulesPanel {
        static NEXT_PANEL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let tmp = std::env::temp_dir().join(format!(
            "langateway-panel-{}-{}.toml",
            std::process::id(),
            NEXT_PANEL.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let config = Config {
            rules: vec![],
            mdns_enabled: false,
            mdns_hostname: String::new(),
            language: Language::EnUs,
            preferred_gateway_ip: "auto".into(),
        };
        let mut panel = RulesPanel::new(config, tmp, false);
        panel.apply_proxy_entries(vec![]);
        panel
    }

    #[test]
    fn deleting_an_earlier_row_keeps_the_same_rule_in_the_editor() {
        let mut panel = make_panel();
        panel.editing_rule_index = Some(2);
        panel.add_name = "edited third rule".into();
        panel.adjust_editing_after_delete(0);
        assert_eq!(panel.editing_rule_index, Some(1));
        assert_eq!(panel.add_name, "edited third rule");
        panel.adjust_editing_after_delete(1);
        assert_eq!(panel.editing_rule_index, None);
        assert!(panel.add_name.is_empty());
    }

    #[test]
    fn health_results_from_a_previous_rules_snapshot_are_discarded() {
        let mut panel = make_panel();
        let (tx, rx) = std::sync::mpsc::channel();
        panel.health_result_rx = Some(rx);
        panel.health_check_running = true;
        tx.send(HealthCheckResult {
            health_map: HashMap::from([(0, HealthStatus::Healthy)]),
            orphan_health: HashMap::new(),
            rules: Vec::new(),
            proxy_entries: vec![make_entry(
                ProxyMode::V4ToV4,
                "0.0.0.0",
                9999,
                "127.0.0.1",
                80,
            )],
        })
        .unwrap();
        panel.apply_health_results();
        assert!(panel.health_map.is_empty());
        assert!(!panel.health_check_running);
    }

    #[test]
    fn disconnected_health_worker_does_not_leave_the_panel_busy() {
        let mut panel = make_panel();
        let (tx, rx) = std::sync::mpsc::channel();
        panel.health_result_rx = Some(rx);
        panel.health_check_running = true;
        drop(tx);
        panel.apply_health_results();
        assert!(!panel.health_check_running);
        assert!(panel.health_result_rx.is_none());
    }

    #[test]
    fn operation_results_are_applied_without_replacing_other_settings() {
        let mut panel = make_panel();
        let (tx, rx) = std::sync::mpsc::channel();
        panel.operation_rx = Some(rx);
        let worker_config = panel.config.clone();
        panel.config.preferred_gateway_ip = "192.0.2.10".into();
        tx.send(RuleOperationResult {
            config: worker_config,
            result: Ok(vec![]),
            recovered_entries: None,
            completion: RuleCompletion::Refresh,
        })
        .unwrap();
        panel.apply_operation_results(&I18n::new(Language::EnUs));
        assert_eq!(panel.config.preferred_gateway_ip, "192.0.2.10");
        assert!(!panel.is_busy());
    }

    #[test]
    fn operations_run_off_the_ui_thread_and_reject_concurrent_commands() {
        let mut panel = make_panel();
        let ui_thread = std::thread::current().id();
        panel
            .start_operation(
                move |_, _| {
                    assert_ne!(std::thread::current().id(), ui_thread);
                    Ok(vec![])
                },
                RuleCompletion::Refresh,
            )
            .unwrap();
        assert!(panel
            .start_operation(|_, _| Ok(vec![]), RuleCompletion::Refresh)
            .is_err());
        let result = panel
            .operation_rx
            .take()
            .unwrap()
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        assert!(result.result.is_ok());
    }

    #[test]
    fn unchanged_refresh_preserves_health_results() {
        let mut panel = make_panel();
        let entries = vec![make_entry(
            ProxyMode::V4ToV4,
            "0.0.0.0",
            8080,
            "127.0.0.1",
            80,
        )];
        panel.apply_proxy_entries(entries.clone());
        let key = OrphanKey::from_entry(&entries[0]);
        panel
            .orphan_health
            .insert(key.clone(), HealthStatus::Healthy);
        panel.apply_proxy_entries(entries);
        assert_eq!(panel.orphan_health.get(&key), Some(&HealthStatus::Healthy));
    }

    #[test]
    fn orphan_detection_includes_listen_address_and_mode() {
        let mut panel = make_panel();
        panel.apply_proxy_entries(vec![
            make_entry(ProxyMode::V4ToV4, "0.0.0.0", 8080, "10.0.0.1", 80),
            make_entry(ProxyMode::V6ToV4, "::", 8080, "10.0.0.1", 80),
        ]);

        assert_eq!(panel.orphan_entries().len(), 2);
    }

    #[test]
    fn orphan_matching_distinguishes_by_listen_address() {
        let mut panel = make_panel();
        panel.proxy_entries = vec![
            make_entry(ProxyMode::V4ToV4, "0.0.0.0", 8080, "10.0.0.1", 80),
            make_entry(ProxyMode::V4ToV4, "192.168.1.1", 8080, "10.0.0.1", 80),
        ];
        let mut rule = ForwardRule {
            id: String::new(),
            name: "Test".into(),
            notes: "".into(),
            listen_address: "0.0.0.0".into(),
            listen_port: 8080,
            connect_address: "10.0.0.1".into(),
            connect_port: 80,
            managed: true,
            protocol: ProxyProtocol::Tcp,
            proxy_mode: ProxyMode::V4ToV4,
            enabled: true,
            firewall_managed: false,
            mdns_publish: false,
            tags: vec![],
        };
        rule.ensure_id();
        panel.config.rules = vec![rule];

        let orphans = panel.orphan_entries();
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].listen_address, "192.168.1.1");
    }

    #[test]
    fn adopt_orphan_adds_rule_to_config() {
        let mut panel = make_panel();
        panel.apply_proxy_entries(vec![make_entry(
            ProxyMode::V4ToV4,
            "0.0.0.0",
            5000,
            "10.108.18.67",
            80,
        )]);

        panel.adopt_orphan(0, &I18n::new(Language::EnUs)).unwrap();

        assert_eq!(panel.config.rules.len(), 1);
        assert_eq!(panel.config.rules[0].listen_port, 5000);
        assert_eq!(panel.config.rules[0].connect_address, "10.108.18.67");
        assert_eq!(panel.config.rules[0].name, "Adopted-5000");
        assert!(panel.config.rules[0].notes.contains("Imported from"));
        assert_eq!(panel.orphan_entries().len(), 0);
    }

    #[test]
    fn adopt_all_orphans_adds_all() {
        let mut panel = make_panel();
        panel.apply_proxy_entries(vec![
            make_entry(ProxyMode::V4ToV4, "0.0.0.0", 5000, "10.0.0.1", 80),
            make_entry(ProxyMode::V4ToV4, "0.0.0.0", 5001, "10.0.0.2", 443),
        ]);

        let adopted = panel.adopt_all_orphans(&I18n::new(Language::EnUs)).unwrap();
        assert_eq!(adopted, 2);
        assert_eq!(panel.config.rules.len(), 2);
        assert_eq!(panel.orphan_entries().len(), 0);
    }

    #[test]
    fn adopt_all_does_not_duplicate() {
        let mut panel = make_panel();
        panel.apply_proxy_entries(vec![make_entry(
            ProxyMode::V4ToV4,
            "0.0.0.0",
            5000,
            "10.0.0.1",
            80,
        )]);

        let count1 = panel.adopt_all_orphans(&I18n::new(Language::EnUs)).unwrap();
        let count2 = panel.adopt_all_orphans(&I18n::new(Language::EnUs)).unwrap();
        assert_eq!(count1, 1);
        assert_eq!(count2, 0);
        assert_eq!(panel.config.rules.len(), 1);
    }

    #[test]
    fn adopt_all_empty_returns_zero() {
        let mut panel = make_panel();
        panel.apply_proxy_entries(vec![]);
        let count = panel.adopt_all_orphans(&I18n::new(Language::EnUs)).unwrap();
        assert_eq!(count, 0);
    }
}
