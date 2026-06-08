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
    pub editing_rule_index: Option<usize>,
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
            editing_rule_index: None,
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
        self.proxy_entries = entries;
        self.health_map.clear();
        for i in 0..self.config.rules.len() {
            self.health_map.insert(i, HealthStatus::NotChecked);
        }
        self.orphan_health.clear();
        self.update_preflight_notes();
    }

    pub fn refresh_proxy(&mut self) {
        match crate::system::portproxy::show_all() {
            Ok(entries) => self.apply_proxy_entries(entries),
            Err(e) => self.status_message = format!("Failed to read rules: {}", e),
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
            });
        });
    }

    pub fn apply_health_results(&mut self) {
        if let Some(rx) = &self.health_result_rx {
            if let Ok(result) = rx.try_recv() {
                self.health_map = result.health_map;
                self.orphan_health = result.orphan_health;
                self.health_check_running = false;
                self.health_result_rx = None;
            }
        }
    }

    pub fn orphan_entries(&self) -> Vec<&PortproxyEntry> {
        self.proxy_entries
            .iter()
            .filter(|e| {
                !self.config.rules.iter().any(|r| {
                    r.proxy_mode == e.proxy_mode
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
        let entries =
            self.service
                .add_rule(&mut self.config, &self.proxy_entries, form, self.is_admin)?;
        self.apply_proxy_entries(entries);
        self.clear_form();
        Ok(())
    }

    pub fn update_rule(&mut self, i18n: &I18n) -> Result<(), String> {
        let idx = self
            .editing_rule_index
            .ok_or_else(|| i18n.text("err.invalid_rule_index").to_string())?;
        let form = self.parse_form(i18n)?;
        let entries = self.service.update_rule(
            &mut self.config,
            &self.proxy_entries,
            idx,
            form,
            self.is_admin,
        )?;
        self.apply_proxy_entries(entries);
        self.clear_form();
        self.editing_rule_index = None;
        Ok(())
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
        let entries = self.service.set_rule_enabled(
            &mut self.config,
            &self.proxy_entries,
            index,
            enabled,
            self.is_admin,
        )?;
        if self.editing_rule_index == Some(index) {
            self.add_enabled = enabled;
        }
        self.apply_proxy_entries(entries);
        Ok(())
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
        let entries = self
            .service
            .delete_rule(&mut self.config, index, self.is_admin)?;
        if self.editing_rule_index == Some(index) {
            self.clear_form();
            self.editing_rule_index = None;
        }
        self.apply_proxy_entries(entries);
        Ok(())
    }

    pub fn delete_orphan(&mut self, orphan_index: usize, i18n: &I18n) -> Result<(), String> {
        let orphans: Vec<PortproxyEntry> = self.orphan_entries().into_iter().cloned().collect();
        let entry = orphans
            .get(orphan_index)
            .ok_or_else(|| i18n.text("err.invalid_orphan_index").to_string())?;
        let entries = self.service.delete_orphan(entry, self.is_admin)?;
        self.apply_proxy_entries(entries);
        Ok(())
    }

    pub fn show(&mut self, ui: &mut egui::Ui, i18n: &I18n) {
        self.apply_health_results();
        ui.heading(i18n.text("rules.title"));

        if !self.status_message.is_empty() {
            ui.colored_label(egui::Color32::from_rgb(220, 80, 60), &self.status_message);
            self.status_message.clear();
        }

        if !self.last_preflight.is_empty() {
            egui::Frame::group(ui.style()).show(ui, |ui| {
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
    }

    fn show_rules_table(&mut self, ui: &mut egui::Ui, i18n: &I18n) {
        if self.config.rules.is_empty() {
            ui.label(i18n.text("rules.no_managed"));
            return;
        }

        let mut delete_idx = None;
        let mut edit_idx = None;
        let mut toggle_idx = None;

        egui::ScrollArea::horizontal().show(ui, |ui| {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                egui::Grid::new("rules_grid")
                    .num_columns(10)
                    .spacing([8.0, 4.0])
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong(i18n.text("col.name"));
                        ui.strong(i18n.text("col.mode"));
                        ui.strong(i18n.text("col.listen_addr"));
                        ui.strong(i18n.text("col.listen_port"));
                        ui.strong(i18n.text("col.connect_addr"));
                        ui.strong(i18n.text("col.connect_port"));
                        ui.strong(i18n.text("col.flags"));
                        ui.strong(i18n.text("col.notes"));
                        ui.strong(i18n.text("col.health"));
                        ui.strong(i18n.text("col.action"));
                        ui.end_row();

                        for (i, rule) in self.config.rules.iter().enumerate() {
                            ui.label(&rule.name);
                            ui.label(format!(
                                "{} {}",
                                rule.protocol.label(),
                                rule.proxy_mode.label()
                            ));
                            ui.label(&rule.listen_address);
                            ui.label(rule.listen_port.to_string());
                            ui.label(&rule.connect_address);
                            ui.label(rule.connect_port.to_string());
                            ui.label(rule_flags(rule));
                            ui.label(&rule.notes);

                            let health =
                                self.health_map.get(&i).unwrap_or(&HealthStatus::NotChecked);
                            ui.colored_label(health.color(), health.label(self.config.language))
                                .on_hover_text(health.detail());

                            ui.horizontal(|ui| {
                                let toggle_label = if rule.enabled {
                                    i18n.text("btn.disable")
                                } else {
                                    i18n.text("btn.enable")
                                };
                                if ui
                                    .add_enabled(self.is_admin, egui::Button::new(toggle_label))
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
                Ok(()) if enabled => {
                    self.status_message = i18n.text("msg.rule_enabled").into();
                }
                Ok(()) => {
                    self.status_message = i18n.text("msg.rule_disabled").into();
                }
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

        egui::ScrollArea::horizontal().show(ui, |ui| {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                egui::Grid::new("orphan_grid")
                    .num_columns(7)
                    .spacing([8.0, 4.0])
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong(i18n.text("col.mode"));
                        ui.strong(i18n.text("col.listen_addr"));
                        ui.strong(i18n.text("col.listen_port"));
                        ui.strong(i18n.text("col.connect_addr"));
                        ui.strong(i18n.text("col.connect_port"));
                        ui.strong(i18n.text("col.health"));
                        ui.strong(i18n.text("col.action"));
                        ui.end_row();

                        for (i, entry) in orphans.iter().enumerate() {
                            ui.label(entry.proxy_mode.label());
                            ui.label(&entry.listen_address);
                            ui.label(entry.listen_port.to_string());
                            ui.label(&entry.connect_address);
                            ui.label(entry.connect_port.to_string());

                            let key = OrphanKey::from_entry(entry);
                            let status = self
                                .orphan_health
                                .get(&key)
                                .unwrap_or(&HealthStatus::NotChecked);
                            ui.colored_label(status.color(), status.label(self.config.language))
                                .on_hover_text(status.detail());

                            ui.horizontal(|ui| {
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

        egui::Frame::group(ui.style()).show(ui, |ui| {
            egui::Grid::new("add_form")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.label(format!("{}:", i18n.text("form.protocol")));
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut self.add_protocol, ProxyProtocol::Tcp, "TCP");
                        ui.radio_value(&mut self.add_protocol, ProxyProtocol::Udp, "UDP");
                    });
                    ui.end_row();

                    ui.label(format!("{}:", i18n.text("form.proxy_mode")));
                    egui::ComboBox::from_id_salt("proxy_mode_combo")
                        .selected_text(self.add_proxy_mode.label())
                        .show_ui(ui, |ui| {
                            for mode in ProxyMode::variants() {
                                ui.selectable_value(&mut self.add_proxy_mode, *mode, mode.label());
                            }
                        });
                    ui.end_row();

                    ui.label(format!("{}:", i18n.text("form.listen_addr")));
                    ui.label(self.add_proxy_mode.listen_any_address());
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
                ui.checkbox(&mut self.add_mdns_publish, i18n.text("form.mdns_publish"));
            });

            if self.add_protocol == ProxyProtocol::Udp {
                ui.colored_label(
                    egui::Color32::from_rgb(200, 160, 0),
                    i18n.text("rules.udp_note"),
                );
            }

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if is_editing {
                    if ui
                        .add_enabled(
                            self.is_admin,
                            egui::Button::new(i18n.text("btn.update_rule")),
                        )
                        .clicked()
                    {
                        match self.update_rule(i18n) {
                            Ok(()) => self.status_message = i18n.text("msg.rule_updated").into(),
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
                    .add_enabled(self.is_admin, egui::Button::new(i18n.text("btn.add_rule")))
                    .clicked()
                {
                    match self.add_rule(i18n) {
                        Ok(()) => self.status_message = i18n.text("msg.rule_added").into(),
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
            .parse()
            .map_err(|_| i18n.text("err.invalid_listen_port").to_string())?;
        let connect_port: u16 = self
            .add_connect_port
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
            listen_address: self.add_proxy_mode.listen_any_address().to_string(),
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
        let tmp = std::env::temp_dir().join("langateway_test_config.toml");
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
