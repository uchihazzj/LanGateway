use crate::core::health;
use crate::core::model::{ForwardRule, HealthStatus, OrphanKey, PortproxyEntry};
use crate::i18n::I18n;
use crate::storage::config::Config;
use crate::system::portproxy;

pub struct HealthCheckResult {
    pub health_map: std::collections::HashMap<usize, HealthStatus>,
    pub orphan_health: std::collections::HashMap<OrphanKey, HealthStatus>,
}

pub struct RulesPanel {
    pub config: Config,
    pub config_path: std::path::PathBuf,
    pub proxy_entries: Vec<PortproxyEntry>,
    pub health_map: std::collections::HashMap<usize, HealthStatus>,
    pub orphan_health: std::collections::HashMap<OrphanKey, HealthStatus>,
    pub status_message: String,
    pub is_admin: bool,
    pub health_check_running: bool,
    pub health_result_rx: Option<std::sync::mpsc::Receiver<HealthCheckResult>>,

    pub editing_rule_index: Option<usize>,

    pub add_listen_port: String,
    pub add_connect_address: String,
    pub add_connect_port: String,
    pub add_name: String,
    pub add_notes: String,
}

impl RulesPanel {
    /// Lightweight constructor — does NOT call netsh.
    /// Caller must set proxy_entries via apply_proxy_entries() or refresh_proxy().
    pub fn new(config: Config, config_path: std::path::PathBuf, is_admin: bool) -> Self {
        Self {
            config,
            config_path,
            proxy_entries: vec![],
            health_map: std::collections::HashMap::new(),
            orphan_health: std::collections::HashMap::new(),
            status_message: String::new(),
            is_admin,
            health_check_running: false,
            health_result_rx: None,
            editing_rule_index: None,
            add_listen_port: String::new(),
            add_connect_address: String::new(),
            add_connect_port: String::new(),
            add_name: String::new(),
            add_notes: String::new(),
        }
    }

    /// Set proxy entries without calling netsh — used by initial background refresh.
    pub fn apply_proxy_entries(&mut self, entries: Vec<PortproxyEntry>) {
        self.proxy_entries = entries;
        self.health_map.clear();
        for i in 0..self.config.rules.len() {
            self.health_map.insert(i, HealthStatus::NotChecked);
        }
        self.orphan_health.clear();
    }

    pub fn refresh_proxy(&mut self) {
        match portproxy::show_all() {
            Ok(entries) => self.apply_proxy_entries(entries),
            Err(e) => {
                self.status_message = format!("Failed to read rules: {}", e);
            }
        }
    }

    pub fn run_health_checks_background(&mut self) {
        if self.health_check_running {
            return;
        }
        self.health_check_running = true;

        let rules: Vec<_> = self.config.rules.clone();
        let proxy_entries: Vec<_> = self.proxy_entries.clone();

        let (tx, rx) = std::sync::mpsc::channel();
        self.health_result_rx = Some(rx);

        std::thread::spawn(move || {
            let mut health_map = std::collections::HashMap::new();
            for (i, rule) in rules.iter().enumerate() {
                let status = health::check_rule(rule, &proxy_entries);
                health_map.insert(i, status);
            }

            let orphans: Vec<_> = proxy_entries
                .iter()
                .filter(|e| {
                    !rules.iter().any(|r| {
                        r.listen_port == e.listen_port
                            && r.listen_address == e.listen_address
                            && r.connect_address == e.connect_address
                            && r.connect_port == e.connect_port
                    })
                })
                .cloned()
                .collect();

            let mut orphan_health = std::collections::HashMap::new();
            for entry in &orphans {
                let key = OrphanKey::from_entry(entry);
                orphan_health.insert(key, health::check_orphan(entry));
            }

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
                    r.listen_port == e.listen_port
                        && r.listen_address == e.listen_address
                        && r.connect_address == e.connect_address
                        && r.connect_port == e.connect_port
                })
            })
            .collect()
    }

    pub fn add_rule(&mut self, i18n: &I18n) -> Result<(), String> {
        let listen_port: u16 = self
            .add_listen_port
            .parse()
            .map_err(|_| i18n.text("err.invalid_listen_port").to_string())?;
        let connect_port: u16 = self
            .add_connect_port
            .parse()
            .map_err(|_| i18n.text("err.invalid_connect_port").to_string())?;
        let connect_address = self.add_connect_address.trim().to_string();
        if connect_address.is_empty() {
            return Err(i18n.text("err.connect_addr_required").to_string());
        }

        portproxy::add_v4tov4(listen_port, &connect_address, connect_port)?;

        let rule = ForwardRule {
            name: if self.add_name.trim().is_empty() {
                format!("Rule-{}", listen_port)
            } else {
                self.add_name.trim().to_string()
            },
            notes: self.add_notes.trim().to_string(),
            listen_address: "0.0.0.0".to_string(),
            listen_port,
            connect_address,
            connect_port,
            managed: true,
        };
        self.config.rules.push(rule);
        if let Err(e) = self.save_config() {
            // netsh already committed, warn about config persistence failure
            self.clear_form();
            self.refresh_proxy();
            return Err(format!("netsh succeeded but config save failed: {}", e));
        }
        self.clear_form();
        self.refresh_proxy();
        Ok(())
    }

    pub fn update_rule(&mut self, i18n: &I18n) -> Result<(), String> {
        let idx = self
            .editing_rule_index
            .ok_or_else(|| i18n.text("err.invalid_rule_index").to_string())?;
        if idx >= self.config.rules.len() {
            return Err(i18n.text("err.invalid_rule_index").to_string());
        }

        let listen_port: u16 = self
            .add_listen_port
            .parse()
            .map_err(|_| i18n.text("err.invalid_listen_port").to_string())?;
        let connect_port: u16 = self
            .add_connect_port
            .parse()
            .map_err(|_| i18n.text("err.invalid_connect_port").to_string())?;
        let connect_address = self.add_connect_address.trim().to_string();
        if connect_address.is_empty() {
            return Err(i18n.text("err.connect_addr_required").to_string());
        }

        let old = &self.config.rules[idx];
        let net_changed = old.listen_address != "0.0.0.0"
            || old.listen_port != listen_port
            || old.connect_address != connect_address
            || old.connect_port != connect_port;

        if net_changed {
            // Remove old netsh rule, add new one
            portproxy::delete_v4tov4(old.listen_port, &old.listen_address)?;
            portproxy::add_v4tov4(listen_port, &connect_address, connect_port)?;
        }

        self.config.rules[idx] = ForwardRule {
            name: if self.add_name.trim().is_empty() {
                format!("Rule-{}", listen_port)
            } else {
                self.add_name.trim().to_string()
            },
            notes: self.add_notes.trim().to_string(),
            listen_address: "0.0.0.0".to_string(),
            listen_port,
            connect_address,
            connect_port,
            managed: true,
        };

        self.save_config()?;
        self.clear_form();
        self.editing_rule_index = None;
        self.refresh_proxy();
        Ok(())
    }

    fn save_config(&self) -> Result<(), String> {
        self.config.save(&self.config_path)
    }

    pub fn adopt_orphan(&mut self, orphan_index: usize, i18n: &I18n) -> Result<(), String> {
        let orphans = self.orphan_entries();
        if orphan_index >= orphans.len() {
            return Err(i18n.text("err.invalid_orphan_index").to_string());
        }
        let entry = orphans[orphan_index];
        let key = OrphanKey::from_entry(entry);

        let rule = ForwardRule {
            name: format!("Adopted-{}", entry.listen_port),
            notes: "Imported from existing Windows PortProxy rule".into(),
            listen_address: entry.listen_address.clone(),
            listen_port: entry.listen_port,
            connect_address: entry.connect_address.clone(),
            connect_port: entry.connect_port,
            managed: true,
        };
        // Do NOT call netsh add — the rule already exists in the system
        self.config.rules.push(rule);
        self.save_config()?;
        // Update health locally (no refresh_proxy needed — rule already in netsh)
        self.health_map
            .insert(self.config.rules.len() - 1, HealthStatus::NotChecked);
        self.orphan_health.remove(&key);
        Ok(())
    }

    pub fn adopt_all_orphans(&mut self, _i18n: &I18n) -> Result<usize, String> {
        let orphans: Vec<PortproxyEntry> = self.orphan_entries().into_iter().cloned().collect();
        if orphans.is_empty() {
            return Ok(0);
        }

        let mut count = 0;
        for entry in &orphans {
            let rule = ForwardRule {
                name: format!("Adopted-{}", entry.listen_port),
                notes: "Imported from existing Windows PortProxy rule".into(),
                listen_address: entry.listen_address.clone(),
                listen_port: entry.listen_port,
                connect_address: entry.connect_address.clone(),
                connect_port: entry.connect_port,
                managed: true,
            };
            self.config.rules.push(rule);
            count += 1;
        }

        self.save_config()?;
        // Update health locally (no refresh_proxy needed — rules already in netsh)
        self.health_map.clear();
        for i in 0..self.config.rules.len() {
            self.health_map.insert(i, HealthStatus::NotChecked);
        }
        self.orphan_health.clear();
        Ok(count)
    }

    fn clear_form(&mut self) {
        self.add_listen_port.clear();
        self.add_connect_address.clear();
        self.add_connect_port.clear();
        self.add_name.clear();
        self.add_notes.clear();
    }

    pub fn delete_rule(&mut self, index: usize, i18n: &I18n) -> Result<(), String> {
        if index >= self.config.rules.len() {
            return Err(i18n.text("err.invalid_rule_index").to_string());
        }
        let rule = &self.config.rules[index];
        portproxy::delete_v4tov4(rule.listen_port, &rule.listen_address)?;
        self.config.rules.remove(index);
        // If we were editing this rule, clear edit state
        if self.editing_rule_index == Some(index) {
            self.clear_form();
            self.editing_rule_index = None;
        }
        if let Err(e) = self.save_config() {
            self.refresh_proxy();
            return Err(format!("netsh succeeded but config save failed: {}", e));
        }
        self.refresh_proxy();
        Ok(())
    }

    pub fn delete_orphan(&mut self, orphan_index: usize, i18n: &I18n) -> Result<(), String> {
        let orphans = self.orphan_entries();
        if orphan_index >= orphans.len() {
            return Err(i18n.text("err.invalid_orphan_index").to_string());
        }
        let entry = orphans[orphan_index];
        portproxy::delete_v4tov4(entry.listen_port, &entry.listen_address)?;
        self.refresh_proxy();
        Ok(())
    }

    pub fn show(&mut self, ui: &mut egui::Ui, i18n: &I18n) {
        // Health results are also consumed in App::update(), but call here
        // too so that results are applied promptly when on this tab.
        self.apply_health_results();

        ui.heading(i18n.text("rules.title"));

        if !self.status_message.is_empty() {
            ui.colored_label(egui::Color32::from_rgb(220, 80, 60), &self.status_message);
            self.status_message.clear();
        }

        ui.add_space(4.0);
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
            if ui
                .add_enabled(
                    !self.health_check_running,
                    egui::Button::new(if self.health_check_running {
                        "..."
                    } else {
                        i18n.text("dashboard.run_health_check")
                    }),
                )
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

        let mut delete_idx: Option<usize> = None;
        let mut edit_idx: Option<usize> = None;

        egui::ScrollArea::horizontal().show(ui, |ui| {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                egui::Grid::new("rules_grid")
                    .num_columns(8)
                    .spacing([8.0, 4.0])
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong(i18n.text("col.name"));
                        ui.strong(i18n.text("col.listen_addr"));
                        ui.strong(i18n.text("col.listen_port"));
                        ui.strong(i18n.text("col.connect_addr"));
                        ui.strong(i18n.text("col.connect_port"));
                        ui.strong(i18n.text("col.notes"));
                        ui.strong(i18n.text("col.health"));
                        ui.strong(i18n.text("col.action"));
                        ui.end_row();

                        for (i, rule) in self.config.rules.iter().enumerate() {
                            ui.label(&rule.name);
                            ui.label(&rule.listen_address);
                            ui.label(rule.listen_port.to_string());
                            ui.label(&rule.connect_address);
                            ui.label(rule.connect_port.to_string());
                            ui.label(&rule.notes);

                            let health =
                                self.health_map.get(&i).unwrap_or(&HealthStatus::NotChecked);
                            ui.colored_label(health.color(), health.label(self.config.language))
                                .on_hover_text(health.detail());

                            ui.horizontal(|ui| {
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

        if let Some(i) = delete_idx {
            if let Err(e) = self.delete_rule(i, i18n) {
                self.status_message = format!("{}: {}", i18n.text("msg.rule_delete_failed"), e);
            }
        }

        if let Some(i) = edit_idx {
            if i < self.config.rules.len() {
                let rule = &self.config.rules[i];
                self.add_listen_port = rule.listen_port.to_string();
                self.add_connect_address = rule.connect_address.clone();
                self.add_connect_port = rule.connect_port.to_string();
                self.add_name = rule.name.clone();
                self.add_notes = rule.notes.clone();
                self.editing_rule_index = Some(i);
            }
        }
    }

    fn show_orphan_table(&mut self, ui: &mut egui::Ui, orphans: &[PortproxyEntry], i18n: &I18n) {
        let mut delete_idx: Option<usize> = None;
        let mut adopt_idx: Option<usize> = None;
        let mut adopt_all = false;

        // Adopt All button
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
                        ui.strong(i18n.text("col.listen_addr"));
                        ui.strong(i18n.text("col.listen_port"));
                        ui.strong(i18n.text("col.connect_addr"));
                        ui.strong(i18n.text("col.connect_port"));
                        ui.strong(i18n.text("col.health"));
                        ui.strong(i18n.text("col.action"));
                        ui.strong(""); // adoption column
                        ui.end_row();

                        for (i, entry) in orphans.iter().enumerate() {
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
                Ok(()) => {
                    self.status_message = i18n.text("msg.orphan_adopted").into();
                }
                Err(e) => {
                    self.status_message = format!("{}: {}", i18n.text("msg.adopt_failed"), e);
                }
            }
        }

        if adopt_all {
            match self.adopt_all_orphans(i18n) {
                Ok(count) => {
                    if count > 0 {
                        self.status_message = i18n
                            .text("msg.orphans_adopted")
                            .replace("{count}", &count.to_string());
                    }
                }
                Err(e) => {
                    self.status_message = format!("{}: {}", i18n.text("msg.adopt_failed"), e);
                }
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
                    ui.label(format!("{}:", i18n.text("form.listen_addr")));
                    ui.label(i18n.text("form.default_hint"));
                    ui.end_row();

                    ui.label(format!("{}:", i18n.text("form.listen_port")));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.add_listen_port).desired_width(120.0),
                    );
                    ui.end_row();

                    ui.label(format!("{}:", i18n.text("form.connect_addr")));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.add_connect_address)
                            .desired_width(200.0),
                    );
                    ui.end_row();

                    ui.label(format!("{}:", i18n.text("form.connect_port")));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.add_connect_port).desired_width(120.0),
                    );
                    ui.end_row();

                    ui.label(format!("{}:", i18n.text("form.name_opt")));
                    ui.add(egui::TextEdit::singleline(&mut self.add_name).desired_width(200.0));
                    ui.end_row();

                    ui.label(format!("{}:", i18n.text("form.notes_opt")));
                    ui.add(egui::TextEdit::singleline(&mut self.add_notes).desired_width(200.0));
                    ui.end_row();
                });

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
                            Ok(()) => {
                                self.status_message = i18n.text("msg.rule_updated").into();
                            }
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
                } else {
                    if ui
                        .add_enabled(self.is_admin, egui::Button::new(i18n.text("btn.add_rule")))
                        .clicked()
                    {
                        match self.add_rule(i18n) {
                            Ok(()) => {
                                self.status_message = i18n.text("msg.rule_added").into();
                            }
                            Err(e) => {
                                self.status_message =
                                    format!("{}: {}", i18n.text("msg.rule_add_failed"), e);
                            }
                        }
                    }
                }
            });
            if !self.is_admin {
                ui.label(i18n.text("msg.admin_required"));
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::model::{ForwardRule, Language, PortproxyEntry};

    fn make_entry(
        listen_addr: &str,
        listen_port: u16,
        connect_addr: &str,
        connect_port: u16,
    ) -> PortproxyEntry {
        PortproxyEntry {
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
    fn orphan_detection_includes_listen_address() {
        let mut panel = make_panel();
        // Two rules with same listen_port but different listen_address
        panel.apply_proxy_entries(vec![
            make_entry("0.0.0.0", 8080, "10.0.0.1", 80),
            make_entry("192.168.1.1", 8080, "10.0.0.1", 80),
        ]);

        // All are orphans (no managed rules)
        assert_eq!(panel.orphan_entries().len(), 2);
    }

    #[test]
    fn orphan_matching_distinguishes_by_listen_address() {
        let mut panel = make_panel();
        panel.proxy_entries = vec![
            make_entry("0.0.0.0", 8080, "10.0.0.1", 80),
            make_entry("192.168.1.1", 8080, "10.0.0.1", 80),
        ];
        panel.config.rules = vec![ForwardRule {
            name: "Test".into(),
            notes: "".into(),
            listen_address: "0.0.0.0".into(),
            listen_port: 8080,
            connect_address: "10.0.0.1".into(),
            connect_port: 80,
            managed: true,
        }];

        // Only 192.168.1.1:8080 should be orphan (different listen_address)
        let orphans = panel.orphan_entries();
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].listen_address, "192.168.1.1");
    }

    #[test]
    fn adopt_orphan_adds_rule_to_config() {
        let mut panel = make_panel();
        panel.apply_proxy_entries(vec![make_entry("0.0.0.0", 5000, "10.108.18.67", 80)]);

        assert_eq!(panel.config.rules.len(), 0);
        assert_eq!(panel.orphan_entries().len(), 1);

        // adopt the orphan
        panel.adopt_orphan(0, &I18n::new(Language::EnUs)).unwrap();

        assert_eq!(panel.config.rules.len(), 1);
        assert_eq!(panel.config.rules[0].listen_port, 5000);
        assert_eq!(panel.config.rules[0].connect_address, "10.108.18.67");
        assert_eq!(panel.config.rules[0].name, "Adopted-5000");
        assert!(panel.config.rules[0].notes.contains("Imported from"));
        // After adoption, no orphans remain
        assert_eq!(panel.orphan_entries().len(), 0);
    }

    #[test]
    fn adopt_all_orphans_adds_all() {
        let mut panel = make_panel();
        panel.apply_proxy_entries(vec![
            make_entry("0.0.0.0", 5000, "10.0.0.1", 80),
            make_entry("0.0.0.0", 5001, "10.0.0.2", 443),
        ]);

        assert_eq!(panel.config.rules.len(), 0);
        let adopted = panel.adopt_all_orphans(&I18n::new(Language::EnUs)).unwrap();
        assert_eq!(adopted, 2);
        assert_eq!(panel.config.rules.len(), 2);
        assert_eq!(panel.orphan_entries().len(), 0);
    }

    #[test]
    fn adopt_all_does_not_duplicate() {
        let mut panel = make_panel();
        panel.apply_proxy_entries(vec![make_entry("0.0.0.0", 5000, "10.0.0.1", 80)]);

        // First adoption
        let count1 = panel.adopt_all_orphans(&I18n::new(Language::EnUs)).unwrap();
        assert_eq!(count1, 1);

        // Second adoption should find no orphans
        let count2 = panel.adopt_all_orphans(&I18n::new(Language::EnUs)).unwrap();
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
