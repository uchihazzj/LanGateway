use crate::core::health;
use crate::core::model::{ForwardRule, HealthStatus, PortproxyEntry};
use crate::i18n::I18n;
use crate::storage::config::Config;
use crate::system::portproxy;

pub struct RulesPanel {
    pub config: Config,
    pub config_path: std::path::PathBuf,
    pub proxy_entries: Vec<PortproxyEntry>,
    pub health_map: std::collections::HashMap<usize, HealthStatus>,
    pub orphan_health: std::collections::HashMap<usize, HealthStatus>,
    pub status_message: String,
    pub is_admin: bool,
    pub health_check_running: bool,

    pub add_listen_port: String,
    pub add_connect_address: String,
    pub add_connect_port: String,
    pub add_name: String,
    pub add_notes: String,
}

impl RulesPanel {
    pub fn new(config: Config, config_path: std::path::PathBuf, is_admin: bool) -> Self {
        let mut panel = Self {
            config,
            config_path,
            proxy_entries: vec![],
            health_map: std::collections::HashMap::new(),
            orphan_health: std::collections::HashMap::new(),
            status_message: String::new(),
            is_admin,
            health_check_running: false,
            add_listen_port: String::new(),
            add_connect_address: String::new(),
            add_connect_port: String::new(),
            add_name: String::new(),
            add_notes: String::new(),
        };
        panel.refresh_proxy();
        panel
    }

    pub fn refresh_proxy(&mut self) {
        match portproxy::show_all() {
            Ok(entries) => {
                self.proxy_entries = entries;
                // Reset health to NotChecked for all managed rules
                self.health_map.clear();
                for i in 0..self.config.rules.len() {
                    self.health_map.insert(i, HealthStatus::NotChecked);
                }
                self.orphan_health.clear();
            }
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
                            && r.connect_address == e.connect_address
                            && r.connect_port == e.connect_port
                    })
                })
                .cloned()
                .collect();

            let mut orphan_health = std::collections::HashMap::new();
            for (i, entry) in orphans.iter().enumerate() {
                orphan_health.insert(i, health::check_orphan(entry));
            }

            // Results are applied in the next call to apply_health_results
            // We use a simple approach: pass results through a static
            PENDING_HEALTH.with(|cell| {
                cell.replace(Some((health_map, orphan_health)));
            });
        });
    }

    pub fn apply_health_results(&mut self) {
        PENDING_HEALTH.with(|cell| {
            if let Some((health_map, orphan_health)) = cell.take() {
                self.health_map = health_map;
                self.orphan_health = orphan_health;
                self.health_check_running = false;
            }
        });
    }

    pub fn orphan_entries(&self) -> Vec<&PortproxyEntry> {
        self.proxy_entries
            .iter()
            .filter(|e| {
                !self.config.rules.iter().any(|r| {
                    r.listen_port == e.listen_port
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
        self.save_config();
        self.clear_form();
        self.refresh_proxy();
        Ok(())
    }

    fn save_config(&self) {
        if let Err(e) = self.config.save(&self.config_path) {
            crate::system::logger::log_to_file(&format!("Failed to save config: {}", e));
        }
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
        self.save_config();
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

        ui.heading(i18n.text("rules.add_new"));
        self.show_add_form(ui, i18n);

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if ui.button(i18n.text("rules.refresh")).clicked() {
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

                            let health = self
                                .health_map
                                .get(&i)
                                .unwrap_or(&HealthStatus::NotChecked);
                            ui.colored_label(
                                health.color(),
                                health.label(self.config.language),
                            );

                            if ui
                                .add_enabled(
                                    self.is_admin,
                                    egui::Button::new(i18n.text("btn.delete")),
                                )
                                .clicked()
                            {
                                delete_idx = Some(i);
                            }
                            ui.end_row();
                        }
                    });
            });
        });

        if let Some(i) = delete_idx {
            if let Err(e) = self.delete_rule(i, i18n) {
                self.status_message =
                    format!("{}: {}", i18n.text("msg.rule_delete_failed"), e);
            }
        }
    }

    fn show_orphan_table(
        &mut self,
        ui: &mut egui::Ui,
        orphans: &[PortproxyEntry],
        i18n: &I18n,
    ) {
        let mut delete_idx: Option<usize> = None;

        egui::ScrollArea::horizontal().show(ui, |ui| {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                egui::Grid::new("orphan_grid")
                    .num_columns(6)
                    .spacing([8.0, 4.0])
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong(i18n.text("col.listen_addr"));
                        ui.strong(i18n.text("col.listen_port"));
                        ui.strong(i18n.text("col.connect_addr"));
                        ui.strong(i18n.text("col.connect_port"));
                        ui.strong(i18n.text("col.health"));
                        ui.strong(i18n.text("col.action"));
                        ui.end_row();

                        for (i, entry) in orphans.iter().enumerate() {
                            ui.label(&entry.listen_address);
                            ui.label(entry.listen_port.to_string());
                            ui.label(&entry.connect_address);
                            ui.label(entry.connect_port.to_string());

                            let status = self
                                .orphan_health
                                .get(&i)
                                .unwrap_or(&HealthStatus::NotChecked);
                            ui.colored_label(
                                status.color(),
                                status.label(self.config.language),
                            );

                            if ui
                                .add_enabled(
                                    self.is_admin,
                                    egui::Button::new(i18n.text("btn.delete")),
                                )
                                .clicked()
                            {
                                delete_idx = Some(i);
                            }
                            ui.end_row();
                        }
                    });
            });
        });

        if let Some(i) = delete_idx {
            if let Err(e) = self.delete_orphan(i, i18n) {
                self.status_message =
                    format!("{}: {}", i18n.text("msg.rule_delete_failed"), e);
            }
        }
    }

    fn show_add_form(&mut self, ui: &mut egui::Ui, i18n: &I18n) {
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
                        egui::TextEdit::singleline(&mut self.add_listen_port)
                            .desired_width(120.0),
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
                        egui::TextEdit::singleline(&mut self.add_connect_port)
                            .desired_width(120.0),
                    );
                    ui.end_row();

                    ui.label(format!("{}:", i18n.text("form.name_opt")));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.add_name).desired_width(200.0),
                    );
                    ui.end_row();

                    ui.label(format!("{}:", i18n.text("form.notes_opt")));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.add_notes).desired_width(200.0),
                    );
                    ui.end_row();
                });

            ui.add_space(6.0);
            if ui
                .add_enabled(
                    self.is_admin,
                    egui::Button::new(i18n.text("btn.add_rule")),
                )
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
            if !self.is_admin {
                ui.label(i18n.text("msg.admin_required"));
            }
        });
    }
}

// Thread-local storage for background health check results
use std::cell::RefCell;
thread_local! {
    static PENDING_HEALTH: RefCell<Option<(std::collections::HashMap<usize, HealthStatus>, std::collections::HashMap<usize, HealthStatus>)>> =
        RefCell::new(None);
}
