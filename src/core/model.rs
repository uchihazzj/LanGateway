use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Language {
    #[serde(rename = "zh-CN")]
    ZhCn,
    #[serde(rename = "en-US")]
    EnUs,
}

impl Default for Language {
    fn default() -> Self {
        Language::ZhCn
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProxyProtocol {
    #[serde(rename = "tcp")]
    Tcp,
    #[serde(rename = "udp")]
    Udp,
}

impl Default for ProxyProtocol {
    fn default() -> Self {
        ProxyProtocol::Tcp
    }
}

impl ProxyProtocol {
    pub fn label(&self) -> &'static str {
        match self {
            ProxyProtocol::Tcp => "TCP",
            ProxyProtocol::Udp => "UDP",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProxyMode {
    #[serde(rename = "v4tov4")]
    V4ToV4,
    #[serde(rename = "v4tov6")]
    V4ToV6,
    #[serde(rename = "v6tov4")]
    V6ToV4,
    #[serde(rename = "v6tov6")]
    V6ToV6,
}

impl Default for ProxyMode {
    fn default() -> Self {
        ProxyMode::V4ToV4
    }
}

impl ProxyMode {
    pub fn netsh_name(&self) -> &'static str {
        match self {
            ProxyMode::V4ToV4 => "v4tov4",
            ProxyMode::V4ToV6 => "v4tov6",
            ProxyMode::V6ToV4 => "v6tov4",
            ProxyMode::V6ToV6 => "v6tov6",
        }
    }

    pub fn label(&self) -> &'static str {
        self.netsh_name()
    }

    pub fn listen_any_address(&self) -> &'static str {
        match self {
            ProxyMode::V4ToV4 | ProxyMode::V4ToV6 => "0.0.0.0",
            ProxyMode::V6ToV4 | ProxyMode::V6ToV6 => "::",
        }
    }

    pub fn variants() -> &'static [ProxyMode] {
        &[
            ProxyMode::V4ToV4,
            ProxyMode::V4ToV6,
            ProxyMode::V6ToV4,
            ProxyMode::V6ToV6,
        ]
    }
}

fn default_rule_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardRule {
    #[serde(default)]
    pub id: String,
    pub name: String,
    pub notes: String,
    pub listen_address: String,
    pub listen_port: u16,
    pub connect_address: String,
    pub connect_port: u16,
    #[serde(default)]
    pub managed: bool,
    #[serde(default)]
    pub protocol: ProxyProtocol,
    #[serde(default)]
    pub proxy_mode: ProxyMode,
    #[serde(default = "default_rule_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub firewall_managed: bool,
    #[serde(default)]
    pub mdns_publish: bool,
    #[serde(default)]
    pub tags: Vec<String>,
}

impl ForwardRule {
    pub fn stable_key(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.proxy_mode.netsh_name(),
            self.listen_address,
            self.listen_port,
            self.connect_address,
            self.connect_port
        )
    }

    pub fn ensure_id(&mut self) {
        if self.id.trim().is_empty() {
            self.id = format!(
                "rule-{}",
                self.stable_key()
                    .replace([':', '.', '[', ']'], "-")
                    .replace("--", "-")
            );
        }
    }

    pub fn netsh_entry(&self) -> PortproxyEntry {
        PortproxyEntry {
            proxy_mode: self.proxy_mode,
            listen_address: self.listen_address.clone(),
            listen_port: self.listen_port,
            connect_address: self.connect_address.clone(),
            connect_port: self.connect_port,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum HealthStatus {
    NotChecked,
    Healthy,
    TargetUnreachable(String),
    MetadataOnly,
}

impl HealthStatus {
    pub fn label(&self, lang: Language) -> &str {
        use Language::*;
        match self {
            HealthStatus::NotChecked => match lang {
                ZhCn => "未检查",
                EnUs => "Not checked",
            },
            HealthStatus::Healthy => match lang {
                ZhCn => "正常",
                EnUs => "Healthy",
            },
            HealthStatus::TargetUnreachable(_) => match lang {
                ZhCn => "目标不可达",
                EnUs => "Target Unreachable",
            },
            HealthStatus::MetadataOnly => match lang {
                ZhCn => "仅本地配置",
                EnUs => "Metadata Only",
            },
        }
    }

    pub fn detail(&self) -> &str {
        match self {
            HealthStatus::TargetUnreachable(detail) => detail.as_str(),
            _ => "",
        }
    }

    pub fn color(&self) -> egui::Color32 {
        match self {
            HealthStatus::NotChecked => egui::Color32::GRAY,
            HealthStatus::Healthy => egui::Color32::from_rgb(0, 180, 80),
            HealthStatus::TargetUnreachable(_) => egui::Color32::from_rgb(220, 80, 60),
            HealthStatus::MetadataOnly => egui::Color32::from_rgb(200, 160, 0),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PortproxyEntry {
    pub proxy_mode: ProxyMode,
    pub listen_address: String,
    pub listen_port: u16,
    pub connect_address: String,
    pub connect_port: u16,
}

impl PortproxyEntry {
    pub fn stable_key(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.proxy_mode.netsh_name(),
            self.listen_address,
            self.listen_port,
            self.connect_address,
            self.connect_port
        )
    }
}

#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub ipv4: String,
    pub ipv6: Vec<String>,
    pub mac: String,
    pub is_virtual: bool,
}

#[derive(Debug, Clone)]
pub enum RefreshState {
    Refreshing { stage: &'static str },
    Done { error: Option<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OrphanKey {
    pub proxy_mode: ProxyMode,
    pub listen_address: String,
    pub listen_port: u16,
    pub connect_address: String,
    pub connect_port: u16,
}

impl OrphanKey {
    pub fn from_entry(entry: &PortproxyEntry) -> Self {
        Self {
            proxy_mode: entry.proxy_mode,
            listen_address: entry.listen_address.clone(),
            listen_port: entry.listen_port,
            connect_address: entry.connect_address.clone(),
            connect_port: entry.connect_port,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DashboardInfo {
    pub hostname: String,
    pub local_ipv4: Vec<String>,
    pub local_ipv6: Vec<String>,
    pub active_interface: String,
    pub is_admin: bool,
    pub rule_count: usize,
    pub gateway_ip: String,
    pub interfaces: Vec<InterfaceInfo>,
    pub refresh_state: RefreshState,
}
