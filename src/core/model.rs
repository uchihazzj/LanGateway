use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Language {
    #[serde(rename = "zh-CN")]
    ZhCn,
    #[serde(rename = "en-US")]
    EnUs,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardRule {
    pub name: String,
    pub notes: String,
    pub listen_address: String,
    pub listen_port: u16,
    pub connect_address: String,
    pub connect_port: u16,
    #[serde(default)]
    pub managed: bool,
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
                ZhCn => "仅有本地配置",
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
    pub listen_address: String,
    pub listen_port: u16,
    pub connect_address: String,
    pub connect_port: u16,
}

#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub ipv4: String,
    pub mac: String,
    pub is_virtual: bool,
}

#[derive(Debug, Clone)]
pub enum RefreshState {
    Refreshing,
    Done {
        at: std::time::Instant,
        error: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OrphanKey {
    pub listen_address: String,
    pub listen_port: u16,
    pub connect_address: String,
    pub connect_port: u16,
}

impl OrphanKey {
    pub fn from_entry(entry: &PortproxyEntry) -> Self {
        Self {
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
    pub active_interface: String,
    pub is_admin: bool,
    pub rule_count: usize,
    pub gateway_ip: String,
    pub interfaces: Vec<InterfaceInfo>,
    pub refresh_state: RefreshState,
}
