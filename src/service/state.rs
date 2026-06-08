use crate::core::model::{DashboardInfo, HealthStatus, OrphanKey, PortproxyEntry};
use crate::service::mdns::MdnsStatus;
use crate::service::update::UpdateStatus;
use crate::storage::config::Config;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum OperationState {
    Idle,
    Refreshing,
    CheckingHealth,
    #[allow(dead_code)]
    ApplyingRules,
    #[allow(dead_code)]
    Failed(String),
}

impl OperationState {
    pub fn is_busy(&self) -> bool {
        matches!(
            self,
            OperationState::Refreshing
                | OperationState::CheckingHealth
                | OperationState::ApplyingRules
        )
    }
}

pub struct AppState {
    pub config: Config,
    pub config_path: PathBuf,
    pub dashboard: DashboardInfo,
    pub proxy_entries: Vec<PortproxyEntry>,
    pub health_map: HashMap<usize, HealthStatus>,
    pub orphan_health: HashMap<OrphanKey, HealthStatus>,
    pub operation: OperationState,
    pub mdns_status: MdnsStatus,
    pub update_status: UpdateStatus,
    pub logs: Vec<String>,
}

impl AppState {
    pub fn new(config: Config, config_path: PathBuf, dashboard: DashboardInfo) -> Self {
        Self {
            config,
            config_path,
            dashboard,
            proxy_entries: Vec::new(),
            health_map: HashMap::new(),
            orphan_health: HashMap::new(),
            operation: OperationState::Idle,
            mdns_status: MdnsStatus::Disabled,
            update_status: UpdateStatus::Idle,
            logs: Vec::new(),
        }
    }

    pub fn add_log(&mut self, msg: impl Into<String>) {
        self.logs.push(msg.into());
        if self.logs.len() > 200 {
            self.logs.remove(0);
        }
    }
}

pub type SharedState = std::sync::Arc<std::sync::Mutex<AppState>>;
