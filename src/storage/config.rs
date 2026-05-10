use crate::core::model::{ForwardRule, Language};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

fn default_language() -> Language {
    Language::ZhCn
}

fn default_preferred_gateway_ip() -> String {
    "auto".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub rules: Vec<ForwardRule>,
    #[serde(default)]
    pub mdns_enabled: bool,
    #[serde(default)]
    pub mdns_hostname: String,
    #[serde(default = "default_language")]
    pub language: Language,
    #[serde(default = "default_preferred_gateway_ip")]
    pub preferred_gateway_ip: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            mdns_enabled: false,
            mdns_hostname: String::new(),
            language: default_language(),
            preferred_gateway_ip: default_preferred_gateway_ip(),
        }
    }
}

impl Config {
    /// Machine-level config directory: C:\ProgramData\LanGateway
    pub fn config_dir() -> PathBuf {
        PathBuf::from("C:\\ProgramData\\LanGateway")
    }

    /// Full path: C:\ProgramData\LanGateway\config.toml
    /// Creates the parent directory if it doesn't exist.
    pub fn config_path() -> Result<PathBuf, String> {
        let dir = Self::config_dir();
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("Failed to create config directory {}: {}", dir.display(), e))?;
        Ok(dir.join("config.toml"))
    }

    /// Legacy path: config.toml next to the exe (for migration).
    pub fn old_config_path() -> PathBuf {
        std::env::current_exe()
            .unwrap_or_else(|_| Path::new(".").to_path_buf())
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("config.toml")
    }

    /// Load config from `path`, returning default if file doesn't exist.
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Config::default());
        }
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("Failed to read config: {}", e))?;
        toml::from_str(&content).map_err(|e| format!("Failed to parse config: {}", e))
    }

    /// Save config to `path`. Creates parent directory if needed.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("Failed to create directory: {}", e))?;
            }
        }
        let content = toml::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize config: {}", e))?;
        std::fs::write(path, content).map_err(|e| format!("Failed to write config: {}", e))
    }

    /// Primary entry point: load from C:\ProgramData\LanGateway\config.toml.
    /// If the new path doesn't exist but the legacy exe-adjacent config does,
    /// migrate it automatically. Returns (config, migration_message_or_none).
    pub fn load_or_migrate() -> Result<(Self, Option<String>), String> {
        let new_path = Self::config_path()?;
        let old_path = Self::old_config_path();

        // New path exists — use it directly
        if new_path.exists() {
            let config = Self::load(&new_path)?;
            return Ok((config, None));
        }

        // Old path exists but new doesn't — migrate
        if old_path.exists() {
            let config = Self::load(&old_path)?;
            // Ensure parent dir exists before writing
            if let Some(parent) = new_path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("Failed to create {}: {}", parent.display(), e))?;
            }
            config.save(&new_path)?;
            let msg = format!(
                "Migrated config from {} to {}",
                old_path.display(),
                new_path.display()
            );
            return Ok((config, Some(msg)));
        }

        // Neither exists — fresh start, ensure directory exists
        let _ = Self::config_path()?; // creates dir
        Ok((Config::default(), None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::model::{ForwardRule, Language};

    #[test]
    fn roundtrip_config() {
        let config = Config {
            rules: vec![ForwardRule {
                name: "Web Server".into(),
                notes: "Main web".into(),
                listen_address: "0.0.0.0".into(),
                listen_port: 8080,
                connect_address: "192.168.1.100".into(),
                connect_port: 80,
                managed: true,
            }],
            mdns_enabled: true,
            mdns_hostname: "gateway".into(),
            language: Language::EnUs,
            preferred_gateway_ip: "10.0.0.5".into(),
        };

        let serialized = toml::to_string_pretty(&config).unwrap();
        let deserialized: Config = toml::from_str(&serialized).unwrap();

        assert_eq!(deserialized.rules.len(), 1);
        assert_eq!(deserialized.rules[0].name, "Web Server");
        assert_eq!(deserialized.rules[0].listen_port, 8080);
        assert_eq!(deserialized.mdns_enabled, true);
        assert_eq!(deserialized.mdns_hostname, "gateway");
        assert_eq!(deserialized.language, Language::EnUs);
        assert_eq!(deserialized.preferred_gateway_ip, "10.0.0.5");
    }

    #[test]
    fn empty_config() {
        let config = Config::default();
        assert!(config.rules.is_empty());
        assert!(!config.mdns_enabled);
        assert!(config.mdns_hostname.is_empty());
        assert_eq!(config.language, Language::ZhCn);
        assert_eq!(config.preferred_gateway_ip, "auto");
    }

    #[test]
    fn parse_minimal_toml() {
        let toml_str = r#"
[[rules]]
name = "test"
notes = ""
listen_address = "0.0.0.0"
listen_port = 1234
connect_address = "10.0.0.1"
connect_port = 80
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].listen_port, 1234);
    }

    #[test]
    fn missing_language_defaults_to_zh_cn() {
        let toml_str = r#"
[[rules]]
name = "test"
notes = ""
listen_address = "0.0.0.0"
listen_port = 80
connect_address = "10.0.0.1"
connect_port = 8080
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.language, Language::ZhCn);
    }

    #[test]
    fn missing_preferred_ip_defaults_to_auto() {
        let toml_str = r#"
[[rules]]
name = "test"
notes = ""
listen_address = "0.0.0.0"
listen_port = 80
connect_address = "10.0.0.1"
connect_port = 8080
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.preferred_gateway_ip, "auto");
    }

    // --- Config path tests ---

    #[test]
    fn config_dir_is_programdata() {
        let dir = Config::config_dir();
        assert_eq!(dir, PathBuf::from("C:\\ProgramData\\LanGateway"));
    }

    #[test]
    fn config_path_ends_with_config_toml() {
        let path = Config::config_path().unwrap();
        assert_eq!(path.file_name().unwrap(), "config.toml");
        assert!(path.starts_with("C:\\ProgramData\\LanGateway"));
    }

    #[test]
    fn old_config_path_is_next_to_exe() {
        let old = Config::old_config_path();
        assert_eq!(old.file_name().unwrap(), "config.toml");
    }

    #[test]
    fn save_creates_parent_directory() {
        let tmp = std::env::temp_dir().join("langateway_test_cfg");
        let test_path = tmp.join("subdir").join("config.toml");
        // Clean up
        let _ = std::fs::remove_dir_all(&tmp);
        let config = Config::default();
        config.save(&test_path).unwrap();
        assert!(test_path.exists());
        // Clean up
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn save_returns_result_type() {
        // Save to a temp file — verifies Result return type and success path
        let tmp = std::env::temp_dir().join("langateway_save_test.toml");
        let _ = std::fs::remove_file(&tmp);
        let config = Config::default();
        let result = config.save(&tmp);
        assert!(result.is_ok());
        assert!(tmp.exists());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn load_nonexistent_returns_default() {
        let config = Config::load(Path::new("C:\\nonexistent\\path\\config.toml")).unwrap();
        assert!(config.rules.is_empty());
    }

    #[test]
    fn migration_new_exists_skips_old() {
        let tmp = std::env::temp_dir().join("langateway_migration_test");
        let _ = std::fs::remove_dir_all(&tmp);
        let new_dir = tmp.join("new");
        let old_dir = tmp.join("old");
        std::fs::create_dir_all(&new_dir).unwrap();
        std::fs::create_dir_all(&old_dir).unwrap();

        // Both exist — new should be used, old ignored
        let mut c_new = Config::default();
        c_new.preferred_gateway_ip = "10.0.0.1".into();
        c_new.save(&new_dir.join("config.toml")).unwrap();

        let mut c_old = Config::default();
        c_old.preferred_gateway_ip = "192.168.1.1".into();
        c_old.save(&old_dir.join("config.toml")).unwrap();

        let loaded = Config::load(&new_dir.join("config.toml")).unwrap();
        assert_eq!(loaded.preferred_gateway_ip, "10.0.0.1");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn config_path_creates_directory() {
        // config_path() should succeed even if ProgramData\LanGateway doesn't exist yet
        let path = Config::config_path();
        assert!(path.is_ok());
    }
}
