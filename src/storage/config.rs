use crate::core::model::{ForwardRule, Language};
use serde::{Deserialize, Serialize};
use std::path::Path;

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
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Config::default());
        }
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config: {}", e))?;
        toml::from_str(&content)
            .map_err(|e| format!("Failed to parse config: {}", e))
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize config: {}", e))?;
        std::fs::write(path, content)
            .map_err(|e| format!("Failed to write config: {}", e))
    }

    pub fn config_path() -> std::path::PathBuf {
        std::env::current_exe()
            .unwrap_or_else(|_| Path::new(".").to_path_buf())
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("config.toml")
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
}
