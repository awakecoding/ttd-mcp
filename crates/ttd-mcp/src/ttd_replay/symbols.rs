use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{env, path::PathBuf};

pub const MICROSOFT_SYMBOL_SERVER: &str = "https://msdl.microsoft.com/download/symbols";
const DEFAULT_SYMBOL_CACHE: &str = ".ttd-symbol-cache";
const DEFAULT_SYMBOL_RUNTIME_DIR: &str = "target/symbol-runtime";

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SymbolSettings {
    #[serde(default)]
    pub binary_paths: Vec<PathBuf>,
    #[serde(default)]
    pub symbol_paths: Vec<String>,
    pub symcache_dir: Option<PathBuf>,
}

impl Default for SymbolSettings {
    fn default() -> Self {
        Self {
            binary_paths: Vec::new(),
            symbol_paths: Vec::new(),
            symcache_dir: Some(PathBuf::from(".ttd-symbol-cache")),
        }
    }
}

impl SymbolSettings {
    pub fn effective_symbol_path(&self) -> String {
        self.resolve(None).symbol_path
    }

    pub fn resolve_for_process(&self) -> ResolvedSymbolConfig {
        self.resolve(Some(default_symbol_runtime_dir()))
    }

    pub fn resolve(&self, symbol_runtime_dir: Option<PathBuf>) -> ResolvedSymbolConfig {
        let mut paths = self.symbol_paths.clone();
        let microsoft_public_symbols = paths
            .iter()
            .any(|path| path.contains(MICROSOFT_SYMBOL_SERVER));

        let symbol_cache_dir = self
            .symcache_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_SYMBOL_CACHE));

        if !microsoft_public_symbols {
            paths.push(format!(
                "srv*{}*{}",
                symbol_cache_dir.to_string_lossy(),
                MICROSOFT_SYMBOL_SERVER
            ));
        }

        ResolvedSymbolConfig {
            symbol_path: paths.join(";"),
            image_path: self
                .binary_paths
                .iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(";"),
            symbol_cache_dir,
            symbol_runtime_dir,
            binary_path_count: self.binary_paths.len(),
            microsoft_public_symbols: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedSymbolConfig {
    pub symbol_path: String,
    pub image_path: String,
    pub symbol_cache_dir: PathBuf,
    pub symbol_runtime_dir: Option<PathBuf>,
    pub binary_path_count: usize,
    pub microsoft_public_symbols: bool,
}

pub fn default_symbol_runtime_dir() -> PathBuf {
    env::var_os("TTD_SYMBOL_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SYMBOL_RUNTIME_DIR))
}

impl ResolvedSymbolConfig {
    pub fn has_image_path(&self) -> bool {
        !self.image_path.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_default_symbol_path() {
        let settings = SymbolSettings::default();
        assert!(settings
            .effective_symbol_path()
            .contains(MICROSOFT_SYMBOL_SERVER));
    }

    #[test]
    fn keeps_custom_symbol_cache_dir() {
        let settings = SymbolSettings {
            symcache_dir: Some(PathBuf::from("target/test-symbol-cache")),
            ..SymbolSettings::default()
        };

        let resolved = settings.resolve(None);
        assert_eq!(
            resolved.symbol_cache_dir,
            PathBuf::from("target/test-symbol-cache")
        );
        assert!(resolved
            .symbol_path
            .contains("srv*target/test-symbol-cache*https://msdl.microsoft.com/download/symbols"));
    }

    #[test]
    fn preserves_caller_symbol_paths_without_duplicating_microsoft_server() {
        let settings = SymbolSettings {
            symbol_paths: vec![format!("srv*C:/symbols*{MICROSOFT_SYMBOL_SERVER}")],
            ..SymbolSettings::default()
        };

        let resolved = settings.resolve(None);
        assert_eq!(
            resolved
                .symbol_path
                .matches(MICROSOFT_SYMBOL_SERVER)
                .count(),
            1
        );
    }

    #[test]
    fn builds_image_path_from_binary_paths() {
        let settings = SymbolSettings {
            binary_paths: vec![
                PathBuf::from("traces/ping/ping.exe"),
                PathBuf::from("C:/Windows/System32"),
            ],
            ..SymbolSettings::default()
        };

        let resolved = settings.resolve(Some(PathBuf::from("target/symbol-runtime")));
        assert_eq!(resolved.binary_path_count, 2);
        assert_eq!(
            resolved.symbol_runtime_dir,
            Some(PathBuf::from("target/symbol-runtime"))
        );
        assert!(resolved.has_image_path());
        assert!(resolved.image_path.contains("traces/ping/ping.exe"));
        assert!(resolved.image_path.contains(';'));
    }

    #[test]
    fn resolves_process_symbol_runtime_dir() {
        let resolved = SymbolSettings::default().resolve_for_process();
        assert_eq!(
            resolved.symbol_runtime_dir,
            Some(default_symbol_runtime_dir())
        );
    }
}
