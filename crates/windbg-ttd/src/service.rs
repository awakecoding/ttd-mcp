use crate::tools::{self, ToolCall};
use crate::ttd_replay::SessionRegistry;
use rmcp::model::Tool;
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

use crate::ttd_replay::SessionSummary;

#[derive(Clone)]
pub struct ReplayService {
    sessions: Arc<Mutex<SessionRegistry>>,
    started: Instant,
    started_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceHealth {
    pub name: String,
    pub version: String,
    pub pid: u32,
    pub uptime_seconds: u64,
    pub started_unix_ms: u128,
    pub active_sessions: usize,
    pub active_cursors: usize,
}

impl Default for ReplayService {
    fn default() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(SessionRegistry::default())),
            started: Instant::now(),
            started_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_millis())
                .unwrap_or_default(),
        }
    }
}

impl ReplayService {
    pub fn list_tools(&self) -> Vec<Tool> {
        tools::definitions()
    }

    pub async fn call_tool(&self, call: ToolCall) -> anyhow::Result<Value> {
        let mut sessions = self.sessions.lock().await;
        tools::call(&mut sessions, call).await
    }

    pub async fn health(&self) -> ServiceHealth {
        let sessions = self.sessions.lock().await;
        ServiceHealth {
            name: "windbg-tool-daemon".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            pid: std::process::id(),
            uptime_seconds: self.started.elapsed().as_secs(),
            started_unix_ms: self.started_unix_ms,
            active_sessions: sessions.session_count(),
            active_cursors: sessions.cursor_count(),
        }
    }

    pub async fn sessions(&self) -> Vec<SessionSummary> {
        self.sessions.lock().await.session_summaries()
    }
}
