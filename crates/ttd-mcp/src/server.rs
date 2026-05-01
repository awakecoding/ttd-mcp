use crate::tools::{self, ToolCall};
use crate::ttd_replay::SessionRegistry;
use anyhow::{bail, Context};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone, Default)]
pub struct TtdMcpServer {
    sessions: Arc<Mutex<SessionRegistry>>,
}

impl TtdMcpServer {
    pub async fn handle_request(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        match method {
            "initialize" => Ok(json!({
                "protocolVersion": "2025-11-25",
                "capabilities": {
                    "tools": { "listChanged": false }
                },
                "serverInfo": {
                    "name": "ttd-mcp",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "instructions": "Offline WinDbg Time Travel Debugging trace inspection. Load .run/.ttd traces, create cursors, seek positions, inspect metadata, and query replay state."
            })),
            "tools/list" => Ok(json!({ "tools": tools::definitions() })),
            "tools/call" => self.call_tool(params).await,
            _ => bail!("unsupported MCP method: {method}"),
        }
    }

    pub async fn handle_notification(&self, method: &str, _params: Value) {
        tracing::debug!(method, "received MCP notification");
    }

    async fn call_tool(&self, params: Value) -> anyhow::Result<Value> {
        let call: ToolCall = serde_json::from_value(params).context("invalid tools/call params")?;
        let mut sessions = self.sessions.lock().await;
        let result = tools::call(&mut sessions, call).await;

        match result {
            Ok(value) => Ok(tool_text(value, false)),
            Err(error) => Ok(tool_text(json!({ "error": error.to_string() }), true)),
        }
    }
}

fn tool_text(value: Value, is_error: bool) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string())
            }
        ],
        "isError": is_error
    })
}
