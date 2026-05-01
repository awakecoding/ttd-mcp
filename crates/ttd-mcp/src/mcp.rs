use crate::server::TtdMcpServer;
use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};

#[derive(Default)]
pub struct StdioTransport;

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse<'a> {
    jsonrpc: &'static str,
    id: &'a Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i64,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

impl StdioTransport {
    pub async fn serve(self, server: TtdMcpServer) -> anyhow::Result<()> {
        let stdin = io::stdin();
        let mut stdout = io::stdout();
        let mut lines = BufReader::new(stdin).lines();

        while let Some(line) = lines.next_line().await.context("reading MCP request")? {
            if line.trim().is_empty() {
                continue;
            }

            let request: JsonRpcRequest = match serde_json::from_str(&line) {
                Ok(request) => request,
                Err(error) => {
                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": null,
                        "error": {
                            "code": -32700,
                            "message": "parse error",
                            "data": error.to_string()
                        }
                    });
                    write_message(&mut stdout, &response).await?;
                    continue;
                }
            };

            let Some(id) = request.id.as_ref() else {
                server
                    .handle_notification(&request.method, request.params)
                    .await;
                continue;
            };

            let response = match server.handle_request(&request.method, request.params).await {
                Ok(result) => JsonRpcResponse {
                    jsonrpc: "2.0",
                    id,
                    result: Some(result),
                    error: None,
                },
                Err(error) => JsonRpcResponse {
                    jsonrpc: "2.0",
                    id,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32603,
                        message: error.to_string(),
                        data: None,
                    }),
                },
            };

            write_message(&mut stdout, &response).await?;
        }

        Ok(())
    }
}

async fn write_message<T: Serialize>(stdout: &mut io::Stdout, message: &T) -> anyhow::Result<()> {
    let payload = serde_json::to_vec(message).context("serializing MCP response")?;
    stdout.write_all(&payload).await?;
    stdout.write_all(b"\n").await?;
    stdout.flush().await?;
    Ok(())
}
