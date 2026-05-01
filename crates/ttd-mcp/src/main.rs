use anyhow::Context;
use rmcp::{transport::stdio, ServiceExt};
use ttd_mcp::server::TtdMcpServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ttd_mcp=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let server = TtdMcpServer::default();
    let service = server
        .serve(stdio())
        .await
        .context("stdio MCP transport failed")?;
    service
        .waiting()
        .await
        .context("stdio MCP service failed")?;
    Ok(())
}
