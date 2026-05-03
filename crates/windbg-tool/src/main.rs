#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "windbg_ttd=info,ttd_mcp=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    windbg_tool::cli::run().await
}
