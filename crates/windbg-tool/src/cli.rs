use anyhow::{bail, Context};
use clap::{Args, Parser, Subcommand};
use rmcp::{transport::stdio, ServiceExt};
use serde_json::{json, Map, Value};
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use windbg_dbgeng::{start_process_server, ProcessServerOptions};
use windbg_install::WindbgManager;
use windbg_ttd::daemon::{default_pipe_name, run_daemon, DaemonClient};
use windbg_ttd::server::TtdMcpServer;
use windbg_ttd::tools::{self, ToolCall};

#[derive(Debug, Parser)]
#[command(about = "WinDbg Time Travel Debugging MCP server, daemon, and CLI")]
struct Cli {
    #[arg(long, global = true, help = "Windows named pipe path for the daemon")]
    pipe: Option<String>,
    #[arg(long, global = true, help = "Emit compact single-line JSON")]
    compact: bool,
    #[arg(
        long,
        global = true,
        help = "Extract a dot-separated field from the JSON result"
    )]
    field: Option<String>,
    #[arg(
        long,
        global = true,
        help = "Print selected scalar values without JSON quoting"
    )]
    raw: bool,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Clone)]
struct OutputOptions {
    compact: bool,
    field: Option<String>,
    raw: bool,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(about = "Run the stdio MCP server (also the no-argument default)")]
    Mcp,
    #[command(about = "Show a structured command/tool guide without contacting the daemon")]
    Discover,
    #[command(about = "Show the JSON schema for one MCP tool without contacting the daemon")]
    Schema(SchemaArgs),
    Trace {
        #[command(subcommand)]
        command: TraceCommand,
    },
    #[command(
        name = "trace-list",
        about = "Enumerate traces in a .run/.idx/.ttd file without opening a session"
    )]
    TraceList(TraceListArgs),
    Daemon {
        #[command(subcommand)]
        command: DaemonCommand,
    },
    #[command(name = "dbgeng")]
    DbgEng {
        #[command(subcommand)]
        command: DbgEngCommand,
    },
    #[command(
        name = "dbgsrv",
        about = "Start a DbgEng process server",
        alias = "debug-server"
    )]
    DbgSrv(DbgEngServerArgs),
    Windbg {
        #[command(subcommand)]
        command: WindbgCommand,
    },
    #[command(about = "Load a trace, create a cursor, optionally seek, and print both handles")]
    Open(OpenArgs),
    #[command(about = "Load a .run/.idx/.ttd trace into the long-lived daemon")]
    Load(LoadArgs),
    #[command(about = "List daemon-owned trace sessions and cursors", alias = "ls")]
    Sessions,
    #[command(about = "Close a daemon-owned trace session")]
    Close(SessionArgs),
    #[command(about = "Show trace metadata for a loaded session")]
    Info(SessionArgs),
    #[command(
        about = "Show available backend features for a loaded session",
        alias = "caps"
    )]
    Capabilities(SessionArgs),
    Index {
        #[command(subcommand)]
        command: IndexCommand,
    },
    #[command(about = "List MCP tools and input schemas without contacting the daemon")]
    Tools,
    #[command(about = "Call any MCP tool by name with raw JSON arguments")]
    Tool(ToolArgs),
    #[command(about = "List trace threads")]
    Threads(SessionArgs),
    #[command(about = "List trace modules", alias = "mods")]
    Modules(SessionArgs),
    #[command(about = "List trace keyframes")]
    Keyframes(SessionArgs),
    #[command(about = "List trace exception events")]
    Exceptions(SessionArgs),
    Events {
        #[command(subcommand)]
        command: EventsCommand,
    },
    Module {
        #[command(subcommand)]
        command: ModuleCommand,
    },
    Address(AddressInfoArgs),
    Cursor {
        #[command(subcommand)]
        command: CursorCommand,
    },
    #[command(about = "List active threads at a cursor", alias = "active")]
    ActiveThreads(CursorArgs),
    Position {
        #[command(subcommand)]
        command: PositionCommand,
    },
    #[command(about = "Step or trace a cursor")]
    Step(StepArgs),
    #[command(about = "Read compact register/thread state", alias = "regs")]
    Registers(CursorArgs),
    #[command(
        about = "Read full x64 scalar and vector register context",
        alias = "ctx"
    )]
    RegisterContext(RegisterContextArgs),
    Stack {
        #[command(subcommand)]
        command: StackCommand,
    },
    #[command(about = "Read the process command line", alias = "cmdline")]
    CommandLine(CursorArgs),
    Memory {
        #[command(subcommand)]
        command: MemoryCommand,
    },
    Watchpoint(WatchpointArgs),
}

#[derive(Debug, Subcommand)]
enum DaemonCommand {
    Start {
        #[arg(
            long,
            help = "Spawn windbg-tool daemon mode and return after it starts"
        )]
        detach: bool,
    },
    Status,
    Ensure,
    Shutdown,
}

#[derive(Debug, Subcommand)]
enum DbgEngCommand {
    #[command(about = "Start a DbgEng user-mode process server and wait for it to exit")]
    Server(DbgEngServerArgs),
}

#[derive(Debug, Subcommand)]
enum WindbgCommand {
    #[command(about = "Show installed and latest WinDbg package status")]
    Status(WindbgCommonArgs),
    #[command(about = "Download, verify, and extract the latest WinDbg package")]
    Install(WindbgInstallArgs),
    #[command(about = "Install the latest WinDbg package if a newer version is available")]
    Update(WindbgCommonArgs),
    #[command(about = "Print the installed DbgX.Shell.exe path")]
    Path(WindbgCommonArgs),
    #[command(about = "Ensure WinDbg is installed, then run DbgX.Shell.exe")]
    Run(WindbgRunArgs),
}

#[derive(Debug, Subcommand)]
enum TraceCommand {
    #[command(about = "Enumerate traces in a .run/.idx/.ttd file without opening a session")]
    List(TraceListArgs),
}

#[derive(Debug, Subcommand)]
enum IndexCommand {
    #[command(about = "Show TTD index status for a loaded session")]
    Status(SessionArgs),
    #[command(about = "Show TTD index file statistics for a loaded session")]
    Stats(SessionArgs),
    #[command(about = "Synchronously build the TTD index for a loaded session")]
    Build(IndexBuildArgs),
}

#[derive(Debug, Subcommand)]
enum EventsCommand {
    Modules(SessionArgs),
    Threads(SessionArgs),
}

#[derive(Debug, Subcommand)]
enum ModuleCommand {
    Info(ModuleInfoArgs),
}

#[derive(Debug, Subcommand)]
enum CursorCommand {
    Create(SessionArgs),
    Modules(CursorArgs),
}

#[derive(Debug, Subcommand)]
enum PositionCommand {
    Get(CursorArgs),
    Set(PositionSetArgs),
}

#[derive(Debug, Subcommand)]
enum StackCommand {
    Info(CursorArgs),
    Read(StackReadArgs),
}

#[derive(Debug, Subcommand)]
enum MemoryCommand {
    Read(MemoryReadArgs),
    Range(MemoryRangeArgs),
    Buffer(MemoryBufferArgs),
    Watchpoint(WatchpointArgs),
}

#[derive(Debug, Args)]
struct DbgEngServerArgs {
    #[arg(
        short = 't',
        long,
        help = "DbgEng process-server transport, for example tcp:port=5005"
    )]
    transport: String,
}

#[derive(Debug, Args)]
struct WindbgCommonArgs {
    #[arg(long = "install-dir")]
    install_dir: Option<PathBuf>,
    #[arg(
        long,
        help = "Accepted for command symmetry; windbg-tool emits JSON by default"
    )]
    json: bool,
}

#[derive(Debug, Args)]
struct WindbgInstallArgs {
    #[arg(long = "install-dir")]
    install_dir: Option<PathBuf>,
    #[arg(long)]
    force: bool,
    #[arg(
        long,
        help = "Accepted for command symmetry; windbg-tool emits JSON by default"
    )]
    json: bool,
}

#[derive(Debug, Args)]
struct WindbgRunArgs {
    #[arg(long = "install-dir")]
    install_dir: Option<PathBuf>,
    #[arg(
        long,
        help = "Accepted for command symmetry; windbg-tool emits JSON by default"
    )]
    json: bool,
    #[arg(last = true, trailing_var_arg = true)]
    args: Vec<String>,
}

#[derive(Debug, Args)]
struct LoadArgs {
    trace_path: PathBuf,
    #[arg(long = "companion-path")]
    companion_path: Option<PathBuf>,
    #[arg(long = "trace-index")]
    trace_index: Option<u32>,
    #[arg(long = "binary-path")]
    binary_paths: Vec<PathBuf>,
    #[arg(long = "symbol-path")]
    symbol_paths: Vec<String>,
    #[arg(long)]
    symcache_dir: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct OpenArgs {
    trace_path: PathBuf,
    #[arg(long = "companion-path")]
    companion_path: Option<PathBuf>,
    #[arg(long = "trace-index")]
    trace_index: Option<u32>,
    #[arg(short = 'b', long = "binary-path")]
    binary_paths: Vec<PathBuf>,
    #[arg(long = "symbol-path")]
    symbol_paths: Vec<String>,
    #[arg(long)]
    symcache_dir: Option<PathBuf>,
    #[arg(
        long,
        help = "Optional initial cursor position as HEX:HEX, percent, or JSON object"
    )]
    position: Option<String>,
    #[arg(long)]
    thread_unique_id: Option<u64>,
}

#[derive(Debug, Args)]
struct TraceListArgs {
    trace_path: PathBuf,
    #[arg(long = "companion-path")]
    companion_path: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct IndexBuildArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(
        long = "flag",
        value_parser = [
            "delete-existing-unloadable",
            "delete_existing_unloadable",
            "temporary",
            "temporary-index-file",
            "temporary_index_file",
            "self-contained",
            "self_contained",
            "make-self-contained",
            "make_self_contained",
            "all",
            "none"
        ]
    )]
    flags: Vec<String>,
}

#[derive(Debug, Args)]
struct SessionArgs {
    #[arg(short = 's', long)]
    session: u64,
}

#[derive(Debug, Args)]
struct CursorArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
}

#[derive(Debug, Args)]
struct SchemaArgs {
    tool: String,
}

#[derive(Debug, Args)]
struct ToolArgs {
    name: String,
    #[arg(
        long,
        default_value = "{}",
        conflicts_with = "json_file",
        help = "JSON object passed as tool arguments"
    )]
    json: String,
    #[arg(
        long,
        value_name = "PATH",
        help = "Read tool arguments from a JSON file"
    )]
    json_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ModuleInfoArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    address: Option<String>,
}

#[derive(Debug, Args)]
struct AddressInfoArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    address: String,
}

#[derive(Debug, Args)]
struct PositionSetArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(
        long,
        help = "Position as HEX:HEX, percent 0-100, or JSON position object"
    )]
    position: String,
    #[arg(long)]
    thread_unique_id: Option<u64>,
}

#[derive(Debug, Args)]
struct StepArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long, value_parser = ["forward", "backward"])]
    direction: Option<String>,
    #[arg(long, value_parser = ["step", "trace"])]
    kind: Option<String>,
    #[arg(long)]
    count: Option<u32>,
}

#[derive(Debug, Args)]
struct RegisterContextArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    thread_id: Option<u32>,
}

#[derive(Debug, Args)]
struct StackReadArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    size: Option<u32>,
    #[arg(long)]
    offset_from_sp: Option<i64>,
    #[arg(long)]
    decode_pointers: bool,
}

#[derive(Debug, Args)]
struct MemoryReadArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    address: String,
    #[arg(long)]
    size: u32,
    #[arg(long, value_parser = query_policy_values())]
    policy: Option<String>,
}

#[derive(Debug, Args)]
struct MemoryRangeArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    address: String,
    #[arg(long)]
    max_bytes: Option<u32>,
    #[arg(long, value_parser = query_policy_values())]
    policy: Option<String>,
}

#[derive(Debug, Args)]
struct MemoryBufferArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    address: String,
    #[arg(long)]
    size: u32,
    #[arg(long)]
    max_ranges: Option<u32>,
    #[arg(long, value_parser = query_policy_values())]
    policy: Option<String>,
}

#[derive(Debug, Args)]
struct WatchpointArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    address: String,
    #[arg(long)]
    size: u32,
    #[arg(long, value_parser = [
        "read",
        "write",
        "execute",
        "code_fetch",
        "overwrite",
        "data_mismatch",
        "new_data",
        "redundant_data",
        "read_write",
        "all"
    ])]
    access: String,
    #[arg(long, value_parser = ["previous", "next"])]
    direction: String,
    #[arg(long)]
    thread_unique_id: Option<u64>,
}

pub async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let output = OutputOptions {
        compact: cli.compact,
        field: cli.field,
        raw: cli.raw,
    };
    let pipe = cli.pipe.unwrap_or_else(default_pipe_name);

    match cli.command {
        None | Some(Commands::Mcp) => run_mcp_stdio().await,
        Some(Commands::Discover) => print_value(discover_manifest(), &output),
        Some(Commands::Schema(args)) => print_value(tool_schema(&args.tool)?, &output),
        Some(Commands::Trace { command }) => match command {
            TraceCommand::List(args) => call_and_print(pipe, trace_list_call(args), &output).await,
        },
        Some(Commands::TraceList(args)) => {
            call_and_print(pipe, trace_list_call(args), &output).await
        }
        Some(Commands::Daemon { command }) => run_daemon_command(command, pipe, &output).await,
        Some(Commands::DbgEng { command }) => match command {
            DbgEngCommand::Server(args) => run_dbgeng_server(args, &output),
        },
        Some(Commands::DbgSrv(args)) => run_dbgeng_server(args, &output),
        Some(Commands::Windbg { command }) => run_windbg_command(command, &output),
        Some(Commands::Open(args)) => open_and_print(pipe, args, &output).await,
        Some(Commands::Load(args)) => call_and_print(pipe, load_call(args), &output).await,
        Some(Commands::Sessions) => {
            let client = DaemonClient::new(pipe);
            print_value(client.sessions().await?, &output)
        }
        Some(Commands::Close(args)) => {
            call_and_print(pipe, session_call("ttd_close_trace", args), &output).await
        }
        Some(Commands::Info(args)) => {
            call_and_print(pipe, session_call("ttd_trace_info", args), &output).await
        }
        Some(Commands::Capabilities(args)) => {
            call_and_print(pipe, session_call("ttd_capabilities", args), &output).await
        }
        Some(Commands::Index { command }) => match command {
            IndexCommand::Status(args) => {
                call_and_print(pipe, session_call("ttd_index_status", args), &output).await
            }
            IndexCommand::Stats(args) => {
                call_and_print(pipe, session_call("ttd_index_stats", args), &output).await
            }
            IndexCommand::Build(args) => {
                call_and_print(pipe, index_build_call(args), &output).await
            }
        },
        Some(Commands::Tools) => print_value(json!({ "tools": tools::definitions() }), &output),
        Some(Commands::Tool(args)) => {
            let name = args.name.clone();
            let arguments = tool_arguments(args)?;
            call_and_print(pipe, ToolCall { name, arguments }, &output).await
        }
        Some(Commands::Threads(args)) => {
            call_and_print(pipe, session_call("ttd_list_threads", args), &output).await
        }
        Some(Commands::Modules(args)) => {
            call_and_print(pipe, session_call("ttd_list_modules", args), &output).await
        }
        Some(Commands::Keyframes(args)) => {
            call_and_print(pipe, session_call("ttd_list_keyframes", args), &output).await
        }
        Some(Commands::Exceptions(args)) => {
            call_and_print(pipe, session_call("ttd_list_exceptions", args), &output).await
        }
        Some(Commands::Events { command }) => match command {
            EventsCommand::Modules(args) => {
                call_and_print(pipe, session_call("ttd_module_events", args), &output).await
            }
            EventsCommand::Threads(args) => {
                call_and_print(pipe, session_call("ttd_thread_events", args), &output).await
            }
        },
        Some(Commands::Module { command }) => match command {
            ModuleCommand::Info(args) => {
                call_and_print(pipe, module_info_call(args)?, &output).await
            }
        },
        Some(Commands::Address(args)) => {
            call_and_print(pipe, address_info_call(args), &output).await
        }
        Some(Commands::Cursor { command }) => match command {
            CursorCommand::Create(args) => {
                call_and_print(pipe, session_call("ttd_cursor_create", args), &output).await
            }
            CursorCommand::Modules(args) => {
                call_and_print(pipe, cursor_call("ttd_cursor_modules", args), &output).await
            }
        },
        Some(Commands::ActiveThreads(args)) => {
            call_and_print(pipe, cursor_call("ttd_active_threads", args), &output).await
        }
        Some(Commands::Position { command }) => match command {
            PositionCommand::Get(args) => {
                call_and_print(pipe, cursor_call("ttd_position_get", args), &output).await
            }
            PositionCommand::Set(args) => {
                call_and_print(pipe, position_set_call(args)?, &output).await
            }
        },
        Some(Commands::Step(args)) => call_and_print(pipe, step_call(args), &output).await,
        Some(Commands::Registers(args)) => {
            call_and_print(pipe, cursor_call("ttd_registers", args), &output).await
        }
        Some(Commands::RegisterContext(args)) => {
            call_and_print(pipe, register_context_call(args), &output).await
        }
        Some(Commands::Stack { command }) => match command {
            StackCommand::Info(args) => {
                call_and_print(pipe, cursor_call("ttd_stack_info", args), &output).await
            }
            StackCommand::Read(args) => call_and_print(pipe, stack_read_call(args), &output).await,
        },
        Some(Commands::CommandLine(args)) => {
            call_and_print(pipe, cursor_call("ttd_command_line", args), &output).await
        }
        Some(Commands::Memory { command }) => match command {
            MemoryCommand::Read(args) => {
                call_and_print(pipe, memory_read_call(args)?, &output).await
            }
            MemoryCommand::Range(args) => {
                call_and_print(pipe, memory_range_call(args)?, &output).await
            }
            MemoryCommand::Buffer(args) => {
                call_and_print(pipe, memory_buffer_call(args)?, &output).await
            }
            MemoryCommand::Watchpoint(args) => {
                call_and_print(pipe, watchpoint_call(args)?, &output).await
            }
        },
        Some(Commands::Watchpoint(args)) => {
            call_and_print(pipe, watchpoint_call(args)?, &output).await
        }
    }
}

fn run_dbgeng_server(args: DbgEngServerArgs, output: &OutputOptions) -> anyhow::Result<()> {
    let result = start_process_server(ProcessServerOptions {
        transport: args.transport,
    })?;
    print_value(serde_json::to_value(result)?, output)
}

fn run_windbg_command(command: WindbgCommand, output: &OutputOptions) -> anyhow::Result<()> {
    match command {
        WindbgCommand::Status(args) => {
            let _ = args.json;
            let manager = WindbgManager::new(args.install_dir)?;
            print_value(serde_json::to_value(manager.status(true)?)?, output)
        }
        WindbgCommand::Install(args) => {
            let _ = args.json;
            let manager = WindbgManager::new(args.install_dir)?;
            print_value(serde_json::to_value(manager.install(args.force)?)?, output)
        }
        WindbgCommand::Update(args) => {
            let _ = args.json;
            let manager = WindbgManager::new(args.install_dir)?;
            print_value(serde_json::to_value(manager.update()?)?, output)
        }
        WindbgCommand::Path(args) => {
            let _ = args.json;
            let manager = WindbgManager::new(args.install_dir)?;
            print_value(json!({ "dbgx_path": manager.dbgx_path()? }), output)
        }
        WindbgCommand::Run(args) => {
            let _ = args.json;
            let manager = WindbgManager::new(args.install_dir)?;
            let installed = manager.install(false)?;
            let status = Command::new(&installed.dbgx_path)
                .args(&args.args)
                .status()
                .with_context(|| format!("launching {}", installed.dbgx_path.display()))?;
            print_value(
                json!({
                    "dbgx_path": installed.dbgx_path,
                    "success": status.success(),
                    "exit_code": status.code(),
                }),
                output,
            )
        }
    }
}

async fn run_mcp_stdio() -> anyhow::Result<()> {
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

async fn run_daemon_command(
    command: DaemonCommand,
    pipe: String,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    match command {
        DaemonCommand::Start { detach } => {
            if detach {
                let client = DaemonClient::new(pipe.clone());
                if let Ok(health) = client.health().await {
                    return print_value(health, output);
                }
                spawn_daemon(&pipe)?;
                let client = DaemonClient::new(pipe);
                print_value(client.health().await?, output)
            } else {
                run_daemon(pipe).await
            }
        }
        DaemonCommand::Status => {
            let client = DaemonClient::new(pipe);
            print_value(client.health().await?, output)
        }
        DaemonCommand::Ensure => {
            let client = DaemonClient::new(pipe.clone());
            if let Ok(health) = client.health().await {
                return print_value(health, output);
            }
            spawn_daemon(&pipe)?;
            let client = DaemonClient::new(pipe);
            print_value(client.health().await?, output)
        }
        DaemonCommand::Shutdown => {
            let client = DaemonClient::new(pipe);
            print_value(client.shutdown().await?, output)
        }
    }
}

async fn open_and_print(
    pipe: String,
    args: OpenArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let client = DaemonClient::new(pipe);
    let load = client
        .call_tool(load_call(LoadArgs {
            trace_path: args.trace_path,
            companion_path: args.companion_path,
            trace_index: args.trace_index,
            binary_paths: args.binary_paths,
            symbol_paths: args.symbol_paths,
            symcache_dir: args.symcache_dir,
        }))
        .await?;
    let session_id = load["session_id"]
        .as_u64()
        .context("ttd_load_trace response did not include session_id")?;
    let cursor = client
        .call_tool(session_call(
            "ttd_cursor_create",
            SessionArgs {
                session: session_id,
            },
        ))
        .await?;
    let cursor_id = cursor["cursor_id"]
        .as_u64()
        .context("ttd_cursor_create response did not include cursor_id")?;

    let position = if let Some(position) = args.position {
        Some(
            client
                .call_tool(position_set_call(PositionSetArgs {
                    session: session_id,
                    cursor: cursor_id,
                    position,
                    thread_unique_id: args.thread_unique_id,
                })?)
                .await?,
        )
    } else {
        None
    };

    print_value(
        json!({
            "session_id": session_id,
            "cursor_id": cursor_id,
            "load": load,
            "cursor": cursor,
            "position": position,
        }),
        output,
    )
}

fn spawn_daemon(pipe: &str) -> anyhow::Result<()> {
    let daemon_path = daemon_exe_path()?;
    Command::new(&daemon_path)
        .arg("daemon")
        .arg("start")
        .arg("--pipe")
        .arg(pipe)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("spawning {}", daemon_path.display()))?;
    Ok(())
}

fn daemon_exe_path() -> anyhow::Result<PathBuf> {
    std::env::current_exe().context("reading current executable path")
}

async fn call_and_print(
    pipe: String,
    call: ToolCall,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let client = DaemonClient::new(pipe);
    print_value(client.call_tool(call).await?, output)
}

fn load_call(args: LoadArgs) -> ToolCall {
    ToolCall {
        name: "ttd_load_trace".to_string(),
        arguments: json!({
            "trace_path": args.trace_path,
            "companion_path": args.companion_path,
            "trace_index": args.trace_index,
            "symbols": {
                "binary_paths": args.binary_paths,
                "symbol_paths": args.symbol_paths,
                "symcache_dir": args.symcache_dir,
            },
        }),
    }
}

fn trace_list_call(args: TraceListArgs) -> ToolCall {
    ToolCall {
        name: "ttd_trace_list".to_string(),
        arguments: json!({
            "trace_path": args.trace_path,
            "companion_path": args.companion_path,
        }),
    }
}

fn index_build_call(args: IndexBuildArgs) -> ToolCall {
    ToolCall {
        name: "ttd_build_index".to_string(),
        arguments: json!({
            "session_id": args.session,
            "flags": args.flags,
        }),
    }
}

fn tool_schema(name: &str) -> anyhow::Result<Value> {
    tools::definitions()
        .into_iter()
        .find(|tool| tool.name.as_ref() == name)
        .map(serde_json::to_value)
        .transpose()?
        .with_context(|| format!("unknown MCP tool: {name}"))
}

fn discover_manifest() -> Value {
    json!({
        "name": "windbg-tool",
        "purpose": "Single executable for WinDbg Time Travel Debugging MCP stdio, daemon mode, and CLI commands",
        "daemon": {
            "transport": "HTTP over Windows named pipes",
            "start": "windbg-tool daemon ensure",
            "status": "windbg-tool daemon status",
            "shutdown": "windbg-tool daemon shutdown",
            "pipe_override": "--pipe \\\\.\\pipe\\windbg-tool-custom, WINDBG_TOOL_PIPE, or legacy TTD_MCP_PIPE"
        },
        "output_controls": {
            "default": "pretty JSON",
            "compact": "--compact emits single-line JSON",
            "field": "--field path.to.value extracts a JSON field",
            "raw": "--raw prints selected scalar fields without JSON quoting"
        },
        "recommended_flow": [
            "windbg-tool daemon ensure",
            "windbg-tool --field session_id --raw open trace.run --binary-path trace.exe",
            "windbg-tool sessions",
            "windbg-tool position set --session <id> --cursor <id> --position 50",
            "windbg-tool registers --session <id> --cursor <id>"
        ],
        "command_groups": {
            "discovery": ["discover", "tools", "schema <tool>"],
            "daemon": ["daemon ensure", "daemon status", "daemon shutdown", "sessions"],
            "dbgeng": ["dbgeng server --transport <transport>", "dbgsrv --transport <transport>"],
            "windbg": ["windbg status", "windbg install", "windbg update", "windbg path", "windbg run -- <args>"],
            "session": ["open", "load", "close", "info", "capabilities"],
            "index": ["index status", "index stats", "index build"],
            "metadata": ["trace list", "trace-list", "threads", "modules", "keyframes", "exceptions", "events modules", "events threads", "module info"],
            "navigation": ["cursor create", "cursor modules", "active-threads", "position get", "position set", "step"],
            "state": ["registers", "register-context", "stack info", "stack read", "command-line", "address"],
            "memory": ["memory read", "memory range", "memory buffer", "memory watchpoint", "watchpoint"],
            "escape_hatch": ["tool <name> --json <object>", "tool <name> --json-file <path>"]
        },
        "tool_command_map": tool_command_map(),
        "ttd_api_coverage": ttd_api_coverage_manifest(),
        "examples": [
            {
                "goal": "Start a DbgEng TCP process server",
                "command": "windbg-tool dbgeng server --transport tcp:port=5005"
            },
            {
                "goal": "Install or update WinDbg in the per-user tool cache",
                "command": "windbg-tool windbg update"
            },
            {
                "goal": "Open a trace and capture handles",
                "command": "windbg-tool --field session_id --raw open traces\\ping\\ping01.run --binary-path traces\\ping\\ping.exe"
            },
            {
                "goal": "Inspect the schema for raw MCP memory reads",
                "command": "windbg-tool schema ttd_read_memory"
            },
            {
                "goal": "Read memory with compact JSON output",
                "command": "windbg-tool --compact memory read --session 1 --cursor 1 --address 0x7ffdf000 --size 64"
            }
        ]
    })
}

fn tool_command_map() -> Value {
    json!([
        { "tool": "ttd_load_trace", "commands": ["load", "open"] },
        { "tool": "ttd_trace_list", "commands": ["trace list", "trace-list"] },
        { "tool": "ttd_close_trace", "commands": ["close"] },
        { "tool": "ttd_trace_info", "commands": ["info"] },
        { "tool": "ttd_capabilities", "commands": ["capabilities", "caps"] },
        { "tool": "ttd_index_status", "commands": ["index status"] },
        { "tool": "ttd_index_stats", "commands": ["index stats"] },
        { "tool": "ttd_build_index", "commands": ["index build"] },
        { "tool": "ttd_list_threads", "commands": ["threads"] },
        { "tool": "ttd_list_modules", "commands": ["modules", "mods"] },
        { "tool": "ttd_cursor_modules", "commands": ["cursor modules"] },
        { "tool": "ttd_list_keyframes", "commands": ["keyframes"] },
        { "tool": "ttd_module_events", "commands": ["events modules"] },
        { "tool": "ttd_thread_events", "commands": ["events threads"] },
        { "tool": "ttd_module_info", "commands": ["module info"] },
        { "tool": "ttd_address_info", "commands": ["address"] },
        { "tool": "ttd_active_threads", "commands": ["active-threads", "active"] },
        { "tool": "ttd_list_exceptions", "commands": ["exceptions"] },
        { "tool": "ttd_cursor_create", "commands": ["cursor create", "open"] },
        { "tool": "ttd_position_get", "commands": ["position get"] },
        { "tool": "ttd_position_set", "commands": ["position set", "open --position"] },
        { "tool": "ttd_step", "commands": ["step"] },
        { "tool": "ttd_registers", "commands": ["registers", "regs"] },
        { "tool": "ttd_register_context", "commands": ["register-context", "ctx"] },
        { "tool": "ttd_stack_info", "commands": ["stack info"] },
        { "tool": "ttd_stack_read", "commands": ["stack read"] },
        { "tool": "ttd_command_line", "commands": ["command-line", "cmdline"] },
        { "tool": "ttd_read_memory", "commands": ["memory read"] },
        { "tool": "ttd_memory_range", "commands": ["memory range"] },
        { "tool": "ttd_memory_buffer", "commands": ["memory buffer"] },
        { "tool": "ttd_memory_watchpoint", "commands": ["memory watchpoint", "watchpoint"] }
    ])
}

fn ttd_api_coverage_manifest() -> Value {
    json!({
        "source": "Microsoft.TimeTravelDebugging.Apis 0.9.5 TTD Replay headers",
        "statuses": {
            "implemented": "Native bridge, Rust facade, MCP tool, and focused CLI coverage exist.",
            "partial": "Some API coverage exists, but meaningful TTD functionality remains missing.",
            "gap": "No focused native bridge/MCP/CLI coverage yet."
        },
        "capabilities": [
            {
                "id": "trace_session",
                "status": "implemented",
                "ttd_api": ["IReplayEngine::Initialize", "IReplayEngine::Destroy"],
                "native_bridge": ["ttd_mcp_open_trace", "ttd_mcp_close_trace"],
                "mcp_tools": ["ttd_load_trace", "ttd_close_trace", "ttd_capabilities"],
                "cli_commands": ["open", "load", "close", "capabilities", "caps"],
                "notes": "Direct single-trace loading is covered; packed trace enumeration is tracked separately."
            },
            {
                "id": "trace_metadata",
                "status": "implemented",
                "ttd_api": ["GetPebAddress", "GetSystemInfo", "GetFirstPosition", "GetLastPosition", "GetLifetime"],
                "native_bridge": ["ttd_mcp_trace_info"],
                "mcp_tools": ["ttd_trace_info"],
                "cli_commands": ["info"],
                "notes": "Current output includes core metadata and counts, but full system/recording/file metadata is partial."
            },
            {
                "id": "trace_thread_module_exception_lists",
                "status": "implemented",
                "ttd_api": ["GetThreadList", "GetModuleInstanceList", "GetExceptionEventList", "GetKeyframeList", "GetModuleLoadedEventList", "GetModuleUnloadedEventList", "GetThreadCreatedEventList", "GetThreadTerminatedEventList"],
                "native_bridge": ["ttd_mcp_list_threads", "ttd_mcp_list_modules", "ttd_mcp_list_exceptions", "ttd_mcp_list_keyframes", "ttd_mcp_list_module_events", "ttd_mcp_list_thread_events"],
                "mcp_tools": ["ttd_list_threads", "ttd_list_modules", "ttd_list_exceptions", "ttd_list_keyframes", "ttd_module_events", "ttd_thread_events", "ttd_module_info"],
                "cli_commands": ["threads", "modules", "mods", "exceptions", "keyframes", "events modules", "events threads", "module info"],
                "notes": "Common trace-wide lists and event lists are covered."
            },
            {
                "id": "cursor_navigation",
                "status": "implemented",
                "ttd_api": ["NewCursor", "GetPosition", "SetPosition", "SetPositionOnThread", "ReplayForward", "ReplayBackward"],
                "native_bridge": ["ttd_mcp_new_cursor", "ttd_mcp_cursor_position", "ttd_mcp_set_position", "ttd_mcp_set_position_on_thread", "ttd_mcp_step_cursor"],
                "mcp_tools": ["ttd_cursor_create", "ttd_position_get", "ttd_position_set", "ttd_step", "ttd_active_threads", "ttd_cursor_modules"],
                "cli_commands": ["cursor create", "position get", "position set", "step", "active-threads", "active", "cursor modules"],
                "notes": "Basic navigation is covered; masks, position watchpoints, limits, clear/clone/interrupt are gaps."
            },
            {
                "id": "register_state",
                "status": "implemented",
                "ttd_api": ["GetThreadInfo", "GetTebAddress", "GetProgramCounter", "GetStackPointer", "GetFramePointer", "GetBasicReturnValue", "GetCrossPlatformContext", "GetAvxExtendedContext"],
                "native_bridge": ["ttd_mcp_cursor_state", "ttd_mcp_x64_context", "ttd_mcp_active_threads"],
                "mcp_tools": ["ttd_registers", "ttd_register_context", "ttd_active_threads"],
                "cli_commands": ["registers", "regs", "register-context", "ctx", "active-threads", "active"],
                "notes": "x64 scalar and SIMD state is covered; x86/ARM/ARM64 models remain gaps."
            },
            {
                "id": "memory_queries",
                "status": "implemented",
                "ttd_api": ["QueryMemoryRange", "QueryMemoryBuffer", "QueryMemoryBufferWithRanges", "QueryMemoryPolicy"],
                "native_bridge": ["ttd_mcp_read_memory", "ttd_mcp_query_memory_range", "ttd_mcp_query_memory_buffer_with_ranges"],
                "mcp_tools": ["ttd_read_memory", "ttd_memory_range", "ttd_memory_buffer", "ttd_address_info"],
                "cli_commands": ["memory read", "memory range", "memory buffer", "address"],
                "notes": "Per-call memory policy is covered; cursor default memory policy is a gap."
            },
            {
                "id": "stack_process_helpers",
                "status": "implemented",
                "ttd_api": ["GetTebAddress", "GetStackPointer", "QueryMemoryBuffer", "GetPebAddress"],
                "native_bridge": ["ttd_mcp_cursor_state", "ttd_mcp_read_memory", "ttd_mcp_trace_info"],
                "mcp_tools": ["ttd_stack_info", "ttd_stack_read", "ttd_command_line"],
                "cli_commands": ["stack info", "stack read", "command-line", "cmdline"],
                "notes": "These are value-added helpers built from lower-level TTD state and memory APIs."
            },
            {
                "id": "memory_watchpoint_first_hit",
                "status": "implemented",
                "ttd_api": ["DataAccessMask", "MemoryWatchpointData", "AddMemoryWatchpoint", "RemoveMemoryWatchpoint", "ReplayForward", "ReplayBackward"],
                "native_bridge": ["ttd_mcp_memory_watchpoint"],
                "mcp_tools": ["ttd_memory_watchpoint"],
                "cli_commands": ["memory watchpoint", "watchpoint"],
                "notes": "First-hit replay is covered with the full TTD DataAccessMask vocabulary and optional thread filters; multi-hit sweep jobs remain a callback-sweep gap."
            },
            {
                "id": "trace_list_packs",
                "status": "implemented",
                "ttd_api": ["ITraceList::LoadFile", "GetTraceCount", "GetTraceInfo", "OpenTrace"],
                "native_bridge": ["ttd_mcp_list_traces", "ttd_mcp_open_trace_at_index"],
                "mcp_tools": ["ttd_trace_list", "ttd_load_trace"],
                "cli_commands": ["trace list", "trace-list", "load --trace-index", "open --trace-index"],
                "notes": "Covers .ttd packs, companion trace/index handling, and selecting traces by index."
            },
            {
                "id": "index_operations",
                "status": "implemented",
                "ttd_api": ["GetIndexStatus", "GetIndexFileStats", "BuildIndex"],
                "native_bridge": ["ttd_mcp_index_status", "ttd_mcp_index_file_stats", "ttd_mcp_build_index"],
                "mcp_tools": ["ttd_index_status", "ttd_index_stats", "ttd_build_index"],
                "cli_commands": ["index status", "index stats", "index build"],
                "notes": "Synchronous status, stats, and build are covered; daemon-managed background jobs with cancellation remain future replay-job work."
            },
            {
                "id": "recording_client_timeline",
                "status": "gap",
                "ttd_api": ["GetRecordClientList", "GetCustomEventList", "GetActivityList", "GetIslandList"],
                "native_bridge": [],
                "mcp_tools": [],
                "cli_commands": [],
                "notes": "Needed for custom event, activity, and island metadata emitted by recording clients."
            },
            {
                "id": "replay_masks_position_watchpoints",
                "status": "gap",
                "ttd_api": ["SetEventMask", "SetGapKindMask", "SetGapEventMask", "SetExceptionMask", "SetReplayFlags", "AddPositionWatchpoint", "RemovePositionWatchpoint", "Clear", "InterruptReplay"],
                "native_bridge": [],
                "mcp_tools": [],
                "cli_commands": [],
                "notes": "Needed for agent-controlled replay-to-event workflows and cancellable long-running replay."
            },
            {
                "id": "callback_sweeps",
                "status": "gap",
                "ttd_api": ["SetMemoryWatchpointCallback", "SetPositionWatchpointCallback", "SetGapEventCallback", "SetReplayProgressCallback", "SetThreadContinuityBreakCallback", "SetFallbackCallback", "SetCallReturnCallback", "SetIndirectJumpCallback", "SetRegisterChangedCallback"],
                "native_bridge": [],
                "mcp_tools": [],
                "cli_commands": [],
                "notes": "Needed for bounded call traces, jump traces, register-change traces, fallback scans, progress, and multi-hit watchpoint collection."
            },
            {
                "id": "module_symbol_enrichment",
                "status": "gap",
                "ttd_api": ["Module::Checksum", "Module::Timestamp"],
                "native_bridge": [],
                "mcp_tools": [],
                "cli_commands": [],
                "notes": "Module checksum/timestamp should be exposed first; symbol/source helpers require DbgHelp/SymSrv integration."
            }
        ]
    })
}

fn session_call(name: &str, args: SessionArgs) -> ToolCall {
    ToolCall {
        name: name.to_string(),
        arguments: json!({ "session_id": args.session }),
    }
}

fn cursor_call(name: &str, args: CursorArgs) -> ToolCall {
    ToolCall {
        name: name.to_string(),
        arguments: cursor_json(args.session, args.cursor),
    }
}

fn cursor_json(session: u64, cursor: u64) -> Value {
    json!({
        "session_id": session,
        "cursor_id": cursor,
    })
}

fn tool_arguments(args: ToolArgs) -> anyhow::Result<Value> {
    let value = if let Some(path) = args.json_file {
        let text = fs::read_to_string(&path)
            .with_context(|| format!("reading JSON arguments from {}", path.display()))?;
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?
    } else {
        serde_json::from_str(&args.json).context("parsing --json")?
    };
    ensure_json_object(value)
}

fn module_info_call(args: ModuleInfoArgs) -> anyhow::Result<ToolCall> {
    if args.name.is_none() && args.address.is_none() {
        bail!("module info requires --name or --address")
    }
    let mut object = session_object(args.session);
    insert_option(&mut object, "name", args.name.map(Value::String));
    insert_option(
        &mut object,
        "address",
        args.address
            .as_deref()
            .map(parse_u64_argument)
            .transpose()?
            .map(Value::from),
    );
    Ok(ToolCall {
        name: "ttd_module_info".to_string(),
        arguments: Value::Object(object),
    })
}

fn address_info_call(args: AddressInfoArgs) -> ToolCall {
    ToolCall {
        name: "ttd_address_info".to_string(),
        arguments: json!({
            "session_id": args.session,
            "cursor_id": args.cursor,
            "address": args.address,
        }),
    }
}

fn position_set_call(args: PositionSetArgs) -> anyhow::Result<ToolCall> {
    let position = parse_position_argument(&args.position)?;
    let mut object = cursor_object(args.session, args.cursor);
    object.insert("position".to_string(), position);
    insert_option(
        &mut object,
        "thread_unique_id",
        args.thread_unique_id.map(Value::from),
    );
    Ok(ToolCall {
        name: "ttd_position_set".to_string(),
        arguments: Value::Object(object),
    })
}

fn step_call(args: StepArgs) -> ToolCall {
    let mut object = cursor_object(args.session, args.cursor);
    insert_option(&mut object, "direction", args.direction.map(Value::String));
    insert_option(&mut object, "kind", args.kind.map(Value::String));
    insert_option(&mut object, "count", args.count.map(Value::from));
    ToolCall {
        name: "ttd_step".to_string(),
        arguments: Value::Object(object),
    }
}

fn register_context_call(args: RegisterContextArgs) -> ToolCall {
    let mut object = cursor_object(args.session, args.cursor);
    insert_option(&mut object, "thread_id", args.thread_id.map(Value::from));
    ToolCall {
        name: "ttd_register_context".to_string(),
        arguments: Value::Object(object),
    }
}

fn stack_read_call(args: StackReadArgs) -> ToolCall {
    let mut object = cursor_object(args.session, args.cursor);
    insert_option(&mut object, "size", args.size.map(Value::from));
    insert_option(
        &mut object,
        "offset_from_sp",
        args.offset_from_sp.map(Value::from),
    );
    if args.decode_pointers {
        object.insert("decode_pointers".to_string(), Value::Bool(true));
    }
    ToolCall {
        name: "ttd_stack_read".to_string(),
        arguments: Value::Object(object),
    }
}

fn memory_read_call(args: MemoryReadArgs) -> anyhow::Result<ToolCall> {
    let mut object = cursor_object(args.session, args.cursor);
    object.insert(
        "address".to_string(),
        Value::from(parse_u64_argument(&args.address)?),
    );
    object.insert("size".to_string(), Value::from(args.size));
    insert_option(&mut object, "policy", args.policy.map(Value::String));
    Ok(ToolCall {
        name: "ttd_read_memory".to_string(),
        arguments: Value::Object(object),
    })
}

fn memory_range_call(args: MemoryRangeArgs) -> anyhow::Result<ToolCall> {
    let mut object = cursor_object(args.session, args.cursor);
    object.insert(
        "address".to_string(),
        Value::from(parse_u64_argument(&args.address)?),
    );
    insert_option(&mut object, "max_bytes", args.max_bytes.map(Value::from));
    insert_option(&mut object, "policy", args.policy.map(Value::String));
    Ok(ToolCall {
        name: "ttd_memory_range".to_string(),
        arguments: Value::Object(object),
    })
}

fn memory_buffer_call(args: MemoryBufferArgs) -> anyhow::Result<ToolCall> {
    let mut object = cursor_object(args.session, args.cursor);
    object.insert(
        "address".to_string(),
        Value::from(parse_u64_argument(&args.address)?),
    );
    object.insert("size".to_string(), Value::from(args.size));
    insert_option(&mut object, "max_ranges", args.max_ranges.map(Value::from));
    insert_option(&mut object, "policy", args.policy.map(Value::String));
    Ok(ToolCall {
        name: "ttd_memory_buffer".to_string(),
        arguments: Value::Object(object),
    })
}

fn watchpoint_call(args: WatchpointArgs) -> anyhow::Result<ToolCall> {
    Ok(ToolCall {
        name: "ttd_memory_watchpoint".to_string(),
        arguments: json!({
            "session_id": args.session,
            "cursor_id": args.cursor,
            "address": parse_u64_argument(&args.address)?,
            "size": args.size,
            "access": args.access,
            "direction": args.direction,
            "thread_unique_id": args.thread_unique_id,
        }),
    })
}

fn session_object(session: u64) -> Map<String, Value> {
    let mut object = Map::new();
    object.insert("session_id".to_string(), Value::from(session));
    object
}

fn cursor_object(session: u64, cursor: u64) -> Map<String, Value> {
    let mut object = session_object(session);
    object.insert("cursor_id".to_string(), Value::from(cursor));
    object
}

fn insert_option(object: &mut Map<String, Value>, key: &str, value: Option<Value>) {
    if let Some(value) = value {
        object.insert(key.to_string(), value);
    }
}

fn parse_position_argument(value: &str) -> anyhow::Result<Value> {
    if let Ok(percent) = value.parse::<u8>() {
        return Ok(json!(percent));
    }
    if value.trim_start().starts_with('{') {
        return serde_json::from_str(value).context("parsing JSON position object");
    }
    Ok(json!(value))
}

fn parse_u64_argument(value: &str) -> anyhow::Result<u64> {
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).context("parsing hexadecimal integer");
    }
    value.parse::<u64>().context("parsing decimal integer")
}

fn ensure_json_object(value: Value) -> anyhow::Result<Value> {
    if value.is_object() {
        Ok(value)
    } else {
        bail!("tool arguments must be a JSON object")
    }
}

fn print_value(mut value: Value, output: &OutputOptions) -> anyhow::Result<()> {
    if let Some(path) = output.field.as_deref() {
        value = select_field(&value, path)?;
    }

    if output.raw {
        print_raw(value)
    } else if output.compact {
        println!("{}", serde_json::to_string(&value)?);
        Ok(())
    } else {
        println!("{}", serde_json::to_string_pretty(&value)?);
        Ok(())
    }
}

fn select_field(value: &Value, path: &str) -> anyhow::Result<Value> {
    let mut current = value;
    for segment in path.split('.') {
        if segment.is_empty() {
            bail!("field path contains an empty segment")
        }
        current = match current {
            Value::Object(object) => object
                .get(segment)
                .with_context(|| format!("field '{segment}' was not found"))?,
            Value::Array(items) => {
                let index = segment
                    .parse::<usize>()
                    .with_context(|| format!("array field segment '{segment}' is not an index"))?;
                items
                    .get(index)
                    .with_context(|| format!("array index {index} is out of range"))?
            }
            _ => bail!("field '{segment}' cannot be selected from a scalar value"),
        };
    }
    Ok(current.clone())
}

fn print_raw(value: Value) -> anyhow::Result<()> {
    match value {
        Value::Null => Ok(()),
        Value::Bool(value) => {
            println!("{value}");
            Ok(())
        }
        Value::Number(value) => {
            println!("{value}");
            Ok(())
        }
        Value::String(value) => {
            println!("{value}");
            Ok(())
        }
        other => {
            println!("{}", serde_json::to_string(&other)?);
            Ok(())
        }
    }
}

fn query_policy_values() -> [&'static str; 5] {
    [
        "default",
        "thread_local",
        "globally_conservative",
        "globally_aggressive",
        "in_fragment_aggressive",
    ]
}
