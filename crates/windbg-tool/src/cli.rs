use crate::pe_symbols::{diagnose_pe, export_symbol_value, read_export_symbols, ExportSymbol};
use anyhow::{bail, ensure, Context};
use clap::{Args, Parser, Subcommand, ValueEnum};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, NasmFormatter, OpKind, Register,
};
use rmcp::{transport::stdio, ServiceExt};
use serde_json::{json, Map, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use windbg_dbgeng::{
    live_launch_initial_break, start_process_server, LiveLaunchEnd, LiveLaunchOptions,
    ProcessServerOptions,
};
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
    #[command(
        about = "Show TimDbg-inspired diagnostic recipes without contacting the daemon",
        alias = "advise"
    )]
    Recipes(RecipeArgs),
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
    Live {
        #[command(subcommand)]
        command: LiveCommand,
    },
    #[command(
        name = "dbgsrv",
        about = "Start a DbgEng process server",
        alias = "debug-server"
    )]
    DbgSrv(DbgEngServerArgs),
    Remote {
        #[command(subcommand)]
        command: RemoteCommand,
    },
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
    Context {
        #[command(subcommand)]
        command: ContextCommand,
    },
    #[command(about = "Close a daemon-owned trace session")]
    Close(SessionArgs),
    #[command(about = "Show trace metadata for a loaded session")]
    Info(SessionArgs),
    Symbols {
        #[command(subcommand)]
        command: SymbolsCommand,
    },
    Source {
        #[command(subcommand)]
        command: SourceCommand,
    },
    #[command(alias = "arch")]
    Architecture {
        #[command(subcommand)]
        command: ArchitectureCommand,
    },
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
    Timeline {
        #[command(subcommand)]
        command: TimelineCommand,
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
    Replay {
        #[command(subcommand)]
        command: ReplayCommand,
    },
    Sweep {
        #[command(subcommand)]
        command: SweepCommand,
    },
    Breakpoint {
        #[command(subcommand)]
        command: BreakpointCommand,
    },
    Datamodel {
        #[command(subcommand)]
        command: DataModelCommand,
    },
    Target {
        #[command(subcommand)]
        command: TargetCommand,
    },
    #[command(
        about = "Disassemble memory at an address or the current cursor RIP",
        alias = "u"
    )]
    Disasm(DisasmArgs),
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
    Object {
        #[command(subcommand)]
        command: ObjectCommand,
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
enum LiveCommand {
    #[command(
        about = "Launch a process under DbgEng, wait for the initial event, then detach or terminate"
    )]
    Launch(LiveLaunchArgs),
    #[command(about = "Show live DbgEng command support and current limitations")]
    Capabilities,
}

#[derive(Debug, Subcommand)]
enum RemoteCommand {
    #[command(about = "Explain remote debugging workflow choices")]
    Explain(RemoteExplainArgs),
    #[command(about = "Generate a target-side remote server command")]
    ServerCommand(RemoteServerCommandArgs),
    #[command(about = "Generate a host-side WinDbg connection command")]
    ConnectCommand(RemoteConnectCommandArgs),
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
enum ContextCommand {
    #[command(about = "Capture an agent-ready snapshot of daemon/session/cursor state")]
    Snapshot(ContextSnapshotArgs),
}

#[derive(Debug, Subcommand)]
enum SymbolsCommand {
    #[command(about = "Diagnose symbol, binary, and source readiness for a session or module")]
    Diagnose(SymbolDiagnoseArgs),
    #[command(about = "Inspect a local PE image and print symbol-server identities")]
    Inspect(SymbolInspectArgs),
    #[command(about = "List local PE exports with optional filtering")]
    Exports(SymbolExportsArgs),
    #[command(about = "Find the nearest exported symbol for a TTD address")]
    Nearest(SymbolNearestArgs),
}

#[derive(Debug, Subcommand)]
enum SourceCommand {
    #[command(about = "Resolve a recorded source path under local search roots")]
    Resolve(SourceResolveArgs),
}

#[derive(Debug, Subcommand)]
enum ReplayCommand {
    #[command(about = "Show supported and missing replay-control capabilities")]
    Capabilities(SessionArgs),
    #[command(about = "Seek a cursor to a position, optionally scoped to a TTD thread")]
    To(ReplayToArgs),
    #[command(about = "Replay to the next/previous memory access for an address range")]
    WatchMemory(WatchpointArgs),
}

#[derive(Debug, Subcommand)]
enum SweepCommand {
    #[command(about = "Collect multiple memory watchpoint hits with explicit bounds")]
    WatchMemory(SweepWatchMemoryArgs),
}

#[derive(Debug, Subcommand)]
enum BreakpointCommand {
    #[command(about = "Show breakpoint/watchpoint manager support and current gaps")]
    Capabilities,
}

#[derive(Debug, Subcommand)]
enum DataModelCommand {
    #[command(about = "Show DbgEng data model / target model support and current gaps")]
    Capabilities,
}

#[derive(Debug, Subcommand)]
enum TargetCommand {
    #[command(
        about = "Show target-kind capabilities for TTD, live, dump, and future target models"
    )]
    Capabilities(TargetCapabilitiesArgs),
}

#[derive(Debug, Subcommand)]
enum ArchitectureCommand {
    #[command(about = "Describe cursor architecture, register model, and helper support")]
    State(ArchitectureStateArgs),
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
enum TimelineCommand {
    #[command(about = "Merge trace events into a single chronological timeline")]
    Events(TimelineEventsArgs),
}

#[derive(Debug, Subcommand)]
enum ModuleCommand {
    Info(ModuleInfoArgs),
    #[command(about = "Audit loaded modules for suspicious paths and duplicate names")]
    Audit(ModuleAuditArgs),
    #[command(about = "Explain DLL search-order candidates and risky directories")]
    SearchOrder(ModuleSearchOrderArgs),
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
    Recover(StackRecoverArgs),
    #[command(
        about = "Build a heuristic backtrace from current PC and recovered stack candidates"
    )]
    Backtrace(StackBacktraceArgs),
}

#[derive(Debug, Subcommand)]
enum MemoryCommand {
    Read(MemoryReadArgs),
    Range(MemoryRangeArgs),
    Buffer(MemoryBufferArgs),
    Dump(MemoryDumpArgs),
    Classify(MemoryClassifyArgs),
    Strings(MemoryStringsArgs),
    Dps(MemoryDpsArgs),
    Chase(MemoryChaseArgs),
    Watchpoint(WatchpointArgs),
}

#[derive(Debug, Subcommand)]
enum ObjectCommand {
    #[command(about = "Read an object vtable pointer and classify vtable entries")]
    Vtable(ObjectVtableArgs),
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
struct LiveLaunchArgs {
    #[arg(long, help = "Full command line to launch under DbgEng")]
    command_line: String,
    #[arg(long, default_value_t = 5000)]
    initial_break_timeout_ms: u32,
    #[arg(long, default_value = "detach", value_parser = ["detach", "terminate"])]
    end: String,
}

#[derive(Debug, Args)]
struct RemoteExplainArgs {
    #[arg(long, value_enum)]
    kind: Option<RemoteKind>,
}

#[derive(Debug, Args)]
struct RemoteServerCommandArgs {
    #[arg(long, value_enum, default_value_t = RemoteKind::Dbgsrv)]
    kind: RemoteKind,
    #[arg(short = 't', long, default_value = "tcp:port=5005")]
    transport: String,
    #[arg(long, help = "Target process id for NTSD/CDB -server attach recipes")]
    pid: Option<u32>,
    #[arg(
        long,
        help = "Target executable or command line for NTSD/CDB -server launch recipes"
    )]
    executable: Option<String>,
}

#[derive(Debug, Args)]
struct RemoteConnectCommandArgs {
    #[arg(long, value_enum, default_value_t = RemoteKind::Dbgsrv)]
    kind: RemoteKind,
    #[arg(long, help = "Target machine name or address")]
    server: String,
    #[arg(short = 't', long, default_value = "tcp:port=5005")]
    transport: String,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RemoteKind {
    Dbgsrv,
    Ntsd,
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
struct RecipeArgs {
    #[arg(
        help = "Optional recipe id or tag to filter, for example remote-debugging or stack-corruption"
    )]
    topic: Option<String>,
}

#[derive(Debug, Args)]
struct ContextSnapshotArgs {
    #[arg(short = 's', long)]
    session: Option<u64>,
    #[arg(short = 'c', long)]
    cursor: Option<u64>,
}

#[derive(Debug, Args)]
struct SymbolDiagnoseArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(long, help = "Module name to diagnose")]
    name: Option<String>,
    #[arg(long, help = "Address used to select a module")]
    address: Option<String>,
}

#[derive(Debug, Args)]
struct SymbolInspectArgs {
    path: PathBuf,
}

#[derive(Debug, Args)]
struct SymbolExportsArgs {
    path: PathBuf,
    #[arg(
        long,
        help = "Case-insensitive substring filter for export names or forwarders"
    )]
    filter: Option<String>,
    #[arg(long, default_value_t = 256)]
    max: usize,
}

#[derive(Debug, Args)]
struct SymbolNearestArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    address: String,
    #[arg(
        long,
        help = "Include a bounded export sample from the selected module"
    )]
    include_exports: bool,
}

#[derive(Debug, Args)]
struct SourceResolveArgs {
    #[arg(
        help = "Recorded source path from a PDB or debugger, for example C:\\build\\src\\foo.cpp"
    )]
    recorded_path: String,
    #[arg(
        long = "search-path",
        short = 'I',
        help = "Local source root to search"
    )]
    search_paths: Vec<PathBuf>,
    #[arg(long, default_value_t = 32)]
    max_candidates: usize,
    #[arg(long, default_value_t = 12)]
    max_depth: usize,
}

#[derive(Debug, Args)]
struct ArchitectureStateArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    thread_id: Option<u32>,
}

#[derive(Debug, Args)]
struct TargetCapabilitiesArgs {
    #[arg(short = 's', long)]
    session: Option<u64>,
    #[arg(short = 'c', long)]
    cursor: Option<u64>,
}

#[derive(Debug, Args)]
struct DisasmArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long, help = "Address to disassemble; defaults to current cursor RIP")]
    address: Option<String>,
    #[arg(long, default_value_t = 16)]
    count: u32,
    #[arg(long, default_value_t = 128)]
    bytes: u32,
    #[arg(long, value_parser = query_policy_values())]
    policy: Option<String>,
    #[arg(long, help = "Thread id used when resolving the default current RIP")]
    thread_id: Option<u32>,
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

#[derive(Debug, Clone, Args)]
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
struct TimelineEventsArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(long, value_parser = ["all", "modules", "threads", "exceptions", "keyframes"], default_value = "all")]
    kind: String,
    #[arg(long, default_value_t = 512)]
    max_events: usize,
}

#[derive(Debug, Args)]
struct ModuleAuditArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(
        short = 'c',
        long,
        help = "Use cursor-local module state instead of trace-wide modules"
    )]
    cursor: Option<u64>,
    #[arg(long, default_value_t = 32)]
    max_suspicious: usize,
}

#[derive(Debug, Args)]
struct ModuleSearchOrderArgs {
    #[arg(help = "DLL basename, for example foo.dll")]
    dll: String,
    #[arg(
        long,
        help = "Application directory used for application-local DLL probing"
    )]
    app_dir: Option<PathBuf>,
    #[arg(
        long,
        help = "Current directory used by unsafe legacy DLL search behavior"
    )]
    current_dir: Option<PathBuf>,
    #[arg(long, help = "Limit PATH directory expansion")]
    max_path_dirs: Option<usize>,
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
struct ReplayToArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    position: String,
    #[arg(long)]
    thread_unique_id: Option<u64>,
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
struct StackRecoverArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    size: Option<u32>,
    #[arg(long)]
    offset_from_sp: Option<i64>,
    #[arg(long, default_value_t = 32)]
    max_candidates: usize,
    #[arg(long, default_value_t = 0.50)]
    min_confidence: f64,
    #[arg(
        long,
        help = "Call address classification for each recovered candidate"
    )]
    target_info: bool,
}

#[derive(Debug, Args)]
struct StackBacktraceArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long, default_value_t = 4096)]
    size: u32,
    #[arg(long)]
    offset_from_sp: Option<i64>,
    #[arg(long, default_value_t = 32)]
    max_frames: usize,
    #[arg(long, default_value_t = 0.50)]
    min_confidence: f64,
    #[arg(long, help = "Call address classification for each frame target")]
    target_info: bool,
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
struct MemoryClassifyArgs {
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
struct MemoryDumpArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    address: String,
    #[arg(long)]
    size: u32,
    #[arg(long, default_value = "db", value_parser = ["db", "dq", "ascii", "utf16"])]
    format: String,
    #[arg(long, value_parser = query_policy_values())]
    policy: Option<String>,
}

#[derive(Debug, Args)]
struct ObjectVtableArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(
        long,
        help = "Object/interface pointer whose first pointer-sized field is a vtable"
    )]
    address: String,
    #[arg(long, default_value_t = 16)]
    entries: u32,
    #[arg(long, value_parser = query_policy_values())]
    policy: Option<String>,
}

#[derive(Debug, Args)]
struct MemoryStringsArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    address: String,
    #[arg(long)]
    size: u32,
    #[arg(long, default_value = "both", value_parser = ["ascii", "utf16", "both"])]
    encoding: String,
    #[arg(long, default_value_t = 4)]
    min_len: usize,
    #[arg(long, default_value_t = 64)]
    max_strings: usize,
    #[arg(long, value_parser = query_policy_values())]
    policy: Option<String>,
}

#[derive(Debug, Args)]
struct MemoryDpsArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    address: String,
    #[arg(long)]
    size: u32,
    #[arg(long, default_value_t = 8)]
    pointer_size: u32,
    #[arg(long, help = "Classify each non-null pointer target with address info")]
    target_info: bool,
    #[arg(long, value_parser = query_policy_values())]
    policy: Option<String>,
}

#[derive(Debug, Args)]
struct MemoryChaseArgs {
    #[arg(short = 's', long)]
    session: u64,
    #[arg(short = 'c', long)]
    cursor: u64,
    #[arg(long)]
    address: String,
    #[arg(long, default_value_t = 8)]
    depth: u32,
    #[arg(long, default_value_t = 0)]
    offset: u64,
    #[arg(long, default_value_t = 8)]
    pointer_size: u32,
    #[arg(long, value_parser = query_policy_values())]
    policy: Option<String>,
    #[arg(long, help = "Classify each non-null target address with address info")]
    target_info: bool,
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

#[derive(Debug, Args)]
struct SweepWatchMemoryArgs {
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
    #[arg(long, default_value_t = 16)]
    max_hits: usize,
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
        Some(Commands::Recipes(args)) => print_value(recipes_value(args)?, &output),
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
        Some(Commands::Live { command }) => match command {
            LiveCommand::Launch(args) => run_live_launch(args, &output),
            LiveCommand::Capabilities => print_value(live_capabilities(), &output),
        },
        Some(Commands::DbgSrv(args)) => run_dbgeng_server(args, &output),
        Some(Commands::Remote { command }) => print_value(remote_command_value(command)?, &output),
        Some(Commands::Windbg { command }) => run_windbg_command(command, &output),
        Some(Commands::Open(args)) => open_and_print(pipe, args, &output).await,
        Some(Commands::Load(args)) => call_and_print(pipe, load_call(args), &output).await,
        Some(Commands::Sessions) => {
            let client = DaemonClient::new(pipe);
            print_value(client.sessions().await?, &output)
        }
        Some(Commands::Context { command }) => match command {
            ContextCommand::Snapshot(args) => context_snapshot_and_print(pipe, args, &output).await,
        },
        Some(Commands::Close(args)) => {
            call_and_print(pipe, session_call("ttd_close_trace", args), &output).await
        }
        Some(Commands::Info(args)) => {
            call_and_print(pipe, session_call("ttd_trace_info", args), &output).await
        }
        Some(Commands::Symbols { command }) => match command {
            SymbolsCommand::Diagnose(args) => symbols_diagnose_and_print(pipe, args, &output).await,
            SymbolsCommand::Inspect(args) => print_value(diagnose_pe(&args.path)?, &output),
            SymbolsCommand::Exports(args) => symbols_exports_and_print(args, &output),
            SymbolsCommand::Nearest(args) => symbols_nearest_and_print(pipe, args, &output).await,
        },
        Some(Commands::Source { command }) => match command {
            SourceCommand::Resolve(args) => print_value(source_resolve(args)?, &output),
        },
        Some(Commands::Architecture { command }) => match command {
            ArchitectureCommand::State(args) => {
                architecture_state_and_print(pipe, args, &output).await
            }
        },
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
        Some(Commands::Timeline { command }) => match command {
            TimelineCommand::Events(args) => timeline_events_and_print(pipe, args, &output).await,
        },
        Some(Commands::Module { command }) => match command {
            ModuleCommand::Info(args) => {
                call_and_print(pipe, module_info_call(args)?, &output).await
            }
            ModuleCommand::Audit(args) => module_audit_and_print(pipe, args, &output).await,
            ModuleCommand::SearchOrder(args) => module_search_order_and_print(args, &output),
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
        Some(Commands::Replay { command }) => match command {
            ReplayCommand::Capabilities(args) => {
                replay_capabilities_and_print(pipe, args, &output).await
            }
            ReplayCommand::To(args) => replay_to_and_print(pipe, args, &output).await,
            ReplayCommand::WatchMemory(args) => {
                call_and_print(pipe, watchpoint_call(args)?, &output).await
            }
        },
        Some(Commands::Sweep { command }) => match command {
            SweepCommand::WatchMemory(args) => {
                sweep_watch_memory_and_print(pipe, args, &output).await
            }
        },
        Some(Commands::Breakpoint { command }) => match command {
            BreakpointCommand::Capabilities => print_value(breakpoint_capabilities(), &output),
        },
        Some(Commands::Datamodel { command }) => match command {
            DataModelCommand::Capabilities => print_value(datamodel_capabilities(), &output),
        },
        Some(Commands::Target { command }) => match command {
            TargetCommand::Capabilities(args) => {
                target_capabilities_and_print(pipe, args, &output).await
            }
        },
        Some(Commands::Disasm(args)) => disasm_and_print(pipe, args, &output).await,
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
            StackCommand::Recover(args) => stack_recover_and_print(pipe, args, &output).await,
            StackCommand::Backtrace(args) => stack_backtrace_and_print(pipe, args, &output).await,
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
            MemoryCommand::Dump(args) => memory_dump_and_print(pipe, args, &output).await,
            MemoryCommand::Classify(args) => memory_classify_and_print(pipe, args, &output).await,
            MemoryCommand::Strings(args) => memory_strings_and_print(pipe, args, &output).await,
            MemoryCommand::Dps(args) => memory_dps_and_print(pipe, args, &output).await,
            MemoryCommand::Chase(args) => memory_chase_and_print(pipe, args, &output).await,
            MemoryCommand::Watchpoint(args) => {
                call_and_print(pipe, watchpoint_call(args)?, &output).await
            }
        },
        Some(Commands::Object { command }) => match command {
            ObjectCommand::Vtable(args) => object_vtable_and_print(pipe, args, &output).await,
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

fn run_live_launch(args: LiveLaunchArgs, output: &OutputOptions) -> anyhow::Result<()> {
    let end = match args.end.as_str() {
        "detach" => LiveLaunchEnd::Detach,
        "terminate" => LiveLaunchEnd::Terminate,
        other => bail!("unsupported live launch end action: {other}"),
    };
    let result = live_launch_initial_break(LiveLaunchOptions {
        command_line: args.command_line,
        initial_break_timeout_ms: args.initial_break_timeout_ms,
        end,
    })?;
    print_value(
        json!({
            "result": result,
            "session_persistence": "one_shot",
            "notes": [
                "This is the first live DbgEng primitive, not the daemon-backed live session manager.",
                "Use --end detach to leave the process running or --end terminate for disposable test targets."
            ]
        }),
        output,
    )
}

fn live_capabilities() -> Value {
    json!({
        "implemented": [
            "dbgeng server",
            "live launch --command-line <cmd> --end detach|terminate"
        ],
        "partial": [
            {
                "feature": "live launch",
                "status": "one_shot_initial_event",
                "notes": "Launches under DbgEng, waits for the initial event, reports execution status, then detaches or terminates."
            }
        ],
        "gaps": [
            "daemon-backed live session persistence",
            "attach by pid",
            "detach/list persisted live sessions",
            "structured debug event polling",
            "live registers/memory/modules/threads",
            "continue and stepping with explicit exception handling",
            "breakpoint manager"
        ],
        "safety": [
            "Live debugging mutates target execution state.",
            "Commands that launch or attach are explicit and are not hidden behind read-only names."
        ]
    })
}

fn breakpoint_capabilities() -> Value {
    json!({
        "implemented": [
            "memory watchpoint",
            "replay watch-memory",
            "sweep watch-memory"
        ],
        "partial": [
            {
                "feature": "TTD multi-hit memory watchpoint sweeps",
                "status": "bounded_foreground_sweep",
                "command": "sweep watch-memory",
                "bounds": ["--max-hits"],
                "notes": "Collects repeated first-hit memory watchpoints by advancing the cursor one step after each hit."
            }
        ],
        "gaps": [
            "live software breakpoint set/list/clear/enable/disable",
            "live hardware execute/data breakpoints",
            "source and symbol breakpoints",
            "daemon-owned background replay jobs",
            "job progress and cancellation",
            "position watchpoints",
            "call/return trace jobs"
        ],
        "safe_next_steps": [
            "Use memory watchpoint for one hit.",
            "Use sweep watch-memory for bounded repeated TTD data-access hits.",
            "Use live capabilities before expecting live breakpoint manager support."
        ]
    })
}

fn datamodel_capabilities() -> Value {
    json!({
        "implemented": [
            "structured JSON command output",
            "discover.command_metadata",
            "recipes",
            "context snapshot",
            "architecture state"
        ],
        "partial": [
            {
                "feature": "data-model-like discovery",
                "status": "JSON manifests and command metadata",
                "notes": "Commands expose stable structured data, but do not yet bridge DbgEng dx or TargetModel services."
            }
        ],
        "gaps": [
            "DbgEng dx expression evaluation",
            "Debugger data model object projection",
            "Microsoft.Debugging.TargetModel.SDK component hosting",
            "service-oriented abstraction shared by TTD/live/dump targets",
            "dump target sessions"
        ],
        "recommended_abstractions": [
            "memory",
            "registers",
            "modules",
            "symbols",
            "threads",
            "events",
            "stack",
            "disassembly",
            "breakpoints"
        ]
    })
}

async fn target_capabilities_and_print(
    pipe: String,
    args: TargetCapabilitiesArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let selected_ttd = if let Some(session) = args.session {
        let client = DaemonClient::new(pipe);
        let capabilities = call_status_value(
            client
                .call_tool(session_call("ttd_capabilities", SessionArgs { session }))
                .await,
        );
        let architecture = if let Some(cursor) = args.cursor {
            Some(call_status_value(
                client
                    .call_tool(register_context_call(RegisterContextArgs {
                        session,
                        cursor,
                        thread_id: None,
                    }))
                    .await,
            ))
        } else {
            None
        };
        Some(json!({
            "session_id": session,
            "cursor_id": args.cursor,
            "capabilities": capabilities,
            "architecture": architecture
        }))
    } else {
        None
    };

    print_value(
        json!({
            "selected_ttd": selected_ttd,
            "target_kinds": [
                {
                    "kind": "ttd_trace",
                    "status": "implemented",
                    "entry": "open/load via daemon",
                    "supports": ["sessions", "cursors", "memory", "registers_x64", "timeline", "watchpoints", "disassembly_x64"]
                },
                {
                    "kind": "live_dbgeng_one_shot",
                    "status": "partial",
                    "entry": "live launch",
                    "supports": ["launch", "initial_debug_event_status", "detach_or_terminate"],
                    "missing": ["persisted_sessions", "attach", "event_loop", "registers", "memory", "breakpoints"]
                },
                {
                    "kind": "live_dbgeng_daemon",
                    "status": "gap",
                    "entry": null,
                    "missing": ["launch_or_attach", "session_list", "event_poll", "continue_step", "registers", "memory", "modules", "threads"]
                },
                {
                    "kind": "dump",
                    "status": "gap",
                    "entry": null,
                    "missing": ["dump_open", "memory", "modules", "threads", "stack", "symbols"]
                },
                {
                    "kind": "target_model",
                    "status": "gap",
                    "entry": null,
                    "missing": ["DbgEng dx", "TargetModel SDK component hosting"]
                }
            ],
            "service_axes": ["memory", "registers", "modules", "threads", "events", "symbols", "stack", "disassembly", "breakpoints"],
            "notes": [
                "Use this command before assuming a command works across TTD, live, dump, and future target model sessions.",
                "TTD replay remains backed by the TTD Replay API; live/dump work should use DbgEng/DbgHelp abstractions."
            ]
        }),
        output,
    )
}

fn remote_command_value(command: RemoteCommand) -> anyhow::Result<Value> {
    match command {
        RemoteCommand::Explain(args) => {
            let workflows = remote_workflows();
            let Some(kind) = args.kind else {
                return Ok(json!({
                    "workflows": workflows,
                    "default": "dbgsrv",
                    "recipes": ["windbg-tool recipes remote-debugging"],
                }));
            };
            Ok(json!({
                "workflow": remote_workflow(kind),
                "recipes": ["windbg-tool recipes remote-debugging"],
            }))
        }
        RemoteCommand::ServerCommand(args) => {
            if matches!(args.kind, RemoteKind::Ntsd)
                && args.pid.is_some()
                && args.executable.is_some()
            {
                bail!("remote server-command --kind ntsd accepts either --pid or --executable, not both")
            }
            Ok(json!({
                "side": "target",
                "workflow": remote_workflow(args.kind),
                "command": remote_server_command(&args),
                "notes": remote_server_notes(&args),
            }))
        }
        RemoteCommand::ConnectCommand(args) => Ok(json!({
            "side": "host",
            "workflow": remote_workflow(args.kind),
            "command": remote_connect_command(&args),
            "notes": remote_connect_notes(&args),
        })),
    }
}

fn remote_workflows() -> Value {
    json!([
        remote_workflow(RemoteKind::Dbgsrv),
        remote_workflow(RemoteKind::Ntsd)
    ])
}

fn remote_workflow(kind: RemoteKind) -> Value {
    match kind {
        RemoteKind::Dbgsrv => json!({
            "kind": "dbgsrv",
            "summary": "DbgEng process server: debugger brains, symbols, and extensions stay on the host.",
            "use_when": [
                "target should stay lightweight",
                "host owns symbol/source paths and extensions",
                "host should launch or attach through -premote"
            ],
            "target_side": "windbg-tool dbgeng server --transport tcp:port=5005",
            "host_side": "windbg-tool windbg run -- -premote tcp:port=5005,server=<target>"
        }),
        RemoteKind::Ntsd => json!({
            "kind": "ntsd",
            "summary": "NTSD/CDB remote session: debugger brains, symbols, and extensions run on the target.",
            "use_when": [
                "latency is high and command execution should be target-local",
                "target has the necessary symbols/extensions",
                "a preexisting debugger session should be exposed remotely"
            ],
            "target_side": "ntsd -server tcp:port=5005 -p <pid>",
            "host_side": "windbg-tool windbg run -- -remote tcp:port=5005,server=<target>"
        }),
    }
}

fn remote_server_command(args: &RemoteServerCommandArgs) -> Vec<String> {
    match args.kind {
        RemoteKind::Dbgsrv => vec![
            "windbg-tool".to_string(),
            "dbgeng".to_string(),
            "server".to_string(),
            "--transport".to_string(),
            args.transport.clone(),
        ],
        RemoteKind::Ntsd => {
            let mut command = vec![
                "ntsd".to_string(),
                "-server".to_string(),
                args.transport.clone(),
            ];
            if let Some(pid) = args.pid {
                command.push("-p".to_string());
                command.push(pid.to_string());
            } else if let Some(executable) = &args.executable {
                command.push(executable.clone());
            } else {
                command.push("-p".to_string());
                command.push("<pid>".to_string());
            }
            command
        }
    }
}

fn remote_server_notes(args: &RemoteServerCommandArgs) -> Value {
    match args.kind {
        RemoteKind::Dbgsrv => json!([
            "Run on the target machine.",
            "The command blocks until the DbgEng process server exits.",
            "Use remote connect-command --kind dbgsrv on the host to generate the WinDbg -premote command."
        ]),
        RemoteKind::Ntsd => json!([
            "Run on the target machine with NTSD or CDB available.",
            "Symbols and extensions are resolved by the target-side debugger process.",
            "Use remote connect-command --kind ntsd on the host to generate the WinDbg -remote command."
        ]),
    }
}

fn remote_connect_command(args: &RemoteConnectCommandArgs) -> Vec<String> {
    let remote = format!("{},server={}", args.transport, args.server);
    match args.kind {
        RemoteKind::Dbgsrv => vec![
            "windbg-tool".to_string(),
            "windbg".to_string(),
            "run".to_string(),
            "--".to_string(),
            "-premote".to_string(),
            remote,
        ],
        RemoteKind::Ntsd => vec![
            "windbg-tool".to_string(),
            "windbg".to_string(),
            "run".to_string(),
            "--".to_string(),
            "-remote".to_string(),
            remote,
        ],
    }
}

fn remote_connect_notes(args: &RemoteConnectCommandArgs) -> Value {
    match args.kind {
        RemoteKind::Dbgsrv => json!([
            "Run on the host machine.",
            "This connects WinDbg to a DbgSrv process server; launch/attach decisions happen from the host.",
            "Append additional WinDbg launch/attach arguments after the generated -premote transport if needed."
        ]),
        RemoteKind::Ntsd => json!([
            "Run on the host machine.",
            "This connects WinDbg to an existing target-side NTSD/CDB -server session.",
            "Do not use -premote for NTSD/CDB -server sessions."
        ]),
    }
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

async fn context_snapshot_and_print(
    pipe: String,
    args: ContextSnapshotArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let client = DaemonClient::new(pipe.clone());
    let sessions = client.sessions().await?;
    let selected = select_snapshot_handles(&sessions, args)?;
    let mut snapshot = json!({
        "daemon": call_status_value(DaemonClient::new(pipe).health().await),
        "sessions": sessions,
        "selected": selected,
        "recipes": [
            "windbg-tool recipes crash-triage",
            "windbg-tool recipes stack-corruption",
            "windbg-tool recipes symbol-health",
            "windbg-tool recipes memory-provenance"
        ],
    });

    if let Some(session_id) = selected["session_id"].as_u64() {
        snapshot["trace_info"] = call_status_value(
            client
                .call_tool(session_call(
                    "ttd_trace_info",
                    SessionArgs {
                        session: session_id,
                    },
                ))
                .await,
        );
        snapshot["capabilities"] = call_status_value(
            client
                .call_tool(session_call(
                    "ttd_capabilities",
                    SessionArgs {
                        session: session_id,
                    },
                ))
                .await,
        );
        if let Some(cursor_id) = selected["cursor_id"].as_u64() {
            let cursor_args = CursorArgs {
                session: session_id,
                cursor: cursor_id,
            };
            snapshot["position"] = call_status_value(
                client
                    .call_tool(cursor_call("ttd_position_get", cursor_args.clone()))
                    .await,
            );
            snapshot["active_threads"] = call_status_value(
                client
                    .call_tool(cursor_call("ttd_active_threads", cursor_args.clone()))
                    .await,
            );
            snapshot["stack"] = call_status_value(
                client
                    .call_tool(cursor_call("ttd_stack_info", cursor_args.clone()))
                    .await,
            );
            snapshot["architecture_state"] = call_status_value(
                architecture_state_value(
                    &client,
                    ArchitectureStateArgs {
                        session: session_id,
                        cursor: cursor_id,
                        thread_id: None,
                    },
                )
                .await,
            );
            let current_disassembly = call_status_value(
                disasm_value(
                    &client,
                    &DisasmArgs {
                        session: session_id,
                        cursor: cursor_id,
                        address: None,
                        count: 4,
                        bytes: 64,
                        policy: None,
                        thread_id: None,
                    },
                )
                .await,
            );
            let nearest_symbol_args =
                current_disassembly["value"]["address"]
                    .as_u64()
                    .map(|address| SymbolNearestArgs {
                        session: session_id,
                        cursor: cursor_id,
                        address: format!("0x{address:X}"),
                        include_exports: false,
                    });
            snapshot["current_disassembly"] = current_disassembly;
            if let Some(args) = nearest_symbol_args {
                snapshot["nearest_symbol"] =
                    call_status_value(nearest_symbol_value(&client, &args).await);
            }
            snapshot["command_line"] = call_status_value(
                client
                    .call_tool(cursor_call("ttd_command_line", cursor_args))
                    .await,
            );
        }
        snapshot["timeline_summary"] = call_status_value(
            timeline_events_value(
                &client,
                &TimelineEventsArgs {
                    session: session_id,
                    kind: "all".to_string(),
                    max_events: 16,
                },
            )
            .await,
        );
    }

    print_value(snapshot, output)
}

async fn symbols_diagnose_and_print(
    pipe: String,
    args: SymbolDiagnoseArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    if args.name.is_some() && args.address.is_some() {
        bail!("symbols diagnose accepts either --name or --address, not both")
    }
    let client = DaemonClient::new(pipe);
    let trace_info = client
        .call_tool(session_call(
            "ttd_trace_info",
            SessionArgs {
                session: args.session,
            },
        ))
        .await;
    let capabilities = client
        .call_tool(session_call(
            "ttd_capabilities",
            SessionArgs {
                session: args.session,
            },
        ))
        .await;
    let module_scope = symbol_module_scope(&client, &args).await?;
    let checks = symbol_diagnostic_checks(capabilities.as_ref().ok(), &module_scope);
    print_value(
        json!({
            "session_id": args.session,
            "trace_info": call_status_value(trace_info),
            "capabilities": call_status_value(capabilities),
            "module_scope": module_scope,
            "checks": checks,
            "next_steps": [
                "Confirm symbols.symbol_path includes the expected symbol server or private symbol path.",
                "Confirm symbols.image_path includes local binaries when stack walking or disassembly is low fidelity.",
                "Use modules/module info to select a narrower module before future PDB/source diagnostics.",
                "Use windbg-tool recipes symbol-health for the broader TimDbg workflow."
            ]
        }),
        output,
    )
}

async fn symbol_module_scope(
    client: &DaemonClient,
    args: &SymbolDiagnoseArgs,
) -> anyhow::Result<Value> {
    if args.name.is_none() && args.address.is_none() {
        let modules = call_status_value(
            client
                .call_tool(session_call(
                    "ttd_list_modules",
                    SessionArgs {
                        session: args.session,
                    },
                ))
                .await,
        );
        let pe_diagnostics = modules["value"]["modules"]
            .as_array()
            .map(|modules| session_pe_diagnostics(modules))
            .unwrap_or_else(|| {
                json!({
                    "ok": false,
                    "error": "module list is unavailable"
                })
            });
        return Ok(json!({
            "kind": "session",
            "modules": modules,
            "pe_diagnostics": pe_diagnostics
        }));
    }

    let mut object = session_object(args.session);
    insert_option(&mut object, "name", args.name.clone().map(Value::String));
    insert_option(
        &mut object,
        "address",
        args.address
            .as_deref()
            .map(parse_u64_argument)
            .transpose()?
            .map(Value::from),
    );
    let module = call_status_value(
        client
            .call_tool(ToolCall {
                name: "ttd_module_info".to_string(),
                arguments: Value::Object(object),
            })
            .await,
    );
    let pe_diagnostics = module["value"]["module"]
        .as_object()
        .map(|_| module_pe_diagnostics(&module["value"]["module"]))
        .unwrap_or_else(|| {
            json!({
                "ok": false,
                "error": "module info is unavailable"
            })
        });
    Ok(json!({
        "kind": if args.name.is_some() { "module_name" } else { "module_address" },
        "module": module,
        "pe_diagnostics": pe_diagnostics
    }))
}

fn symbols_exports_and_print(
    args: SymbolExportsArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    ensure!(
        args.max <= 10_000,
        "symbols exports --max must not exceed 10000"
    );
    let exports = read_export_symbols(&args.path)?;
    let filter = args.filter.as_ref().map(|value| value.to_ascii_lowercase());
    let filtered = filter_exports(&exports, filter.as_deref());
    let values = filtered
        .iter()
        .take(args.max)
        .map(|export| export_symbol_value(export))
        .collect::<Vec<_>>();
    print_value(
        json!({
            "path": args.path,
            "total_exports": exports.len(),
            "filtered_exports": filtered.len(),
            "max": args.max,
            "truncated": filtered.len() > args.max,
            "exports": values,
        }),
        output,
    )
}

async fn symbols_nearest_and_print(
    pipe: String,
    args: SymbolNearestArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let client = DaemonClient::new(pipe);
    print_value(nearest_symbol_value(&client, &args).await?, output)
}

async fn nearest_symbol_value(
    client: &DaemonClient,
    args: &SymbolNearestArgs,
) -> anyhow::Result<Value> {
    let address_info = client
        .call_tool(address_info_call(AddressInfoArgs {
            session: args.session,
            cursor: args.cursor,
            address: args.address.clone(),
        }))
        .await?;
    let Some(module) = address_info["module"].as_object() else {
        return Ok(json!({
            "session_id": args.session,
            "cursor_id": args.cursor,
            "address": parse_u64_argument(&args.address)?,
            "address_info": address_info,
            "symbol": null,
            "reason": "address did not resolve to a loaded module"
        }));
    };
    let Some(path) = module.get("path").and_then(Value::as_str) else {
        return Ok(json!({
            "session_id": args.session,
            "cursor_id": args.cursor,
            "address_info": address_info,
            "symbol": null,
            "reason": "module path is not available"
        }));
    };
    let rva = module
        .get("rva")
        .and_then(Value::as_u64)
        .context("address_info module did not include an RVA")?;
    let path = PathBuf::from(path);
    let exports = read_export_symbols(&path)?;
    let nearest = nearest_export(&exports, rva as u32);
    let export_sample = args.include_exports.then(|| {
        exports
            .iter()
            .take(64)
            .map(export_symbol_value)
            .collect::<Vec<_>>()
    });
    let nearest_value = nearest.map(|export| {
        let displacement = rva.saturating_sub(export.rva as u64);
        json!({
            "export": export_symbol_value(export),
            "displacement": displacement,
            "displacement_hex": format!("{displacement:X}"),
            "display": export_display_name(export, displacement),
            "confidence": if export.forwarder.is_some() { "forwarder" } else { "export_nearest" }
        })
    });

    Ok(json!({
        "session_id": args.session,
        "cursor_id": args.cursor,
        "address": parse_u64_argument(&args.address)?,
        "address_info": address_info,
        "module_path": path,
        "rva": rva,
        "rva_hex": format!("{rva:X}"),
        "symbol": nearest_value,
        "exports": {
            "count": exports.len(),
            "sample": export_sample,
            "sample_limit": if args.include_exports { 64 } else { 0 },
            "sample_truncated": args.include_exports && exports.len() > 64
        },
        "notes": [
            "Nearest export is not the same as private PDB symbol lookup.",
            "Use this as a low-fidelity fallback when private symbols are unavailable."
        ]
    }))
}

fn session_pe_diagnostics(modules: &[Value]) -> Value {
    const MAX_PARSED_MODULES: usize = 32;

    let mut with_path_count = 0usize;
    let mut local_file_count = 0usize;
    let mut parsed_count = 0usize;
    let mut samples = Vec::new();

    for module in modules {
        let Some(path) = module_path(module) else {
            continue;
        };
        with_path_count += 1;
        let path = PathBuf::from(path);
        if !path.exists() {
            continue;
        }
        local_file_count += 1;
        if samples.len() >= MAX_PARSED_MODULES {
            continue;
        }
        let diagnostic = module_pe_diagnostics(module);
        if diagnostic["ok"].as_bool() == Some(true) {
            parsed_count += 1;
        }
        samples.push(diagnostic);
    }

    json!({
        "ok": true,
        "total_modules": modules.len(),
        "modules_with_path": with_path_count,
        "local_files": local_file_count,
        "parsed_count": parsed_count,
        "sample_limit": MAX_PARSED_MODULES,
        "truncated": local_file_count > MAX_PARSED_MODULES,
        "samples": samples,
        "hint": "Use symbols diagnose --name <module> or --address <addr> for a single-module PE/PDB identity."
    })
}

fn module_pe_diagnostics(module: &Value) -> Value {
    let name = module["name"].as_str().unwrap_or_default();
    let Some(path) = module_path(module) else {
        return json!({
            "ok": false,
            "module": name,
            "reason": "module path is not available"
        });
    };
    let path = PathBuf::from(path);
    if !path.exists() {
        return json!({
            "ok": false,
            "module": name,
            "path": path,
            "reason": "module binary is not available at this path"
        });
    }

    match diagnose_pe(&path) {
        Ok(pe) => json!({
            "ok": true,
            "module": name,
            "path": path,
            "pe": pe
        }),
        Err(error) => json!({
            "ok": false,
            "module": name,
            "path": path,
            "error": error.to_string()
        }),
    }
}

fn module_path(module: &Value) -> Option<&str> {
    module["path"].as_str().filter(|path| !path.is_empty())
}

fn audit_modules(modules: &[Value], max_suspicious: usize) -> Value {
    let mut missing_path = 0usize;
    let mut local_file_missing = 0usize;
    let mut user_writable_path = 0usize;
    let mut temp_path = 0usize;
    let mut network_path = 0usize;
    let mut outside_windows_dir = 0usize;
    let mut suspicious = Vec::new();
    let mut names: std::collections::BTreeMap<String, Vec<Value>> =
        std::collections::BTreeMap::new();
    let windows_dir = std::env::var("WINDIR")
        .or_else(|_| std::env::var("SystemRoot"))
        .unwrap_or_else(|_| String::from(r"C:\Windows"))
        .to_ascii_lowercase();

    for module in modules {
        let name = module["name"].as_str().unwrap_or_default();
        names
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push(json!({
                "name": name,
                "path": module_path(module),
                "base_address": module["base_address"],
                "size": module["size"],
            }));

        let mut reasons = Vec::new();
        let Some(path) = module_path(module) else {
            missing_path += 1;
            reasons.push("missing_module_path");
            push_suspicious_module(&mut suspicious, module, reasons, max_suspicious);
            continue;
        };
        let lower = path.to_ascii_lowercase();
        let path_buf = PathBuf::from(path);
        if lower.starts_with(r"\\") {
            network_path += 1;
            reasons.push("network_path");
        }
        if lower.contains(r"\users\") || lower.contains(r"\programdata\") {
            user_writable_path += 1;
            reasons.push("user_or_programdata_path");
        }
        if lower.contains(r"\temp\")
            || lower.contains(r"\tmp\")
            || lower.contains(r"\appdata\local\temp\")
            || lower.contains(r"\downloads\")
        {
            temp_path += 1;
            reasons.push("temp_or_download_path");
        }
        if path_buf.is_absolute() && !lower.starts_with(&windows_dir) {
            outside_windows_dir += 1;
            reasons.push("outside_windows_directory");
        }
        if !path_buf.exists() {
            local_file_missing += 1;
            reasons.push("binary_not_available_locally");
        }
        if !reasons.is_empty() {
            push_suspicious_module(&mut suspicious, module, reasons, max_suspicious);
        }
    }

    let duplicates = names
        .into_iter()
        .filter_map(|(name, instances)| {
            let distinct_paths = instances
                .iter()
                .filter_map(|instance| instance["path"].as_str())
                .map(|path| path.to_ascii_lowercase())
                .collect::<std::collections::BTreeSet<_>>();
            (instances.len() > 1 && distinct_paths.len() > 1).then(|| {
                json!({
                    "name": name,
                    "instances": instances,
                    "distinct_path_count": distinct_paths.len(),
                    "reason": "same module basename loaded from multiple paths"
                })
            })
        })
        .collect::<Vec<_>>();

    json!({
        "summary": {
            "missing_path": missing_path,
            "binary_not_available_locally": local_file_missing,
            "network_path": network_path,
            "user_or_programdata_path": user_writable_path,
            "temp_or_download_path": temp_path,
            "outside_windows_directory": outside_windows_dir,
            "duplicate_name_groups": duplicates.len(),
        },
        "suspicious_modules": suspicious,
        "suspicious_truncated": suspicious.len() >= max_suspicious,
        "duplicate_name_groups": duplicates,
        "safe_next_steps": [
            "Run symbols diagnose for suspicious module paths that are available locally.",
            "Use memory range/classify around unexpected executable addresses.",
            "Use TTD watchpoints to identify writes to suspicious dispatch tables or return addresses."
        ]
    })
}

fn push_suspicious_module(
    suspicious: &mut Vec<Value>,
    module: &Value,
    reasons: Vec<&'static str>,
    max_suspicious: usize,
) {
    if suspicious.len() >= max_suspicious {
        return;
    }
    suspicious.push(json!({
        "name": module["name"],
        "path": module["path"],
        "base_address": module["base_address"],
        "size": module["size"],
        "load_position": module["load_position"],
        "unload_position": module["unload_position"],
        "reasons": reasons,
    }));
}

fn collect_timeline_events(events: &mut Vec<Value>, kind: &str, source: &Value, array_key: &str) {
    let Some(items) = source["value"][array_key].as_array() else {
        return;
    };
    for item in items {
        let position = item
            .get("position")
            .cloned()
            .or_else(|| {
                item.get("module")
                    .and_then(|module| module.get("load_position"))
                    .cloned()
            })
            .unwrap_or(Value::Null);
        events.push(json!({
            "kind": kind,
            "event_kind": item.get("kind").cloned().unwrap_or(Value::Null),
            "position": position,
            "sequence": position.get("sequence").cloned().unwrap_or(Value::Null),
            "payload": item,
        }));
    }
}

fn collect_keyframe_events(events: &mut Vec<Value>, source: &Value) {
    let Some(items) = source["value"]["keyframes"].as_array() else {
        return;
    };
    for position in items {
        events.push(json!({
            "kind": "keyframe",
            "event_kind": "keyframe",
            "position": position,
            "sequence": position.get("sequence").cloned().unwrap_or(Value::Null),
            "payload": position,
        }));
    }
}

fn timeline_sequence(event: &Value) -> u64 {
    event["sequence"].as_u64().unwrap_or(u64::MAX)
}

fn normalize_dll_name(name: &str) -> anyhow::Result<String> {
    let trimmed = name.trim();
    ensure!(!trimmed.is_empty(), "DLL name must not be empty");
    ensure!(
        !trimmed.contains('\\') && !trimmed.contains('/'),
        "DLL search-order diagnostics require a basename, not a path"
    );
    if Path::new(trimmed).extension().is_some() {
        Ok(trimmed.to_string())
    } else {
        Ok(format!("{trimmed}.dll"))
    }
}

fn search_candidate(order: usize, kind: &str, directory: &Path, dll: &str) -> Value {
    let candidate = directory.join(dll);
    let risk = directory_risk(directory);
    json!({
        "order": order,
        "kind": kind,
        "directory": directory,
        "candidate": candidate,
        "exists": candidate.exists(),
        "risk": risk,
    })
}

fn directory_risk(directory: &Path) -> &'static str {
    let lower = directory.to_string_lossy().to_ascii_lowercase();
    let windows_dir = std::env::var("WINDIR")
        .or_else(|_| std::env::var("SystemRoot"))
        .unwrap_or_else(|_| String::from(r"C:\Windows"))
        .to_ascii_lowercase();
    if lower.starts_with(&windows_dir) {
        "system_controlled"
    } else if lower.starts_with(r"\\") {
        "network_path"
    } else if lower.contains(r"\temp\")
        || lower.contains(r"\tmp\")
        || lower.contains(r"\downloads\")
        || lower.contains(r"\appdata\local\temp\")
    {
        "temp_or_download_path"
    } else if lower.contains(r"\users\") || lower.contains(r"\programdata\") {
        "user_or_programdata_path"
    } else {
        "review_path_acl"
    }
}

fn filter_exports<'a>(exports: &'a [ExportSymbol], filter: Option<&str>) -> Vec<&'a ExportSymbol> {
    exports
        .iter()
        .filter(|export| {
            let Some(filter) = filter else {
                return true;
            };
            export
                .name
                .as_deref()
                .is_some_and(|name| name.to_ascii_lowercase().contains(filter))
                || export
                    .forwarder
                    .as_deref()
                    .is_some_and(|name| name.to_ascii_lowercase().contains(filter))
                || export.ordinal.to_string().contains(filter)
        })
        .collect()
}

fn nearest_export(exports: &[ExportSymbol], rva: u32) -> Option<&ExportSymbol> {
    exports
        .iter()
        .filter(|export| export.forwarder.is_none() && export.rva <= rva)
        .max_by_key(|export| export.rva)
}

fn export_display_name(export: &ExportSymbol, displacement: u64) -> String {
    let name = export
        .name
        .clone()
        .unwrap_or_else(|| format!("#{}", export.ordinal));
    if displacement == 0 {
        name
    } else {
        format!("{name}+0x{displacement:x}")
    }
}

fn symbol_diagnostic_checks(capabilities: Option<&Value>, module_scope: &Value) -> Value {
    let symbols = capabilities.and_then(|value| value.get("symbols"));
    let native = capabilities
        .and_then(|value| value.get("native"))
        .and_then(Value::as_bool);
    let symbol_path = symbols
        .and_then(|value| value.get("symbol_path"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let image_path = symbols
        .and_then(|value| value.get("image_path"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let public_symbols = symbols
        .and_then(|value| value.get("microsoft_public_symbols"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let binary_path_count = symbols
        .and_then(|value| value.get("binary_path_count"))
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let module_data_available = module_scope["modules"]["ok"].as_bool() == Some(true)
        || module_scope["module"]["ok"].as_bool() == Some(true);
    let pe_diagnostics = &module_scope["pe_diagnostics"];
    let pe_identity_available = pe_diagnostics["ok"].as_bool() == Some(true)
        && (pe_diagnostics["parsed_count"].as_u64().unwrap_or_default() > 0
            || pe_diagnostics["pe"].is_object());
    let pdb_identity_available = pe_diagnostics["pe"]["codeview"].is_object()
        || pe_diagnostics["samples"].as_array().is_some_and(|samples| {
            samples
                .iter()
                .any(|sample| sample["pe"]["codeview"].is_object())
        });

    json!([
        {
            "id": "native-replay",
            "status": if native == Some(true) { "pass" } else { "warn" },
            "evidence": native,
            "why_it_matters": "Native replay is required for real module inventories and cursor-backed symbol context."
        },
        {
            "id": "symbol-path",
            "status": if symbol_path.is_empty() { "warn" } else { "pass" },
            "evidence": symbol_path,
            "why_it_matters": "DbgHelp/SymSrv need a symbol path before public or private PDBs can be found."
        },
        {
            "id": "microsoft-public-symbols",
            "status": if public_symbols { "pass" } else { "info" },
            "evidence": public_symbols,
            "why_it_matters": "Public Microsoft symbols are enough for many Windows module/function names."
        },
        {
            "id": "binary-path",
            "status": if !image_path.is_empty() || binary_path_count > 0 { "pass" } else { "info" },
            "evidence": {
                "image_path": image_path,
                "binary_path_count": binary_path_count
            },
            "why_it_matters": "Local binaries improve stack walking, disassembly, and symbol-server binary fallback workflows."
        },
        {
            "id": "module-data",
            "status": if module_data_available { "pass" } else { "warn" },
            "evidence": module_scope,
            "why_it_matters": "Module identity is the anchor for timestamp/size/PDB/source diagnostics."
        },
        {
            "id": "pe-image-identity",
            "status": if pe_identity_available { "pass" } else { "info" },
            "evidence": pe_diagnostics,
            "why_it_matters": "PE timestamp and SizeOfImage form the symbol-server key for image/binary lookup."
        },
        {
            "id": "pdb-codeview-identity",
            "status": if pdb_identity_available { "pass" } else { "info" },
            "evidence": pe_diagnostics,
            "why_it_matters": "RSDS GUID plus age form the symbol-server key for PDB lookup."
        },
        {
            "id": "source-fidelity",
            "status": "future",
            "evidence": "PDB source-file and checksum inspection is not implemented yet.",
            "why_it_matters": "Source paths should be resolved with trailing-component matching and verified with hashes where available."
        }
    ])
}

fn source_resolve(args: SourceResolveArgs) -> anyhow::Result<Value> {
    let recorded_components = normalized_components(&PathBuf::from(&args.recorded_path));
    if recorded_components.is_empty() {
        bail!("recorded source path has no usable path components")
    }
    let search_paths = if args.search_paths.is_empty() {
        vec![std::env::current_dir().context("resolving current directory")?]
    } else {
        args.search_paths
    };

    let mut matches = Vec::new();
    let recorded_path = PathBuf::from(&args.recorded_path);
    if recorded_path.exists() {
        matches.push(source_match_value(
            &recorded_path,
            &recorded_components,
            true,
        ));
    }

    for root in &search_paths {
        collect_source_matches(
            root,
            &recorded_components,
            args.max_candidates,
            args.max_depth,
            0,
            &mut matches,
        )?;
    }
    matches.sort_by(|left, right| {
        right["matched_components"]
            .as_u64()
            .cmp(&left["matched_components"].as_u64())
            .then_with(|| left["path"].as_str().cmp(&right["path"].as_str()))
    });
    matches.dedup_by(|left, right| left["path"] == right["path"]);
    if matches.len() > args.max_candidates {
        matches.truncate(args.max_candidates);
    }
    let best = matches.first().cloned();

    Ok(json!({
        "recorded_path": args.recorded_path,
        "recorded_components": recorded_components,
        "search_paths": search_paths,
        "best": best,
        "matches": matches,
        "strategy": "Trailing path-component match, preferring the candidate with the longest matching suffix.",
        "source_hash_verification": "future"
    }))
}

async fn architecture_state_and_print(
    pipe: String,
    args: ArchitectureStateArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let client = DaemonClient::new(pipe);
    print_value(architecture_state_value(&client, args).await?, output)
}

async fn architecture_state_value(
    client: &DaemonClient,
    args: ArchitectureStateArgs,
) -> anyhow::Result<Value> {
    let capabilities = call_status_value(
        client
            .call_tool(session_call(
                "ttd_capabilities",
                SessionArgs {
                    session: args.session,
                },
            ))
            .await,
    );
    let registers = call_status_value(
        client
            .call_tool(cursor_call(
                "ttd_registers",
                CursorArgs {
                    session: args.session,
                    cursor: args.cursor,
                },
            ))
            .await,
    );
    let context = call_status_value(
        client
            .call_tool(register_context_call(RegisterContextArgs {
                session: args.session,
                cursor: args.cursor,
                thread_id: args.thread_id,
            }))
            .await,
    );
    let architecture = context["value"]["architecture"]
        .as_str()
        .or_else(|| capabilities["value"]["architecture"].as_str())
        .unwrap_or("unknown");
    let x64 = architecture.eq_ignore_ascii_case("x64")
        || context["value"]["registers"]["rip"].is_u64()
        || registers["value"]["program_counter"].is_u64();

    Ok(json!({
        "session_id": args.session,
        "cursor_id": args.cursor,
        "thread_id": args.thread_id,
        "architecture": architecture,
        "detected": {
            "x64": x64,
            "source": if context["ok"].as_bool() == Some(true) { "register_context" } else { "capabilities_or_fallback" }
        },
        "supported_helpers": {
            "compact_registers": registers["ok"],
            "x64_register_context": x64 && context["ok"].as_bool() == Some(true),
            "x64_disassembly": x64,
            "stack_info": true,
            "peb_teb_helpers": x64
        },
        "unsupported_or_partial": [
            {
                "architecture": "x86",
                "status": "not_yet_exposed",
                "note": "TTD headers can represent multiple architectures, but the current Rust register/disassembly model is x64-first."
            },
            {
                "architecture": "arm64",
                "status": "not_yet_exposed",
                "note": "ARM64 register and disassembly models need a separate decoder and typed register schema."
            }
        ],
        "capabilities": capabilities,
        "registers": registers,
        "register_context": context,
        "next_steps": [
            "Use register-context for full x64 scalar/SIMD state when available.",
            "Use disasm only when x64_disassembly is true.",
            "Treat unsupported architectures as explicit gaps instead of retrying x64-only commands."
        ]
    }))
}

fn collect_source_matches(
    root: &PathBuf,
    recorded_components: &[String],
    max_candidates: usize,
    max_depth: usize,
    depth: usize,
    matches: &mut Vec<Value>,
) -> anyhow::Result<()> {
    if matches.len() >= max_candidates || depth > max_depth || !root.exists() {
        return Ok(());
    }
    let metadata = match fs::metadata(root) {
        Ok(metadata) => metadata,
        Err(error) => {
            matches.push(json!({
                "path": root,
                "error": error.to_string()
            }));
            return Ok(());
        }
    };
    if metadata.is_file() {
        let matched = matching_suffix_len(&normalized_components(root), recorded_components);
        if matched > 0 {
            matches.push(source_match_value(root, recorded_components, false));
        }
        return Ok(());
    }
    if !metadata.is_dir() {
        return Ok(());
    }

    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) => {
            matches.push(json!({
                "path": root,
                "error": error.to_string()
            }));
            return Ok(());
        }
    };
    for entry in entries {
        if matches.len() >= max_candidates {
            break;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                matches.push(json!({ "error": error.to_string() }));
                continue;
            }
        };
        collect_source_matches(
            &entry.path(),
            recorded_components,
            max_candidates,
            max_depth,
            depth + 1,
            matches,
        )?;
    }
    Ok(())
}

fn source_match_value(path: &PathBuf, recorded_components: &[String], direct: bool) -> Value {
    let candidate_components = normalized_components(path);
    let matched_components = matching_suffix_len(&candidate_components, recorded_components);
    json!({
        "path": path,
        "direct": direct,
        "matched_components": matched_components,
        "candidate_components": candidate_components,
    })
}

fn matching_suffix_len(candidate: &[String], recorded: &[String]) -> usize {
    candidate
        .iter()
        .rev()
        .zip(recorded.iter().rev())
        .take_while(|(candidate, recorded)| candidate == recorded)
        .count()
}

fn normalized_components(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => {
                Some(value.to_string_lossy().to_ascii_lowercase())
            }
            _ => None,
        })
        .collect()
}

fn select_snapshot_handles(sessions: &Value, args: ContextSnapshotArgs) -> anyhow::Result<Value> {
    if args.cursor.is_some() && args.session.is_none() {
        bail!("context snapshot requires --session when --cursor is supplied")
    }
    let session_id = args.session.or_else(|| {
        sessions["sessions"]
            .as_array()
            .and_then(|items| items.first())
            .and_then(|session| session["session_id"].as_u64())
    });
    let cursor_id = args.cursor.or_else(|| {
        let session_id = session_id?;
        sessions["sessions"].as_array()?.iter().find_map(|session| {
            (session["session_id"].as_u64() == Some(session_id))
                .then(|| {
                    session["cursors"]
                        .as_array()
                        .and_then(|cursors| cursors.first())
                        .and_then(|cursor| cursor["cursor_id"].as_u64())
                })
                .flatten()
        })
    });
    Ok(json!({
        "session_id": session_id,
        "cursor_id": cursor_id,
        "selection": if args.session.is_some() || args.cursor.is_some() { "explicit" } else { "first_available" }
    }))
}

fn call_status_value(result: anyhow::Result<Value>) -> Value {
    match result {
        Ok(value) => json!({ "ok": true, "value": value }),
        Err(error) => json!({ "ok": false, "error": error.to_string() }),
    }
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
            "discovery": ["discover", "recipes [topic]", "advise [topic]", "tools", "schema <tool>"],
            "daemon": ["daemon ensure", "daemon status", "daemon shutdown", "sessions"],
            "context": ["context snapshot", "context snapshot --session <id> --cursor <id>"],
            "remote": ["remote explain", "remote server-command", "remote connect-command"],
            "live": ["live capabilities", "live launch --command-line <cmd> --end detach|terminate"],
            "breakpoint": ["breakpoint capabilities", "memory watchpoint", "sweep watch-memory"],
            "datamodel": ["datamodel capabilities"],
            "target": ["target capabilities", "target capabilities --session <id> --cursor <id>"],
            "symbols": ["symbols diagnose --session <id>", "symbols diagnose --session <id> --name <module>", "symbols diagnose --session <id> --address <addr>", "symbols inspect <path>", "symbols exports <path>", "symbols nearest --session <id> --cursor <id> --address <addr>"],
            "source": ["source resolve <recorded-path> --search-path <root>"],
            "architecture": ["architecture state --session <id> --cursor <id>", "arch state --session <id> --cursor <id>"],
            "dbgeng": ["dbgeng server --transport <transport>", "dbgsrv --transport <transport>"],
            "windbg": ["windbg status", "windbg install", "windbg update", "windbg path", "windbg run -- <args>"],
            "session": ["open", "load", "close", "info", "capabilities"],
            "index": ["index status", "index stats", "index build"],
            "metadata": ["trace list", "trace-list", "threads", "modules", "keyframes", "exceptions", "events modules", "events threads", "timeline events", "module info", "module audit", "module search-order"],
            "navigation": ["cursor create", "cursor modules", "active-threads", "position get", "position set", "step", "replay capabilities", "replay to", "replay watch-memory", "sweep watch-memory"],
            "state": ["architecture state", "arch state", "registers", "register-context", "stack info", "stack read", "stack recover", "stack backtrace", "command-line", "address"],
            "disassembly": ["disasm --session <id> --cursor <id>", "u --session <id> --cursor <id> --address <addr>"],
            "memory": ["memory read", "memory range", "memory buffer", "memory dump", "memory strings", "memory dps", "memory classify", "memory chase", "memory watchpoint", "watchpoint"],
            "object": ["object vtable --session <id> --cursor <id> --address <object>"],
            "escape_hatch": ["tool <name> --json <object>", "tool <name> --json-file <path>"]
        },
        "tool_command_map": tool_command_map(),
        "command_metadata": command_metadata(),
        "recipes": recipes_manifest(),
        "diagnostic_guidance": diagnostic_guidance(),
        "ttd_api_coverage": ttd_api_coverage_manifest(),
        "examples": [
            {
                "goal": "Pick the right debugging workflow for a symptom",
                "command": "windbg-tool recipes diagnostic-technique"
            },
            {
                "goal": "Capture a one-shot agent context summary",
                "command": "windbg-tool context snapshot --session 1 --cursor 1"
            },
            {
                "goal": "Start a DbgEng TCP process server",
                "command": "windbg-tool dbgeng server --transport tcp:port=5005"
            },
            {
                "goal": "Generate host/target remote-debugging commands",
                "command": "windbg-tool remote explain"
            },
            {
                "goal": "Diagnose symbol and binary readiness",
                "command": "windbg-tool symbols diagnose --session 1"
            },
            {
                "goal": "Inspect a PE image for symbol-server keys",
                "command": "windbg-tool symbols inspect C:\\Windows\\System32\\notepad.exe"
            },
            {
                "goal": "Resolve a recorded source path under a local checkout",
                "command": "windbg-tool source resolve C:\\build\\repo\\src\\main.cpp --search-path D:\\src\\repo"
            },
            {
                "goal": "Disassemble at the current TTD cursor instruction pointer",
                "command": "windbg-tool disasm --session 1 --cursor 1 --count 12"
            },
            {
                "goal": "Inspect a COM/C++-style vtable without mutating the target",
                "command": "windbg-tool object vtable --session 1 --cursor 1 --address <object>"
            },
            {
                "goal": "Recover plausible return addresses from stack memory",
                "command": "windbg-tool stack recover --session 1 --cursor 1 --target-info"
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

fn recipes_value(args: RecipeArgs) -> anyhow::Result<Value> {
    let recipes = recipes_manifest();
    let Some(topic) = args.topic else {
        return Ok(json!({
            "recipes": recipes,
            "usage": "windbg-tool recipes <id-or-tag>",
        }));
    };
    let topic = topic.to_ascii_lowercase();
    let matches = recipes
        .as_array()
        .into_iter()
        .flatten()
        .filter(|recipe| recipe_matches_topic(recipe, &topic))
        .cloned()
        .collect::<Vec<_>>();
    if matches.is_empty() {
        bail!("unknown recipe topic: {topic}")
    }
    Ok(json!({ "recipes": matches }))
}

fn recipe_matches_topic(recipe: &Value, topic: &str) -> bool {
    recipe["id"]
        .as_str()
        .is_some_and(|id| id.eq_ignore_ascii_case(topic))
        || recipe["tags"].as_array().is_some_and(|tags| {
            tags.iter()
                .filter_map(Value::as_str)
                .any(|tag| tag.eq_ignore_ascii_case(topic))
        })
}

fn diagnostic_guidance() -> Value {
    json!({
        "principles": [
            {
                "id": "lightweight-first",
                "summary": "Start with the cheapest signal that can answer the question.",
                "use_when": ["known failure mode", "customer repro cost is high", "logs already exist"],
                "next_step": "Escalate to dumps, live debugging, or TTD only when logs/traces cannot isolate a time or state."
            },
            {
                "id": "time-vs-space",
                "summary": "Use time-oriented evidence to find when something changed; use space-oriented evidence to explain state at a point.",
                "time_tools": ["logs", "ETW/tracing", "TTD replay", "memory watchpoints"],
                "space_tools": ["crash dumps", "context snapshot", "stack/register/memory inspection"]
            },
            {
                "id": "structured-output",
                "summary": "Prefer JSON commands over terminal text so agent skills can compose results without brittle parsing.",
                "commands": ["discover", "recipes", "context snapshot", "tools", "schema <tool>"]
            }
        ],
        "safety": {
            "code_injection": "Analysis-only in windbg-tool; do not add general-purpose injection automation.",
            "registry_or_admin_changes": "Emit explicit recipes or plans unless a command name clearly states it mutates system state."
        }
    })
}

fn recipes_manifest() -> Value {
    json!([
        {
            "id": "diagnostic-technique",
            "title": "Choose the lightest diagnostic technique that can answer the question",
            "source_posts": ["why-you-should-printf", "first-post"],
            "tags": ["advisor", "logs", "tracing", "dump", "ttd", "live-debugging"],
            "problem": "The user has a symptom but has not chosen whether to use logs, dumps, live debugging, TTD, or remote debugging.",
            "guidance": [
                "Use logs or tracing first when they already contain enough temporal context.",
                "Use dumps when there is a crash/hang anchor point and state-at-time matters most.",
                "Use TTD when the important question is what changed before the anchor point.",
                "Use live or remote debugging when the process must be controlled interactively."
            ],
            "commands": ["windbg-tool discover", "windbg-tool context snapshot", "windbg-tool recipes crash-triage"]
        },
        {
            "id": "remote-debugging",
            "title": "Pick NTSD/CDB remote debugging vs DbgSrv process server",
            "source_posts": ["remote-debugging"],
            "tags": ["remote", "dbgeng", "dbgsrv", "ntsd", "cdb", "windbg"],
            "problem": "An agent needs to debug a target on another machine or in a sensitive desktop/session.",
            "guidance": [
                "Use NTSD/CDB -server when debugger brains, symbols, and extensions should live on the target and latency matters.",
                "Use DbgSrv when the target should stay minimal and symbols/extensions should stay on the host.",
                "Use WinDbg -remote for an existing NTSD/CDB remote session.",
                "Use WinDbg -premote for a DbgSrv process server that will launch or attach from the host side."
            ],
            "commands": [
                "windbg-tool dbgeng server --transport tcp:port=5005",
                "windbg-tool windbg run -- -premote tcp:port=5005,server=<target>",
                "windbg-tool recipes remote-debugging"
            ]
        },
        {
            "id": "crash-triage",
            "title": "Summarize a crash or end-of-trace state",
            "source_posts": ["writing-a-debugger-from-scratch-part-1", "writing-a-debugger-from-scratch-part-2", "debugger-lies-part-1"],
            "tags": ["crash", "triage", "exception", "stack", "registers"],
            "problem": "A trace/session is loaded and the agent needs the first actionable summary.",
            "guidance": [
                "Capture trace info, capabilities, current position, active thread state, registers, stack info, modules, and exceptions.",
                "Treat stack output as evidence, not truth; corrupted stacks can hide callers.",
                "If native replay is unavailable, stop before requesting native-only register/memory commands."
            ],
            "commands": [
                "windbg-tool context snapshot --session <id> --cursor <id>",
                "windbg-tool exceptions --session <id>",
                "windbg-tool registers --session <id> --cursor <id>",
                "windbg-tool stack info --session <id> --cursor <id>"
            ]
        },
        {
            "id": "stack-corruption",
            "title": "Find what overwrote a return address in TTD",
            "source_posts": ["debugger-lies-part-1", "writing-a-debugger-from-scratch-part-5", "writing-a-debugger-from-scratch-part-6"],
            "tags": ["ttd", "stack", "corruption", "watchpoint", "memory"],
            "problem": "The stack looks truncated, impossible, or corrupted near a crash.",
            "guidance": [
                "At the crashing position, identify the suspicious frame and return-address slot.",
                "Seek backward to the function entry if possible.",
                "Use a write watchpoint on the return-address slot to find the overwrite.",
                "Record stop position, thread, instruction, and stack bytes around the write."
            ],
            "commands": [
                "windbg-tool stack recover --session <id> --cursor <id> --target-info",
                "windbg-tool stack backtrace --session <id> --cursor <id> --target-info",
                "windbg-tool stack read --session <id> --cursor <id> --decode-pointers",
                "windbg-tool memory watchpoint --session <id> --cursor <id> --address <rsp> --size 8 --access write --direction next",
                "windbg-tool sweep watch-memory --session <id> --cursor <id> --address <rsp> --size 8 --access write --direction next --max-hits 8"
            ]
        },
        {
            "id": "symbol-health",
            "title": "Diagnose symbol and binary availability",
            "source_posts": ["symbol-indexing", "writing-a-debugger-from-scratch-part-4", "writing-a-debugger-from-scratch-part-8"],
            "tags": ["symbols", "pdb", "source", "binary", "modules"],
            "problem": "Names, stacks, source, or disassembly are missing or low fidelity.",
            "guidance": [
                "Check module timestamp/checksum/size and CodeView RSDS PDB identity when available.",
                "Remember symbol servers can serve binaries as well as PDBs; missing binaries can break stack walking.",
                "Use source path search and source hashes to avoid opening the wrong file."
            ],
            "commands": [
                "windbg-tool symbols diagnose --session <id>",
                "windbg-tool symbols inspect <path-to-exe-or-dll>",
                "windbg-tool symbols exports <path-to-exe-or-dll> --filter <name>",
                "windbg-tool symbols nearest --session <id> --cursor <id> --address <addr>",
                "windbg-tool source resolve <recorded-path> --search-path <checkout-root>",
                "windbg-tool modules --session <id>",
                "windbg-tool module info --session <id> --address <addr>",
                "windbg-tool schema ttd_module_info"
            ]
        },
        {
            "id": "memory-provenance",
            "title": "Classify unknown memory and find where it came from",
            "source_posts": ["writing-a-debugger-from-scratch-part-3", "recognizing-patterns", "useless-x86-trivia"],
            "tags": ["memory", "pointers", "strings", "code", "patterns"],
            "problem": "A byte range is suspicious and needs interpretation.",
            "guidance": [
                "Check whether values look like aligned integers, pointers, UTF-16/ASCII strings, code bytes, or high-entropy data.",
                "Use address classification before assuming a 64-bit value is a pointer, or use memory chase for bounded pointer-chain inspection.",
                "Use TTD memory provenance and watchpoints to connect a suspicious range to writes over time."
            ],
            "commands": [
                "windbg-tool address --session <id> --cursor <id> --address <addr>",
                "windbg-tool memory read --session <id> --cursor <id> --address <addr> --size 128",
                "windbg-tool memory dump --session <id> --cursor <id> --address <addr> --size 128 --format dq",
                "windbg-tool memory classify --session <id> --cursor <id> --address <addr> --size 128",
                "windbg-tool memory chase --session <id> --cursor <id> --address <addr> --depth 8 --target-info",
                "windbg-tool memory range --session <id> --cursor <id> --address <addr>",
                "windbg-tool memory buffer --session <id> --cursor <id> --address <addr> --size <n>"
            ]
        },
        {
            "id": "assembly-or-source",
            "title": "Move between instruction bytes, symbols, and source",
            "source_posts": ["fakers-guide-to-assembly", "writing-a-debugger-from-scratch-part-7", "writing-a-debugger-from-scratch-part-8"],
            "tags": ["assembly", "disassembly", "source", "instructions"],
            "problem": "Source is unavailable, misleading, or insufficient and the agent needs instruction-level truth.",
            "guidance": [
                "Prefer Intel syntax for Windows debugger workflows.",
                "Show instruction bytes, current address, decoded instruction, and nearest symbol together.",
                "When source exists, map both address-to-source and source-to-address; line mappings are not one-to-one."
            ],
            "commands": [
                "windbg-tool disasm --session <id> --cursor <id>",
                "windbg-tool u --session <id> --cursor <id> --address <rip> --count 16",
                "windbg-tool registers --session <id> --cursor <id>",
                "windbg-tool memory read --session <id> --cursor <id> --address <rip> --size 64"
            ]
        },
        {
            "id": "com-vtable",
            "title": "Investigate impossible calls through vtables or COM interfaces",
            "source_posts": ["vtables"],
            "tags": ["com", "vtable", "object", "dynamic-type"],
            "problem": "A call stack or source line appears to call the wrong method.",
            "guidance": [
                "Read the object pointer, then read the first pointer-sized field as the vtable pointer.",
                "Resolve vtable entries to symbols and confirm they live in an expected loaded image.",
                "Suspect interface layout mismatches when method ordinals point to unrelated symbols."
            ],
            "commands": [
                "windbg-tool object vtable --session <id> --cursor <id> --address <object>",
                "windbg-tool memory read --session <id> --cursor <id> --address <object> --size 8",
                "windbg-tool address --session <id> --cursor <id> --address <vtable>",
                "windbg-tool memory read --session <id> --cursor <id> --address <vtable> --size 64"
            ]
        },
        {
            "id": "injection-analysis",
            "title": "Analyze injection-like symptoms without automating injection",
            "source_posts": ["run-my-code"],
            "tags": ["injection", "modules", "memory-protection", "safety"],
            "problem": "A process may have unexpected code, DLLs, hooks, or executable memory.",
            "guidance": [
                "Do not use windbg-tool to inject arbitrary code.",
                "Inventory modules, DLL search-order clues, and executable memory regions.",
                "Classify unbacked executable memory and unexpected loaded modules as evidence for further review."
            ],
            "commands": [
                "windbg-tool modules --session <id>",
                "windbg-tool module audit --session <id>",
                "windbg-tool module search-order suspicious.dll --app-dir <app-dir>",
                "windbg-tool memory range --session <id> --cursor <id> --address <addr>",
                "windbg-tool address --session <id> --cursor <id> --address <addr>"
            ]
        }
    ])
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
        { "tool": "ttd_address_info", "commands": ["address", "memory chase --target-info"] },
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
        { "tool": "ttd_read_memory", "commands": ["memory read", "memory dump", "memory strings", "memory dps", "memory classify", "memory chase"] },
        { "tool": "ttd_memory_range", "commands": ["memory range"] },
        { "tool": "ttd_memory_buffer", "commands": ["memory buffer"] },
        { "tool": "ttd_memory_watchpoint", "commands": ["memory watchpoint", "watchpoint"] }
    ])
}

fn command_metadata() -> Value {
    json!([
        {
            "command": "discover",
            "requires_daemon": false,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "low",
            "safety": "read_only"
        },
        {
            "command": "open",
            "requires_daemon": true,
            "requires_native_ttd": "trace-backed sessions require native TTD; placeholder sessions are test-only",
            "session_required": false,
            "cost": "high_initial_load_then_reused",
            "safety": "read_only_trace_load"
        },
        {
            "command": "context snapshot",
            "requires_daemon": true,
            "requires_native_ttd": false,
            "session_required": "optional_but_recommended",
            "cost": "medium",
            "safety": "read_only"
        },
        {
            "command": "timeline events",
            "requires_daemon": true,
            "requires_native_ttd": true,
            "session_required": true,
            "cost": "medium",
            "safety": "read_only"
        },
        {
            "command": "register-context",
            "requires_daemon": true,
            "requires_native_ttd": true,
            "session_required": true,
            "cursor_required": true,
            "cost": "low",
            "safety": "read_only",
            "architecture": "x64"
        },
        {
            "command": "disasm",
            "requires_daemon": true,
            "requires_native_ttd": true,
            "session_required": true,
            "cursor_required": true,
            "cost": "low_to_medium",
            "safety": "read_only",
            "architecture": "x64"
        },
        {
            "command": "memory strings",
            "requires_daemon": true,
            "requires_native_ttd": true,
            "session_required": true,
            "cursor_required": true,
            "cost": "bounded_memory_read",
            "safety": "read_only_memory",
            "bounds": ["--size", "--max-strings", "--min-len"]
        },
        {
            "command": "memory dps",
            "requires_daemon": true,
            "requires_native_ttd": true,
            "session_required": true,
            "cursor_required": true,
            "cost": "bounded_memory_read",
            "safety": "read_only_memory",
            "bounds": ["--size", "--pointer-size"]
        },
        {
            "command": "memory watchpoint",
            "requires_daemon": true,
            "requires_native_ttd": true,
            "session_required": true,
            "cursor_required": true,
            "cost": "potentially_high_replay",
            "safety": "read_only_replay_cursor_moves"
        },
        {
            "command": "sweep watch-memory",
            "requires_daemon": true,
            "requires_native_ttd": true,
            "session_required": true,
            "cursor_required": true,
            "cost": "bounded_high_replay",
            "safety": "read_only_replay_cursor_moves",
            "bounds": ["--max-hits"]
        },
        {
            "command": "symbols inspect",
            "requires_daemon": false,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "low",
            "safety": "local_file_read"
        },
        {
            "command": "windbg install",
            "requires_daemon": false,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "network_and_disk",
            "safety": "downloads_and_extracts_microsoft_signed_package"
        },
        {
            "command": "dbgeng server",
            "requires_daemon": false,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "long_running",
            "safety": "opens_debug_process_server_transport"
        },
        {
            "command": "live launch",
            "requires_daemon": false,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "launches_process",
            "safety": "live_debugging_changes_target_execution_state",
            "bounds": ["--initial-break-timeout-ms", "--end detach|terminate"]
        },
        {
            "command": "target capabilities",
            "requires_daemon": false,
            "requires_native_ttd": false,
            "session_required": false,
            "cost": "low",
            "safety": "read_only_discovery"
        }
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
                "cli_commands": ["threads", "modules", "mods", "exceptions", "keyframes", "events modules", "events threads", "timeline events", "module info", "module audit", "symbols exports", "symbols nearest"],
                "notes": "Common trace-wide lists and event lists are covered. Local PE export parsing adds a low-fidelity nearest-export fallback when PDB symbols are unavailable."
            },
            {
                "id": "cursor_navigation",
                "status": "implemented",
                "ttd_api": ["NewCursor", "GetPosition", "SetPosition", "SetPositionOnThread", "ReplayForward", "ReplayBackward"],
                "native_bridge": ["ttd_mcp_new_cursor", "ttd_mcp_cursor_position", "ttd_mcp_set_position", "ttd_mcp_set_position_on_thread", "ttd_mcp_step_cursor"],
                "mcp_tools": ["ttd_cursor_create", "ttd_position_get", "ttd_position_set", "ttd_step", "ttd_active_threads", "ttd_cursor_modules"],
                "cli_commands": ["cursor create", "position get", "position set", "step", "replay capabilities", "replay to", "replay watch-memory", "sweep watch-memory", "active-threads", "active", "cursor modules"],
                "notes": "Basic navigation, replay-to-memory wrappers, and bounded client-side memory sweeps are covered; masks, position watchpoints, native jobs, clear/clone/interrupt remain native bridge gaps."
            },
            {
                "id": "register_state",
                "status": "implemented",
                "ttd_api": ["GetThreadInfo", "GetTebAddress", "GetProgramCounter", "GetStackPointer", "GetFramePointer", "GetBasicReturnValue", "GetCrossPlatformContext", "GetAvxExtendedContext"],
                "native_bridge": ["ttd_mcp_cursor_state", "ttd_mcp_x64_context", "ttd_mcp_active_threads"],
                "mcp_tools": ["ttd_registers", "ttd_register_context", "ttd_active_threads"],
                "cli_commands": ["architecture state", "arch state", "registers", "regs", "register-context", "ctx", "active-threads", "active"],
                "notes": "x64 scalar and SIMD state is covered and architecture support is now explicit; x86/ARM/ARM64 typed models remain gaps."
            },
            {
                "id": "memory_queries",
                "status": "implemented",
                "ttd_api": ["QueryMemoryRange", "QueryMemoryBuffer", "QueryMemoryBufferWithRanges", "QueryMemoryPolicy"],
                "native_bridge": ["ttd_mcp_read_memory", "ttd_mcp_query_memory_range", "ttd_mcp_query_memory_buffer_with_ranges"],
                "mcp_tools": ["ttd_read_memory", "ttd_memory_range", "ttd_memory_buffer", "ttd_address_info"],
                "cli_commands": ["memory read", "memory range", "memory buffer", "memory dump", "memory strings", "memory dps", "memory classify", "memory chase", "address"],
                "notes": "Per-call memory policy is covered; higher-level dump/strings/dps/classify/chase helpers are built on read_memory and address_info. Cursor default memory policy is a gap."
            },
            {
                "id": "stack_process_helpers",
                "status": "implemented",
                "ttd_api": ["GetTebAddress", "GetStackPointer", "QueryMemoryBuffer", "GetPebAddress"],
                "native_bridge": ["ttd_mcp_cursor_state", "ttd_mcp_read_memory", "ttd_mcp_trace_info"],
                "mcp_tools": ["ttd_stack_info", "ttd_stack_read", "ttd_command_line"],
                "cli_commands": ["stack info", "stack read", "stack recover", "stack backtrace", "command-line", "cmdline"],
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
                "status": "partial",
                "ttd_api": ["GetRecordClientList", "GetCustomEventList", "GetActivityList", "GetIslandList"],
                "native_bridge": [],
                "mcp_tools": [],
                "cli_commands": ["timeline events"],
                "notes": "timeline events merges currently exposed module/thread/exception/keyframe metadata; custom event, activity, island, and record-client payloads still need native bridge coverage."
            },
            {
                "id": "replay_masks_position_watchpoints",
                "status": "partial",
                "ttd_api": ["SetEventMask", "SetGapKindMask", "SetGapEventMask", "SetExceptionMask", "SetReplayFlags", "AddPositionWatchpoint", "RemovePositionWatchpoint", "Clear", "InterruptReplay"],
                "native_bridge": [],
                "mcp_tools": [],
                "cli_commands": ["replay capabilities", "replay to", "replay watch-memory"],
                "notes": "CLI wrappers expose supported position and memory replay operations and report unsupported controls; masks, position watchpoints, clear, and interrupt still need native bridge coverage."
            },
            {
                "id": "callback_sweeps",
                "status": "partial",
                "ttd_api": ["SetMemoryWatchpointCallback", "SetPositionWatchpointCallback", "SetGapEventCallback", "SetReplayProgressCallback", "SetThreadContinuityBreakCallback", "SetFallbackCallback", "SetCallReturnCallback", "SetIndirectJumpCallback", "SetRegisterChangedCallback"],
                "native_bridge": [],
                "mcp_tools": [],
                "cli_commands": ["sweep watch-memory", "breakpoint capabilities"],
                "notes": "sweep watch-memory provides bounded foreground multi-hit collection over first-hit memory watchpoints; native callbacks are still needed for progress, cancellation, call/return traces, jump traces, and register-change traces."
            },
            {
                "id": "module_symbol_enrichment",
                "status": "partial",
                "ttd_api": ["Module::Checksum", "Module::Timestamp"],
                "native_bridge": [],
                "mcp_tools": [],
                "cli_commands": ["symbols diagnose", "symbols inspect", "symbols exports", "symbols nearest"],
                "notes": "Local PE/PDB/export diagnostics and nearest-export fallback are covered; native TraceModule checksum/timestamp fields and true DbgHelp/SymSrv/PDB nearest-symbol/source helpers remain gaps."
            },
            {
                "id": "cursor_lifecycle_and_replay_jobs",
                "status": "gap",
                "ttd_api": ["Cursor::Clone", "Cursor::Clear", "Cursor::InterruptReplay", "ReplayProgressCallback"],
                "native_bridge": [],
                "mcp_tools": [],
                "cli_commands": [],
                "notes": "Needed for daemon-owned cancellable replay jobs, progress reporting, cursor cloning, and explicit cursor state clearing."
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

async fn module_audit_and_print(
    pipe: String,
    args: ModuleAuditArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    ensure!(
        args.max_suspicious <= 10_000,
        "module audit --max-suspicious must not exceed 10000"
    );
    let client = DaemonClient::new(pipe);
    let modules = if let Some(cursor) = args.cursor {
        client
            .call_tool(cursor_call(
                "ttd_cursor_modules",
                CursorArgs {
                    session: args.session,
                    cursor,
                },
            ))
            .await?
    } else {
        client
            .call_tool(session_call(
                "ttd_list_modules",
                SessionArgs {
                    session: args.session,
                },
            ))
            .await?
    };
    let module_items = modules["modules"]
        .as_array()
        .context("module list response did not include modules")?;
    print_value(
        json!({
            "session_id": args.session,
            "cursor_id": args.cursor,
            "source": if args.cursor.is_some() { "cursor_modules" } else { "trace_modules" },
            "module_count": module_items.len(),
            "audit": audit_modules(module_items, args.max_suspicious),
            "modules": modules,
            "notes": [
                "This is read-only triage based on module paths and load inventory.",
                "Suspicious paths are evidence for review, not proof of injection."
            ]
        }),
        output,
    )
}

async fn timeline_events_and_print(
    pipe: String,
    args: TimelineEventsArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let client = DaemonClient::new(pipe);
    print_value(timeline_events_value(&client, &args).await?, output)
}

async fn timeline_events_value(
    client: &DaemonClient,
    args: &TimelineEventsArgs,
) -> anyhow::Result<Value> {
    ensure!(
        args.max_events <= 100_000,
        "timeline events --max-events must not exceed 100000"
    );
    let include = |kind: &str| args.kind == "all" || args.kind == kind;
    let mut events = Vec::new();
    let mut sources = Map::new();

    if include("modules") {
        let value = call_status_value(
            client
                .call_tool(session_call(
                    "ttd_module_events",
                    SessionArgs {
                        session: args.session,
                    },
                ))
                .await,
        );
        collect_timeline_events(&mut events, "module", &value, "events");
        sources.insert("modules".to_string(), value);
    }
    if include("threads") {
        let value = call_status_value(
            client
                .call_tool(session_call(
                    "ttd_thread_events",
                    SessionArgs {
                        session: args.session,
                    },
                ))
                .await,
        );
        collect_timeline_events(&mut events, "thread", &value, "events");
        sources.insert("threads".to_string(), value);
    }
    if include("exceptions") {
        let value = call_status_value(
            client
                .call_tool(session_call(
                    "ttd_list_exceptions",
                    SessionArgs {
                        session: args.session,
                    },
                ))
                .await,
        );
        collect_timeline_events(&mut events, "exception", &value, "exceptions");
        sources.insert("exceptions".to_string(), value);
    }
    if include("keyframes") {
        let value = call_status_value(
            client
                .call_tool(session_call(
                    "ttd_list_keyframes",
                    SessionArgs {
                        session: args.session,
                    },
                ))
                .await,
        );
        collect_keyframe_events(&mut events, &value);
        sources.insert("keyframes".to_string(), value);
    }

    events.sort_by(|left, right| {
        timeline_sequence(left)
            .cmp(&timeline_sequence(right))
            .then_with(|| left["kind"].as_str().cmp(&right["kind"].as_str()))
    });
    let total_events = events.len();
    if events.len() > args.max_events {
        events.truncate(args.max_events);
    }
    Ok(json!({
        "session_id": args.session,
        "kind": args.kind,
        "total_events": total_events,
        "max_events": args.max_events,
        "truncated": total_events > args.max_events,
        "events": events,
        "sources": Value::Object(sources),
        "unsupported_recording_metadata": [
            "record clients",
            "custom events",
            "activities",
            "islands",
            "bounded user-data payload extraction"
        ],
        "notes": [
            "This timeline merges currently exposed trace metadata.",
            "Recording-client/custom-event/activity/island metadata requires additional native TTD bridge coverage."
        ]
    }))
}

fn module_search_order_and_print(
    args: ModuleSearchOrderArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let dll = normalize_dll_name(&args.dll)?;
    let current_dir = args
        .current_dir
        .unwrap_or(std::env::current_dir().context("resolving current directory")?);
    let windows_dir = PathBuf::from(
        std::env::var("WINDIR")
            .or_else(|_| std::env::var("SystemRoot"))
            .unwrap_or_else(|_| String::from(r"C:\Windows")),
    );
    let system32 = windows_dir.join("System32");
    let system = windows_dir.join("System");
    let max_path_dirs = args.max_path_dirs.unwrap_or(64);

    let mut candidates = Vec::new();
    candidates.push(json!({
        "order": 0,
        "kind": "known_dlls",
        "directory": null,
        "candidate": null,
        "exists": null,
        "risk": "system_controlled",
        "notes": "KnownDLLs are resolved by the loader before filesystem probing when the name is registered."
    }));
    let mut order = 1usize;
    if let Some(app_dir) = args.app_dir {
        candidates.push(search_candidate(
            order,
            "application_directory",
            &app_dir,
            &dll,
        ));
        order += 1;
    }
    for (kind, directory) in [
        ("system32", system32.as_path()),
        ("system", system.as_path()),
        ("windows", windows_dir.as_path()),
        ("current_directory", current_dir.as_path()),
    ] {
        candidates.push(search_candidate(order, kind, directory, &dll));
        order += 1;
    }
    let path_dirs = std::env::var_os("PATH")
        .map(|value| {
            std::env::split_paths(&value)
                .take(max_path_dirs)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for directory in &path_dirs {
        candidates.push(search_candidate(order, "path_directory", directory, &dll));
        order += 1;
    }
    let risky_candidates = candidates
        .iter()
        .filter(|candidate| candidate["risk"] != "system_controlled")
        .count();
    print_value(
        json!({
            "dll": dll,
            "candidate_count": candidates.len(),
            "path_dirs_included": path_dirs.len(),
            "path_dirs_truncated": std::env::var_os("PATH")
                .map(|value| std::env::split_paths(&value).count() > path_dirs.len())
                .unwrap_or(false),
            "risky_candidate_count": risky_candidates,
            "candidates": candidates,
            "notes": [
                "This is a diagnostic model for common user-mode DLL search-order reasoning, not a loader trace.",
                "SafeDllSearchMode, package identity, API sets, manifests, KnownDLLs, SetDllDirectory/AddDllDirectory, and LoadLibrary flags can change real behavior.",
                "Prefer absolute paths or application-local signed dependencies when diagnosing DLL search-order issues."
            ]
        }),
        output,
    )
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

async fn replay_capabilities_and_print(
    pipe: String,
    args: SessionArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let client = DaemonClient::new(pipe);
    let capabilities = client
        .call_tool(session_call("ttd_capabilities", args))
        .await?;
    print_value(
        json!({
            "capabilities": capabilities,
            "supported_controls": [
                "position get",
                "position set",
                "position set --thread-unique-id",
                "step --direction forward|backward --kind step|trace",
                "memory watchpoint --direction next|previous",
                "replay to",
                "replay watch-memory"
            ],
            "unsupported_native_controls": [
                "cursor clone",
                "cursor clear",
                "cursor close",
                "interrupt replay",
                "event masks",
                "gap masks",
                "exception masks",
                "replay flags",
                "position watchpoints",
                "bounded replay-to-position with native stop masks"
            ],
            "notes": [
                "Supported controls are built from currently exposed TTD replay primitives.",
                "Unsupported controls need additional native bridge coverage before they can be safely exposed as real controls."
            ]
        }),
        output,
    )
}

async fn replay_to_and_print(
    pipe: String,
    args: ReplayToArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let client = DaemonClient::new(pipe);
    let before = call_status_value(
        client
            .call_tool(cursor_call(
                "ttd_position_get",
                CursorArgs {
                    session: args.session,
                    cursor: args.cursor,
                },
            ))
            .await,
    );
    let after = client
        .call_tool(position_set_call(PositionSetArgs {
            session: args.session,
            cursor: args.cursor,
            position: args.position.clone(),
            thread_unique_id: args.thread_unique_id,
        })?)
        .await?;
    print_value(
        json!({
            "session_id": args.session,
            "cursor_id": args.cursor,
            "requested_position": args.position,
            "thread_unique_id": args.thread_unique_id,
            "before": before,
            "after": after,
            "method": if args.thread_unique_id.is_some() { "set_position_on_thread" } else { "set_position" }
        }),
        output,
    )
}

async fn sweep_watch_memory_and_print(
    pipe: String,
    args: SweepWatchMemoryArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    ensure!(
        args.max_hits > 0,
        "sweep watch-memory max-hits must be greater than zero"
    );
    ensure!(
        args.max_hits <= 1024,
        "sweep watch-memory max-hits must not exceed 1024"
    );
    let client = DaemonClient::new(pipe);
    let mut hits = Vec::new();
    let mut seen_positions = std::collections::BTreeSet::new();
    let mut stop_reason = "max_hits";

    for _ in 0..args.max_hits {
        let hit = client
            .call_tool(watchpoint_call(WatchpointArgs {
                session: args.session,
                cursor: args.cursor,
                address: args.address.clone(),
                size: args.size,
                access: args.access.clone(),
                direction: args.direction.clone(),
                thread_unique_id: args.thread_unique_id,
            })?)
            .await?;
        if hit["found"].as_bool() != Some(true) {
            stop_reason = "not_found";
            hits.push(hit);
            break;
        }
        let sequence = hit["position"]["sequence"].as_u64();
        if let Some(sequence) = sequence {
            if !seen_positions.insert(sequence) {
                stop_reason = "duplicate_position";
                hits.push(hit);
                break;
            }
        }
        hits.push(hit);
        client
            .call_tool(step_call(StepArgs {
                session: args.session,
                cursor: args.cursor,
                direction: Some(match args.direction.as_str() {
                    "previous" => "backward".to_string(),
                    _ => "forward".to_string(),
                }),
                kind: Some("step".to_string()),
                count: Some(1),
            }))
            .await?;
    }

    print_value(
        json!({
            "session_id": args.session,
            "cursor_id": args.cursor,
            "address": parse_u64_argument(&args.address)?,
            "size": args.size,
            "access": args.access,
            "direction": args.direction,
            "thread_unique_id": args.thread_unique_id,
            "max_hits": args.max_hits,
            "hit_count": hits.iter().filter(|hit| hit["found"].as_bool() == Some(true)).count(),
            "stop_reason": stop_reason,
            "hits": hits,
            "notes": [
                "This is a bounded client-side sweep over first-hit TTD watchpoints.",
                "The command advances one step after each hit to avoid reporting the same position repeatedly.",
                "Daemon-owned background jobs with progress/cancel remain future native/daemon work."
            ]
        }),
        output,
    )
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

async fn stack_recover_and_print(
    pipe: String,
    args: StackRecoverArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    ensure!(
        (0.0..=1.0).contains(&args.min_confidence),
        "min-confidence must be between 0.0 and 1.0"
    );
    ensure!(
        args.max_candidates > 0,
        "max-candidates must be greater than zero"
    );
    ensure!(
        args.max_candidates <= 512,
        "max-candidates must be 512 or less"
    );

    let client = DaemonClient::new(pipe);
    let stack_read = client
        .call_tool(stack_read_call(StackReadArgs {
            session: args.session,
            cursor: args.cursor,
            size: args.size.or(Some(4096)),
            offset_from_sp: args.offset_from_sp,
            decode_pointers: true,
        }))
        .await?;
    let mut candidates =
        recover_stack_candidates(&stack_read, args.max_candidates, args.min_confidence);
    if args.target_info {
        enrich_stack_candidates(&client, args.session, args.cursor, &mut candidates).await;
    }

    print_value(
        json!({
            "session_id": args.session,
            "cursor_id": args.cursor,
            "stack": stack_read,
            "candidates": candidates,
            "heuristics": [
                "Pointer-sized stack values that land inside a loaded module are likely return-address candidates.",
                "Confidence is higher for module hits, aligned stack slots, and values that look like canonical x64 pointers.",
                "This is recovery evidence, not a trusted unwind; validate candidates with symbols, disassembly, and call-site context."
            ],
            "follow_up": [
                "Use disasm --address <candidate> to inspect code near a candidate.",
                "Use memory watchpoint on a corrupted return-address slot to find writes in TTD."
            ]
        }),
        output,
    )
}

async fn stack_backtrace_and_print(
    pipe: String,
    args: StackBacktraceArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    ensure!(
        args.max_frames > 0,
        "stack backtrace max-frames must be greater than zero"
    );
    ensure!(
        args.max_frames <= 1024,
        "stack backtrace max-frames must not exceed 1024"
    );
    let client = DaemonClient::new(pipe);
    let registers = client
        .call_tool(cursor_call(
            "ttd_registers",
            CursorArgs {
                session: args.session,
                cursor: args.cursor,
            },
        ))
        .await?;
    let stack_read = client
        .call_tool(stack_read_call(StackReadArgs {
            session: args.session,
            cursor: args.cursor,
            size: Some(args.size),
            offset_from_sp: args.offset_from_sp,
            decode_pointers: true,
        }))
        .await?;
    let candidate_budget = args.max_frames.saturating_sub(1);
    let mut candidates =
        recover_stack_candidates(&stack_read, candidate_budget, args.min_confidence);
    if args.target_info {
        enrich_stack_candidates(&client, args.session, args.cursor, &mut candidates).await;
    }
    let mut frames = Vec::new();
    if let Some(pc) = registers["program_counter"].as_u64() {
        let mut current = json!({
            "index": 0,
            "kind": "current_instruction",
            "address": pc,
            "address_hex": format!("0x{pc:016x}"),
            "confidence": 1.0,
            "reasons": ["current_program_counter"],
        });
        if args.target_info {
            current["target_info"] = client
                .call_tool(address_info_call(AddressInfoArgs {
                    session: args.session,
                    cursor: args.cursor,
                    address: pc.to_string(),
                }))
                .await?;
        }
        frames.push(current);
    }
    for (index, candidate) in candidates.into_iter().enumerate() {
        frames.push(json!({
            "index": frames.len(),
            "kind": "recovered_return_address",
            "address": candidate["target"],
            "address_hex": candidate["target_hex"],
            "stack_slot": candidate["slot_address"],
            "stack_slot_hex": candidate["slot_address_hex"],
            "module": candidate["module"],
            "confidence": candidate["confidence"],
            "reasons": candidate["reasons"],
            "target_info": candidate.get("target_info").cloned().unwrap_or(Value::Null),
            "candidate_rank": index,
        }));
    }
    print_value(
        json!({
            "session_id": args.session,
            "cursor_id": args.cursor,
            "position": registers["position"],
            "thread": registers["thread"],
            "method": "heuristic_stack_scan",
            "trusted_unwind": false,
            "frames": frames,
            "stack_read": stack_read,
            "warnings": [
                "This is not a DbgHelp/DbgEng unwind and may include false positives.",
                "Use stack recover output, disassembly, symbols, and TTD watchpoints to validate suspicious return-address candidates."
            ]
        }),
        output,
    )
}

fn recover_stack_candidates(
    stack_read: &Value,
    max_candidates: usize,
    min_confidence: f64,
) -> Vec<Value> {
    let mut candidates = stack_read["pointers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|pointer| {
            let value = pointer["value"].as_u64()?;
            let slot_address = pointer["address"].as_u64()?;
            let module = pointer["module"].as_str();
            let confidence = stack_candidate_confidence(value, slot_address, module.is_some());
            (confidence >= min_confidence).then(|| {
                json!({
                    "slot_address": slot_address,
                    "slot_address_hex": format!("0x{slot_address:X}"),
                    "offset": pointer["offset"].as_u64().unwrap_or_default(),
                    "target": value,
                    "target_hex": format!("0x{value:X}"),
                    "module": module,
                    "confidence": confidence,
                    "reasons": stack_candidate_reasons(value, slot_address, module.is_some()),
                })
            })
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        right["confidence"]
            .as_f64()
            .partial_cmp(&left["confidence"].as_f64())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                left["slot_address"]
                    .as_u64()
                    .cmp(&right["slot_address"].as_u64())
            })
    });
    candidates.truncate(max_candidates);
    candidates
}

fn stack_candidate_confidence(value: u64, slot_address: u64, in_module: bool) -> f64 {
    let mut confidence = 0.15;
    if in_module {
        confidence += 0.55;
    }
    if slot_address.is_multiple_of(8) {
        confidence += 0.10;
    }
    if plausible_x64_pointer(value) {
        confidence += 0.15;
    }
    if value.is_multiple_of(16) {
        confidence += 0.05;
    }
    f64::min(confidence, 1.0)
}

fn stack_candidate_reasons(value: u64, slot_address: u64, in_module: bool) -> Vec<&'static str> {
    let mut reasons = Vec::new();
    if in_module {
        reasons.push("target_in_loaded_module");
    }
    if slot_address.is_multiple_of(8) {
        reasons.push("aligned_stack_slot");
    }
    if plausible_x64_pointer(value) {
        reasons.push("canonical_aligned_x64_pointer");
    }
    if value.is_multiple_of(16) {
        reasons.push("target_16_byte_aligned");
    }
    reasons
}

async fn enrich_stack_candidates(
    client: &DaemonClient,
    session: u64,
    cursor: u64,
    candidates: &mut [Value],
) {
    for candidate in candidates {
        let Some(target) = candidate["target"].as_u64() else {
            continue;
        };
        candidate["target_info"] = call_status_value(
            client
                .call_tool(ToolCall {
                    name: "ttd_address_info".to_string(),
                    arguments: json!({
                        "session_id": session,
                        "cursor_id": cursor,
                        "address": target,
                    }),
                })
                .await,
        );
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

async fn disasm_and_print(
    pipe: String,
    args: DisasmArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let client = DaemonClient::new(pipe);
    print_value(disasm_value(&client, &args).await?, output)
}

async fn disasm_value(client: &DaemonClient, args: &DisasmArgs) -> anyhow::Result<Value> {
    ensure!(args.count > 0, "count must be greater than zero");
    ensure!(args.count <= 256, "count must be 256 instructions or less");
    ensure!(args.bytes > 0, "bytes must be greater than zero");
    ensure!(args.bytes <= 4096, "bytes must be 4096 or less");

    let (address, context) = disasm_address(client, args).await?;
    let read = client
        .call_tool(memory_read_call(MemoryReadArgs {
            session: args.session,
            cursor: args.cursor,
            address: format!("0x{address:X}"),
            size: args.bytes,
            policy: args.policy.clone(),
        })?)
        .await?;
    let data = read["data"]
        .as_str()
        .context("ttd_read_memory response did not include hex data")?;
    let bytes = hex_to_bytes(data)?;
    Ok(json!({
        "session_id": args.session,
        "cursor_id": args.cursor,
        "architecture": "x64",
        "address": address,
        "address_hex": format!("0x{address:X}"),
        "context": context,
        "read": read,
        "instructions": disassemble_x64(address, &bytes, args.count as usize),
    }))
}

async fn object_vtable_and_print(
    pipe: String,
    args: ObjectVtableArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    ensure!(args.entries > 0, "entries must be greater than zero");
    ensure!(args.entries <= 256, "entries must be 256 or less");
    let object_address = parse_u64_argument(&args.address)?;
    let client = DaemonClient::new(pipe);
    let object_read = client
        .call_tool(memory_read_call(MemoryReadArgs {
            session: args.session,
            cursor: args.cursor,
            address: format!("0x{object_address:X}"),
            size: 8,
            policy: args.policy.clone(),
        })?)
        .await?;
    let object_bytes = hex_to_bytes(
        object_read["data"]
            .as_str()
            .context("object pointer read did not include hex data")?,
    )?;
    ensure!(
        object_bytes.len() >= 8,
        "object pointer read returned fewer than 8 bytes"
    );
    let vtable_address = u64::from_le_bytes(object_bytes[..8].try_into()?);
    ensure!(vtable_address != 0, "object vtable pointer is null");

    let table_size = args.entries.saturating_mul(8);
    let vtable_read = client
        .call_tool(memory_read_call(MemoryReadArgs {
            session: args.session,
            cursor: args.cursor,
            address: format!("0x{vtable_address:X}"),
            size: table_size,
            policy: args.policy,
        })?)
        .await?;
    let vtable_bytes = hex_to_bytes(
        vtable_read["data"]
            .as_str()
            .context("vtable read did not include hex data")?,
    )?;
    let mut entries = Vec::new();
    for (index, chunk) in vtable_bytes.chunks_exact(8).enumerate() {
        let target = u64::from_le_bytes(chunk.try_into()?);
        let target_info = if target == 0 {
            json!({ "ok": false, "error": "null vtable entry" })
        } else {
            call_status_value(
                client
                    .call_tool(ToolCall {
                        name: "ttd_address_info".to_string(),
                        arguments: json!({
                            "session_id": args.session,
                            "cursor_id": args.cursor,
                            "address": target,
                        }),
                    })
                    .await,
            )
        };
        entries.push(json!({
            "index": index,
            "slot_address": vtable_address + (index as u64 * 8),
            "slot_address_hex": format!("0x{:X}", vtable_address + (index as u64 * 8)),
            "target": target,
            "target_hex": format!("0x{target:X}"),
            "plausible_x64_pointer": plausible_x64_pointer(target),
            "target_info": target_info,
        }));
    }

    let vtable_info = call_status_value(
        client
            .call_tool(ToolCall {
                name: "ttd_address_info".to_string(),
                arguments: json!({
                    "session_id": args.session,
                    "cursor_id": args.cursor,
                    "address": vtable_address,
                }),
            })
            .await,
    );
    print_value(
        json!({
            "session_id": args.session,
            "cursor_id": args.cursor,
            "object_address": object_address,
            "object_address_hex": format!("0x{object_address:X}"),
            "vtable_address": vtable_address,
            "vtable_address_hex": format!("0x{vtable_address:X}"),
            "object_read": object_read,
            "vtable_read": vtable_read,
            "vtable_info": vtable_info,
            "entries": entries,
            "safety": "read_only_analysis"
        }),
        output,
    )
}

async fn disasm_address(client: &DaemonClient, args: &DisasmArgs) -> anyhow::Result<(u64, Value)> {
    if let Some(address) = args.address.as_deref() {
        return Ok((
            parse_u64_argument(address)?,
            json!({ "source": "explicit" }),
        ));
    }

    let context = client
        .call_tool(register_context_call(RegisterContextArgs {
            session: args.session,
            cursor: args.cursor,
            thread_id: args.thread_id,
        }))
        .await
        .context("resolving current RIP with ttd_register_context")?;
    let rip = context["registers"]["rip"]
        .as_u64()
        .or_else(|| context["rip"].as_u64())
        .context("ttd_register_context response did not include registers.rip")?;
    Ok((
        rip,
        json!({ "source": "cursor_rip", "register_context": context }),
    ))
}

fn disassemble_x64(address: u64, bytes: &[u8], count: usize) -> Vec<Value> {
    let mut decoder = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    let mut instructions = Vec::new();
    while decoder.can_decode() && instructions.len() < count {
        let instruction = decoder.decode();
        let mut text = String::new();
        formatter.format(&instruction, &mut text);
        let len = instruction.len();
        let offset = instruction.ip().saturating_sub(address) as usize;
        let end = offset.saturating_add(len).min(bytes.len());
        let instruction_bytes = if offset < bytes.len() {
            bytes[offset..end]
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        instructions.push(json!({
            "address": instruction.ip(),
            "address_hex": format!("0x{:X}", instruction.ip()),
            "length": len,
            "bytes": instruction_bytes,
            "text": text,
            "mnemonic": format!("{:?}", instruction.mnemonic()).to_ascii_lowercase(),
            "flow_control": format!("{:?}", instruction.flow_control()).to_ascii_lowercase(),
            "classification": instruction_classification(&instruction, &text),
            "operands": instruction_operands(&instruction),
        }));
    }
    instructions
}

fn instruction_classification(instruction: &Instruction, text: &str) -> Value {
    let lower = text.to_ascii_lowercase();
    let mut tags = Vec::new();
    match instruction.flow_control() {
        FlowControl::Next => {}
        FlowControl::Call | FlowControl::IndirectCall => tags.push("call"),
        FlowControl::Return => tags.push("return"),
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => tags.push("jump"),
        FlowControl::ConditionalBranch => tags.push("conditional_jump"),
        FlowControl::Interrupt | FlowControl::XbeginXabortXend => tags.push("control_transfer"),
        _ => tags.push("control_transfer"),
    }
    if has_memory_operand(instruction) {
        tags.push("memory_access");
    }
    if lower.contains("rsp")
        || lower.contains("rbp")
        || lower.contains("esp")
        || lower.contains("ebp")
    {
        tags.push("stack_related");
    }
    if instruction.memory_segment() == Register::FS || instruction.memory_segment() == Register::GS
    {
        tags.push("teb_tls_segment");
    }
    if lower.contains("int3") || lower == "db 0cch" {
        tags.push("breakpoint");
    }
    if lower.starts_with("syscall") || lower.starts_with("sysenter") {
        tags.push("system_call");
    }
    json!({
        "tags": tags,
        "is_control_flow": instruction.flow_control() != FlowControl::Next,
        "has_memory_operand": has_memory_operand(instruction),
        "is_stack_related": lower.contains("rsp") || lower.contains("rbp") || lower.contains("esp") || lower.contains("ebp"),
    })
}

fn instruction_operands(instruction: &Instruction) -> Vec<Value> {
    (0..instruction.op_count())
        .map(|index| {
            let op_kind = instruction.op_kind(index);
            let mut operand = json!({
                "index": index,
                "kind": format!("{op_kind:?}").to_ascii_lowercase(),
            });
            if is_memory_op_kind(op_kind) {
                operand["memory"] = json!({
                    "segment": register_name(instruction.memory_segment()),
                    "base": register_name(instruction.memory_base()),
                    "index": register_name(instruction.memory_index()),
                    "scale": instruction.memory_index_scale(),
                    "displacement": instruction.memory_displacement64(),
                    "displacement_hex": format!("0x{:X}", instruction.memory_displacement64()),
                });
            }
            operand
        })
        .collect()
}

fn has_memory_operand(instruction: &Instruction) -> bool {
    (0..instruction.op_count()).any(|index| is_memory_op_kind(instruction.op_kind(index)))
}

fn is_memory_op_kind(op_kind: OpKind) -> bool {
    matches!(
        op_kind,
        OpKind::Memory
            | OpKind::MemorySegSI
            | OpKind::MemorySegESI
            | OpKind::MemorySegRSI
            | OpKind::MemorySegDI
            | OpKind::MemorySegEDI
            | OpKind::MemorySegRDI
            | OpKind::MemoryESDI
            | OpKind::MemoryESEDI
            | OpKind::MemoryESRDI
    )
}

fn register_name(register: Register) -> Option<String> {
    (register != Register::None).then(|| format!("{register:?}").to_ascii_lowercase())
}

async fn memory_dump_and_print(
    pipe: String,
    args: MemoryDumpArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let client = DaemonClient::new(pipe);
    let format = args.format.clone();
    let read = client
        .call_tool(memory_read_call(MemoryReadArgs {
            session: args.session,
            cursor: args.cursor,
            address: args.address,
            size: args.size,
            policy: args.policy,
        })?)
        .await?;
    let data = read["data"]
        .as_str()
        .context("ttd_read_memory response did not include hex data")?;
    let bytes = hex_to_bytes(data)?;
    let address = read["address"].as_u64().unwrap_or_default();
    print_value(
        json!({
            "read": read,
            "dump": memory_dump(address, &bytes, &format)?,
        }),
        output,
    )
}

async fn memory_classify_and_print(
    pipe: String,
    args: MemoryClassifyArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let client = DaemonClient::new(pipe);
    let read = client
        .call_tool(memory_read_call(MemoryReadArgs {
            session: args.session,
            cursor: args.cursor,
            address: args.address,
            size: args.size,
            policy: args.policy,
        })?)
        .await?;
    let data = read["data"]
        .as_str()
        .context("ttd_read_memory response did not include hex data")?;
    let bytes = hex_to_bytes(data)?;
    let address = read["address"].as_u64().unwrap_or_default();
    print_value(
        json!({
            "read": read,
            "classification": classify_memory(address, &bytes),
        }),
        output,
    )
}

async fn memory_strings_and_print(
    pipe: String,
    args: MemoryStringsArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    ensure!(
        args.max_strings <= 10_000,
        "memory strings --max-strings must not exceed 10000"
    );
    let client = DaemonClient::new(pipe);
    let read = client
        .call_tool(memory_read_call(MemoryReadArgs {
            session: args.session,
            cursor: args.cursor,
            address: args.address,
            size: args.size,
            policy: args.policy,
        })?)
        .await?;
    let data = read["data"]
        .as_str()
        .context("ttd_read_memory response did not include hex data")?;
    let bytes = hex_to_bytes(data)?;
    let address = read["address"].as_u64().unwrap_or_default();
    let mut strings = Vec::new();
    if args.encoding == "ascii" || args.encoding == "both" {
        strings.extend(
            ascii_strings(address, &bytes)
                .into_iter()
                .filter(|item| {
                    item["text"]
                        .as_str()
                        .is_some_and(|text| text.len() >= args.min_len)
                })
                .map(|mut item| {
                    item["encoding"] = Value::String("ascii".to_string());
                    item
                }),
        );
    }
    if args.encoding == "utf16" || args.encoding == "both" {
        strings.extend(
            utf16le_strings(address, &bytes)
                .into_iter()
                .filter(|item| {
                    item["text"]
                        .as_str()
                        .is_some_and(|text| text.len() >= args.min_len)
                })
                .map(|mut item| {
                    item["encoding"] = Value::String("utf16".to_string());
                    item
                }),
        );
    }
    strings.sort_by_key(|item| item["address"].as_u64().unwrap_or(u64::MAX));
    let total_strings = strings.len();
    if strings.len() > args.max_strings {
        strings.truncate(args.max_strings);
    }
    print_value(
        json!({
            "read": read,
            "encoding": args.encoding,
            "min_len": args.min_len,
            "total_strings": total_strings,
            "max_strings": args.max_strings,
            "truncated": total_strings > args.max_strings,
            "strings": strings,
            "unavailable_bytes": if read["complete"].as_bool() == Some(false) { read["requested_size"].as_u64().unwrap_or_default().saturating_sub(read["bytes_read"].as_u64().unwrap_or_default()) } else { 0 }
        }),
        output,
    )
}

async fn memory_dps_and_print(
    pipe: String,
    args: MemoryDpsArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    ensure!(
        matches!(args.pointer_size, 4 | 8),
        "memory dps pointer size must be 4 or 8"
    );
    let client = DaemonClient::new(pipe);
    let read = client
        .call_tool(memory_read_call(MemoryReadArgs {
            session: args.session,
            cursor: args.cursor,
            address: args.address,
            size: args.size,
            policy: args.policy,
        })?)
        .await?;
    let data = read["data"]
        .as_str()
        .context("ttd_read_memory response did not include hex data")?;
    let bytes = hex_to_bytes(data)?;
    let base = read["address"].as_u64().unwrap_or_default();
    let mut rows = Vec::new();
    for (index, chunk) in bytes.chunks(args.pointer_size as usize).enumerate() {
        if chunk.len() < args.pointer_size as usize {
            break;
        }
        let slot = base + (index as u64 * args.pointer_size as u64);
        let target = read_pointer_value(chunk, args.pointer_size)?;
        let mut row = json!({
            "slot": slot,
            "slot_hex": format!("0x{slot:016x}"),
            "value": target,
            "value_hex": format!("0x{target:016x}"),
            "plausible_x64_pointer": plausible_x64_pointer(target),
            "null": target == 0
        });
        if args.target_info && target != 0 {
            row["target_info"] = call_status_value(
                client
                    .call_tool(address_info_call(AddressInfoArgs {
                        session: args.session,
                        cursor: args.cursor,
                        address: target.to_string(),
                    }))
                    .await,
            );
        }
        rows.push(row);
    }
    print_value(
        json!({
            "read": read,
            "pointer_size": args.pointer_size,
            "row_count": rows.len(),
            "rows": rows
        }),
        output,
    )
}

async fn memory_chase_and_print(
    pipe: String,
    args: MemoryChaseArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    ensure!(
        args.depth > 0,
        "memory chase depth must be greater than zero"
    );
    ensure!(args.depth <= 256, "memory chase depth must not exceed 256");
    ensure!(
        matches!(args.pointer_size, 4 | 8),
        "memory chase pointer size must be 4 or 8"
    );

    let client = DaemonClient::new(pipe);
    let root_address = parse_u64_argument(&args.address)?;
    let mut current = root_address;
    let mut hops = Vec::new();
    let mut stop_reason = "max_depth";

    for depth in 0..args.depth {
        let read_address = current
            .checked_add(args.offset)
            .context("pointer read address overflowed")?;
        let read = client
            .call_tool(memory_read_call(MemoryReadArgs {
                session: args.session,
                cursor: args.cursor,
                address: read_address.to_string(),
                size: args.pointer_size,
                policy: args.policy.clone(),
            })?)
            .await?;
        let data = read["data"]
            .as_str()
            .context("ttd_read_memory response did not include hex data")?;
        let bytes = hex_to_bytes(data)?;
        let target = read_pointer_value(&bytes, args.pointer_size)?;
        let mut hop = json!({
            "index": depth,
            "base_address": current,
            "read_address": read_address,
            "offset": args.offset,
            "pointer_size": args.pointer_size,
            "bytes": data,
            "target": target,
            "target_hex": format!("0x{target:016x}"),
            "null": target == 0,
            "read": read,
        });

        if args.target_info && target != 0 {
            hop["target_info"] = client
                .call_tool(address_info_call(AddressInfoArgs {
                    session: args.session,
                    cursor: args.cursor,
                    address: target.to_string(),
                }))
                .await?;
        }

        hops.push(hop);
        if target == 0 {
            stop_reason = "null_pointer";
            break;
        }
        current = target;
    }

    print_value(
        json!({
            "session_id": args.session,
            "cursor_id": args.cursor,
            "root_address": root_address,
            "offset": args.offset,
            "pointer_size": args.pointer_size,
            "requested_depth": args.depth,
            "stop_reason": stop_reason,
            "hops": hops,
            "notes": [
                "Reads one pointer at base_address + offset per hop.",
                "Pointer chains are evidence, not proof of ownership or object type."
            ]
        }),
        output,
    )
}

fn memory_dump(address: u64, bytes: &[u8], format: &str) -> anyhow::Result<Value> {
    let rows = match format {
        "db" => dump_db_rows(address, bytes),
        "dq" => dump_dq_rows(address, bytes),
        "ascii" => ascii_strings(address, bytes),
        "utf16" => utf16le_strings(address, bytes),
        other => bail!("unsupported memory dump format: {other}"),
    };
    Ok(json!({
        "format": format,
        "rows": rows,
    }))
}

fn dump_db_rows(address: u64, bytes: &[u8]) -> Vec<Value> {
    bytes
        .chunks(16)
        .enumerate()
        .map(|(row, chunk)| {
            let offset = row * 16;
            json!({
                "address": address + offset as u64,
                "offset": offset,
                "bytes": chunk.iter().map(|byte| format!("{byte:02X}")).collect::<Vec<_>>(),
                "ascii": chunk.iter().map(|byte| if byte.is_ascii_graphic() || *byte == b' ' { *byte as char } else { '.' }).collect::<String>(),
            })
        })
        .collect()
}

fn dump_dq_rows(address: u64, bytes: &[u8]) -> Vec<Value> {
    bytes
        .chunks(16)
        .enumerate()
        .map(|(row, chunk)| {
            let offset = row * 16;
            let qwords = chunk
                .chunks(8)
                .filter(|chunk| chunk.len() == 8)
                .map(|chunk| {
                    let value = u64::from_le_bytes(chunk.try_into().expect("chunk length checked"));
                    json!({
                        "value": value,
                        "hex": format!("0x{value:016X}"),
                        "plausible_x64_pointer": plausible_x64_pointer(value),
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "address": address + offset as u64,
                "offset": offset,
                "qwords": qwords,
            })
        })
        .collect()
}

fn classify_memory(address: u64, bytes: &[u8]) -> Value {
    json!({
        "address": address,
        "size": bytes.len(),
        "byte_histogram": byte_histogram_summary(bytes),
        "entropy_bits_per_byte": shannon_entropy(bytes),
        "ascii_strings": ascii_strings(address, bytes),
        "utf16le_strings": utf16le_strings(address, bytes),
        "qwords": qword_values(address, bytes),
        "instruction_hints": instruction_hints(bytes),
        "summary": memory_summary(bytes),
    })
}

fn memory_summary(bytes: &[u8]) -> Vec<&'static str> {
    let mut summary = Vec::new();
    if bytes.is_empty() {
        summary.push("empty");
        return summary;
    }
    let histogram = byte_counts(bytes);
    let zero_ratio = histogram[0] as f64 / bytes.len() as f64;
    let ff_ratio = histogram[0xff] as f64 / bytes.len() as f64;
    let max_ratio = histogram.iter().copied().max().unwrap_or_default() as f64 / bytes.len() as f64;
    let entropy = shannon_entropy(bytes);
    if zero_ratio >= 0.90 {
        summary.push("mostly_zero");
    }
    if ff_ratio >= 0.90 {
        summary.push("mostly_ff");
    }
    if max_ratio >= 0.90 {
        summary.push("repeated_fill_pattern");
    }
    if entropy >= 7.5 {
        summary.push("high_entropy");
    }
    if !ascii_strings(0, bytes).is_empty() {
        summary.push("contains_ascii");
    }
    if !utf16le_strings(0, bytes).is_empty() {
        summary.push("contains_utf16le");
    }
    if qword_values(0, bytes).as_array().is_some_and(|items| {
        items
            .iter()
            .any(|item| item["plausible_x64_pointer"] == true)
    }) {
        summary.push("contains_plausible_pointer");
    }
    if !instruction_hints(bytes).is_empty() {
        summary.push("instruction_like_prefix");
    }
    if summary.is_empty() {
        summary.push("unclassified");
    }
    summary
}

fn byte_histogram_summary(bytes: &[u8]) -> Value {
    let histogram = byte_counts(bytes);
    let mut top = histogram
        .iter()
        .enumerate()
        .filter(|(_, count)| **count > 0)
        .map(|(byte, count)| {
            json!({
                "byte": byte,
                "hex": format!("{byte:02X}"),
                "count": count,
            })
        })
        .collect::<Vec<_>>();
    top.sort_by(|left, right| {
        right["count"]
            .as_u64()
            .cmp(&left["count"].as_u64())
            .then_with(|| left["byte"].as_u64().cmp(&right["byte"].as_u64()))
    });
    top.truncate(8);
    json!({
        "unique_bytes": histogram.iter().filter(|count| **count > 0).count(),
        "top": top,
    })
}

fn byte_counts(bytes: &[u8]) -> [usize; 256] {
    let mut counts = [0usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    counts
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let counts = byte_counts(bytes);
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = *count as f64 / bytes.len() as f64;
            -probability * probability.log2()
        })
        .sum()
}

fn ascii_strings(address: u64, bytes: &[u8]) -> Vec<Value> {
    let mut strings = Vec::new();
    let mut start = None;
    for (index, byte) in bytes.iter().enumerate() {
        if byte.is_ascii_graphic() || *byte == b' ' {
            start.get_or_insert(index);
        } else if let Some(begin) = start.take() {
            push_ascii_string(address, bytes, begin, index, &mut strings);
        }
    }
    if let Some(begin) = start {
        push_ascii_string(address, bytes, begin, bytes.len(), &mut strings);
    }
    strings
}

fn push_ascii_string(
    address: u64,
    bytes: &[u8],
    begin: usize,
    end: usize,
    strings: &mut Vec<Value>,
) {
    if end.saturating_sub(begin) >= 4 {
        strings.push(json!({
            "address": address + begin as u64,
            "offset": begin,
            "length": end - begin,
            "text": String::from_utf8_lossy(&bytes[begin..end]),
        }));
    }
}

fn utf16le_strings(address: u64, bytes: &[u8]) -> Vec<Value> {
    let mut strings = Vec::new();
    let mut index = 0usize;
    while index + 1 < bytes.len() {
        let begin = index;
        let mut values = Vec::new();
        while index + 1 < bytes.len() {
            let value = u16::from_le_bytes([bytes[index], bytes[index + 1]]);
            let Some(character) = char::from_u32(value as u32) else {
                break;
            };
            if !(character.is_ascii_graphic() || character == ' ') {
                break;
            }
            values.push(value);
            index += 2;
        }
        if values.len() >= 4 {
            strings.push(json!({
                "address": address + begin as u64,
                "offset": begin,
                "code_units": values.len(),
                "text": String::from_utf16_lossy(&values),
            }));
        }
        index = begin + 2;
    }
    strings
}

fn qword_values(address: u64, bytes: &[u8]) -> Value {
    let qwords = bytes
        .chunks_exact(8)
        .take(32)
        .enumerate()
        .map(|(index, chunk)| {
            let value = u64::from_le_bytes(chunk.try_into().expect("chunk size is exact"));
            json!({
                "address": address + (index * 8) as u64,
                "offset": index * 8,
                "value": value,
                "hex": format!("0x{value:016X}"),
                "aligned": value.is_multiple_of(8),
                "plausible_x64_pointer": plausible_x64_pointer(value),
            })
        })
        .collect::<Vec<_>>();
    json!(qwords)
}

fn plausible_x64_pointer(value: u64) -> bool {
    value != 0
        && value.is_multiple_of(8)
        && !(0x0000_8000_0000_0000..0xffff_8000_0000_0000).contains(&value)
}

fn instruction_hints(bytes: &[u8]) -> Vec<Value> {
    let mut hints = Vec::new();
    if let Some(first) = bytes.first() {
        match *first {
            0x55 => hints.push(json!({"offset": 0, "kind": "push_rbp_prologue"})),
            0x48 | 0x4c => hints.push(json!({"offset": 0, "kind": "x64_rex_prefix"})),
            0xe8 => hints.push(json!({"offset": 0, "kind": "relative_call"})),
            0xe9 | 0xeb => hints.push(json!({"offset": 0, "kind": "relative_jump"})),
            0xc3 | 0xc2 => hints.push(json!({"offset": 0, "kind": "return"})),
            0xcc => hints.push(json!({"offset": 0, "kind": "int3_breakpoint"})),
            _ => {}
        }
    }
    for (offset, window) in bytes.windows(2).take(32).enumerate() {
        if window == [0x0f, 0x05] {
            hints.push(json!({"offset": offset, "kind": "syscall"}));
        }
    }
    hints
}

fn hex_to_bytes(data: &str) -> anyhow::Result<Vec<u8>> {
    ensure!(data.len().is_multiple_of(2), "hex data length must be even");
    (0..data.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&data[index..index + 2], 16)
                .with_context(|| format!("parsing hex byte at offset {index}"))
        })
        .collect()
}

fn read_pointer_value(bytes: &[u8], pointer_size: u32) -> anyhow::Result<u64> {
    match pointer_size {
        4 => {
            ensure!(bytes.len() >= 4, "pointer read returned fewer than 4 bytes");
            let mut value = [0_u8; 4];
            value.copy_from_slice(&bytes[..4]);
            Ok(u32::from_le_bytes(value) as u64)
        }
        8 => {
            ensure!(bytes.len() >= 8, "pointer read returned fewer than 8 bytes");
            let mut value = [0_u8; 8];
            value.copy_from_slice(&bytes[..8]);
            Ok(u64::from_le_bytes(value))
        }
        other => bail!("unsupported pointer size: {other}"),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_strings_fill_and_pointers() {
        let bytes = [
            b'H', b'e', b'l', b'l', b'o', 0, 0, 0, 0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let classification = classify_memory(0x1000, &bytes);
        assert!(
            classification["ascii_strings"]
                .as_array()
                .is_some_and(|items| items.iter().any(|item| item["text"] == "Hello")),
            "{classification}"
        );
        assert!(
            classification["qwords"]
                .as_array()
                .is_some_and(|items| items
                    .iter()
                    .any(|item| item["plausible_x64_pointer"] == true)),
            "{classification}"
        );
    }

    #[test]
    fn parses_hex_bytes_for_memory_classification() -> anyhow::Result<()> {
        assert_eq!(hex_to_bytes("4869ff")?, vec![0x48, 0x69, 0xff]);
        assert!(hex_to_bytes("123").is_err());
        Ok(())
    }

    #[test]
    fn dumps_memory_as_db_and_dq_rows() -> anyhow::Result<()> {
        let bytes = hex_to_bytes("48656c6c6f0000000010400000000000")?;
        let db = memory_dump(0x1000, &bytes, "db")?;
        assert_eq!(db["rows"][0]["ascii"], "Hello.....@.....");
        let dq = memory_dump(0x1000, &bytes, "dq")?;
        assert_eq!(dq["rows"][0]["qwords"].as_array().unwrap().len(), 2);
        Ok(())
    }

    #[test]
    fn reads_little_endian_pointer_values() -> anyhow::Result<()> {
        assert_eq!(
            read_pointer_value(&hex_to_bytes("78563412")?, 4)?,
            0x12345678
        );
        assert_eq!(
            read_pointer_value(&hex_to_bytes("8877665544332211")?, 8)?,
            0x1122334455667788
        );
        assert!(read_pointer_value(&[0, 1, 2], 4).is_err());
        Ok(())
    }

    #[test]
    fn disassembles_and_classifies_x64_instructions() -> anyhow::Result<()> {
        let bytes = hex_to_bytes("554889e5e801000000c3")?;
        let instructions = disassemble_x64(0x140001000, &bytes, 4);
        assert!(
            instructions
                .iter()
                .any(|instruction| instruction["classification"]["tags"]
                    .as_array()
                    .is_some_and(|tags| tags.iter().any(|tag| tag == "call"))),
            "{instructions:?}"
        );
        assert!(
            instructions
                .iter()
                .any(|instruction| instruction["classification"]["tags"]
                    .as_array()
                    .is_some_and(|tags| tags.iter().any(|tag| tag == "return"))),
            "{instructions:?}"
        );
        assert!(
            instructions
                .iter()
                .any(|instruction| instruction["classification"]["tags"]
                    .as_array()
                    .is_some_and(|tags| tags.iter().any(|tag| tag == "stack_related"))),
            "{instructions:?}"
        );
        Ok(())
    }

    #[test]
    fn recovers_stack_candidates_from_module_pointers() {
        let stack = json!({
            "pointers": [
                {
                    "offset": 0,
                    "address": 0x1000u64,
                    "value": 0x7ff612341000u64,
                    "module": "app.exe"
                },
                {
                    "offset": 8,
                    "address": 0x1008u64,
                    "value": 0x1234u64,
                    "module": null
                }
            ]
        });
        let candidates = recover_stack_candidates(&stack, 8, 0.5);
        assert_eq!(candidates.len(), 1, "{candidates:?}");
        assert_eq!(candidates[0]["module"], "app.exe");
        assert!(
            candidates[0]["reasons"]
                .as_array()
                .is_some_and(|reasons| reasons
                    .iter()
                    .any(|reason| reason == "target_in_loaded_module")),
            "{candidates:?}"
        );
    }

    #[test]
    fn audits_suspicious_module_paths() {
        let modules = vec![
            json!({
                "name": "good.dll",
                "path": r"C:\Windows\System32\good.dll",
                "base_address": 0x1000u64,
                "size": 4096,
                "load_position": null,
                "unload_position": null
            }),
            json!({
                "name": "odd.dll",
                "path": r"C:\Users\user\Downloads\odd.dll",
                "base_address": 0x2000u64,
                "size": 4096,
                "load_position": null,
                "unload_position": null
            }),
            json!({
                "name": "odd.dll",
                "path": r"C:\Temp\odd.dll",
                "base_address": 0x3000u64,
                "size": 4096,
                "load_position": null,
                "unload_position": null
            }),
        ];
        let audit = audit_modules(&modules, 16);
        assert!(
            audit["summary"]["temp_or_download_path"]
                .as_u64()
                .unwrap_or_default()
                >= 2,
            "{audit}"
        );
        assert_eq!(audit["summary"]["duplicate_name_groups"].as_u64(), Some(1));
    }

    #[test]
    fn normalizes_dll_search_order_names() -> anyhow::Result<()> {
        assert_eq!(normalize_dll_name("example")?, "example.dll");
        assert_eq!(normalize_dll_name("example.dll")?, "example.dll");
        assert!(normalize_dll_name(r"C:\temp\example.dll").is_err());
        Ok(())
    }
}
