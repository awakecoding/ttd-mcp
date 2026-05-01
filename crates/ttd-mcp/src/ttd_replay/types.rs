use super::{Position, PositionOrPercent, ResolvedSymbolConfig, SymbolSettings};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LoadTraceRequest {
    pub trace_path: PathBuf,
    #[serde(default)]
    pub symbols: SymbolSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadTraceResponse {
    pub session_id: u64,
    pub trace: TraceInfo,
    pub symbol_path: String,
    pub symbols: ResolvedSymbolConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceInfo {
    pub trace_path: PathBuf,
    pub backend: String,
    pub index_status: String,
    pub process_id: Option<u32>,
    pub peb_address: Option<u64>,
    pub lifetime_start: Position,
    pub lifetime_end: Position,
    pub architecture: Option<String>,
    pub thread_count: usize,
    pub module_count: usize,
    pub module_instance_count: usize,
    pub exception_count: usize,
    pub keyframe_count: Option<usize>,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceThread {
    pub unique_id: u64,
    pub thread_id: u32,
    pub lifetime_start: Position,
    pub lifetime_end: Position,
    pub active_start: Option<Position>,
    pub active_end: Option<Position>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceModule {
    pub name: String,
    pub path: Option<PathBuf>,
    pub base_address: u64,
    pub size: u64,
    pub load_position: Option<Position>,
    pub unload_position: Option<Position>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleList {
    pub modules: Vec<TraceModule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceException {
    pub position: Position,
    pub thread_unique_id: Option<u64>,
    pub code: u32,
    pub flags: u32,
    pub program_counter: u64,
    pub record_address: u64,
    pub parameters: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CursorPosition {
    pub session_id: u64,
    pub cursor_id: u64,
    pub position: Position,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CursorThreadState {
    pub unique_id: u64,
    pub thread_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CursorRegisters {
    pub session_id: u64,
    pub cursor_id: u64,
    pub position: Position,
    pub previous_position: Option<Position>,
    pub thread: Option<CursorThreadState>,
    pub teb_address: Option<u64>,
    pub program_counter: u64,
    pub stack_pointer: u64,
    pub frame_pointer: u64,
    pub basic_return_value: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessCommandLine {
    pub session_id: u64,
    pub cursor_id: u64,
    pub peb_address: u64,
    pub process_parameters_address: u64,
    pub command_line_address: u64,
    pub command_line: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct PositionRequest {
    pub session_id: u64,
    pub cursor_id: u64,
    pub position: PositionOrPercent,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct StepRequest {
    pub session_id: u64,
    pub cursor_id: u64,
    #[serde(default)]
    pub direction: StepDirection,
    #[serde(default)]
    pub kind: StepKind,
    #[serde(default = "default_step_count")]
    pub count: u32,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StepDirection {
    #[default]
    Forward,
    Backward,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StepKind {
    #[default]
    Step,
    Trace,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ReadMemoryRequest {
    pub session_id: u64,
    pub cursor_id: u64,
    pub address: u64,
    pub size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadMemoryResponse {
    pub session_id: u64,
    pub cursor_id: u64,
    pub requested_address: u64,
    pub address: u64,
    pub requested_size: u32,
    pub bytes_read: usize,
    pub complete: bool,
    pub encoding: String,
    pub data: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct MemoryWatchpointRequest {
    pub session_id: u64,
    pub cursor_id: u64,
    pub address: u64,
    pub size: u32,
    pub access: MemoryAccessMask,
    pub direction: MemoryAccessDirection,
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MemoryAccessMask {
    Read,
    Write,
    Execute,
    ReadWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MemoryAccessDirection {
    Previous,
    Next,
    #[serde(other)]
    Unknown,
}

fn default_step_count() -> u32 {
    1
}
