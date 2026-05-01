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
pub struct CapabilitiesResponse {
    pub session_id: u64,
    pub backend: String,
    pub native: bool,
    pub symbols: ResolvedSymbolConfig,
    pub features: ReplayCapabilities,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayCapabilities {
    pub trace_info: bool,
    pub close_trace: bool,
    pub list_threads: bool,
    pub list_modules: bool,
    pub module_info: bool,
    pub address_info: bool,
    pub list_exceptions: bool,
    pub cursor_create: bool,
    pub position_get: bool,
    pub position_set: bool,
    pub step: bool,
    pub compact_registers: bool,
    pub full_registers: bool,
    pub stack_info: bool,
    pub stack_read: bool,
    pub command_line: bool,
    pub read_memory: bool,
    pub memory_watchpoint: bool,
    pub memory_regions: bool,
    pub search_memory: bool,
    pub search_trace_strings: bool,
    pub symbol_resolution: bool,
    pub api_calls: bool,
    pub call_trace: bool,
    pub console_output: bool,
    pub stdout_events: bool,
    pub network_summary: bool,
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

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ModuleInfoRequest {
    pub session_id: u64,
    pub name: Option<String>,
    pub address: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfoResponse {
    pub session_id: u64,
    pub matched_by: String,
    pub module: TraceModule,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct AddressInfoRequest {
    pub session_id: u64,
    pub cursor_id: u64,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressInfoResponse {
    pub session_id: u64,
    pub cursor_id: u64,
    pub address: u64,
    pub address_hex: String,
    pub position: Position,
    pub thread: Option<CursorThreadState>,
    pub classification: AddressClassification,
    pub module: Option<AddressModuleCoordinate>,
    pub registers: AddressRegisterContext,
    pub stack: Option<AddressStackContext>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressClassification {
    Module,
    Stack,
    Teb,
    Peb,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressModuleCoordinate {
    pub name: String,
    pub path: Option<PathBuf>,
    pub runtime_base: u64,
    pub runtime_base_hex: String,
    pub size: u64,
    pub size_hex: String,
    pub rva: u64,
    pub rva_hex: String,
    pub module_offset: String,
    pub load_position: Option<Position>,
    pub unload_position: Option<Position>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressRegisterContext {
    pub program_counter: u64,
    pub program_counter_hex: String,
    pub stack_pointer: u64,
    pub stack_pointer_hex: String,
    pub frame_pointer: u64,
    pub frame_pointer_hex: String,
    pub basic_return_value: u64,
    pub basic_return_value_hex: String,
    pub teb_address: Option<u64>,
    pub teb_address_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressStackContext {
    pub stack_base: u64,
    pub stack_base_hex: String,
    pub stack_limit: u64,
    pub stack_limit_hex: String,
    pub stack_pointer_in_range: bool,
    pub address_in_stack: bool,
    pub offset_from_sp: Option<i64>,
    pub offset_from_fp: Option<i64>,
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
pub struct StackInfo {
    pub session_id: u64,
    pub cursor_id: u64,
    pub position: Position,
    pub thread: Option<CursorThreadState>,
    pub teb_address: u64,
    pub stack_base: u64,
    pub stack_limit: u64,
    pub stack_pointer: u64,
    pub frame_pointer: u64,
    pub stack_pointer_in_range: bool,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct StackReadRequest {
    pub session_id: u64,
    pub cursor_id: u64,
    #[serde(default = "default_stack_read_size")]
    pub size: u32,
    #[serde(default)]
    pub offset_from_sp: i64,
    #[serde(default)]
    pub decode_pointers: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackReadResponse {
    pub session_id: u64,
    pub cursor_id: u64,
    pub position: Position,
    pub stack_pointer: u64,
    pub offset_from_sp: i64,
    pub address: u64,
    pub requested_size: u32,
    pub bytes_read: usize,
    pub complete: bool,
    pub encoding: String,
    pub data: String,
    pub pointer_size: u8,
    pub pointers: Vec<StackPointerValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackPointerValue {
    pub offset: u32,
    pub address: u64,
    pub value: u64,
    pub module: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub session_id: u64,
    pub cursor_id: u64,
    pub position: Position,
    pub previous_position: Option<Position>,
    pub direction: StepDirection,
    pub kind: StepKind,
    pub requested_count: u32,
    pub steps_executed: u64,
    pub instructions_executed: u64,
    pub stop_reason: String,
    pub stop_reason_code: u32,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StepDirection {
    #[default]
    Forward,
    Backward,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, JsonSchema)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryWatchpointResponse {
    pub session_id: u64,
    pub cursor_id: u64,
    pub requested_address: u64,
    pub requested_size: u32,
    pub requested_access: MemoryAccessMask,
    pub direction: MemoryAccessDirection,
    pub found: bool,
    pub position: Position,
    pub previous_position: Option<Position>,
    pub thread: Option<CursorThreadState>,
    pub program_counter: u64,
    pub match_address: Option<u64>,
    pub match_size: Option<u64>,
    pub match_access: Option<MemoryAccessKind>,
    pub stop_reason: String,
    pub stop_reason_code: u32,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MemoryAccessMask {
    Read,
    Write,
    Execute,
    ReadWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MemoryAccessDirection {
    Previous,
    Next,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryAccessKind {
    Read,
    Write,
    Execute,
    CodeFetch,
    Overwrite,
    DataMismatch,
    NewData,
    RedundantData,
    Unknown,
}

fn default_step_count() -> u32 {
    1
}

fn default_stack_read_size() -> u32 {
    256
}
