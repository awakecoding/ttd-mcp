use crate::ttd_replay::{
    AddressInfoRequest, CursorId, IndexBuildRequest, IndexStatsRequest, IndexStatusRequest,
    LoadTraceRequest, MemoryAccessDirection, MemoryBufferRequest, MemoryRangeRequest,
    MemoryWatchpointRequest, ModuleInfoRequest, Position, PositionRequest, ReadMemoryRequest,
    RegisterContextRequest, SessionId, SessionRegistry, StackReadRequest, StepRequest,
    TraceListRequest,
};
use anyhow::{bail, Context};
use rmcp::model::{JsonObject, Tool};
use schemars::{schema_for, JsonSchema};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;

#[derive(Debug, Deserialize, Serialize)]
pub struct ToolCall {
    pub name: String,
    #[serde(default)]
    pub arguments: Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SessionArg {
    session_id: SessionId,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct CursorArg {
    session_id: SessionId,
    cursor_id: CursorId,
}

pub fn definitions() -> Vec<Tool> {
    vec![
        tool::<LoadTraceRequest>(
            "ttd_load_trace",
            "Load a .run/.idx/.ttd trace for offline replay.",
        ),
        tool::<TraceListRequest>(
            "ttd_trace_list",
            "Enumerate traces inside a .run/.idx/.ttd file or trace pack without opening a replay session.",
        ),
        tool::<SessionArg>("ttd_close_trace", "Close an offline TTD trace session."),
        tool::<SessionArg>(
            "ttd_trace_info",
            "Return summary metadata for a loaded TTD trace.",
        ),
        tool::<SessionArg>(
            "ttd_capabilities",
            "Return backend features available for a loaded TTD trace session.",
        ),
        tool::<IndexStatusRequest>(
            "ttd_index_status",
            "Return TTD index status for a loaded trace session.",
        ),
        tool::<IndexStatsRequest>(
            "ttd_index_stats",
            "Return TTD index file statistics for a loaded trace session.",
        ),
        tool::<IndexBuildRequest>(
            "ttd_build_index",
            "Synchronously build the TTD index for a loaded trace session.",
        ),
        tool::<SessionArg>(
            "ttd_list_threads",
            "List threads captured in a loaded TTD trace.",
        ),
        tool::<SessionArg>(
            "ttd_list_modules",
            "List modules and module instances captured in a loaded TTD trace.",
        ),
        tool::<CursorArg>(
            "ttd_cursor_modules",
            "List modules loaded at a replay cursor position.",
        ),
        tool::<SessionArg>(
            "ttd_list_keyframes",
            "List replay keyframe positions captured in a loaded TTD trace.",
        ),
        tool::<SessionArg>(
            "ttd_module_events",
            "List module load and unload events captured in a loaded TTD trace.",
        ),
        tool::<SessionArg>(
            "ttd_thread_events",
            "List thread create and terminate events captured in a loaded TTD trace.",
        ),
        tool::<ModuleInfoRequest>(
            "ttd_module_info",
            "Find a loaded module by name or guest address.",
        ),
        tool::<AddressInfoRequest>(
            "ttd_address_info",
            "Translate a runtime address into module/RVA coordinates with current cursor context.",
        ),
        tool::<CursorArg>(
            "ttd_active_threads",
            "List active threads at a replay cursor position with runtime PCs and module/RVA coordinates.",
        ),
        tool::<SessionArg>(
            "ttd_list_exceptions",
            "List exception events captured in a loaded TTD trace.",
        ),
        tool::<SessionArg>(
            "ttd_cursor_create",
            "Create an independent replay cursor for a loaded trace.",
        ),
        tool::<CursorArg>(
            "ttd_position_get",
            "Read the current position of a replay cursor.",
        ),
        tool::<PositionRequest>(
            "ttd_position_set",
            "Move a replay cursor to a HEX:HEX position, approximate percent, or nearest position on a TTD unique thread.",
        ),
        tool::<StepRequest>(
            "ttd_step",
            "Step or trace a replay cursor forward or backward.",
        ),
        tool::<CursorArg>(
            "ttd_registers",
            "Read core register and thread state at a replay cursor position.",
        ),
        tool::<RegisterContextRequest>(
            "ttd_register_context",
            "Read x64 scalar and SIMD/vector register context at a replay cursor position.",
        ),
        tool::<CursorArg>(
            "ttd_stack_info",
            "Read current thread stack bounds and stack registers at a replay cursor position.",
        ),
        tool::<StackReadRequest>(
            "ttd_stack_read",
            "Read a bounded stack window around the current stack pointer.",
        ),
        tool::<CursorArg>(
            "ttd_command_line",
            "Read the process command line from PEB process parameters at a replay cursor position.",
        ),
        tool::<ReadMemoryRequest>(
            "ttd_read_memory",
            "Read guest memory at a replay cursor position.",
        ),
        tool::<MemoryRangeRequest>(
            "ttd_memory_range",
            "Query the trace-backed contiguous memory range and provenance for a guest address.",
        ),
        tool::<MemoryBufferRequest>(
            "ttd_memory_buffer",
            "Read guest memory with per-subrange trace provenance for decompiler correlation.",
        ),
        tool::<MemoryWatchpointRequest>(
            "ttd_memory_watchpoint",
            "Find the previous or next access matching a TTD DataAccessMask for a guest memory range.",
        ),
    ]
}

pub async fn call(registry: &mut SessionRegistry, call: ToolCall) -> anyhow::Result<Value> {
    match call.name.as_str() {
        "ttd_load_trace" => {
            let request = parse::<LoadTraceRequest>(call.arguments)?;
            Ok(serde_json::to_value(registry.load_trace(request)?)?)
        }
        "ttd_trace_list" => {
            let request = parse::<TraceListRequest>(call.arguments)?;
            Ok(serde_json::to_value(registry.list_trace_file(request)?)?)
        }
        "ttd_close_trace" => {
            let request = parse::<SessionArg>(call.arguments)?;
            registry.close_trace(request.session_id)?;
            Ok(json!({ "closed": true, "session_id": request.session_id }))
        }
        "ttd_trace_info" => {
            let request = parse::<SessionArg>(call.arguments)?;
            Ok(serde_json::to_value(
                registry.trace_info(request.session_id)?,
            )?)
        }
        "ttd_capabilities" => {
            let request = parse::<SessionArg>(call.arguments)?;
            Ok(serde_json::to_value(
                registry.capabilities(request.session_id)?,
            )?)
        }
        "ttd_index_status" => {
            let request = parse::<IndexStatusRequest>(call.arguments)?;
            Ok(serde_json::to_value(registry.index_status(request)?)?)
        }
        "ttd_index_stats" => {
            let request = parse::<IndexStatsRequest>(call.arguments)?;
            Ok(serde_json::to_value(registry.index_stats(request)?)?)
        }
        "ttd_build_index" => {
            let request = parse::<IndexBuildRequest>(call.arguments)?;
            Ok(serde_json::to_value(registry.build_index(request)?)?)
        }
        "ttd_list_threads" => {
            let request = parse::<SessionArg>(call.arguments)?;
            Ok(serde_json::to_value(
                registry.list_threads(request.session_id)?,
            )?)
        }
        "ttd_list_modules" => {
            let request = parse::<SessionArg>(call.arguments)?;
            Ok(serde_json::to_value(
                registry.list_modules(request.session_id)?,
            )?)
        }
        "ttd_cursor_modules" => {
            let request = parse::<CursorArg>(call.arguments)?;
            Ok(serde_json::to_value(
                registry.cursor_modules(request.session_id, request.cursor_id)?,
            )?)
        }
        "ttd_list_keyframes" => {
            let request = parse::<SessionArg>(call.arguments)?;
            Ok(serde_json::to_value(
                registry.list_keyframes(request.session_id)?,
            )?)
        }
        "ttd_module_events" => {
            let request = parse::<SessionArg>(call.arguments)?;
            Ok(serde_json::to_value(
                registry.list_module_events(request.session_id)?,
            )?)
        }
        "ttd_thread_events" => {
            let request = parse::<SessionArg>(call.arguments)?;
            Ok(serde_json::to_value(
                registry.list_thread_events(request.session_id)?,
            )?)
        }
        "ttd_module_info" => {
            let request = parse::<ModuleInfoRequest>(call.arguments)?;
            Ok(serde_json::to_value(registry.module_info(request)?)?)
        }
        "ttd_address_info" => {
            let request = parse::<AddressInfoRequest>(call.arguments)?;
            Ok(serde_json::to_value(registry.address_info(request)?)?)
        }
        "ttd_active_threads" => {
            let request = parse::<CursorArg>(call.arguments)?;
            Ok(serde_json::to_value(
                registry.active_threads(request.session_id, request.cursor_id)?,
            )?)
        }
        "ttd_list_exceptions" => {
            let request = parse::<SessionArg>(call.arguments)?;
            Ok(serde_json::to_value(
                registry.list_exceptions(request.session_id)?,
            )?)
        }
        "ttd_cursor_create" => {
            let request = parse::<SessionArg>(call.arguments)?;
            Ok(serde_json::to_value(
                registry.create_cursor(request.session_id)?,
            )?)
        }
        "ttd_position_get" => {
            let request = parse::<CursorArg>(call.arguments)?;
            Ok(serde_json::to_value(
                registry.cursor_position(request.session_id, request.cursor_id)?,
            )?)
        }
        "ttd_position_set" => {
            let request = parse::<PositionRequest>(call.arguments)?;
            Ok(serde_json::to_value(registry.set_position(request)?)?)
        }
        "ttd_step" => {
            let request = parse::<StepRequest>(call.arguments)?;
            Ok(serde_json::to_value(registry.step(request)?)?)
        }
        "ttd_registers" => {
            let request = parse::<CursorArg>(call.arguments)?;
            Ok(serde_json::to_value(
                registry.registers(request.session_id, request.cursor_id)?,
            )?)
        }
        "ttd_register_context" => {
            let request = parse::<RegisterContextRequest>(call.arguments)?;
            Ok(serde_json::to_value(registry.register_context(request)?)?)
        }
        "ttd_stack_info" => {
            let request = parse::<CursorArg>(call.arguments)?;
            Ok(serde_json::to_value(
                registry.stack_info(request.session_id, request.cursor_id)?,
            )?)
        }
        "ttd_stack_read" => {
            let request = parse::<StackReadRequest>(call.arguments)?;
            Ok(serde_json::to_value(registry.stack_read(request)?)?)
        }
        "ttd_command_line" => {
            let request = parse::<CursorArg>(call.arguments)?;
            Ok(serde_json::to_value(
                registry.command_line(request.session_id, request.cursor_id)?,
            )?)
        }
        "ttd_read_memory" => {
            let request = parse::<ReadMemoryRequest>(call.arguments)?;
            Ok(serde_json::to_value(registry.read_memory(request)?)?)
        }
        "ttd_memory_range" => {
            let request = parse::<MemoryRangeRequest>(call.arguments)?;
            Ok(serde_json::to_value(registry.memory_range(request)?)?)
        }
        "ttd_memory_buffer" => {
            let request = parse::<MemoryBufferRequest>(call.arguments)?;
            Ok(serde_json::to_value(registry.memory_buffer(request)?)?)
        }
        "ttd_memory_watchpoint" => {
            let request = parse::<MemoryWatchpointRequest>(call.arguments)?;
            if request.direction == MemoryAccessDirection::Unknown {
                bail!("direction must be 'previous' or 'next'");
            }
            Ok(serde_json::to_value(registry.memory_watchpoint(request)?)?)
        }
        _ => bail!("unknown tool: {}", call.name),
    }
}

fn parse<T: for<'de> Deserialize<'de>>(value: Value) -> anyhow::Result<T> {
    serde_json::from_value(value).context("invalid tool arguments")
}

fn tool<T: JsonSchema>(name: &str, description: &str) -> Tool {
    let input_schema = input_schema::<T>();
    Tool::new(
        name.to_string(),
        description.to_string(),
        Arc::new(input_schema),
    )
}

fn input_schema<T: JsonSchema>() -> JsonObject {
    let input_schema = serde_json::to_value(schema_for!(T)).expect("tool schema is serializable");
    match input_schema {
        Value::Object(object) => object,
        _ => JsonObject::new(),
    }
}

#[allow(dead_code)]
fn _position_schema_anchor(_: Position) {}
