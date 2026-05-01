use crate::ttd_replay::{
    CursorId, LoadTraceRequest, MemoryAccessDirection, MemoryWatchpointRequest, Position,
    PositionRequest, ReadMemoryRequest, SessionId, SessionRegistry, StepRequest,
};
use anyhow::{bail, Context};
use schemars::{schema_for, JsonSchema};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Debug, Deserialize)]
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

pub fn definitions() -> Vec<Value> {
    vec![
        tool::<LoadTraceRequest>(
            "ttd_load_trace",
            "Load a .run or .ttd trace for offline replay.",
        ),
        tool::<SessionArg>("ttd_close_trace", "Close an offline TTD trace session."),
        tool::<SessionArg>(
            "ttd_trace_info",
            "Return summary metadata for a loaded TTD trace.",
        ),
        tool::<SessionArg>(
            "ttd_list_threads",
            "List threads captured in a loaded TTD trace.",
        ),
        tool::<SessionArg>(
            "ttd_list_modules",
            "List modules and module instances captured in a loaded TTD trace.",
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
            "Move a replay cursor to a HEX:HEX position or approximate percent.",
        ),
        tool::<StepRequest>(
            "ttd_step",
            "Step or trace a replay cursor forward or backward.",
        ),
        tool::<CursorArg>(
            "ttd_registers",
            "Read register state at a replay cursor position.",
        ),
        tool::<ReadMemoryRequest>(
            "ttd_read_memory",
            "Read guest memory at a replay cursor position.",
        ),
        tool::<MemoryWatchpointRequest>(
            "ttd_memory_watchpoint",
            "Find the previous or next read/write/execute access to a guest memory range.",
        ),
    ]
}

pub async fn call(registry: &mut SessionRegistry, call: ToolCall) -> anyhow::Result<Value> {
    match call.name.as_str() {
        "ttd_load_trace" => {
            let request = parse::<LoadTraceRequest>(call.arguments)?;
            Ok(serde_json::to_value(registry.load_trace(request)?)?)
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
        "ttd_read_memory" => {
            let request = parse::<ReadMemoryRequest>(call.arguments)?;
            Ok(serde_json::to_value(registry.read_memory(request)?)?)
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

fn tool<T: JsonSchema>(name: &str, description: &str) -> Value {
    let input_schema = serde_json::to_value(schema_for!(T)).expect("tool schema is serializable");
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema,
    })
}

#[allow(dead_code)]
fn _position_schema_anchor(_: Position) {}
