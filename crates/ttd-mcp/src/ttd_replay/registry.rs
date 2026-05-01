use super::native::{NativeBridge, NativeCursor, NativeTrace};
use super::types::*;
use super::{Position, ResolvedSymbolConfig};
use anyhow::{bail, ensure};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

pub type SessionId = u64;
pub type CursorId = u64;

#[derive(Default)]
pub struct SessionRegistry {
    next_session_id: SessionId,
    sessions: HashMap<SessionId, TraceSession>,
}

struct TraceSession {
    info: TraceInfo,
    symbols: ResolvedSymbolConfig,
    native: Option<NativeTrace>,
    next_cursor_id: CursorId,
    cursors: HashMap<CursorId, ReplayCursor>,
}

struct ReplayCursor {
    position: Position,
    native: Option<NativeCursor>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CursorCreated {
    pub session_id: SessionId,
    pub cursor_id: CursorId,
    pub position: Position,
}

impl SessionRegistry {
    pub fn load_trace(&mut self, request: LoadTraceRequest) -> anyhow::Result<LoadTraceResponse> {
        validate_trace_path(&request.trace_path)?;

        let session_id = self.allocate_session_id();
        let symbols = request.symbols.resolve_for_process();
        let symbol_path = symbols.symbol_path.clone();
        let (info, native) = match try_open_native_trace(&request.trace_path, &symbols) {
            Ok((info, native)) => (info, Some(native)),
            Err(error) => (
                placeholder_trace_info(request.trace_path.clone(), error),
                None,
            ),
        };

        self.sessions.insert(
            session_id,
            TraceSession {
                info: info.clone(),
                symbols: symbols.clone(),
                native,
                next_cursor_id: 0,
                cursors: HashMap::new(),
            },
        );

        Ok(LoadTraceResponse {
            session_id,
            trace: info,
            symbol_path,
            symbols,
        })
    }

    pub fn close_trace(&mut self, session_id: SessionId) -> anyhow::Result<()> {
        self.sessions
            .remove(&session_id)
            .map(|_| ())
            .ok_or_else(|| anyhow::anyhow!("unknown session id: {session_id}"))
    }

    pub fn trace_info(&self, session_id: SessionId) -> anyhow::Result<TraceInfo> {
        Ok(self.session(session_id)?.info.clone())
    }

    pub fn list_threads(&self, session_id: SessionId) -> anyhow::Result<Vec<TraceThread>> {
        let session = self.session(session_id)?;
        if let Some(native) = session.native.as_ref() {
            return native.list_threads();
        }
        Ok(Vec::new())
    }

    pub fn list_modules(&self, session_id: SessionId) -> anyhow::Result<ModuleList> {
        let session = self.session(session_id)?;
        if let Some(native) = session.native.as_ref() {
            return Ok(ModuleList {
                modules: native.list_modules()?,
            });
        }

        Ok(ModuleList {
            modules: Vec::new(),
        }
        .with_symbol_hint(session.symbols.symbol_path.clone()))
    }

    pub fn list_exceptions(&self, session_id: SessionId) -> anyhow::Result<Vec<TraceException>> {
        let session = self.session(session_id)?;
        if let Some(native) = session.native.as_ref() {
            return native.list_exceptions();
        }
        Ok(Vec::new())
    }

    pub fn create_cursor(&mut self, session_id: SessionId) -> anyhow::Result<CursorCreated> {
        let session = self.session_mut(session_id)?;
        session.next_cursor_id += 1;
        let cursor_id = session.next_cursor_id;
        let native = session
            .native
            .as_ref()
            .map(NativeTrace::new_cursor)
            .transpose()?;
        let position = if let Some(native) = native.as_ref() {
            native.position()?
        } else {
            session.info.lifetime_start
        };
        session
            .cursors
            .insert(cursor_id, ReplayCursor { position, native });
        Ok(CursorCreated {
            session_id,
            cursor_id,
            position,
        })
    }

    pub fn cursor_position(
        &self,
        session_id: SessionId,
        cursor_id: CursorId,
    ) -> anyhow::Result<CursorPosition> {
        let cursor = self.cursor(session_id, cursor_id)?;
        let position = if let Some(native) = cursor.native.as_ref() {
            native.position()?
        } else {
            cursor.position
        };
        Ok(CursorPosition {
            session_id,
            cursor_id,
            position,
        })
    }

    pub fn set_position(&mut self, request: PositionRequest) -> anyhow::Result<CursorPosition> {
        let session = self.session_mut(request.session_id)?;
        let position = request
            .position
            .resolve_against(session.info.lifetime_start, session.info.lifetime_end)?;
        let cursor = session
            .cursors
            .get_mut(&request.cursor_id)
            .ok_or_else(|| anyhow::anyhow!("unknown cursor id: {}", request.cursor_id))?;
        if let Some(native) = cursor.native.as_ref() {
            native.set_position(position)?;
        }
        cursor.position = position;
        Ok(CursorPosition {
            session_id: request.session_id,
            cursor_id: request.cursor_id,
            position,
        })
    }

    pub fn step(&mut self, request: StepRequest) -> anyhow::Result<Value> {
        let _ = self.cursor_mut(request.session_id, request.cursor_id)?;
        ensure!(request.count > 0, "count must be greater than zero");
        ensure!(request.count <= 10_000, "count must be 10,000 or less");
        let _ = (request.direction, request.kind);
        bail!("ttd_step is not implemented in the native TTD Replay API bridge yet")
    }

    pub fn registers(&self, session_id: SessionId, cursor_id: CursorId) -> anyhow::Result<Value> {
        let _ = self.cursor(session_id, cursor_id)?;
        bail!("ttd_registers is not implemented in the native TTD Replay API bridge yet")
    }

    pub fn read_memory(&self, request: ReadMemoryRequest) -> anyhow::Result<Value> {
        ensure!(request.size > 0, "size must be greater than zero");
        ensure!(request.size <= 0x10000, "size must be 64 KiB or less");
        ensure!(request.address != 0, "address must be non-zero");
        let _ = self.cursor(request.session_id, request.cursor_id)?;
        bail!("ttd_read_memory is not implemented in the native TTD Replay API bridge yet")
    }

    pub fn memory_watchpoint(&self, request: MemoryWatchpointRequest) -> anyhow::Result<Value> {
        ensure!(request.size > 0, "size must be greater than zero");
        ensure!(request.address != 0, "address must be non-zero");
        let _ = request.access;
        let _ = self.cursor(request.session_id, request.cursor_id)?;
        bail!("ttd_memory_watchpoint is not implemented in the native TTD Replay API bridge yet")
    }

    fn allocate_session_id(&mut self) -> SessionId {
        self.next_session_id += 1;
        self.next_session_id
    }

    fn session(&self, session_id: SessionId) -> anyhow::Result<&TraceSession> {
        self.sessions
            .get(&session_id)
            .ok_or_else(|| anyhow::anyhow!("unknown session id: {session_id}"))
    }

    fn session_mut(&mut self, session_id: SessionId) -> anyhow::Result<&mut TraceSession> {
        self.sessions
            .get_mut(&session_id)
            .ok_or_else(|| anyhow::anyhow!("unknown session id: {session_id}"))
    }

    fn cursor(&self, session_id: SessionId, cursor_id: CursorId) -> anyhow::Result<&ReplayCursor> {
        self.session(session_id)?
            .cursors
            .get(&cursor_id)
            .ok_or_else(|| anyhow::anyhow!("unknown cursor id: {cursor_id}"))
    }

    fn cursor_mut(
        &mut self,
        session_id: SessionId,
        cursor_id: CursorId,
    ) -> anyhow::Result<&mut ReplayCursor> {
        self.session_mut(session_id)?
            .cursors
            .get_mut(&cursor_id)
            .ok_or_else(|| anyhow::anyhow!("unknown cursor id: {cursor_id}"))
    }
}

fn try_open_native_trace(
    trace_path: &Path,
    symbols: &ResolvedSymbolConfig,
) -> anyhow::Result<(TraceInfo, NativeTrace)> {
    let bridge = NativeBridge::load()?;
    let native = bridge.open_trace(trace_path, symbols)?;
    let info = native.trace_info()?;

    Ok((
        TraceInfo {
            trace_path: trace_path.to_path_buf(),
            backend: "ttd-replay-native".to_string(),
            index_status: "loaded".to_string(),
            process_id: info.process_id(),
            peb_address: info.peb_address(),
            lifetime_start: info.lifetime_start(),
            lifetime_end: info.lifetime_end(),
            architecture: None,
            thread_count: info.thread_count(),
            module_count: info.module_count(),
            module_instance_count: info.module_instance_count(),
            exception_count: info.exception_count(),
            keyframe_count: info.keyframe_count(),
            warning: None,
        },
        native,
    ))
}

fn placeholder_trace_info(
    trace_path: impl Into<std::path::PathBuf>,
    error: anyhow::Error,
) -> TraceInfo {
    TraceInfo {
        trace_path: trace_path.into(),
        backend: "unavailable-native-bridge".to_string(),
        index_status: "unknown".to_string(),
        process_id: None,
        peb_address: None,
        lifetime_start: Position::MIN,
        lifetime_end: Position::MIN,
        architecture: None,
        thread_count: 0,
        module_count: 0,
        module_instance_count: 0,
        exception_count: 0,
        keyframe_count: None,
        warning: Some(format!(
            "Native TTD Replay API bridge is not available yet: {error}"
        )),
    }
}

fn validate_trace_path(path: &Path) -> anyhow::Result<()> {
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    ensure!(
        matches!(extension.as_str(), "run" | "ttd"),
        "trace_path must point to a .run or .ttd trace"
    );
    Ok(())
}

trait ModuleListExt {
    fn with_symbol_hint(self, symbol_path: String) -> Self;
}

impl ModuleListExt for ModuleList {
    fn with_symbol_hint(self, _symbol_path: String) -> Self {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use crate::ttd_replay::SymbolSettings;

    #[test]
    fn rejects_non_ttd_extensions() {
        let error = validate_trace_path(Path::new("trace.dmp")).unwrap_err();
        assert!(error.to_string().contains(".run or .ttd"));
    }

    #[test]
    fn creates_placeholder_session_and_cursor() {
        let mut registry = SessionRegistry::default();
        let loaded = registry
            .load_trace(LoadTraceRequest {
                trace_path: PathBuf::from("sample.run"),
                symbols: SymbolSettings::default(),
            })
            .unwrap();
        let cursor = registry.create_cursor(loaded.session_id).unwrap();
        assert_eq!(cursor.position, Position::MIN);
    }
}
