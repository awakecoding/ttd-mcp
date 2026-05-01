use super::types::{
    CursorRegisters, CursorThreadState, ReadMemoryResponse, TraceException, TraceModule,
    TraceThread,
};
use super::{Position, ResolvedSymbolConfig};
use anyhow::{bail, Context};
use libloading::{Library, Symbol};
use std::ffi::CStr;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::sync::Arc;

const NATIVE_BRIDGE_DLL: &str = "ttd_replay_bridge.dll";
const TTD_MCP_OK: i32 = 0;
const MODULE_NAME_CHARS: usize = 260;
const MODULE_PATH_CHARS: usize = 1024;
const EXCEPTION_PARAMETER_COUNT: usize = 15;

#[repr(C)]
struct TtdMcpTrace;

#[repr(C)]
struct TtdMcpCursor;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TtdMcpPosition {
    sequence: u64,
    steps: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TtdMcpTraceInfo {
    first_position: TtdMcpPosition,
    last_position: TtdMcpPosition,
    peb_address: u64,
    process_id: u32,
    thread_count: u32,
    module_count: u32,
    module_instance_count: u32,
    exception_count: u32,
    keyframe_count: u32,
}

#[repr(C)]
struct TtdMcpSymbolConfig {
    symbol_path: *const u16,
    image_path: *const u16,
    symbol_cache_dir: *const u16,
    symbol_runtime_dir: *const u16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TtdMcpThreadInfo {
    unique_id: u64,
    thread_id: u32,
    lifetime_start: TtdMcpPosition,
    lifetime_end: TtdMcpPosition,
    active_start: TtdMcpPosition,
    active_end: TtdMcpPosition,
    has_active_time: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TtdMcpModuleInfo {
    name: [u16; MODULE_NAME_CHARS],
    path: [u16; MODULE_PATH_CHARS],
    base_address: u64,
    size: u64,
    load_position: TtdMcpPosition,
    unload_position: TtdMcpPosition,
    has_unload_position: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TtdMcpExceptionInfo {
    position: TtdMcpPosition,
    thread_unique_id: u64,
    code: u32,
    flags: u32,
    program_counter: u64,
    record_address: u64,
    parameter_count: u32,
    parameters: [u64; EXCEPTION_PARAMETER_COUNT],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TtdMcpMemoryRead {
    address: u64,
    bytes_read: u32,
    complete: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TtdMcpCursorState {
    position: TtdMcpPosition,
    previous_position: TtdMcpPosition,
    thread_unique_id: u64,
    thread_id: u32,
    teb_address: u64,
    program_counter: u64,
    stack_pointer: u64,
    frame_pointer: u64,
    basic_return_value: u64,
}

type OpenTraceFn =
    unsafe extern "C" fn(*const u16, *const TtdMcpSymbolConfig, *mut *mut TtdMcpTrace) -> i32;
type CloseTraceFn = unsafe extern "C" fn(*mut TtdMcpTrace);
type TraceInfoFn = unsafe extern "C" fn(*mut TtdMcpTrace, *mut TtdMcpTraceInfo) -> i32;
type ListThreadsFn =
    unsafe extern "C" fn(*mut TtdMcpTrace, *mut TtdMcpThreadInfo, u32, *mut u32) -> i32;
type ListModulesFn =
    unsafe extern "C" fn(*mut TtdMcpTrace, *mut TtdMcpModuleInfo, u32, *mut u32) -> i32;
type ListExceptionsFn =
    unsafe extern "C" fn(*mut TtdMcpTrace, *mut TtdMcpExceptionInfo, u32, *mut u32) -> i32;
type NewCursorFn = unsafe extern "C" fn(*mut TtdMcpTrace, *mut *mut TtdMcpCursor) -> i32;
type FreeCursorFn = unsafe extern "C" fn(*mut TtdMcpCursor);
type CursorPositionFn = unsafe extern "C" fn(*mut TtdMcpCursor, *mut TtdMcpPosition) -> i32;
type SetPositionFn = unsafe extern "C" fn(*mut TtdMcpCursor, TtdMcpPosition) -> i32;
type ReadMemoryFn =
    unsafe extern "C" fn(*mut TtdMcpCursor, u64, *mut u8, u32, *mut TtdMcpMemoryRead) -> i32;
type CursorStateFn = unsafe extern "C" fn(*mut TtdMcpCursor, *mut TtdMcpCursorState) -> i32;
type LastErrorFn = unsafe extern "C" fn() -> *const i8;

pub struct NativeBridge {
    library: Library,
}

pub struct NativeTrace {
    bridge: Arc<NativeBridge>,
    handle: NonNull<TtdMcpTrace>,
}

pub struct NativeCursor {
    bridge: Arc<NativeBridge>,
    handle: NonNull<TtdMcpCursor>,
}

unsafe impl Send for NativeBridge {}
unsafe impl Sync for NativeBridge {}
unsafe impl Send for NativeTrace {}
unsafe impl Send for NativeCursor {}

impl NativeBridge {
    pub fn load() -> anyhow::Result<Arc<Self>> {
        let mut errors = Vec::new();
        for path in bridge_candidates() {
            if !path.is_file() {
                continue;
            }

            add_dll_search_paths(&path);
            let library = unsafe { Library::new(&path) };
            match library {
                Ok(library) => return Ok(Arc::new(Self { library })),
                Err(error) => errors.push(format!("{}: {error}", path.display())),
            }
        }

        if errors.is_empty() {
            bail!("native TTD replay bridge DLL was not found; run cargo xtask native-build")
        }

        bail!(
            "failed to load native TTD replay bridge: {}",
            errors.join("; ")
        )
    }

    pub fn open_trace(
        self: &Arc<Self>,
        trace_path: &Path,
        symbols: &ResolvedSymbolConfig,
    ) -> anyhow::Result<NativeTrace> {
        let trace_path = wide_path(trace_path);
        let symbol_path = wide_str(&symbols.symbol_path);
        let image_path = wide_str(&symbols.image_path);
        let symbol_cache_dir = wide_path(&symbols.symbol_cache_dir);
        let symbol_runtime_dir = symbols
            .symbol_runtime_dir
            .as_ref()
            .map(|path| wide_path(path))
            .unwrap_or_else(wide_empty);

        let config = TtdMcpSymbolConfig {
            symbol_path: symbol_path.as_ptr(),
            image_path: image_path.as_ptr(),
            symbol_cache_dir: symbol_cache_dir.as_ptr(),
            symbol_runtime_dir: symbol_runtime_dir.as_ptr(),
        };

        let mut handle = std::ptr::null_mut();
        let open_trace: Symbol<OpenTraceFn> = unsafe { self.symbol(b"ttd_mcp_open_trace\0")? };
        let status = unsafe { open_trace(trace_path.as_ptr(), &config, &mut handle) };
        self.ensure_ok(status, "opening TTD trace")?;
        let handle = NonNull::new(handle).context("native bridge returned a null trace handle")?;

        Ok(NativeTrace {
            bridge: Arc::clone(self),
            handle,
        })
    }

    unsafe fn symbol<T>(&self, name: &[u8]) -> anyhow::Result<Symbol<'_, T>> {
        self.library
            .get(name)
            .with_context(|| format!("loading native symbol {}", String::from_utf8_lossy(name)))
    }

    fn ensure_ok(&self, status: i32, operation: &str) -> anyhow::Result<()> {
        if status == TTD_MCP_OK {
            return Ok(());
        }

        bail!(
            "native bridge failed while {operation}: {}",
            self.last_error()
        )
    }

    fn last_error(&self) -> String {
        let last_error: anyhow::Result<Symbol<LastErrorFn>> =
            unsafe { self.symbol(b"ttd_mcp_last_error\0") };
        let Ok(last_error) = last_error else {
            return "native bridge did not expose ttd_mcp_last_error".to_string();
        };

        let pointer = unsafe { last_error() };
        if pointer.is_null() {
            return "native bridge did not provide an error string".to_string();
        }

        unsafe { CStr::from_ptr(pointer) }
            .to_string_lossy()
            .into_owned()
    }
}

impl NativeTrace {
    pub fn trace_info(&self) -> anyhow::Result<TtdMcpTraceInfo> {
        let trace_info: Symbol<TraceInfoFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_trace_info\0")? };
        let mut info = TtdMcpTraceInfo::default();

        let status = unsafe { trace_info(self.handle.as_ptr(), &mut info) };
        self.bridge.ensure_ok(status, "reading trace info")?;
        Ok(info)
    }

    pub fn new_cursor(&self) -> anyhow::Result<NativeCursor> {
        let new_cursor: Symbol<NewCursorFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_new_cursor\0")? };
        let mut handle = std::ptr::null_mut();
        let status = unsafe { new_cursor(self.handle.as_ptr(), &mut handle) };
        self.bridge.ensure_ok(status, "creating replay cursor")?;
        let handle = NonNull::new(handle).context("native bridge returned a null cursor handle")?;

        Ok(NativeCursor {
            bridge: Arc::clone(&self.bridge),
            handle,
        })
    }

    pub fn list_threads(&self) -> anyhow::Result<Vec<TraceThread>> {
        let list_threads: Symbol<ListThreadsFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_list_threads\0")? };
        let mut count = 0;
        let status =
            unsafe { list_threads(self.handle.as_ptr(), std::ptr::null_mut(), 0, &mut count) };
        self.bridge.ensure_ok(status, "querying thread count")?;

        let mut threads = vec![TtdMcpThreadInfo::default(); count as usize];
        let status = unsafe {
            list_threads(
                self.handle.as_ptr(),
                threads.as_mut_ptr(),
                count,
                &mut count,
            )
        };
        self.bridge.ensure_ok(status, "listing threads")?;
        threads.truncate(count as usize);
        Ok(threads.into_iter().map(TraceThread::from).collect())
    }

    pub fn list_modules(&self) -> anyhow::Result<Vec<TraceModule>> {
        let list_modules: Symbol<ListModulesFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_list_modules\0")? };
        let mut count = 0;
        let status =
            unsafe { list_modules(self.handle.as_ptr(), std::ptr::null_mut(), 0, &mut count) };
        self.bridge.ensure_ok(status, "querying module count")?;

        let mut modules = vec![TtdMcpModuleInfo::default(); count as usize];
        let status = unsafe {
            list_modules(
                self.handle.as_ptr(),
                modules.as_mut_ptr(),
                count,
                &mut count,
            )
        };
        self.bridge.ensure_ok(status, "listing modules")?;
        modules.truncate(count as usize);
        Ok(modules.into_iter().map(TraceModule::from).collect())
    }

    pub fn list_exceptions(&self) -> anyhow::Result<Vec<TraceException>> {
        let list_exceptions: Symbol<ListExceptionsFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_list_exceptions\0")? };
        let mut count = 0;
        let status =
            unsafe { list_exceptions(self.handle.as_ptr(), std::ptr::null_mut(), 0, &mut count) };
        self.bridge.ensure_ok(status, "querying exception count")?;

        let mut exceptions = vec![TtdMcpExceptionInfo::default(); count as usize];
        let status = unsafe {
            list_exceptions(
                self.handle.as_ptr(),
                exceptions.as_mut_ptr(),
                count,
                &mut count,
            )
        };
        self.bridge.ensure_ok(status, "listing exceptions")?;
        exceptions.truncate(count as usize);
        Ok(exceptions.into_iter().map(TraceException::from).collect())
    }
}

impl Drop for NativeTrace {
    fn drop(&mut self) {
        let close_trace: anyhow::Result<Symbol<CloseTraceFn>> =
            unsafe { self.bridge.symbol(b"ttd_mcp_close_trace\0") };
        if let Ok(close_trace) = close_trace {
            unsafe { close_trace(self.handle.as_ptr()) };
        }
    }
}

impl NativeCursor {
    pub fn position(&self) -> anyhow::Result<Position> {
        let cursor_position: Symbol<CursorPositionFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_cursor_position\0")? };
        let mut position = TtdMcpPosition {
            sequence: 0,
            steps: 0,
        };
        let status = unsafe { cursor_position(self.handle.as_ptr(), &mut position) };
        self.bridge.ensure_ok(status, "reading cursor position")?;
        Ok(position.into())
    }

    pub fn set_position(&self, position: Position) -> anyhow::Result<()> {
        let set_position: Symbol<SetPositionFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_set_position\0")? };
        let status = unsafe { set_position(self.handle.as_ptr(), position.into()) };
        self.bridge.ensure_ok(status, "setting cursor position")
    }

    pub fn read_memory(
        &self,
        session_id: u64,
        cursor_id: u64,
        address: u64,
        size: u32,
    ) -> anyhow::Result<ReadMemoryResponse> {
        let read_memory: Symbol<ReadMemoryFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_read_memory\0")? };
        let mut buffer = vec![0; size as usize];
        let mut result = TtdMcpMemoryRead::default();
        let status = unsafe {
            read_memory(
                self.handle.as_ptr(),
                address,
                buffer.as_mut_ptr(),
                size,
                &mut result,
            )
        };
        self.bridge.ensure_ok(status, "reading cursor memory")?;

        let bytes_read = (result.bytes_read as usize).min(buffer.len());
        buffer.truncate(bytes_read);
        Ok(ReadMemoryResponse {
            session_id,
            cursor_id,
            requested_address: address,
            address: result.address,
            requested_size: size,
            bytes_read,
            complete: result.complete != 0,
            encoding: "hex".to_string(),
            data: bytes_to_hex(&buffer),
        })
    }

    pub fn registers(&self, session_id: u64, cursor_id: u64) -> anyhow::Result<CursorRegisters> {
        let cursor_state: Symbol<CursorStateFn> =
            unsafe { self.bridge.symbol(b"ttd_mcp_cursor_state\0")? };
        let mut state = TtdMcpCursorState::default();
        let status = unsafe { cursor_state(self.handle.as_ptr(), &mut state) };
        self.bridge
            .ensure_ok(status, "reading cursor register state")?;

        Ok(CursorRegisters {
            session_id,
            cursor_id,
            position: state.position.into(),
            previous_position: valid_position(state.previous_position).map(Into::into),
            thread: (state.thread_unique_id != 0 || state.thread_id != 0).then_some(
                CursorThreadState {
                    unique_id: state.thread_unique_id,
                    thread_id: state.thread_id,
                },
            ),
            teb_address: (state.teb_address != 0).then_some(state.teb_address),
            program_counter: state.program_counter,
            stack_pointer: state.stack_pointer,
            frame_pointer: state.frame_pointer,
            basic_return_value: state.basic_return_value,
        })
    }
}

impl Drop for NativeCursor {
    fn drop(&mut self) {
        let free_cursor: anyhow::Result<Symbol<FreeCursorFn>> =
            unsafe { self.bridge.symbol(b"ttd_mcp_free_cursor\0") };
        if let Ok(free_cursor) = free_cursor {
            unsafe { free_cursor(self.handle.as_ptr()) };
        }
    }
}

impl From<TtdMcpPosition> for Position {
    fn from(position: TtdMcpPosition) -> Self {
        Self {
            sequence: position.sequence,
            steps: position.steps,
        }
    }
}

impl From<Position> for TtdMcpPosition {
    fn from(position: Position) -> Self {
        Self {
            sequence: position.sequence,
            steps: position.steps,
        }
    }
}

impl Default for TtdMcpModuleInfo {
    fn default() -> Self {
        Self {
            name: [0; MODULE_NAME_CHARS],
            path: [0; MODULE_PATH_CHARS],
            base_address: 0,
            size: 0,
            load_position: TtdMcpPosition::default(),
            unload_position: TtdMcpPosition::default(),
            has_unload_position: 0,
        }
    }
}

impl From<TtdMcpThreadInfo> for TraceThread {
    fn from(thread: TtdMcpThreadInfo) -> Self {
        Self {
            unique_id: thread.unique_id,
            thread_id: thread.thread_id,
            lifetime_start: thread.lifetime_start.into(),
            lifetime_end: thread.lifetime_end.into(),
            active_start: (thread.has_active_time != 0).then(|| thread.active_start.into()),
            active_end: (thread.has_active_time != 0).then(|| thread.active_end.into()),
        }
    }
}

impl From<TtdMcpModuleInfo> for TraceModule {
    fn from(module: TtdMcpModuleInfo) -> Self {
        let path = utf16_fixed_to_string(&module.path);
        let mut name = utf16_fixed_to_string(&module.name);
        if name.is_empty() && !path.is_empty() {
            name = Path::new(&path)
                .file_name()
                .map(|value| value.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.clone());
        }

        Self {
            name,
            path: (!path.is_empty()).then(|| PathBuf::from(path)),
            base_address: module.base_address,
            size: module.size,
            load_position: Some(module.load_position.into()),
            unload_position: (module.has_unload_position != 0)
                .then(|| module.unload_position.into()),
        }
    }
}

impl From<TtdMcpExceptionInfo> for TraceException {
    fn from(exception: TtdMcpExceptionInfo) -> Self {
        let parameter_count = (exception.parameter_count as usize).min(EXCEPTION_PARAMETER_COUNT);
        Self {
            position: exception.position.into(),
            thread_unique_id: (exception.thread_unique_id != 0)
                .then_some(exception.thread_unique_id),
            code: exception.code,
            flags: exception.flags,
            program_counter: exception.program_counter,
            record_address: exception.record_address,
            parameters: exception.parameters[..parameter_count].to_vec(),
        }
    }
}

impl TtdMcpTraceInfo {
    pub fn lifetime_start(&self) -> Position {
        self.first_position.into()
    }

    pub fn lifetime_end(&self) -> Position {
        self.last_position.into()
    }

    pub fn peb_address(&self) -> Option<u64> {
        (self.peb_address != 0).then_some(self.peb_address)
    }

    pub fn process_id(&self) -> Option<u32> {
        (self.process_id != 0).then_some(self.process_id)
    }

    pub fn thread_count(&self) -> usize {
        self.thread_count as usize
    }

    pub fn module_count(&self) -> usize {
        self.module_count as usize
    }

    pub fn module_instance_count(&self) -> usize {
        self.module_instance_count as usize
    }

    pub fn exception_count(&self) -> usize {
        self.exception_count as usize
    }

    pub fn keyframe_count(&self) -> Option<usize> {
        Some(self.keyframe_count as usize)
    }
}

fn bridge_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = std::env::var_os("TTD_NATIVE_BRIDGE_DLL").map(PathBuf::from) {
        candidates.push(path);
    }

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            candidates.push(exe_dir.join(NATIVE_BRIDGE_DLL));
        }
    }

    let build_dir = PathBuf::from("target/native/ttd-replay-bridge");
    candidates.push(build_dir.join("bin/Release").join(NATIVE_BRIDGE_DLL));
    candidates.push(build_dir.join("bin/Debug").join(NATIVE_BRIDGE_DLL));
    candidates.push(build_dir.join("Release").join(NATIVE_BRIDGE_DLL));
    candidates.push(build_dir.join("Debug").join(NATIVE_BRIDGE_DLL));

    if let Some(root) = workspace_root() {
        let build_dir = root.join("target/native/ttd-replay-bridge");
        candidates.push(build_dir.join("bin/Release").join(NATIVE_BRIDGE_DLL));
        candidates.push(build_dir.join("bin/Debug").join(NATIVE_BRIDGE_DLL));
        candidates.push(build_dir.join("Release").join(NATIVE_BRIDGE_DLL));
        candidates.push(build_dir.join("Debug").join(NATIVE_BRIDGE_DLL));
    }

    candidates
}

fn add_dll_search_paths(bridge_path: &Path) {
    let mut paths = Vec::new();
    if let Some(bridge_dir) = bridge_path.parent() {
        paths.push(bridge_dir.to_path_buf());
    }
    if let Some(runtime_dir) = std::env::var_os("TTD_RUNTIME_DIR").map(PathBuf::from) {
        paths.push(runtime_dir);
    } else {
        paths.push(PathBuf::from("target/ttd-runtime"));
        if let Some(root) = workspace_root() {
            paths.push(root.join("target/ttd-runtime"));
        }
    }
    if let Some(symbol_runtime_dir) = std::env::var_os("TTD_SYMBOL_RUNTIME_DIR").map(PathBuf::from)
    {
        paths.push(symbol_runtime_dir);
    } else {
        paths.push(PathBuf::from("target/symbol-runtime"));
        if let Some(root) = workspace_root() {
            paths.push(root.join("target/symbol-runtime"));
        }
    }

    let mut path_var = std::env::var_os("PATH").unwrap_or_default();
    for path in paths {
        ensure_path_component(&mut path_var, &path);
    }
    std::env::set_var("PATH", path_var);
}

fn workspace_root() -> Option<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
}

fn ensure_path_component(path_var: &mut std::ffi::OsString, path: &Path) {
    if !path.is_dir() {
        return;
    }

    let already_present = std::env::split_paths(path_var).any(|existing| existing == path);
    if already_present {
        return;
    }

    let mut paths = vec![path.to_path_buf()];
    paths.extend(std::env::split_paths(path_var));
    if let Ok(joined) = std::env::join_paths(paths) {
        *path_var = joined;
    }
}

fn wide_empty() -> Vec<u16> {
    vec![0]
}

fn wide_str(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn utf16_fixed_to_string(value: &[u16]) -> String {
    let length = value
        .iter()
        .position(|character| *character == 0)
        .unwrap_or(value.len());
    String::from_utf16_lossy(&value[..length])
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn valid_position(position: TtdMcpPosition) -> Option<TtdMcpPosition> {
    (position.sequence != u64::MAX).then_some(position)
}

#[cfg(windows)]
fn wide_path(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(not(windows))]
fn wide_path(path: &Path) -> Vec<u16> {
    path.to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}
