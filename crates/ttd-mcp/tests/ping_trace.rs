use anyhow::{bail, ensure, Context};
use std::env;
use std::path::{Path, PathBuf};
use ttd_mcp::ttd_replay::{
    LoadTraceRequest, Position, PositionOrPercent, PositionRequest, SessionRegistry,
    SymbolSettings, TraceInfo,
};

const EXPECT_NATIVE_ENV: &str = "TTD_MCP_EXPECT_NATIVE_REPLAY";

#[test]
fn ping_fixture_recorder_output_is_available() -> anyhow::Result<()> {
    let output_path = workspace_root().join("traces/ping/ping01.out");
    if !output_path.is_file() {
        eprintln!(
            "skipping ping recorder output test: {} is not present",
            output_path.display()
        );
        return Ok(());
    }

    let output = std::fs::read_to_string(&output_path)
        .with_context(|| format!("reading {}", output_path.display()))?;

    assert!(output.contains("TTDRecord"));
    assert!(output.contains("ping.exe"));
    assert!(output.contains("google.com -n 10"));
    assert!(output.contains("Guest process exited with exit code 0"));
    Ok(())
}

#[test]
fn loads_ping_trace_fixture_and_exercises_cursor_path() -> anyhow::Result<()> {
    let Some(trace_path) = ping_trace_path()? else {
        eprintln!("skipping ping trace replay test: no local trace fixture found");
        return Ok(());
    };

    let symbol_settings = ping_symbol_settings(&trace_path);
    let resolved_symbols = symbol_settings.resolve_for_process();

    let mut registry = SessionRegistry::default();
    let loaded = registry.load_trace(LoadTraceRequest {
        trace_path: trace_path.clone(),
        symbols: symbol_settings,
    })?;
    assert_eq!(loaded.symbol_path, resolved_symbols.symbol_path);
    assert_eq!(loaded.symbols, resolved_symbols);
    assert!(resolved_symbols
        .symbol_path
        .contains("https://msdl.microsoft.com/download/symbols"));
    assert!(resolved_symbols.has_image_path());
    assert_eq!(resolved_symbols.binary_path_count, 1);
    assert!(resolved_symbols.symbol_runtime_dir.is_some());

    let info = registry.trace_info(loaded.session_id)?;
    let cursor = registry.create_cursor(loaded.session_id)?;
    let current = registry.cursor_position(loaded.session_id, cursor.cursor_id)?;
    assert_eq!(cursor.position, current.position);

    let end_position = registry
        .set_position(PositionRequest {
            session_id: loaded.session_id,
            cursor_id: cursor.cursor_id,
            position: PositionOrPercent::Position(info.lifetime_end),
        })?
        .position;
    assert_eq!(end_position, info.lifetime_end);

    let midpoint = registry
        .set_position(PositionRequest {
            session_id: loaded.session_id,
            cursor_id: cursor.cursor_id,
            position: PositionOrPercent::Percent(50),
        })?
        .position;
    assert_position_in_range(midpoint, info.lifetime_start, info.lifetime_end);

    if expect_native_replay() {
        assert_native_trace_info(&info)?;
        assert_native_lists(&registry, loaded.session_id, &info)?;
    } else if info.backend != "ttd-replay-native" {
        eprintln!(
            "ping trace fixture loaded through placeholder backend; set {EXPECT_NATIVE_ENV}=1 once native replay is wired"
        );
    }

    Ok(())
}

fn ping_trace_path() -> anyhow::Result<Option<PathBuf>> {
    if let Some(path) = env::var_os("TTD_TEST_TRACE").map(PathBuf::from) {
        ensure!(
            path.is_file(),
            "TTD_TEST_TRACE does not point to a file: {}",
            path.display()
        );
        return Ok(Some(path));
    }

    let default_trace = workspace_root().join("traces/ping/ping01.run");
    Ok(default_trace.is_file().then_some(default_trace))
}

fn ping_symbol_settings(trace_path: &Path) -> SymbolSettings {
    let mut settings = SymbolSettings::default();
    if let Some(trace_dir) = trace_path.parent() {
        let binary_path = trace_dir.join("ping.exe");
        if binary_path.is_file() {
            settings.binary_paths.push(binary_path);
        }
    }
    settings
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate lives under <workspace>/crates/ttd-mcp")
        .to_path_buf()
}

fn expect_native_replay() -> bool {
    env::var_os(EXPECT_NATIVE_ENV).is_some_and(|value| value != "0" && value != "false")
}

fn assert_native_trace_info(info: &TraceInfo) -> anyhow::Result<()> {
    if info.backend != "ttd-replay-native" {
        bail!(
            "expected native replay backend, got {} with warning {:?}",
            info.backend,
            info.warning
        );
    }

    ensure!(
        info.warning.is_none(),
        "native trace info should not include a placeholder warning"
    );
    ensure!(
        info.thread_count > 0,
        "native trace should report at least one thread"
    );
    ensure!(
        info.module_count > 0,
        "native trace should report at least one module"
    );
    ensure!(
        position_after(info.lifetime_end, info.lifetime_start),
        "native trace lifetime end should be after start"
    );
    Ok(())
}

fn assert_native_lists(
    registry: &SessionRegistry,
    session_id: u64,
    info: &TraceInfo,
) -> anyhow::Result<()> {
    let threads = registry.list_threads(session_id)?;
    ensure!(
        threads.len() == info.thread_count,
        "thread list count {} should match trace info {}",
        threads.len(),
        info.thread_count
    );

    let modules = registry.list_modules(session_id)?;
    ensure!(
        modules.modules.len() == info.module_instance_count,
        "module instance list count {} should match trace info {}",
        modules.modules.len(),
        info.module_instance_count
    );
    ensure!(
        modules
            .modules
            .iter()
            .any(|module| module.name.eq_ignore_ascii_case("ping.exe")),
        "native module list should include ping.exe"
    );

    let exceptions = registry.list_exceptions(session_id)?;
    ensure!(
        exceptions.len() == info.exception_count,
        "exception list count {} should match trace info {}",
        exceptions.len(),
        info.exception_count
    );

    Ok(())
}

fn assert_position_in_range(position: Position, start: Position, end: Position) {
    assert!(!position_after(start, position));
    assert!(!position_after(position, end));
}

fn position_after(left: Position, right: Position) -> bool {
    (left.sequence, left.steps) > (right.sequence, right.steps)
}
