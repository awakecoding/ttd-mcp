use anyhow::{bail, ensure, Context};
mod common;
use common::{
    ensure_ping_fixture_extracted, ping_symbol_settings, ping_trace_path, workspace_root,
    EXPECT_NATIVE_ENV,
};
use ttd_mcp::ttd_replay::{
    AddressClassification, AddressInfoRequest, LoadTraceRequest, MemoryAccessDirection,
    MemoryAccessMask, MemoryWatchpointRequest, ModuleInfoRequest, Position, PositionOrPercent,
    PositionRequest, ReadMemoryRequest, SessionRegistry, StackReadRequest, StepDirection, StepKind,
    StepRequest, TraceInfo,
};

#[test]
fn ping_fixture_recorder_output_is_available() -> anyhow::Result<()> {
    if !ensure_ping_fixture_extracted()? {
        eprintln!("skipping ping recorder output test: no local trace fixture found");
        return Ok(());
    }

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
    let capabilities = registry.capabilities(loaded.session_id)?;
    ensure!(
        capabilities.session_id == loaded.session_id,
        "capabilities should echo the loaded session id"
    );
    ensure!(
        capabilities.backend == info.backend,
        "capabilities backend should match trace info backend"
    );
    ensure!(
        capabilities.features.trace_info,
        "trace_info capability should always be available for a loaded session"
    );
    ensure!(
        capabilities.features.cursor_create,
        "cursor_create capability should always be available for a loaded session"
    );
    ensure!(
        capabilities.features.position_get && capabilities.features.position_set,
        "position get/set capabilities should always be available for a loaded session"
    );
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
        ensure!(
            capabilities.native,
            "native capability flag should be true for native replay"
        );
        ensure!(
            capabilities.features.read_memory && capabilities.features.memory_watchpoint,
            "native replay should advertise memory read and watchpoint support"
        );
        ensure!(
            capabilities.features.module_info
                && capabilities.features.address_info
                && capabilities.features.stack_info
                && capabilities.features.stack_read,
            "native replay should advertise address, module, and stack helper support"
        );
        assert_native_lists(&registry, loaded.session_id, &info)?;
        assert_native_module_info(&registry, loaded.session_id)?;
        assert_native_address_info(&registry, loaded.session_id, cursor.cursor_id)?;
        assert_native_registers(&registry, loaded.session_id, cursor.cursor_id)?;
        assert_native_stack_helpers(&registry, loaded.session_id, cursor.cursor_id)?;
        assert_native_step(&mut registry, loaded.session_id, cursor.cursor_id, &info)?;
        assert_native_memory_read(&registry, loaded.session_id, cursor.cursor_id, &info)?;
        assert_trace_command_line(&registry, loaded.session_id, cursor.cursor_id)?;
        assert_native_memory_watchpoint(&mut registry, loaded.session_id, cursor.cursor_id, &info)?;
    } else if info.backend != "ttd-replay-native" {
        eprintln!(
            "ping trace fixture loaded through placeholder backend; set {EXPECT_NATIVE_ENV}=1 once native replay is wired"
        );
    }

    Ok(())
}

fn expect_native_replay() -> bool {
    std::env::var_os(EXPECT_NATIVE_ENV).is_some_and(|value| value != "0" && value != "false")
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

fn assert_native_registers(
    registry: &SessionRegistry,
    session_id: u64,
    cursor_id: u64,
) -> anyhow::Result<()> {
    let current = registry.cursor_position(session_id, cursor_id)?;
    let registers = registry.registers(session_id, cursor_id)?;

    ensure!(
        registers.position == current.position,
        "register snapshot position should match cursor position"
    );
    ensure!(
        registers.thread.is_some(),
        "register snapshot should include current thread ids"
    );
    ensure!(
        registers.teb_address.is_some(),
        "register snapshot should include a TEB address"
    );
    ensure!(
        registers.program_counter != 0,
        "register snapshot should include a non-zero program counter"
    );
    ensure!(
        registers.stack_pointer != 0,
        "register snapshot should include a non-zero stack pointer"
    );

    Ok(())
}

fn assert_native_module_info(registry: &SessionRegistry, session_id: u64) -> anyhow::Result<()> {
    let by_name = registry.module_info(ModuleInfoRequest {
        session_id,
        name: Some("ping.exe".to_string()),
        address: None,
    })?;
    ensure!(
        by_name.matched_by == "name",
        "module lookup by name should report a name match"
    );
    ensure!(
        by_name.module.name.eq_ignore_ascii_case("ping.exe"),
        "module lookup by name should return ping.exe"
    );

    let by_address = registry.module_info(ModuleInfoRequest {
        session_id,
        name: None,
        address: Some(by_name.module.base_address),
    })?;
    ensure!(
        by_address.matched_by == "address",
        "module lookup by address should report an address match"
    );
    ensure!(
        by_address.module.name.eq_ignore_ascii_case("ping.exe"),
        "module lookup by address should return ping.exe"
    );

    Ok(())
}

fn assert_native_address_info(
    registry: &SessionRegistry,
    session_id: u64,
    cursor_id: u64,
) -> anyhow::Result<()> {
    let module = registry.module_info(ModuleInfoRequest {
        session_id,
        name: Some("ping.exe".to_string()),
        address: None,
    })?;
    let address = registry.address_info(AddressInfoRequest {
        session_id,
        cursor_id,
        address: format!("{:#x}", module.module.base_address),
    })?;

    ensure!(
        address.classification == AddressClassification::Module,
        "module base should be classified as a module address: {:?}",
        address
    );
    let coordinate = address
        .module
        .as_ref()
        .context("address_info should include module coordinates")?;
    ensure!(
        coordinate.name.eq_ignore_ascii_case("ping.exe"),
        "address_info should return ping.exe coordinates: {:?}",
        address
    );
    ensure!(
        coordinate.runtime_base == module.module.base_address,
        "address_info should echo the runtime module base: {:?}",
        address
    );
    ensure!(
        coordinate.rva == 0 && coordinate.rva_hex == "0x0",
        "address_info should report RVA zero at module base: {:?}",
        address
    );
    ensure!(
        coordinate.module_offset == "ping.exe+0x0",
        "address_info should report module+offset coordinates: {:?}",
        address
    );
    ensure!(
        address.registers.program_counter != 0 && address.registers.stack_pointer != 0,
        "address_info should include register context: {:?}",
        address
    );
    ensure!(
        address.stack.is_some(),
        "address_info should include stack context when stack_info is available: {:?}",
        address
    );

    Ok(())
}

fn assert_native_stack_helpers(
    registry: &SessionRegistry,
    session_id: u64,
    cursor_id: u64,
) -> anyhow::Result<()> {
    let registers = registry.registers(session_id, cursor_id)?;
    let stack = registry.stack_info(session_id, cursor_id)?;
    ensure!(
        stack.stack_pointer == registers.stack_pointer,
        "stack_info should report the register stack pointer"
    );
    ensure!(
        stack.teb_address != 0 && stack.stack_base != 0 && stack.stack_limit != 0,
        "stack_info should include TEB and stack bounds"
    );
    ensure!(
        stack.stack_limit <= stack.stack_base,
        "stack limit should not be above stack base"
    );

    let stack_read = registry.stack_read(StackReadRequest {
        session_id,
        cursor_id,
        size: 128,
        offset_from_sp: 0,
        decode_pointers: true,
    })?;
    ensure!(
        stack_read.stack_pointer == registers.stack_pointer,
        "stack_read should report the register stack pointer"
    );
    ensure!(
        stack_read.bytes_read > 0,
        "stack_read should read at least one byte"
    );
    ensure!(
        stack_read.data.len() == stack_read.bytes_read * 2,
        "stack_read hex payload length should match bytes read"
    );
    ensure!(
        stack_read.pointer_size == 8,
        "stack_read should report x64 pointer size"
    );

    Ok(())
}

fn assert_native_memory_read(
    registry: &SessionRegistry,
    session_id: u64,
    cursor_id: u64,
    info: &TraceInfo,
) -> anyhow::Result<()> {
    let peb_address = info
        .peb_address
        .context("native trace should expose a PEB address")?;
    let memory = registry.read_memory(ReadMemoryRequest {
        session_id,
        cursor_id,
        address: peb_address,
        size: 64,
    })?;

    ensure!(
        memory.address == peb_address,
        "PEB memory read should start at requested address"
    );
    ensure!(
        memory.bytes_read >= 16,
        "PEB memory read should return at least 16 bytes, got {}",
        memory.bytes_read
    );
    ensure!(
        memory.data.len() == memory.bytes_read * 2,
        "hex payload length should match bytes read"
    );

    Ok(())
}

fn assert_native_step(
    registry: &mut SessionRegistry,
    session_id: u64,
    cursor_id: u64,
    info: &TraceInfo,
) -> anyhow::Result<()> {
    let before = registry.cursor_position(session_id, cursor_id)?.position;
    let stepped = registry.step(StepRequest {
        session_id,
        cursor_id,
        direction: StepDirection::Forward,
        kind: StepKind::Step,
        count: 1,
    })?;
    let current = registry.cursor_position(session_id, cursor_id)?;

    ensure!(
        stepped.position == current.position,
        "step result should match the updated cursor position"
    );
    ensure!(
        !position_after(before, stepped.position),
        "forward step should not move backward: before {:?}, after {:?}",
        before,
        stepped.position
    );
    assert_position_in_range(stepped.position, info.lifetime_start, info.lifetime_end);
    ensure!(
        stepped.requested_count == 1,
        "step result should echo the requested count: {:?}",
        stepped
    );
    ensure!(
        stepped.steps_executed <= 1,
        "single-step result should execute at most one step: {:?}",
        stepped
    );
    ensure!(
        stepped.stop_reason != "Unknown",
        "step result should include a known stop reason: {:?}",
        stepped
    );

    Ok(())
}

fn assert_trace_command_line(
    registry: &SessionRegistry,
    session_id: u64,
    cursor_id: u64,
) -> anyhow::Result<()> {
    let command_line = registry.command_line(session_id, cursor_id)?;
    ensure!(
        command_line.command_line.contains("ping.exe"),
        "trace-derived command line should include ping.exe: {}",
        command_line.command_line
    );
    ensure!(
        command_line.command_line.contains("google.com"),
        "trace-derived command line should include google.com: {}",
        command_line.command_line
    );
    ensure!(
        command_line.command_line.contains("-n 10"),
        "trace-derived command line should include -n 10: {}",
        command_line.command_line
    );

    Ok(())
}

fn assert_native_memory_watchpoint(
    registry: &mut SessionRegistry,
    session_id: u64,
    cursor_id: u64,
    info: &TraceInfo,
) -> anyhow::Result<()> {
    let command_line = registry.command_line(session_id, cursor_id)?;
    registry.set_position(PositionRequest {
        session_id,
        cursor_id,
        position: PositionOrPercent::Position(info.lifetime_end),
    })?;

    let watchpoint = registry.memory_watchpoint(MemoryWatchpointRequest {
        session_id,
        cursor_id,
        address: command_line.command_line_address,
        size: 16,
        access: MemoryAccessMask::Read,
        direction: MemoryAccessDirection::Previous,
    })?;
    let current = registry.cursor_position(session_id, cursor_id)?;

    ensure!(
        watchpoint.found,
        "command-line read watchpoint should find a previous access: {:?}",
        watchpoint
    );
    ensure!(
        current.position == watchpoint.position,
        "watchpoint result should match the updated cursor position"
    );
    assert_position_in_range(watchpoint.position, info.lifetime_start, info.lifetime_end);
    ensure!(
        watchpoint.match_address.is_some(),
        "watchpoint hit should include a matched address: {:?}",
        watchpoint
    );
    ensure!(
        watchpoint.match_size.is_some_and(|size| size > 0),
        "watchpoint hit should include a matched size: {:?}",
        watchpoint
    );
    ensure!(
        watchpoint.match_access == Some(ttd_mcp::ttd_replay::MemoryAccessKind::Read),
        "watchpoint hit should be a read access: {:?}",
        watchpoint
    );
    ensure!(
        watchpoint.thread.is_some(),
        "watchpoint hit should include current thread ids: {:?}",
        watchpoint
    );
    ensure!(
        watchpoint.program_counter != 0,
        "watchpoint hit should include a non-zero program counter: {:?}",
        watchpoint
    );
    ensure!(
        watchpoint.stop_reason == "MemoryWatchpoint",
        "watchpoint hit should stop for a memory watchpoint: {:?}",
        watchpoint
    );

    registry.set_position(PositionRequest {
        session_id,
        cursor_id,
        position: PositionOrPercent::Position(info.lifetime_start),
    })?;
    let no_hit = registry.memory_watchpoint(MemoryWatchpointRequest {
        session_id,
        cursor_id,
        address: command_line.command_line_address,
        size: 16,
        access: MemoryAccessMask::Read,
        direction: MemoryAccessDirection::Previous,
    })?;
    ensure!(
        !no_hit.found,
        "watchpoint search before trace start should report no hit: {:?}",
        no_hit
    );
    ensure!(
        !no_hit.stop_reason.is_empty(),
        "no-hit watchpoint result should include a stop reason: {:?}",
        no_hit
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
