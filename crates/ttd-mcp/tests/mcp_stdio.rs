use anyhow::{bail, ensure, Context};
use serde_json::{json, Value};
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Mutex, OnceLock};

const PING_TRACE_ARCHIVE: &str = "traces/ping.7z";
const PING_TRACE_RUN: &str = "traces/ping/ping01.run";

static PING_FIXTURE_EXTRACT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[test]
fn initialize_ping_and_tools_list_roundtrip_over_stdio() -> anyhow::Result<()> {
    let mut client = McpClient::start()?;

    let initialize = client.initialize()?;
    assert_eq!(initialize["result"]["serverInfo"]["name"], "ttd-mcp");
    ensure!(
        initialize["result"]["capabilities"]["tools"].is_object(),
        "initialize result should advertise tools capability: {initialize}"
    );

    let ping = client.request(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "ping",
        "params": {}
    }))?;
    assert_success_id(&ping, 2)?;
    assert_eq!(ping["result"], json!({}));

    let tools = client.request(json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/list",
        "params": {}
    }))?;
    assert_success_id(&tools, 3)?;
    let tools = tools["result"]["tools"]
        .as_array()
        .context("tools/list result should include a tools array")?;
    let names = tools
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect::<Vec<_>>();

    ensure!(
        names.contains(&"ttd_load_trace"),
        "missing ttd_load_trace tool"
    );
    ensure!(
        names.contains(&"ttd_command_line"),
        "missing ttd_command_line tool"
    );
    ensure!(
        names.contains(&"ttd_read_memory"),
        "missing ttd_read_memory tool"
    );
    for tool in tools {
        ensure!(
            tool["name"].is_string(),
            "tool is missing a string name: {tool}"
        );
        ensure!(
            tool["description"].is_string(),
            "tool is missing a string description: {tool}"
        );
        ensure!(
            tool["inputSchema"].is_object(),
            "tool is missing an object inputSchema: {tool}"
        );
    }

    Ok(())
}

#[test]
fn protocol_errors_use_json_rpc_error_codes() -> anyhow::Result<()> {
    let mut client = McpClient::start()?;
    client.initialize()?;

    let method_not_found = client.request(json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "not/a-method",
        "params": {}
    }))?;
    assert_error_code(&method_not_found, json!(11), -32601)?;

    Ok(())
}

#[test]
fn tool_failures_are_reported_as_mcp_tool_results() -> anyhow::Result<()> {
    let mut client = McpClient::start()?;
    client.initialize()?;

    let response = client.request(json!({
        "jsonrpc": "2.0",
        "id": 20,
        "method": "tools/call",
        "params": {
            "name": "ttd_trace_info",
            "arguments": {
                "session_id": 999999
            }
        }
    }))?;

    assert_success_id(&response, 20)?;
    ensure!(
        response["result"]["isError"].as_bool() == Some(true),
        "tool failure should be a tools/call result with isError=true: {response}"
    );
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .context("tool result should include text content")?;
    ensure!(
        text.contains("unknown session id"),
        "unexpected tool error text: {text}"
    );

    Ok(())
}

#[test]
fn ping_trace_replay_scenario_over_mcp_stdio() -> anyhow::Result<()> {
    let Some(trace_path) = ping_trace_path()? else {
        eprintln!("skipping MCP ping replay scenario: no local trace fixture found");
        return Ok(());
    };

    let mut client = McpClient::start()?;
    client.initialize()?;

    let load_args = ping_load_trace_args(&trace_path);
    let loaded = client.call_tool_json(30, "ttd_load_trace", load_args)?;
    let session_id = loaded["session_id"]
        .as_u64()
        .context("ttd_load_trace response should include a session_id")?;
    ensure!(session_id > 0, "session_id should be non-zero: {loaded}");
    ensure!(
        loaded["trace"]["trace_path"].is_string(),
        "load response should include trace metadata: {loaded}"
    );
    ensure!(
        loaded["symbol_path"]
            .as_str()
            .is_some_and(|path| path.contains("https://msdl.microsoft.com/download/symbols")),
        "load response should include the Microsoft symbol server path: {loaded}"
    );

    let info = client.call_tool_json(
        31,
        "ttd_trace_info",
        json!({
            "session_id": session_id,
        }),
    )?;
    ensure!(
        info["backend"].is_string(),
        "trace info should include a backend: {info}"
    );

    let cursor = client.call_tool_json(
        32,
        "ttd_cursor_create",
        json!({
            "session_id": session_id,
        }),
    )?;
    let cursor_id = cursor["cursor_id"]
        .as_u64()
        .context("ttd_cursor_create response should include a cursor_id")?;
    ensure!(cursor_id > 0, "cursor_id should be non-zero: {cursor}");

    let current = client.call_tool_json(
        33,
        "ttd_position_get",
        json!({
            "session_id": session_id,
            "cursor_id": cursor_id,
        }),
    )?;
    ensure!(
        current["position"].is_object(),
        "position_get should include a position: {current}"
    );

    let midpoint = client.call_tool_json(
        34,
        "ttd_position_set",
        json!({
            "session_id": session_id,
            "cursor_id": cursor_id,
            "position": 50,
        }),
    )?;
    ensure!(
        midpoint["position"].is_object(),
        "position_set should include a position: {midpoint}"
    );

    if info["backend"] != "ttd-replay-native" {
        ensure!(
            info["warning"].is_string(),
            "non-native MCP replay should explain why native replay is unavailable: {info}"
        );
        let closed = client.call_tool_json(
            35,
            "ttd_close_trace",
            json!({
                "session_id": session_id,
            }),
        )?;
        ensure!(
            closed["closed"] == true,
            "close response should succeed: {closed}"
        );
        return Ok(());
    }

    let modules = client.call_tool_json(
        35,
        "ttd_list_modules",
        json!({
            "session_id": session_id,
        }),
    )?;
    let module_entries = modules["modules"]
        .as_array()
        .context("ttd_list_modules response should include modules")?;
    ensure!(
        module_entries.iter().any(|module| module["name"]
            .as_str()
            .is_some_and(|name| name.eq_ignore_ascii_case("ping.exe"))),
        "native MCP module list should include ping.exe: {modules}"
    );

    let registers = client.call_tool_json(
        36,
        "ttd_registers",
        json!({
            "session_id": session_id,
            "cursor_id": cursor_id,
        }),
    )?;
    ensure!(
        registers["program_counter"]
            .as_u64()
            .is_some_and(|value| value != 0),
        "register snapshot should include a non-zero program counter: {registers}"
    );
    ensure!(
        registers["stack_pointer"]
            .as_u64()
            .is_some_and(|value| value != 0),
        "register snapshot should include a non-zero stack pointer: {registers}"
    );

    let command_line = client.call_tool_json(
        37,
        "ttd_command_line",
        json!({
            "session_id": session_id,
            "cursor_id": cursor_id,
        }),
    )?;
    let command_line_text = command_line["command_line"]
        .as_str()
        .context("ttd_command_line response should include command_line")?;
    ensure!(
        command_line_text.contains("ping.exe") && command_line_text.contains("google.com"),
        "command line should identify the ping capture: {command_line_text}"
    );

    let peb_address = info["peb_address"]
        .as_u64()
        .context("native trace info should include a PEB address")?;
    let memory = client.call_tool_json(
        38,
        "ttd_read_memory",
        json!({
            "session_id": session_id,
            "cursor_id": cursor_id,
            "address": peb_address,
            "size": 64,
        }),
    )?;
    ensure!(
        memory["bytes_read"]
            .as_u64()
            .is_some_and(|value| value >= 16),
        "PEB memory read should return at least 16 bytes: {memory}"
    );
    ensure!(
        memory["encoding"] == "hex",
        "memory response should be hex encoded: {memory}"
    );

    let closed = client.call_tool_json(
        39,
        "ttd_close_trace",
        json!({
            "session_id": session_id,
        }),
    )?;
    ensure!(
        closed["closed"] == true,
        "close response should succeed: {closed}"
    );

    Ok(())
}

struct McpClient {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl McpClient {
    fn start() -> anyhow::Result<Self> {
        let mut child = Command::new(server_binary())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawning ttd-mcp")?;
        let stdin = child.stdin.take().context("child stdin was not piped")?;
        let stdout = child.stdout.take().context("child stdout was not piped")?;

        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        })
    }

    fn notify(&mut self, value: Value) -> anyhow::Result<()> {
        writeln!(self.stdin, "{}", serde_json::to_string(&value)?)?;
        self.stdin.flush()?;
        Ok(())
    }

    fn initialize(&mut self) -> anyhow::Result<Value> {
        let response = self.request(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "ttd-mcp-test",
                    "version": "0.0.0"
                }
            }
        }))?;
        assert_success_id(&response, 1)?;
        self.notify(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }))?;
        Ok(response)
    }

    fn request(&mut self, value: Value) -> anyhow::Result<Value> {
        self.raw_request(&serde_json::to_string(&value)?)
    }

    fn call_tool_json(&mut self, id: u64, name: &str, arguments: Value) -> anyhow::Result<Value> {
        let response = self.request(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments,
            }
        }))?;
        assert_success_id(&response, id)?;
        ensure!(
            response["result"]["isError"].as_bool() != Some(true),
            "{name} returned an MCP tool error: {response}"
        );
        parse_tool_json(&response)
    }

    fn raw_request(&mut self, line: &str) -> anyhow::Result<Value> {
        writeln!(self.stdin, "{line}")?;
        self.stdin.flush()?;

        let mut response = String::new();
        let bytes = self.stdout.read_line(&mut response)?;
        ensure!(bytes > 0, "server closed stdout before writing a response");
        serde_json::from_str(response.trim_end()).context("parsing MCP response")
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn server_binary() -> PathBuf {
    option_env!("CARGO_BIN_EXE_ttd-mcp")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let mut path = std::env::current_exe().expect("current test executable path");
            path.pop();
            if path.ends_with("deps") {
                path.pop();
            }
            path.push(format!("ttd-mcp{}", std::env::consts::EXE_SUFFIX));
            path
        })
}

fn parse_tool_json(response: &Value) -> anyhow::Result<Value> {
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .context("tool result should include text content")?;
    serde_json::from_str(text).context("parsing tool result JSON")
}

fn ping_load_trace_args(trace_path: &Path) -> Value {
    let mut binary_paths = Vec::new();
    if let Some(trace_dir) = trace_path.parent() {
        let binary_path = trace_dir.join("ping.exe");
        if binary_path.is_file() {
            binary_paths.push(path_string(&binary_path));
        }
    }

    json!({
        "trace_path": path_string(trace_path),
        "symbols": {
            "binary_paths": binary_paths,
        }
    })
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

    let default_trace = workspace_root().join(PING_TRACE_RUN);
    if default_trace.is_file() {
        return Ok(Some(default_trace));
    }

    if !ensure_ping_fixture_extracted()? {
        return Ok(None);
    }

    Ok(default_trace.is_file().then_some(default_trace))
}

fn ensure_ping_fixture_extracted() -> anyhow::Result<bool> {
    let fixture_lock = PING_FIXTURE_EXTRACT_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = fixture_lock
        .lock()
        .map_err(|error| anyhow::anyhow!("ping fixture extraction lock is poisoned: {error}"))?;

    let root = workspace_root();
    let default_trace = root.join(PING_TRACE_RUN);
    if default_trace.is_file() {
        return Ok(true);
    }

    let archive_path = root.join(PING_TRACE_ARCHIVE);
    if !archive_path.is_file() {
        eprintln!(
            "ping trace archive is not present at {}; tests can still use TTD_TEST_TRACE",
            archive_path.display()
        );
        return Ok(false);
    }

    let Some(seven_zip) = seven_zip_command() else {
        eprintln!(
            "ping trace archive is present at {}, but no 7z/7zz executable was found; set TTD_TEST_7Z to extract automatically",
            archive_path.display()
        );
        return Ok(false);
    };

    let traces_dir = root.join("traces");
    std::fs::create_dir_all(&traces_dir)
        .with_context(|| format!("creating {}", traces_dir.display()))?;
    let output = Command::new(&seven_zip)
        .arg("x")
        .arg(&archive_path)
        .arg(format!("-o{}", traces_dir.display()))
        .arg("-y")
        .output()
        .with_context(|| format!("running {}", seven_zip.display()))?;

    if !output.status.success() {
        bail!(
            "failed to extract {} with {}\nstdout:\n{}\nstderr:\n{}",
            archive_path.display(),
            seven_zip.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    ensure!(
        default_trace.is_file(),
        "extracted {}, but {} was not created",
        archive_path.display(),
        default_trace.display()
    );

    Ok(true)
}

fn seven_zip_command() -> Option<PathBuf> {
    if let Some(path) = env::var_os("TTD_TEST_7Z") {
        return Some(PathBuf::from(path));
    }

    ["7z", "7zz"]
        .into_iter()
        .map(PathBuf::from)
        .find(|candidate| Command::new(candidate).arg("i").output().is_ok())
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate lives under <workspace>/crates/ttd-mcp")
        .to_path_buf()
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn assert_success_id(response: &Value, expected_id: u64) -> anyhow::Result<()> {
    ensure!(
        response["jsonrpc"] == "2.0",
        "missing JSON-RPC version: {response}"
    );
    ensure!(
        response["id"] == expected_id,
        "unexpected response id: {response}"
    );
    ensure!(
        response.get("error").is_none(),
        "response should not be an error: {response}"
    );
    ensure!(
        response.get("result").is_some(),
        "response should include a result: {response}"
    );
    Ok(())
}

fn assert_error_code(
    response: &Value,
    expected_id: Value,
    expected_code: i64,
) -> anyhow::Result<()> {
    ensure!(
        response["jsonrpc"] == "2.0",
        "missing JSON-RPC version: {response}"
    );
    ensure!(
        response["id"] == expected_id,
        "unexpected response id: {response}"
    );
    let Some(code) = response["error"]["code"].as_i64() else {
        bail!("response should include an error code: {response}");
    };
    ensure!(
        code == expected_code,
        "expected error code {expected_code}, got {code}: {response}"
    );
    Ok(())
}
