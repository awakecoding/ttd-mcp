use serde::Serialize;

#[derive(Debug, Clone)]
pub struct ProcessServerOptions {
    pub transport: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessServerResult {
    pub transport: String,
    pub exited: bool,
}

#[derive(Debug, Clone)]
pub struct LiveLaunchOptions {
    pub command_line: String,
    pub initial_break_timeout_ms: u32,
    pub end: LiveLaunchEnd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveLaunchEnd {
    Detach,
    Terminate,
}

#[derive(Debug, Clone, Serialize)]
pub struct LiveLaunchResult {
    pub command_line: String,
    pub initial_break_timeout_ms: u32,
    pub wait_succeeded: bool,
    pub execution_status: Option<u32>,
    pub execution_status_name: Option<String>,
    pub end: LiveLaunchEnd,
}

pub fn start_process_server(options: ProcessServerOptions) -> anyhow::Result<ProcessServerResult> {
    start_process_server_impl(options)
}

pub fn live_launch_initial_break(options: LiveLaunchOptions) -> anyhow::Result<LiveLaunchResult> {
    live_launch_initial_break_impl(options)
}

#[cfg(windows)]
fn start_process_server_impl(options: ProcessServerOptions) -> anyhow::Result<ProcessServerResult> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Diagnostics::Debug::Extensions::{
        DebugCreate, IDebugClient5, DEBUG_CLASS_USER_WINDOWS,
    };
    use windows::Win32::System::Threading::INFINITE;

    let mut transport = options.transport.encode_utf16().collect::<Vec<_>>();
    transport.push(0);

    let client: IDebugClient5 = unsafe { DebugCreate()? };
    unsafe {
        client.StartProcessServerWide(
            DEBUG_CLASS_USER_WINDOWS,
            PCWSTR(transport.as_ptr()),
            None,
        )?;
        client.WaitForProcessServerEnd(INFINITE)?;
    }

    Ok(ProcessServerResult {
        transport: options.transport,
        exited: true,
    })
}

#[cfg(windows)]
fn live_launch_initial_break_impl(options: LiveLaunchOptions) -> anyhow::Result<LiveLaunchResult> {
    use windows::core::{Interface, PCWSTR};
    use windows::Win32::System::Diagnostics::Debug::Extensions::{
        DebugCreate, IDebugClient5, IDebugControl, DEBUG_PROCESS_ONLY_THIS_PROCESS,
        DEBUG_STATUS_BREAK, DEBUG_STATUS_GO, DEBUG_STATUS_GO_HANDLED, DEBUG_STATUS_GO_NOT_HANDLED,
        DEBUG_STATUS_NO_DEBUGGEE, DEBUG_STATUS_STEP_INTO, DEBUG_STATUS_TIMEOUT, DEBUG_WAIT_DEFAULT,
    };

    let mut command_line = options.command_line.encode_utf16().collect::<Vec<_>>();
    command_line.push(0);

    let client: IDebugClient5 = unsafe { DebugCreate()? };
    let control: IDebugControl = client.cast()?;
    unsafe {
        client.CreateProcessWide(
            0,
            PCWSTR(command_line.as_ptr()),
            DEBUG_PROCESS_ONLY_THIS_PROCESS,
        )?;
    }

    let wait_result =
        unsafe { control.WaitForEvent(DEBUG_WAIT_DEFAULT, options.initial_break_timeout_ms) };
    let wait_succeeded = wait_result.is_ok();
    let execution_status = unsafe { control.GetExecutionStatus().ok() };
    match options.end {
        LiveLaunchEnd::Detach => unsafe {
            client.DetachProcesses()?;
        },
        LiveLaunchEnd::Terminate => unsafe {
            client.TerminateProcesses()?;
        },
    }

    Ok(LiveLaunchResult {
        command_line: options.command_line,
        initial_break_timeout_ms: options.initial_break_timeout_ms,
        wait_succeeded,
        execution_status,
        execution_status_name: execution_status.map(|status| {
            match status {
                DEBUG_STATUS_GO => "go",
                DEBUG_STATUS_GO_HANDLED => "go_handled",
                DEBUG_STATUS_GO_NOT_HANDLED => "go_not_handled",
                DEBUG_STATUS_STEP_INTO => "step_into",
                DEBUG_STATUS_BREAK => "break",
                DEBUG_STATUS_NO_DEBUGGEE => "no_debuggee",
                DEBUG_STATUS_TIMEOUT => "timeout",
                _ => "unknown",
            }
            .to_string()
        }),
        end: options.end,
    })
}

#[cfg(not(windows))]
fn start_process_server_impl(options: ProcessServerOptions) -> anyhow::Result<ProcessServerResult> {
    let _ = options;
    anyhow::bail!("DbgEng process servers are only supported on Windows")
}

#[cfg(not(windows))]
fn live_launch_initial_break_impl(options: LiveLaunchOptions) -> anyhow::Result<LiveLaunchResult> {
    let _ = options;
    anyhow::bail!("DbgEng live launch is only supported on Windows")
}
