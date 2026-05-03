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

pub fn start_process_server(options: ProcessServerOptions) -> anyhow::Result<ProcessServerResult> {
    start_process_server_impl(options)
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

#[cfg(not(windows))]
fn start_process_server_impl(options: ProcessServerOptions) -> anyhow::Result<ProcessServerResult> {
    let _ = options;
    anyhow::bail!("DbgEng process servers are only supported on Windows")
}
