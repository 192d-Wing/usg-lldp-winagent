//! Pipe client.

use lldp_ipc::Request;

/// Sends one request and decodes the result.
#[cfg(windows)]
pub async fn call<T: for<'de> serde::Deserialize<'de>>(
    pipe: &str,
    request: Request,
) -> Result<T, String> {
    let mut stream = lldp_windows::pipe::connect(pipe)
        .await
        .map_err(|e| format!("cannot connect to {pipe}: {e}. Is the WinLLDP service running?"))?;
    let resp = lldp_ipc::call(&mut stream, request)
        .await
        .map_err(|e| format!("IPC failure: {e}"))?;
    resp.into_result::<T>().map_err(|e| e.to_string())
}

/// Not available off Windows.
#[cfg(not(windows))]
#[allow(clippy::unused_async)]
pub async fn call<T: for<'de> serde::Deserialize<'de>>(
    pipe: &str,
    _request: Request,
) -> Result<T, String> {
    Err(format!("named pipe {pipe} is only available on Windows"))
}
