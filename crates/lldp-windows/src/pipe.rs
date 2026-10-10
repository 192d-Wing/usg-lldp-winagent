//! Named pipe IPC server with an explicit security descriptor and
//! per-request caller identity.
//!
//! Read-class operations are available to the configured read group;
//! mutating operations additionally require that the client's token holds
//! the Administrators group enabled (that is, an elevated administrator).
//! The check uses `ImpersonateNamedPipeClient` on the current thread after
//! the first message has been read, as the API requires, and reverts
//! immediately.
//!
//! Resource limits for untrusted local clients: at most [`MAX_CLIENTS`]
//! connections at a time (further connections are closed at once), each
//! request at most `MAX_REQUEST_LEN` bytes, and a connection that sends
//! nothing for [`IDLE_TIMEOUT`] is closed.

use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;
use std::sync::Arc;
use std::time::Duration;

use lldp_ipc::{Caller, Handler, MAX_REQUEST_LEN, dispatch, read_message_limited, write_message};
use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use tokio::sync::Semaphore;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, PSECURITY_DESCRIPTOR, PSID, RevertToSelf,
    SECURITY_ATTRIBUTES, TOKEN_QUERY, WinBuiltinAdministratorsSid,
};
use windows::Win32::System::Pipes::ImpersonateNamedPipeClient;
use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};
use windows::core::PCWSTR;

use crate::util::to_wide;

/// Pipe server errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipeError(pub String);

impl std::fmt::Display for PipeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "named pipe: {}", self.0)
    }
}

impl std::error::Error for PipeError {}

/// Most clients served at the same time. The CLI and the PowerShell module
/// open one connection per command.
pub const MAX_CLIENTS: usize = 32;

/// A connected client that sends no request for this long is disconnected.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Access the read group gets on the pipe: `FILE_GENERIC_READ` plus
/// `FILE_WRITE_DATA`, `FILE_WRITE_ATTRIBUTES`, and `FILE_WRITE_EA`. That is
/// `GENERIC_WRITE` without `FILE_APPEND_DATA`, which on a named pipe is
/// `FILE_CREATE_PIPE_INSTANCE`: with it, any member of the read group could
/// create instances of the pipe and answer other clients in place of the
/// service.
const READ_GROUP_ACCESS: u32 = 0x0012_019B;

/// Builds the SDDL for the pipe: full control for SYSTEM and
/// Administrators, read and write (but not instance creation) for
/// `read_group` (a SID string or a well-known SDDL alias such as `AU`).
pub fn sddl(read_group: &str) -> String {
    let g = if read_group.is_empty() {
        "AU"
    } else {
        read_group
    };
    format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x{READ_GROUP_ACCESS:x};;;{g})")
}

/// A security descriptor allocated by the system.
struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

// SAFETY: the descriptor is immutable after creation and only read by the
// pipe creation call; freeing happens once in Drop.
#[allow(unsafe_code)]
unsafe impl Send for SecurityDescriptor {}
#[allow(unsafe_code)]
unsafe impl Sync for SecurityDescriptor {}

impl SecurityDescriptor {
    #[allow(unsafe_code)]
    fn from_sddl(sddl: &str) -> Result<Self, PipeError> {
        let w = to_wide(sddl);
        let mut sd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `w` is NUL-terminated; `sd` receives a LocalAlloc'd
        // descriptor freed in Drop.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(w.as_ptr()),
                SDDL_REVISION_1,
                &raw mut sd,
                None,
            )
        }
        .map_err(|e| PipeError(format!("invalid SDDL '{sddl}': {e}")))?;
        Ok(Self(sd))
    }
}

impl Drop for SecurityDescriptor {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: the descriptor was allocated with LocalAlloc by the system.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.0.0)));
        }
    }
}

/// Creates one server pipe instance.
#[allow(unsafe_code)]
fn create_instance(
    name: &str,
    sd: &SecurityDescriptor,
    first: bool,
) -> Result<NamedPipeServer, PipeError> {
    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
        lpSecurityDescriptor: sd.0.0,
        bInheritHandle: false.into(),
    };
    // SAFETY: `attrs` is a valid SECURITY_ATTRIBUTES for the duration of
    // the call and the descriptor it points to outlives it.
    unsafe {
        ServerOptions::new()
            .pipe_mode(PipeMode::Byte)
            .reject_remote_clients(true)
            .first_pipe_instance(first)
            .create_with_security_attributes_raw(name, (&raw mut attrs).cast::<c_void>())
    }
    .map_err(|e| PipeError(format!("create {name}: {e}")))
}

/// Determines whether the connected client is an elevated administrator.
/// Must be called after at least one message has been read from the pipe.
#[allow(unsafe_code)]
fn client_is_admin(pipe: &NamedPipeServer) -> bool {
    let handle = HANDLE(pipe.as_raw_handle());
    // SAFETY: `handle` is the live pipe handle; every impersonation path
    // below reverts before returning.
    unsafe {
        if ImpersonateNamedPipeClient(handle).is_err() {
            return false;
        }
        let mut token = HANDLE::default();
        let opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &raw mut token).is_ok();
        let _ = RevertToSelf();
        if !opened {
            return false;
        }
        let mut sid_buf = [0u8; 68];
        let mut sid_len = u32::try_from(sid_buf.len()).unwrap_or(0);
        let sid = PSID(sid_buf.as_mut_ptr().cast());
        let is_admin = CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            None,
            Some(sid),
            &raw mut sid_len,
        )
        .is_ok()
            && {
                let mut member = windows::core::BOOL(0);
                CheckTokenMembership(Some(token), sid, &raw mut member).is_ok() && member.as_bool()
            };
        let _ = CloseHandle(token);
        is_admin
    }
}

/// Serves one connected client until it disconnects, sends an unreadable
/// request, or stays idle for [`IDLE_TIMEOUT`].
async fn serve_client(mut pipe: NamedPipeServer, handler: Arc<dyn Handler>) {
    let mut caller: Option<Caller> = None;
    loop {
        let read = tokio::time::timeout(
            IDLE_TIMEOUT,
            read_message_limited(&mut pipe, MAX_REQUEST_LEN),
        )
        .await;
        let raw = match read {
            Ok(Ok(Some(r))) => r,
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::InvalidData => {
                let resp = lldp_ipc::Response::err(lldp_ipc::IpcError::new(
                    lldp_ipc::ErrorCode::BadRequest,
                    e.to_string(),
                ));
                let _ = write_message(&mut pipe, &serde_json_bytes(&resp)).await;
                break;
            }
            Ok(Ok(None) | Err(_)) | Err(_) => break,
        };
        let c = *caller.get_or_insert_with(|| Caller {
            is_admin: client_is_admin(&pipe),
        });
        let resp = dispatch(handler.as_ref(), &raw, c).await;
        if write_message(&mut pipe, &serde_json_bytes(&resp))
            .await
            .is_err()
        {
            break;
        }
    }
    let _ = pipe.disconnect();
}

fn serde_json_bytes(resp: &lldp_ipc::Response) -> Vec<u8> {
    serde_json::to_vec(resp).unwrap_or_default()
}

/// Runs the pipe server until `shutdown` resolves.
pub async fn serve(
    name: &str,
    read_group: &str,
    handler: Arc<dyn Handler>,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), PipeError> {
    let sd = SecurityDescriptor::from_sddl(&sddl(read_group))?;
    let mut server = create_instance(name, &sd, true)?;
    let slots = Arc::new(Semaphore::new(MAX_CLIENTS));
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => return Ok(()),
            r = server.connect() => {
                if let Err(e) = r {
                    return Err(PipeError(format!("connect: {e}")));
                }
                let next = create_instance(name, &sd, false)?;
                let connected = std::mem::replace(&mut server, next);
                // Over the limit, the client is disconnected without a
                // response; dropping the instance does that.
                if let Ok(permit) = Arc::clone(&slots).try_acquire_owned() {
                    let handler = Arc::clone(&handler);
                    tokio::spawn(async move {
                        serve_client(connected, handler).await;
                        drop(permit);
                    });
                }
            }
        }
    }
}

/// `SECURITY_IDENTIFICATION`: the server may learn who the client is but
/// cannot act as the client. Tokio sets this by default; it is spelled out
/// here because the CLI connects by name, and a pipe of that name created
/// by another process must not obtain an impersonation-level token.
const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;

/// Connects as a client (used by the CLI).
pub async fn connect(
    name: &str,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use tokio::net::windows::named_pipe::ClientOptions;
    const ERROR_PIPE_BUSY: i32 = 231;
    for _ in 0..20 {
        match ClientOptions::new()
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(name)
        {
            Ok(c) => return Ok(c),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "pipe busy",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn sddl_shape() {
        assert_eq!(
            super::sddl(""),
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;AU)"
        );
        assert_eq!(
            super::sddl("S-1-5-32-545"),
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;S-1-5-32-545)"
        );
    }

    #[test]
    fn read_group_cannot_create_pipe_instances() {
        const FILE_CREATE_PIPE_INSTANCE: u32 = 0x0004;
        const FILE_READ_DATA: u32 = 0x0001;
        const FILE_WRITE_DATA: u32 = 0x0002;
        const SYNCHRONIZE: u32 = 0x0010_0000;
        let m = super::READ_GROUP_ACCESS;
        assert_eq!(m & FILE_CREATE_PIPE_INSTANCE, 0);
        assert_eq!(
            m & (FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE),
            FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE
        );
        // No generic bits: they would expand to the full generic mapping.
        assert_eq!(m & 0xF000_0000, 0);
    }

    #[test]
    fn sddl_parses() {
        assert!(super::SecurityDescriptor::from_sddl(&super::sddl("")).is_ok());
    }
}
