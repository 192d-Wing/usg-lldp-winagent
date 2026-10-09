//! WinLLDP local IPC contract, version 1.
//!
//! Wire format: each message is a 4-byte big-endian length followed by one
//! UTF-8 JSON object, at most [`MAX_MESSAGE_LEN`] bytes. Requests carry
//! `{"v":1,"op":"<Name>","params":{...}}`; responses carry
//! `{"v":1,"ok":true,"result":...}` or
//! `{"v":1,"ok":false,"error":{"code":"...","message":"..."}}`.
//!
//! Transport (the named pipe, its ACL, and caller identity) lives in the
//! platform crate; this crate is transport agnostic.

#![forbid(unsafe_code)]

pub mod framing;
pub mod view;

use core::fmt;
use std::future::Future;
use std::pin::Pin;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use framing::{MAX_MESSAGE_LEN, read_message, write_message};
pub use view::*;

/// Protocol version this build speaks.
pub const PROTOCOL_VERSION: u32 = 1;

/// Default pipe name.
pub const PIPE_NAME: &str = r"\\.\pipe\WinLLDP";

/// Operations. Serialized as the `op` and `params` members.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", content = "params", deny_unknown_fields)]
pub enum Request {
    /// Service health and version.
    GetServiceStatus,
    /// Every interface the agent knows, managed or not.
    ListInterfaces,
    /// One interface by alias or GUID.
    GetInterfaceStatus {
        /// Alias or GUID.
        interface: String,
    },
    /// Neighbors, optionally filtered to one interface.
    ListNeighbors {
        /// Alias or GUID.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        interface: Option<String>,
    },
    /// One neighbor.
    GetNeighborDetails {
        /// Alias or GUID.
        interface: String,
        /// Chassis ID as displayed.
        chassis_id: String,
        /// Port ID as displayed.
        port_id: String,
    },
    /// What this system advertises, optionally for one interface.
    GetLocalAdvertisement {
        /// Alias or GUID.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        interface: Option<String>,
    },
    /// Counters, optionally for one interface.
    GetStatistics {
        /// Alias or GUID.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        interface: Option<String>,
    },
    /// Change an interface's administrative mode at runtime. Administrators only.
    SetInterfaceMode {
        /// Alias or GUID.
        interface: String,
        /// `disabled`, `rx_only`, `tx_only`, or `rx_tx`.
        mode: InterfaceModeView,
    },
    /// Re-read the configuration file and policy. Administrators only.
    ReloadConfiguration,
}

impl Request {
    /// Whether the operation changes state and therefore requires an
    /// administrative caller.
    pub const fn requires_admin(&self) -> bool {
        matches!(
            self,
            Self::SetInterfaceMode { .. } | Self::ReloadConfiguration
        )
    }

    /// Operation name as it appears on the wire.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::GetServiceStatus => "GetServiceStatus",
            Self::ListInterfaces => "ListInterfaces",
            Self::GetInterfaceStatus { .. } => "GetInterfaceStatus",
            Self::ListNeighbors { .. } => "ListNeighbors",
            Self::GetNeighborDetails { .. } => "GetNeighborDetails",
            Self::GetLocalAdvertisement { .. } => "GetLocalAdvertisement",
            Self::GetStatistics { .. } => "GetStatistics",
            Self::SetInterfaceMode { .. } => "SetInterfaceMode",
            Self::ReloadConfiguration => "ReloadConfiguration",
        }
    }
}

/// A request envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelope {
    /// Protocol version.
    pub v: u32,
    /// The operation.
    #[serde(flatten)]
    pub request: Request,
}

impl RequestEnvelope {
    /// Wraps a request with the current version.
    pub const fn new(request: Request) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            request,
        }
    }
}

/// Machine-readable error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// The request's `v` is not supported.
    UnsupportedVersion,
    /// The request could not be parsed.
    BadRequest,
    /// The caller is not an administrator.
    Forbidden,
    /// The named interface does not exist.
    InterfaceNotFound,
    /// The named neighbor does not exist.
    NeighborNotFound,
    /// The configuration is invalid; message has details.
    InvalidConfiguration,
    /// Something else went wrong.
    Internal,
}

/// An error response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcError {
    /// Code.
    pub code: ErrorCode,
    /// Human-readable message.
    pub message: String,
}

impl IpcError {
    /// Builds an error.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for IpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for IpcError {}

/// A response envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    /// Protocol version.
    pub v: u32,
    /// Success flag.
    pub ok: bool,
    /// Result on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error on failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<IpcError>,
}

impl Response {
    /// A success response.
    pub fn ok<T: Serialize>(result: &T) -> Self {
        match serde_json::to_value(result) {
            Ok(v) => Self {
                v: PROTOCOL_VERSION,
                ok: true,
                result: Some(v),
                error: None,
            },
            Err(e) => Self::err(IpcError::new(
                ErrorCode::Internal,
                format!("serialize: {e}"),
            )),
        }
    }

    /// An error response.
    pub fn err(error: IpcError) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            ok: false,
            result: None,
            error: Some(error),
        }
    }

    /// Converts into a `Result`, deserializing the result on success.
    pub fn into_result<T: for<'de> Deserialize<'de>>(self) -> Result<T, IpcError> {
        if self.ok {
            let v = self.result.unwrap_or(Value::Null);
            serde_json::from_value(v)
                .map_err(|e| IpcError::new(ErrorCode::Internal, format!("decode result: {e}")))
        } else {
            Err(self
                .error
                .unwrap_or_else(|| IpcError::new(ErrorCode::Internal, "no error body")))
        }
    }
}

/// Who is calling, as established by the transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Caller {
    /// The caller is a member of the local Administrators group.
    pub is_admin: bool,
}

/// Boxed future returned by handlers.
pub type HandlerFuture<'a> = Pin<Box<dyn Future<Output = Result<Value, IpcError>> + Send + 'a>>;

/// Implements the operations. The service provides this.
pub trait Handler: Send + Sync {
    /// Handles one request. Authorization has already been enforced.
    fn handle(&self, request: Request, caller: Caller) -> HandlerFuture<'_>;
}

/// Decodes a request, enforces version and authorization, and runs it.
pub async fn dispatch(handler: &dyn Handler, raw: &[u8], caller: Caller) -> Response {
    let env: RequestEnvelope = match serde_json::from_slice(raw) {
        Ok(e) => e,
        Err(e) => return Response::err(IpcError::new(ErrorCode::BadRequest, e.to_string())),
    };
    if env.v != PROTOCOL_VERSION {
        return Response::err(IpcError::new(
            ErrorCode::UnsupportedVersion,
            format!(
                "protocol version {} is not supported; this service speaks version {PROTOCOL_VERSION}",
                env.v
            ),
        ));
    }
    if env.request.requires_admin() && !caller.is_admin {
        return Response::err(IpcError::new(
            ErrorCode::Forbidden,
            format!("{} requires administrative rights", env.request.name()),
        ));
    }
    match handler.handle(env.request, caller).await {
        Ok(v) => Response {
            v: PROTOCOL_VERSION,
            ok: true,
            result: Some(v),
            error: None,
        },
        Err(e) => Response::err(e),
    }
}

/// Serves one connection: reads requests until EOF, answering each.
pub async fn serve_connection<S>(
    mut stream: S,
    handler: &dyn Handler,
    caller: Caller,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        let raw = match read_message(&mut stream).await {
            Ok(Some(r)) => r,
            Ok(None) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                let resp = Response::err(IpcError::new(ErrorCode::BadRequest, e.to_string()));
                let bytes = serde_json::to_vec(&resp).unwrap_or_default();
                write_message(&mut stream, &bytes).await?;
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        let resp = dispatch(handler, &raw, caller).await;
        let bytes = serde_json::to_vec(&resp).unwrap_or_default();
        write_message(&mut stream, &bytes).await?;
    }
}

/// Sends one request on an open stream and reads the response.
pub async fn call<S>(stream: &mut S, request: Request) -> std::io::Result<Response>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let bytes = serde_json::to_vec(&RequestEnvelope::new(request))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    write_message(stream, &bytes).await?;
    let raw = read_message(stream).await?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "connection closed before response",
        )
    })?;
    serde_json::from_slice(&raw)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}
