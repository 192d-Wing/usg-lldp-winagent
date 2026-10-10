//! Length-prefixed message framing.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest message accepted or sent, in bytes. Responses carrying every
/// neighbor's full TLV set can be large; this is the client-side bound.
pub const MAX_MESSAGE_LEN: usize = 8 * 1024 * 1024;

/// Largest request the server accepts, in bytes. Every request fits in a
/// few hundred bytes, so the server never allocates more than this per
/// connection for an untrusted peer.
pub const MAX_REQUEST_LEN: usize = 64 * 1024;

/// Reads one message of at most [`MAX_MESSAGE_LEN`] bytes. Returns
/// `Ok(None)` on a clean EOF before any length byte, `InvalidData` if the
/// length is zero or exceeds the limit.
pub async fn read_message<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Option<Vec<u8>>> {
    read_message_limited(r, MAX_MESSAGE_LEN).await
}

/// Reads one message of at most `max` bytes. The length prefix is checked
/// before any allocation, so a hostile peer cannot make the reader
/// allocate more than `max`.
pub async fn read_message_limited<R: AsyncRead + Unpin>(
    r: &mut R,
    max: usize,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("message length {n} out of range (1 to {max})"),
        ));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

/// Writes one message.
pub async fn write_message<W: AsyncWrite + Unpin>(w: &mut W, msg: &[u8]) -> std::io::Result<()> {
    if msg.is_empty() || msg.len() > MAX_MESSAGE_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("message length {} out of range", msg.len()),
        ));
    }
    let len = u32::try_from(msg.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "too long"))?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(msg).await?;
    w.flush().await
}
