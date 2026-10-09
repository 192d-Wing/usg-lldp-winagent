//! Length-prefixed message framing.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest message accepted or sent, in bytes.
pub const MAX_MESSAGE_LEN: usize = 1024 * 1024;

/// Reads one message. Returns `Ok(None)` on a clean EOF before any length
/// byte, `InvalidData` if the length exceeds [`MAX_MESSAGE_LEN`].
pub async fn read_message<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > MAX_MESSAGE_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("message length {n} out of range"),
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
