//! The connection I/O layer. The h2 driver talks to the transport only through
//! [`Wire`], so the driver code is transport-agnostic (buffered stream in tests and
//! plaintext h2c; a rustls stream once TLS-terminated upstream).

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) enum Wire<IO> {
    Buffered(IO),
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Wire<IO> {
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let Self::Buffered(io) = self;
        io.read_exact(buf).await.map(|_| ())
    }

    pub async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        let Self::Buffered(io) = self;
        io.write_all(buf).await
    }

    pub async fn shutdown(&mut self) -> io::Result<()> {
        let Self::Buffered(io) = self;
        io.shutdown().await
    }
}
