//! The container **guest-log sink**: the re-exec'd worker's
//! stdout/stderr — which become the guest entrypoint's stdout/stderr after
//! `execve` — are drained line-by-line, mirrored to `tracing`, and appended to a
//! per-container log file (`<data_dir>/compute/logs/<id>.log`).
//!
//! This also closes a correctness gap: the launcher MUST keep reading the
//! worker's stdout pipe after the handshake. If it dropped the read end, the
//! guest's first write to stdout past the pipe buffer would `EPIPE`. Draining it
//! here keeps the guest's stdout open for its whole life.
//!
//! Cross-platform + pure over its IO args (a single ordered writer fed by the
//! per-stream pumps over an mpsc channel), so it is unit-tested with in-memory
//! pipes — no real jail required.

use std::path::{Path, PathBuf};

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

/// One captured guest line, tagged with the stream it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestLine {
    /// `"stdout"` or `"stderr"`.
    pub stream: &'static str,
    /// The line text (trailing newline stripped).
    pub text: String,
}

/// The per-container guest-log file path under `logs_dir`.
pub fn log_path(logs_dir: &Path, id: &str) -> PathBuf {
    logs_dir.join(format!("{id}.log"))
}

/// Drain `reader` (a guest stdout/stderr stream) line-by-line until EOF,
/// mirroring each line to `tracing` (tagged with `id` + `stream`) and forwarding
/// it to the single-writer `sink`. Returns the number of lines pumped. A send
/// failure (writer gone) ends the pump cleanly. Pure over its IO args.
pub async fn pump<R: AsyncBufRead + Unpin>(
    reader: R,
    id: &str,
    stream: &'static str,
    sink: mpsc::UnboundedSender<GuestLine>,
) -> std::io::Result<u64> {
    let mut lines = reader.lines();
    let mut n = 0u64;
    while let Some(text) = lines.next_line().await? {
        n += 1;
        tracing::info!(target: "boatramp::guest", container = id, stream, "{text}");
        if sink.send(GuestLine { stream, text }).is_err() {
            break; // writer task gone — stop draining
        }
    }
    Ok(n)
}

/// The single ordered writer: drain `rx` and append `<stream>: <line>\n` to
/// `out` until all pump senders close. Owning one writer keeps the merged
/// stdout/stderr stream free of interleaved partial lines.
pub async fn write_lines<W: AsyncWriteExt + Unpin>(
    mut out: W,
    mut rx: mpsc::UnboundedReceiver<GuestLine>,
) -> std::io::Result<()> {
    while let Some(line) = rx.recv().await {
        out.write_all(format!("{}: {}\n", line.stream, line.text).as_bytes())
            .await?;
        out.flush().await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_path_is_per_container() {
        assert_eq!(
            log_path(Path::new("/d/logs"), "web-0"),
            PathBuf::from("/d/logs/web-0.log")
        );
    }

    #[tokio::test]
    async fn pump_forwards_lines_and_counts() {
        let input = b"hello\nworld\n".as_slice();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let n = pump(input, "web-0", "stdout", tx).await.unwrap();
        assert_eq!(n, 2);
        assert_eq!(
            rx.recv().await.unwrap(),
            GuestLine {
                stream: "stdout",
                text: "hello".into()
            }
        );
        assert_eq!(rx.recv().await.unwrap().text, "world");
        assert!(rx.recv().await.is_none(), "sender dropped → channel closed");
    }

    #[tokio::test]
    async fn pump_handles_unterminated_final_line() {
        // A guest that exits mid-line still yields its partial last line.
        let input = b"partial".as_slice();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let n = pump(input, "w-0", "stderr", tx).await.unwrap();
        assert_eq!(n, 1);
        assert_eq!(rx.recv().await.unwrap().text, "partial");
    }

    #[tokio::test]
    async fn writer_merges_both_streams_into_one_file() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut buf: Vec<u8> = Vec::new();
        // Feed a few lines then close the channel so the writer returns.
        tx.send(GuestLine {
            stream: "stdout",
            text: "out-1".into(),
        })
        .unwrap();
        tx.send(GuestLine {
            stream: "stderr",
            text: "err-1".into(),
        })
        .unwrap();
        drop(tx);
        write_lines(&mut buf, rx).await.unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "stdout: out-1\nstderr: err-1\n"
        );
    }

    #[tokio::test]
    async fn pump_into_writer_end_to_end() {
        // Two concurrent pumps + the single writer, exactly as `launch` wires it.
        let (tx, rx) = mpsc::unbounded_channel();
        let out = b"app started\napp ready\n".as_slice();
        let err = b"a warning\n".as_slice();
        let writer = tokio::spawn(async move {
            let mut sink: Vec<u8> = Vec::new();
            write_lines(&mut sink, rx).await.unwrap();
            sink
        });
        let p1 = pump(out, "w-0", "stdout", tx.clone());
        let p2 = pump(err, "w-0", "stderr", tx);
        let (a, b) = tokio::join!(p1, p2);
        assert_eq!(a.unwrap() + b.unwrap(), 3, "3 lines total");
        let buf = writer.await.unwrap();
        let s = String::from_utf8(buf).unwrap();
        // Ordering between the two pumps isn't fixed, but every line is present
        // and tagged, and no line is torn.
        assert!(s.contains("stdout: app started\n"));
        assert!(s.contains("stdout: app ready\n"));
        assert!(s.contains("stderr: a warning\n"));
        assert_eq!(s.lines().count(), 3);
    }
}
