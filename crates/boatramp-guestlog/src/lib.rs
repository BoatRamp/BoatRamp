//! The shared **guest-log sink** for boatramp's compute backends.
//!
//! A launched workload's stdout/stderr — whether it is the native container
//! backend's re-exec'd self-jail worker ([`boatramp-container`]) or a container on
//! a remote Docker daemon ([`boatramp-docker`]) — is drained here line-by-line,
//! mirrored to `tracing` (`target: "boatramp::guest"`, tagged `container` +
//! `stream`), and appended to a per-container log file
//! (`<data_dir>/compute/logs/<id>.log`). One sink, every backend: the two backends
//! differ only in where the stdout/stderr byte streams come from (two OS pipes vs.
//! one demuxed Docker attach stream), and both feed the SAME [`pump`] →
//! [`write_lines_rotating`] pipeline.
//!
//! A container's log output is **untrusted, high-volume input**, so the sink is
//! bounded on every axis:
//! - **Per-line byte cap** ([`MAX_LINE_BYTES`]): a hostile container that writes
//!   gigabytes with no newline cannot grow an in-memory line buffer without bound —
//!   the line is truncated (with a marker) and the rest discarded to the next `\n`.
//! - **Channel back-pressure** ([`CHANNEL_CAP`]): the single writer is the bounded
//!   consumer, so a flood back-pressures the pump, then the pipe, then the producer,
//!   rather than queuing unbounded lines in memory.
//! - **File size cap + rotation** ([`DEFAULT_FILE_CAP_BYTES`]): the per-container
//!   file is bounded on disk — at the cap it rotates to a single `<id>.log.1`
//!   backup and starts fresh, so disk use is capped at ~2× the cap.
//! - **Injection-safe framing**: each drained line is sanitized (control / ANSI /
//!   carriage-return bytes neutralized) and written as exactly one physical
//!   `<stream>: <line>\n`, so a crafted line cannot forge tracing fields, inject a
//!   fake log frame, or corrupt the file format.
//!
//! Pure over its IO args (readers + a file path), so it is unit-tested with
//! in-memory pipes + a temp file — no real jail or daemon required.

use std::path::{Path, PathBuf};

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

/// Max bytes buffered for a single logical (newline-delimited) line before it is
/// truncated. Bounds the pump's per-line memory against a no-newline flood.
pub const MAX_LINE_BYTES: usize = 16 * 1024;

/// Bounded capacity of the pump → writer channel. The writer (a disk file) is the
/// slow consumer, so a bounded channel turns a flood into back-pressure instead of
/// an unbounded in-memory queue. Kept modest so the worst-case transient memory under
/// an all-max-length-line flood (`CHANNEL_CAP` × [`MAX_LINE_BYTES`] ≈ 4 MiB/container)
/// stays small; in practice the per-line file flush keeps the queue near-empty.
pub const CHANNEL_CAP: usize = 256;

/// Default per-container log-file size cap. At the cap the file rotates to a single
/// `<id>.log.1` backup and a fresh `<id>.log` starts, bounding disk use at ~2× this.
pub const DEFAULT_FILE_CAP_BYTES: u64 = 8 * 1024 * 1024;

/// Appended to a line that hit [`MAX_LINE_BYTES`] before a newline. Our own text
/// (never attacker-controlled), so it can carry a `\n`-free marker safely.
const TRUNCATION_MARKER: &str = "\u{2026}[boatramp: line truncated]";

/// One captured guest line, tagged with the stream it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestLine {
    /// `"stdout"` or `"stderr"`.
    pub stream: &'static str,
    /// The sanitized line text (trailing newline stripped; control bytes neutralized).
    pub text: String,
}

/// The per-container guest-log file path under `logs_dir`.
#[must_use]
pub fn log_path(logs_dir: &Path, id: &str) -> PathBuf {
    logs_dir.join(format!("{id}.log"))
}

/// Neutralize a line for structured logging + file framing.
///
/// Strips every control character (C0 + DEL + C1) except horizontal tab, replacing
/// each with the Unicode replacement character. The newline that delimits lines is
/// already removed by the pump, so this additionally defuses a `\r` overwrite, an
/// ANSI/VT escape (`ESC`), and an embedded `NUL` — none of which can then forge a
/// tracing field, inject a fake log frame, or move the terminal cursor when the log
/// is later `cat`'d. Ordinary UTF-8 text is preserved.
#[must_use]
pub fn sanitize_line(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c == '\t' || !c.is_control() {
                c
            } else {
                '\u{FFFD}'
            }
        })
        .collect()
}

/// Drain `reader` (a guest stdout/stderr stream) line-by-line until EOF, mirroring
/// each line to `tracing` (tagged with `id` + `stream`) and forwarding it to the
/// single-writer `sink`. Returns the number of lines pumped.
///
/// Bounded + injection-safe:
/// - a logical line is capped at [`MAX_LINE_BYTES`]; past the cap it is truncated
///   (with [`TRUNCATION_MARKER`]) and the overflow discarded to the next newline, so
///   a no-newline flood cannot grow the buffer without bound;
/// - the line text is [`sanitize_line`]d before it reaches `tracing` or the sink
///   (a single trailing `\r` is stripped first, so a CRLF line is not left ending in
///   a replacement glyph — matching the old `str::lines()` behavior);
/// - the structured `container` / `stream` fields are passed as their own key-values
///   (never interpolated into the message), so a crafted line cannot forge them.
///
/// **Writer-death behavior (`keep_draining`)** — what happens when the sink (the file
/// writer task) closes while the guest is still producing output:
/// - `true` (the NATIVE, local-process path): the pump keeps draining-and-discarding
///   the reader to EOF, so the guest's stdout/stderr OS pipe stays drained and the
///   guest never hits `EPIPE`/`SIGPIPE` on its next write. Lines still mirror to
///   `tracing` (an independent sink) even once the file is gone. This preserves the
///   core invariant this module exists for: the launcher must never drop the guest's
///   pipe reader while the guest runs.
/// - `false` (the DOCKER, remote path): there is no local guest pipe to protect (the
///   reader is an in-memory pipe fed from the daemon attach stream), so the pump may
///   stop once the sink is gone and let the forwarder wind down.
///
/// Pure over its IO args.
pub async fn pump<R: AsyncBufRead + Unpin>(
    mut reader: R,
    id: &str,
    stream: &'static str,
    sink: mpsc::Sender<GuestLine>,
    keep_draining: bool,
) -> std::io::Result<u64> {
    let mut n = 0u64;
    let mut buf: Vec<u8> = Vec::new();
    // The current logical line already hit the cap: keep discarding its bytes until
    // the next newline (resync) instead of buffering them.
    let mut overflowed = false;
    // The sink is still accepting lines. Once a send fails (writer task gone) this
    // flips false; with `keep_draining` the pump keeps reading (to protect the guest's
    // pipe) but stops sending.
    let mut sink_open = true;

    loop {
        let chunk = reader.fill_buf().await?;
        if chunk.is_empty() {
            // EOF. Flush a final unterminated line, if any (bytes buffered, or an
            // overflow that never saw its closing newline).
            if !buf.is_empty() || overflowed {
                n += 1;
                let dst = sink_open.then_some(&sink);
                let _ = emit(&buf, overflowed, id, stream, dst).await;
            }
            break;
        }

        match chunk.iter().position(|&b| b == b'\n') {
            Some(pos) => {
                append_bounded(&mut buf, &chunk[..pos], &mut overflowed);
                reader.consume(pos + 1);
                n += 1;
                let dst = sink_open.then_some(&sink);
                let sent = emit(&buf, overflowed, id, stream, dst).await;
                if sink_open && !sent {
                    // The writer task is gone.
                    sink_open = false;
                    if !keep_draining {
                        break; // remote path: nothing local to protect — stop.
                    }
                    // local path: fall through and keep draining to EOF.
                }
                buf.clear();
                overflowed = false;
            }
            None => {
                let len = chunk.len();
                append_bounded(&mut buf, chunk, &mut overflowed);
                reader.consume(len);
            }
        }
    }
    Ok(n)
}

/// Append `src` to `buf` but never past [`MAX_LINE_BYTES`]; mark `overflowed` once
/// the cap is reached so the remainder of the logical line is dropped (not buffered).
fn append_bounded(buf: &mut Vec<u8>, src: &[u8], overflowed: &mut bool) {
    if *overflowed {
        return;
    }
    let room = MAX_LINE_BYTES.saturating_sub(buf.len());
    if src.len() > room {
        buf.extend_from_slice(&src[..room]);
        *overflowed = true;
    } else {
        buf.extend_from_slice(src);
    }
}

/// Emit one logical line: always mirror to `tracing`, and — when `sink` is `Some` —
/// forward to the file writer. Returns `false` ONLY when a present sink's `send`
/// failed (writer gone); `None` (already draining) returns `true`. `send().await` is
/// the back-pressure point.
async fn emit(
    raw: &[u8],
    overflowed: bool,
    id: &str,
    stream: &'static str,
    sink: Option<&mpsc::Sender<GuestLine>>,
) -> bool {
    // Strip a single trailing CR so a CRLF line is not left ending in a replacement
    // glyph; an interior `\r` is still neutralized by `sanitize_line`.
    let lossy = String::from_utf8_lossy(raw);
    let trimmed = lossy.strip_suffix('\r').unwrap_or(&lossy);
    let mut text = sanitize_line(trimmed);
    if overflowed {
        text.push_str(TRUNCATION_MARKER);
    }
    tracing::info!(target: "boatramp::guest", container = id, stream, "{text}");
    match sink {
        Some(s) => s.send(GuestLine { stream, text }).await.is_ok(),
        None => true,
    }
}

/// The single ordered writer with a bounded, rotating file.
///
/// Drains `rx` and appends `<stream>: <line>\n` to the file at `path` until all
/// pump senders close. Owning one writer keeps the merged stdout/stderr stream free
/// of interleaved partial lines. When the file would exceed `cap_bytes`, it rotates:
/// the current file is renamed to `<path>.1` (replacing any prior backup) and a
/// fresh file is started — so a flood is bounded on disk at ~2× `cap_bytes` while
/// the most-recent window is always retained.
pub async fn write_lines_rotating(
    path: PathBuf,
    mut rx: mpsc::Receiver<GuestLine>,
    cap_bytes: u64,
) -> std::io::Result<()> {
    let mut file = tokio::fs::File::create(&path).await?;
    let mut written: u64 = 0;

    while let Some(line) = rx.recv().await {
        let framed = frame(&line);
        let len = framed.len() as u64;
        // Rotate before a write that would cross the cap — but never rotate away a
        // still-empty file (a single line larger than the cap, already bounded by
        // MAX_LINE_BYTES, is written whole rather than lost).
        if written > 0 && written.saturating_add(len) > cap_bytes {
            file.flush().await?;
            drop(file);
            rotate(&path).await?;
            file = tokio::fs::File::create(&path).await?;
            written = 0;
        }
        file.write_all(framed.as_bytes()).await?;
        file.flush().await?;
        written = written.saturating_add(len);
    }
    Ok(())
}

/// Run [`write_lines_rotating`] as a spawned task and log a diagnostic if it stops on
/// an IO error (file create / rotate / write — ENOSPC, EISDIR, EMFILE, …) rather than
/// swallowing it. Both backends spawn THIS so a dead writer is never silent; the guest
/// is unaffected (the native pump keeps its stdout/stderr drained — see [`pump`]'s
/// `keep_draining`).
pub async fn run_file_writer(
    path: PathBuf,
    rx: mpsc::Receiver<GuestLine>,
    cap_bytes: u64,
    container: String,
) {
    if let Err(e) = write_lines_rotating(path, rx, cap_bytes).await {
        tracing::warn!(
            target: "boatramp::guest",
            container = %container,
            error = %e,
            "guest-log writer stopped on an IO error; per-container file capture ended \
             (the guest is unaffected and still mirrors to tracing)"
        );
    }
}

/// The one physical line written per logical line: `<stream>: <sanitized-text>\n`.
/// `text` is already sanitized by the pump, so it carries no interior newline — the
/// only `\n` is the framing terminator, keeping one physical line per logical line.
fn frame(line: &GuestLine) -> String {
    format!("{}: {}\n", line.stream, line.text)
}

/// Rotate `<path>` to `<path>.1`, replacing any existing backup. Best-effort on the
/// unlink of a stale backup (a fresh rotation has none); the rename is the load-
/// bearing step.
async fn rotate(path: &Path) -> std::io::Result<()> {
    let backup = backup_path(path);
    let _ = tokio::fs::remove_file(&backup).await;
    tokio::fs::rename(path, &backup).await
}

/// The single-backup path for a log file (`<id>.log` → `<id>.log.1`).
#[must_use]
pub fn backup_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".1");
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex, OnceLock};
    use tokio::io::BufReader;

    /// A `MakeWriter` over a shared buffer so a `tracing` fmt subscriber's output can
    /// be asserted in-process.
    #[derive(Clone)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for SharedBuf {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Install ONCE a process-global fmt subscriber over a shared buffer and return
    /// the buffer. A global default (not a thread-local `with_default`) is required:
    /// `set_global_default` rebuilds `tracing`'s callsite-interest cache, so the pump's
    /// `info!` callsite is re-evaluated as interested even when a parallel test hit it
    /// first with no subscriber (the thread-local path leaves that cache "Never" and
    /// the event is dropped — a flaky empty capture).
    static TRACING_CAPTURE: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    fn install_tracing_capture() -> Arc<Mutex<Vec<u8>>> {
        TRACING_CAPTURE
            .get_or_init(|| {
                let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
                let sink = SharedBuf(buf.clone());
                let subscriber = tracing_subscriber::fmt()
                    .with_ansi(false)
                    .with_max_level(tracing::Level::INFO)
                    .with_writer(move || sink.clone())
                    .finish();
                let _ = tracing::subscriber::set_global_default(subscriber);
                buf
            })
            .clone()
    }

    fn read_file(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap()
    }

    #[test]
    fn log_path_is_per_container() {
        assert_eq!(
            log_path(Path::new("/d/logs"), "web-0"),
            PathBuf::from("/d/logs/web-0.log")
        );
        assert_eq!(
            backup_path(&log_path(Path::new("/d/logs"), "web-0")),
            PathBuf::from("/d/logs/web-0.log.1")
        );
    }

    #[test]
    fn sanitize_neutralizes_control_and_ansi_keeps_tab_and_text() {
        // ESC-based ANSI clear + a carriage return + a NUL are all neutralized; a tab
        // and ordinary (incl. non-ASCII) text survive.
        let dirty = "ok\x1b[2Jclear\rboom\x00end\tπ";
        let clean = sanitize_line(dirty);
        assert!(!clean.contains('\x1b'));
        assert!(!clean.contains('\r'));
        assert!(!clean.contains('\x00'));
        assert!(clean.contains('\t'), "tab is preserved");
        assert!(clean.contains('π'), "utf-8 text is preserved");
        assert!(clean.contains("ok") && clean.contains("end"));
    }

    #[tokio::test]
    async fn pump_forwards_lines_and_counts() {
        let input = b"hello\nworld\n".as_slice();
        let (tx, mut rx) = mpsc::channel(8);
        let n = pump(input, "web-0", "stdout", tx, true).await.unwrap();
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
        let input = b"partial".as_slice();
        let (tx, mut rx) = mpsc::channel(8);
        let n = pump(input, "w-0", "stderr", tx, true).await.unwrap();
        assert_eq!(n, 1);
        assert_eq!(rx.recv().await.unwrap().text, "partial");
    }

    #[tokio::test]
    async fn pump_caps_a_no_newline_flood_per_line() {
        // A single logical line far larger than the cap, with no newline, must not
        // buffer unbounded: the emitted line is capped + marked truncated.
        let flood = vec![b'A'; MAX_LINE_BYTES * 4];
        let (tx, mut rx) = mpsc::channel(8);
        let n = pump(flood.as_slice(), "w-0", "stdout", tx, true)
            .await
            .unwrap();
        assert_eq!(n, 1, "the whole flood is ONE (truncated) logical line");
        let line = rx.recv().await.unwrap();
        assert!(
            line.text.len() <= MAX_LINE_BYTES + TRUNCATION_MARKER.len(),
            "line buffer bounded by the cap, got {}",
            line.text.len()
        );
        assert!(line.text.ends_with(TRUNCATION_MARKER), "truncation marked");
    }

    #[tokio::test]
    async fn pump_resyncs_after_truncation_to_next_line() {
        // After an over-long line is truncated, the pump resyncs on the next newline
        // and the following line is delivered whole.
        let mut input = vec![b'A'; MAX_LINE_BYTES * 2];
        input.push(b'\n');
        input.extend_from_slice(b"after\n");
        let (tx, mut rx) = mpsc::channel(8);
        let n = pump(input.as_slice(), "w-0", "stdout", tx, true)
            .await
            .unwrap();
        assert_eq!(n, 2);
        assert!(rx.recv().await.unwrap().text.ends_with(TRUNCATION_MARKER));
        assert_eq!(rx.recv().await.unwrap().text, "after");
    }

    #[tokio::test]
    async fn pump_strips_a_trailing_cr_from_crlf_lines() {
        // A CRLF line yields `hello\r` between the split; the trailing CR is stripped
        // (not turned into U+FFFD), matching the old `str::lines()` behavior. An
        // interior CR is still neutralized.
        let (tx, mut rx) = mpsc::channel(8);
        let n = pump(
            b"hello\r\nmid\rtext\r\n".as_slice(),
            "w-0",
            "stdout",
            tx,
            true,
        )
        .await
        .unwrap();
        assert_eq!(n, 2);
        assert_eq!(
            rx.recv().await.unwrap().text,
            "hello",
            "trailing CR stripped"
        );
        let second = rx.recv().await.unwrap().text;
        assert!(!second.ends_with('\r') && !second.contains('\r'));
        assert!(
            second.starts_with("mid") && second.ends_with("text"),
            "interior CR neutralized, trailing CR stripped: {second:?}"
        );
    }

    /// MEDIUM-1: when the file writer dies mid-run (here: its path is a directory, so
    /// `File::create` fails and `rx` drops), the NATIVE pump (`keep_draining = true`)
    /// must keep draining the guest reader to EOF — if it `break`s instead, it would
    /// drop the guest's stdout pipe reader and the running guest would `EPIPE`. It must
    /// also surface the writer error via a `tracing::warn!`. Mutation-sensitive: with
    /// the old break-on-send-failure behavior the pumps stop early and the counts drop
    /// below the line totals.
    #[tokio::test]
    async fn native_pump_drains_guest_and_warns_when_the_file_writer_dies() {
        let buf = install_tracing_capture();
        let dir = tempfile::tempdir().unwrap();
        // Make the "log file" a DIRECTORY so the writer's `File::create` fails → the
        // writer task returns Err and drops `rx`.
        let bad = log_path(dir.path(), "web-0");
        std::fs::create_dir(&bad).unwrap();

        let (tx, rx) = mpsc::channel(CHANNEL_CAP);
        let writer = tokio::spawn(run_file_writer(
            bad,
            rx,
            DEFAULT_FILE_CAP_BYTES,
            "web-0".into(),
        ));

        // Two guest streams each emit far more lines than the channel can buffer, so
        // the writer's death forces a send failure mid-stream.
        let n_lines: usize = 2000;
        let mk = |tag: &str| {
            let mut v = Vec::new();
            for i in 0..n_lines {
                v.extend_from_slice(format!("{tag}-{i}\n").as_bytes());
            }
            v
        };
        let out = mk("o");
        let err = mk("e");
        let p_out = pump(out.as_slice(), "web-0", "stdout", tx.clone(), true);
        let p_err = pump(err.as_slice(), "web-0", "stderr", tx, true);
        let (a, b) = tokio::join!(p_out, p_err);

        assert_eq!(
            a.unwrap() as usize,
            n_lines,
            "stdout drained to EOF despite the dead writer (guest pipe protected)"
        );
        assert_eq!(
            b.unwrap() as usize,
            n_lines,
            "stderr drained to EOF despite the dead writer"
        );
        writer.await.unwrap();

        let logged = String::from_utf8_lossy(&buf.lock().unwrap()).to_string();
        assert!(
            logged.contains("guest-log writer stopped"),
            "the writer death is logged: {logged}"
        );
    }

    /// The DOCKER/remote counterpart: `keep_draining = false` lets the pump stop once
    /// the sink is gone (no local pipe to protect), so the forwarder can wind down.
    #[tokio::test]
    async fn remote_pump_stops_after_the_sink_closes() {
        let (tx, rx) = mpsc::channel::<GuestLine>(1);
        drop(rx); // sink gone before the first send
        let mut input = Vec::new();
        for i in 0..1000 {
            input.extend_from_slice(format!("l-{i}\n").as_bytes());
        }
        let n = pump(input.as_slice(), "web-0", "stdout", tx, false)
            .await
            .unwrap();
        assert!(
            (n as usize) < 1000,
            "remote pump stops once the sink closes, got {n}"
        );
    }

    #[tokio::test]
    async fn pump_mirrors_each_line_to_tracing_with_its_fields() {
        let buf = install_tracing_capture();
        // A unique marker so the assertion is robust to events other parallel tests
        // emit into the shared global buffer.
        let marker = "MIRROR_MARK_ready_31";
        let line = format!("{marker}\n");
        let (tx, mut rx) = mpsc::channel(8);
        let n = pump(line.as_bytes(), "web-0", "stdout", tx, true)
            .await
            .unwrap();
        assert_eq!(n, 1);
        assert_eq!(rx.recv().await.unwrap().text, marker);

        let logged = String::from_utf8_lossy(&buf.lock().unwrap()).to_string();
        assert!(
            logged.contains("boatramp::guest"),
            "target present: {logged}"
        );
        assert!(
            logged.contains("web-0"),
            "container field present: {logged}"
        );
        assert!(logged.contains("stdout"), "stream field present: {logged}");
        assert!(
            logged.contains(marker),
            "the line text is mirrored: {logged}"
        );
    }

    #[tokio::test]
    async fn writer_merges_both_streams_into_one_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(dir.path(), "w-0");
        let (tx, rx) = mpsc::channel(8);
        tx.send(GuestLine {
            stream: "stdout",
            text: "out-1".into(),
        })
        .await
        .unwrap();
        tx.send(GuestLine {
            stream: "stderr",
            text: "err-1".into(),
        })
        .await
        .unwrap();
        drop(tx);
        write_lines_rotating(path.clone(), rx, DEFAULT_FILE_CAP_BYTES)
            .await
            .unwrap();
        assert_eq!(read_file(&path), "stdout: out-1\nstderr: err-1\n");
    }

    #[tokio::test]
    async fn writer_rotates_at_the_cap_and_keeps_one_backup() {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(dir.path(), "w-0");
        // A tiny cap so a few lines force a rotation. Each framed line is
        // `stdout: L<i>\n` (10 bytes), so cap=25 holds two lines then rotates.
        let (tx, rx) = mpsc::channel(32);
        let writer = tokio::spawn(write_lines_rotating(path.clone(), rx, 25));
        for i in 0..6 {
            tx.send(GuestLine {
                stream: "stdout",
                text: format!("L{i}"),
            })
            .await
            .unwrap();
        }
        drop(tx);
        writer.await.unwrap().unwrap();

        // Live file holds only the most-recent window; a single `.1` backup exists;
        // disk stays bounded at ~2× cap. Older lines rolled into the backup, and
        // `rotate` removes the prior backup before renaming, so there is only ever
        // ONE backup regardless of how many rotations occurred.
        let live = read_file(&path);
        let backup = read_file(&backup_path(&path));
        assert!(live.contains("L5"), "newest line retained in the live file");
        assert!(
            live.len() as u64 <= 25 + "stdout: Lx\n".len() as u64,
            "live file bounded near the cap, got {}",
            live.len()
        );
        assert!(!backup.is_empty(), "a backup exists after rotation");
        assert!(
            !backup.contains("L0") && !backup.contains("L1"),
            "a prior backup is replaced each rotation (only the latest rolled window): {backup}"
        );
    }

    #[tokio::test]
    async fn pump_into_writer_end_to_end() {
        // Two concurrent pumps + the single writer, exactly as a backend wires it.
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(dir.path(), "w-0");
        let (tx, rx) = mpsc::channel(CHANNEL_CAP);
        let writer = tokio::spawn(write_lines_rotating(
            path.clone(),
            rx,
            DEFAULT_FILE_CAP_BYTES,
        ));
        let out = BufReader::new(b"app started\napp ready\n".as_slice());
        let err = BufReader::new(b"a warning\n".as_slice());
        let p1 = pump(out, "w-0", "stdout", tx.clone(), true);
        let p2 = pump(err, "w-0", "stderr", tx, true);
        let (a, b) = tokio::join!(p1, p2);
        assert_eq!(a.unwrap() + b.unwrap(), 3, "3 lines total");
        writer.await.unwrap().unwrap();
        let s = read_file(&path);
        assert!(s.contains("stdout: app started\n"));
        assert!(s.contains("stdout: app ready\n"));
        assert!(s.contains("stderr: a warning\n"));
        assert_eq!(s.lines().count(), 3);
    }
}
