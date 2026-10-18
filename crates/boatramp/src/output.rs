//! Consistent command output.
//!
//! Every `boatramp` subcommand returns a *typed result value* and this module renders it once, at
//! the dispatch boundary, as either human-readable text (the default) or machine-readable JSON
//! (`--output-format json`, env `BOATRAMP_OUTPUT_FORMAT=json`). The point is that a command's output
//! no longer depends on how it was invoked: the same typed value renders the same way for a terminal,
//! a captured pipe, or a programmatic caller that wants JSON — instead of each command hand-printing
//! to stdout with `println!`, which only ever produces one ad-hoc text shape.
//!
//! Division of labor:
//! - A command's **result** (what it computed / changed) is the `Rendered` value it returns here.
//! - Transient **progress / status** during a long operation stays on the `tracing` sink (stderr,
//!   and JSON-structured under `BOATRAMP_LOG_FORMAT=json`) — it is not a result and does not pass
//!   through `emit`.
//! - **Errors** propagate as the command's `Result::Err`; `emit` only renders the `Ok` value.

use std::io::{self, Write};

use clap::ValueEnum;

/// How a command's result value is rendered to stdout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum OutputMode {
    /// Human-readable text (the default) — what the command historically printed.
    #[default]
    Human,
    /// Pretty JSON: the `serde` serialization of the result value, for scripts and other callers.
    Json,
}

/// A typed command result. JSON rendering is free via the `serde::Serialize` bound, so an
/// implementor only supplies the human view (the text the command used to `println!`).
///
/// Keep the two faithful to each other: the JSON object should carry the same facts the human text
/// shows, so switching `--output-format` never changes *what* a command reports, only its shape.
pub trait Rendered: serde::Serialize {
    /// Write the human-readable rendering to `w`. Called only in [`OutputMode::Human`]; include any
    /// trailing newline the output needs.
    fn render_human(&self, w: &mut dyn Write) -> io::Result<()>;
}

/// Render `value` to stdout in `mode`: the human text, or pretty JSON followed by a newline.
pub fn emit<T: Rendered + ?Sized>(mode: OutputMode, value: &T) -> io::Result<()> {
    let stdout = io::stdout();
    let mut w = stdout.lock();
    match mode {
        OutputMode::Human => value.render_human(&mut w)?,
        OutputMode::Json => {
            serde_json::to_writer_pretty(&mut w, value).map_err(io::Error::other)?;
            w.write_all(b"\n")?;
        }
    }
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Serialize)]
    struct Sample {
        name: String,
        count: u32,
    }
    impl Rendered for Sample {
        fn render_human(&self, w: &mut dyn Write) -> io::Result<()> {
            writeln!(w, "{} x{}", self.name, self.count)
        }
    }

    fn render<T: Rendered>(mode: OutputMode, v: &T) -> String {
        // Exercise the same rendering `emit` performs, into a buffer (so the test does not depend on
        // the process stdout). Mirrors `emit`'s two arms.
        let mut buf: Vec<u8> = Vec::new();
        match mode {
            OutputMode::Human => v.render_human(&mut buf).unwrap(),
            OutputMode::Json => {
                serde_json::to_writer_pretty(&mut buf, v).unwrap();
                buf.push(b'\n');
            }
        }
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn human_and_json_carry_the_same_facts() {
        let s = Sample {
            name: "api".into(),
            count: 3,
        };
        assert_eq!(render(OutputMode::Human, &s), "api x3\n");
        let json = render(OutputMode::Json, &s);
        assert!(json.contains("\"name\": \"api\""));
        assert!(json.contains("\"count\": 3"));
        assert!(json.ends_with('\n'));
    }
}
