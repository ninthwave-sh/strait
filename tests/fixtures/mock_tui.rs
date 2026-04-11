//! Test-only interactive TUI fixture for PTY-backed integration coverage.
//!
//! Contract:
//! - On startup, emit a `boot` JSON line with TTY flags and terminal size.
//! - Immediately after startup, emit a `draw` JSON line with `reason: "start"`.
//! - Emit a `draw` JSON line with `reason: "resize"` on each `SIGWINCH`.
//! - Echo every input line as an `input` JSON line.
//! - Exit with code 0 after emitting `{"event":"exit","code":0}` for `exit`.
//!
//! The line-oriented JSON format keeps the fixture deterministic and easy for
//! PTY-backed tests to parse without depending on any real agent harness.

use anyhow::Context;
use serde::Serialize;
use signal_hook::consts::signal::SIGWINCH;
use signal_hook::iterator::Signals;
use std::io::{self, BufRead, IsTerminal, Write};
use std::sync::mpsc;
use std::thread;
use terminal_size::{terminal_size_of, Height, Width};

#[derive(Debug, Serialize, PartialEq, Eq)]
struct BootEvent {
    event: &'static str,
    stdin_tty: bool,
    stdout_tty: bool,
    cols: u16,
    rows: u16,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct DrawEvent {
    event: &'static str,
    seq: u64,
    reason: &'static str,
    cols: u16,
    rows: u16,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct InputEvent<'a> {
    event: &'static str,
    line: &'a str,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct ExitEvent {
    event: &'static str,
    code: i32,
}

enum Command {
    Input(String),
    Resize,
    Eof,
}

fn boot_event(stdin_tty: bool, stdout_tty: bool, cols: u16, rows: u16) -> BootEvent {
    BootEvent {
        event: "boot",
        stdin_tty,
        stdout_tty,
        cols,
        rows,
    }
}

fn draw_event(seq: u64, reason: &'static str, cols: u16, rows: u16) -> DrawEvent {
    DrawEvent {
        event: "draw",
        seq,
        reason,
        cols,
        rows,
    }
}

fn input_event(line: &str) -> InputEvent<'_> {
    InputEvent {
        event: "input",
        line,
    }
}

fn exit_event(code: i32) -> ExitEvent {
    ExitEvent {
        event: "exit",
        code,
    }
}

fn should_exit(line: &str) -> bool {
    line == "exit"
}

fn terminal_size() -> (u16, u16) {
    terminal_size_of(io::stdout())
        .or_else(|| terminal_size_of(io::stdin()))
        .map(|(Width(cols), Height(rows))| (cols, rows))
        .unwrap_or((0, 0))
}

fn emit<T: Serialize>(event: &T) -> anyhow::Result<()> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, event).context("failed to serialize mock TUI event")?;
    writeln!(stdout).context("failed to write mock TUI event line")?;
    stdout.flush().context("failed to flush mock TUI event")
}

fn spawn_stdin_thread(tx: mpsc::Sender<Command>) {
    thread::spawn(move || {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            match line {
                Ok(line) => {
                    if tx.send(Command::Input(line)).is_err() {
                        return;
                    }
                }
                Err(_) => break,
            }
        }

        let _ = tx.send(Command::Eof);
    });
}

#[cfg(unix)]
fn spawn_resize_thread(tx: mpsc::Sender<Command>) -> anyhow::Result<()> {
    let mut signals = Signals::new([SIGWINCH]).context("failed to register SIGWINCH handler")?;
    thread::spawn(move || {
        for _ in signals.forever() {
            if tx.send(Command::Resize).is_err() {
                return;
            }
        }
    });
    Ok(())
}

#[cfg(not(unix))]
fn spawn_resize_thread(_tx: mpsc::Sender<Command>) -> anyhow::Result<()> {
    Ok(())
}

fn run() -> anyhow::Result<i32> {
    let (tx, rx) = mpsc::channel();
    spawn_stdin_thread(tx.clone());
    spawn_resize_thread(tx)?;

    let stdin_tty = io::stdin().is_terminal();
    let stdout_tty = io::stdout().is_terminal();
    let (cols, rows) = terminal_size();

    emit(&boot_event(stdin_tty, stdout_tty, cols, rows))?;

    let mut seq = 1;
    emit(&draw_event(seq, "start", cols, rows))?;

    while let Ok(command) = rx.recv() {
        match command {
            Command::Input(line) => {
                if should_exit(&line) {
                    emit(&exit_event(0))?;
                    return Ok(0);
                }

                emit(&input_event(&line))?;
            }
            Command::Resize => {
                seq += 1;
                let (cols, rows) = terminal_size();
                emit(&draw_event(seq, "resize", cols, rows))?;
            }
            Command::Eof => {
                emit(&exit_event(0))?;
                return Ok(0);
            }
        }
    }

    Ok(0)
}

fn main() -> anyhow::Result<()> {
    std::process::exit(run()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn boot_event_serializes_as_documented() {
        let encoded = serde_json::to_value(boot_event(true, true, 80, 24)).unwrap();
        assert_eq!(
            encoded,
            json!({
                "event": "boot",
                "stdin_tty": true,
                "stdout_tty": true,
                "cols": 80,
                "rows": 24,
            })
        );
    }

    #[test]
    fn draw_event_serializes_as_documented() {
        let encoded = serde_json::to_value(draw_event(2, "resize", 100, 40)).unwrap();
        assert_eq!(
            encoded,
            json!({
                "event": "draw",
                "seq": 2,
                "reason": "resize",
                "cols": 100,
                "rows": 40,
            })
        );
    }

    #[test]
    fn exit_command_is_line_exact() {
        assert!(should_exit("exit"));
        assert!(!should_exit("exit now"));
        assert!(!should_exit(" EXIT "));
    }
}
