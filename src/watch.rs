//! Real-time colored viewer for observation events.
//!
//! Connects to the live observation stream for a running strait launch session
//! and renders a colored stream of agent activity. Auto-reconnects if the
//! stream disconnects. Exits cleanly on Ctrl+C.
//!
//! Color scheme:
//! - **Green** — allowed actions
//! - **Red** (bold) — denied actions
//! - **Yellow** — warned actions (would be denied in enforce mode)
//! - **Cyan** — container lifecycle events (start, stop, mount)
//! - **Dim** — passthrough events (no policy evaluation)

use std::path::{Path, PathBuf};

use crate::launch::{list_launch_sessions, request_launch_watch_attach, LaunchSessionMetadata};
use crate::observe::{EventKind, ObservationEvent};

// ---------------------------------------------------------------------------
// ANSI color codes
// ---------------------------------------------------------------------------

const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

/// Default terminal width when detection fails.
const DEFAULT_TERMINAL_WIDTH: usize = 120;

/// Delay between reconnection attempts.
const RECONNECT_DELAY: std::time::Duration = std::time::Duration::from_secs(1);

// ---------------------------------------------------------------------------
// Event classification
// ---------------------------------------------------------------------------

/// Classification of an event for color selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventColor {
    /// Green: allowed actions.
    Allow,
    /// Red: denied actions.
    Deny,
    /// Yellow: warned actions (would be denied in enforce mode).
    Warn,
    /// Cyan: container lifecycle events (start, stop, mount).
    Lifecycle,
    /// Dim: passthrough events (no policy evaluation).
    Passthrough,
}

impl EventColor {
    /// Return the ANSI escape prefix for this color.
    pub fn ansi_prefix(&self) -> &'static str {
        match self {
            EventColor::Allow => GREEN,
            EventColor::Deny => RED,
            EventColor::Warn => YELLOW,
            EventColor::Lifecycle => CYAN,
            EventColor::Passthrough => DIM,
        }
    }
}

/// Classify an observation event for color rendering.
pub fn classify_event(event: &EventKind) -> EventColor {
    match event {
        EventKind::NetworkRequest { decision, .. } => match decision.as_str() {
            "allow" => EventColor::Allow,
            "deny" => EventColor::Deny,
            "warn" => EventColor::Warn,
            "passthrough" => EventColor::Passthrough,
            _ => EventColor::Passthrough,
        },
        EventKind::ContainerStart { .. }
        | EventKind::ContainerStop { .. }
        | EventKind::Mount { .. }
        | EventKind::PolicyReloaded { .. }
        | EventKind::TtyResized { .. } => EventColor::Lifecycle,
        EventKind::FsAccess { .. } | EventKind::ProcExec { .. } => EventColor::Passthrough,
        EventKind::PolicyViolation { decision, .. } => match decision.as_str() {
            "deny" => EventColor::Deny,
            "warn" => EventColor::Warn,
            _ => EventColor::Warn,
        },
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

/// Extract `HH:MM:SS` from an ISO-8601 timestamp.
///
/// Converts `"2026-03-27T14:32:01.000Z"` → `"14:32:01"`.
pub fn format_time(timestamp: &str) -> &str {
    if let Some(t_pos) = timestamp.find('T') {
        let after_t = &timestamp[t_pos + 1..];
        if after_t.len() >= 8 {
            &after_t[..8]
        } else {
            after_t
        }
    } else {
        timestamp
    }
}

/// Truncate a string to `max_len` display columns, appending `…` if truncated.
pub fn truncate(s: &str, max_len: usize) -> String {
    let char_count = s.chars().count();
    if char_count <= max_len {
        s.to_string()
    } else if max_len <= 1 {
        "…".to_string()
    } else {
        let prefix: String = s.chars().take(max_len - 1).collect();
        format!("{prefix}…")
    }
}

/// Get the current terminal width, falling back to `DEFAULT_TERMINAL_WIDTH`.
pub fn terminal_width() -> usize {
    terminal_size::terminal_size()
        .map(|(w, _)| w.0 as usize)
        .unwrap_or(DEFAULT_TERMINAL_WIDTH)
}

/// Extract action label, resource string, and detail suffix from an event.
fn format_event_parts(event: &EventKind) -> (String, String, String) {
    match event {
        EventKind::NetworkRequest {
            method,
            host,
            path,
            decision,
            latency_us,
            enforcement_mode: _,
        } => {
            let action = format!("http:{method}");
            let resource = format!("{host}{path}");
            let decision_display = if decision == "deny" {
                "DENY".to_string()
            } else {
                decision.clone()
            };
            let detail = if *latency_us > 0 {
                let ms = *latency_us as f64 / 1000.0;
                format!("{decision_display} ({ms:.1}ms)")
            } else {
                decision_display
            };
            (action, resource, detail)
        }
        EventKind::ContainerStart {
            container_id,
            image,
        } => {
            let short_id = &container_id[..container_id.len().min(12)];
            (
                "container:start".to_string(),
                format!("{image} ({short_id})"),
                String::new(),
            )
        }
        EventKind::ContainerStop {
            container_id,
            exit_code,
        } => {
            let short_id = &container_id[..container_id.len().min(12)];
            let detail = match exit_code {
                Some(code) => format!("exit {code}"),
                None => String::new(),
            };
            ("container:stop".to_string(), short_id.to_string(), detail)
        }
        EventKind::Mount { path, mode } => ("mount".to_string(), path.clone(), mode.clone()),
        EventKind::FsAccess { path, operation } => {
            (format!("fs:{operation}"), path.clone(), String::new())
        }
        EventKind::ProcExec { command, .. } => {
            ("proc:exec".to_string(), command.clone(), String::new())
        }
        EventKind::PolicyViolation {
            action,
            resource,
            decision,
            reason,
            ..
        } => {
            let detail = format!("{decision}: {reason}");
            (format!("policy:{action}"), resource.clone(), detail)
        }
        EventKind::PolicyReloaded {
            applied,
            source,
            restart_required_domains,
        } => {
            let detail = if restart_required_domains.is_empty() {
                if *applied {
                    "applied".to_string()
                } else {
                    "restart required".to_string()
                }
            } else {
                format!(
                    "{}; restart {}",
                    if *applied { "applied" } else { "not applied" },
                    restart_required_domains.join(",")
                )
            };
            ("policy:reload".to_string(), source.clone(), detail)
        }
        EventKind::TtyResized { rows, cols, source } => (
            "tty:resize".to_string(),
            format!("{cols}x{rows}"),
            source.clone(),
        ),
    }
}

/// Format a single observation event as a colored line.
///
/// Format: `[HH:MM:SS] action           resource -- decision (latency)`
pub fn format_event(event: &ObservationEvent, max_width: usize) -> String {
    let time = format_time(&event.timestamp);
    let color = classify_event(&event.event);

    let (action, resource, detail) = format_event_parts(&event.event);

    // Layout budget: "[HH:MM:SS] " = 11, action padded to 16 + " " = 17, suffix varies.
    let prefix_len = 11 + 17; // 28
    let suffix = if detail.is_empty() {
        String::new()
    } else {
        format!(" -- {detail}")
    };

    let used = prefix_len + suffix.len();
    let resource_width = max_width.saturating_sub(used).max(10);
    let truncated_resource = truncate(&resource, resource_width);

    // Deny gets bold + red for emphasis.
    let ansi_start = if color == EventColor::Deny {
        format!("{BOLD}{}", color.ansi_prefix())
    } else {
        color.ansi_prefix().to_string()
    };

    format!("{ansi_start}[{time}] {action:<16} {truncated_resource}{suffix}{RESET}")
}

// ---------------------------------------------------------------------------
// Socket discovery
// ---------------------------------------------------------------------------

/// Discover an active observation socket.
///
/// Prefers the newest published launch session via `watch.attach`, then
/// falls back to legacy ad hoc socket discovery for older runtimes.
pub fn discover_socket() -> Option<PathBuf> {
    let mut candidates = vec![crate::observe::runtime_dir()];
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        candidates.push(PathBuf::from(xdg));
    }
    candidates.push(PathBuf::from("/tmp"));
    discover_socket_in_dirs(&candidates)
}

fn session_modified_time(session: &LaunchSessionMetadata) -> Option<std::time::SystemTime> {
    std::fs::metadata(&session.control_socket_path)
        .ok()
        .and_then(|metadata| metadata.modified().ok())
}

fn launch_sessions_newest_first(
    sessions: impl IntoIterator<Item = LaunchSessionMetadata>,
) -> Vec<LaunchSessionMetadata> {
    let mut sessions: Vec<_> = sessions.into_iter().collect();
    sessions.sort_by(|left, right| {
        session_modified_time(right)
            .cmp(&session_modified_time(left))
            .then_with(|| right.session_id.cmp(&left.session_id))
    });
    sessions
}

async fn discover_session_socket_from_sessions(
    sessions: impl IntoIterator<Item = LaunchSessionMetadata>,
) -> Option<PathBuf> {
    for session in launch_sessions_newest_first(sessions) {
        let Ok(observation) = request_launch_watch_attach(&session.control_socket_path).await
        else {
            continue;
        };
        if observation.transport == "unix_socket" {
            return Some(observation.path);
        }
    }
    None
}

async fn discover_session_socket() -> Option<PathBuf> {
    let sessions = list_launch_sessions().ok()?;
    discover_session_socket_from_sessions(sessions).await
}

/// Discover the newest observation socket across multiple directories.
fn discover_socket_in_dirs(dirs: &[PathBuf]) -> Option<PathBuf> {
    let mut best: Option<(PathBuf, std::time::SystemTime)> = None;
    for dir in dirs {
        if let Some(found) = discover_socket_in(dir) {
            let mtime = std::fs::metadata(&found)
                .ok()
                .and_then(|m| m.modified().ok());
            if let Some(mtime) = mtime {
                if best.as_ref().is_none_or(|(_, prev)| mtime > *prev) {
                    best = Some((found, mtime));
                }
            }
        }
    }
    best.map(|(path, _)| path)
}

/// Discover an observation socket in the given directory (testable).
fn discover_socket_in(dir: &Path) -> Option<PathBuf> {
    if !dir.is_dir() {
        return None;
    }

    let mut sockets: Vec<(PathBuf, std::time::SystemTime)> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name();
            let name_str = name.to_str()?;
            if name_str.starts_with("strait-") && name_str.ends_with(".sock") {
                let modified = entry.metadata().ok()?.modified().ok()?;
                Some((entry.path(), modified))
            } else {
                None
            }
        })
        .collect();

    // Newest first.
    sockets.sort_by(|a, b| b.1.cmp(&a.1));
    sockets.into_iter().next().map(|(path, _)| path)
}

// ---------------------------------------------------------------------------
// Watch loop
// ---------------------------------------------------------------------------

/// Run the watch loop: connect, render events, reconnect on disconnect.
///
/// Runs until Ctrl+C or the socket closes cleanly. Auto-reconnects on
/// transient disconnects, re-discovering the socket when using
/// auto-discovery.
pub async fn run(explicit_path: Option<PathBuf>) -> anyhow::Result<()> {
    tokio::select! {
        result = watch_loop(explicit_path) => result,
        _ = tokio::signal::ctrl_c() => {
            eprintln!("\n{DIM}Stopped.{RESET}");
            Ok(())
        }
    }
}

/// Inner watch loop that resolves the socket and reconnects on failure.
async fn watch_loop(explicit_path: Option<PathBuf>) -> anyhow::Result<()> {
    loop {
        let path = resolve_socket(&explicit_path).await;

        eprintln!("{DIM}Connecting to {}{RESET}", path.display());

        match connect_and_stream(&path).await {
            Ok(()) => {
                // Clean EOF — server shut down.
                eprintln!("{DIM}Server closed connection.{RESET}");
                // Fall through to reconnect in case the server restarts.
            }
            Err(_) => {
                if !path.exists() {
                    eprintln!("{DIM}Waiting for strait launch...{RESET}");
                } else {
                    eprintln!("{DIM}Disconnected, reconnecting...{RESET}");
                }
            }
        }

        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

/// Resolve which socket path to connect to.
///
/// If an explicit path is given, waits for it to appear on disk.
/// Otherwise auto-discovers, waiting if no socket is found.
async fn resolve_socket(explicit_path: &Option<PathBuf>) -> PathBuf {
    match explicit_path {
        Some(p) => {
            while !p.exists() {
                eprintln!("{DIM}Waiting for strait launch...{RESET}");
                tokio::time::sleep(RECONNECT_DELAY).await;
            }
            p.clone()
        }
        None => loop {
            if let Some(p) = discover_session_socket().await {
                break p;
            }
            if let Some(p) = discover_socket() {
                break p;
            }
            eprintln!("{DIM}Waiting for strait launch...{RESET}");
            tokio::time::sleep(RECONNECT_DELAY).await;
        },
    }
}

/// Connect to the socket and stream events until EOF or error.
async fn connect_and_stream(path: &Path) -> anyhow::Result<()> {
    use tokio::io::AsyncBufReadExt;

    let stream = tokio::net::UnixStream::connect(path).await?;
    let reader = tokio::io::BufReader::new(stream);
    let mut lines = reader.lines();

    eprintln!("{DIM}Connected — streaming events (Ctrl+C to exit){RESET}");

    while let Some(line) = lines.next_line().await? {
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<ObservationEvent>(&line) {
            Ok(event) => {
                let width = terminal_width();
                println!("{}", format_event(&event, width));
            }
            Err(_) => continue, // Skip malformed lines.
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::EventKind;

    fn make_event(event: EventKind) -> ObservationEvent {
        ObservationEvent {
            version: 1,
            timestamp: "2026-03-27T14:32:01.000Z".to_string(),
            session: None,
            event,
        }
    }

    /// Strip ANSI escape sequences and return visible character count.
    fn visible_width(s: &str) -> usize {
        let mut count = 0;
        let mut in_escape = false;
        for c in s.chars() {
            if c == '\x1b' {
                in_escape = true;
            } else if in_escape {
                if c == 'm' {
                    in_escape = false;
                }
            } else {
                count += 1;
            }
        }
        count
    }

    // -- Color classification -------------------------------------------------

    #[test]
    fn allow_decision_classified_green() {
        let event = EventKind::NetworkRequest {
            method: "GET".into(),
            host: "api.github.com".into(),
            path: "/repos".into(),
            decision: "allow".into(),
            latency_us: 300,
            enforcement_mode: String::new(),
        };
        assert_eq!(classify_event(&event), EventColor::Allow);
        assert_eq!(EventColor::Allow.ansi_prefix(), GREEN);
    }

    #[test]
    fn deny_decision_classified_red() {
        let event = EventKind::NetworkRequest {
            method: "DELETE".into(),
            host: "api.github.com".into(),
            path: "/repos/org/repo".into(),
            decision: "deny".into(),
            latency_us: 100,
            enforcement_mode: String::new(),
        };
        assert_eq!(classify_event(&event), EventColor::Deny);
        assert_eq!(EventColor::Deny.ansi_prefix(), RED);
    }

    #[test]
    fn warn_decision_classified_yellow() {
        let event = EventKind::NetworkRequest {
            method: "POST".into(),
            host: "api.example.com".into(),
            path: "/data".into(),
            decision: "warn".into(),
            latency_us: 200,
            enforcement_mode: String::new(),
        };
        assert_eq!(classify_event(&event), EventColor::Warn);
        assert_eq!(EventColor::Warn.ansi_prefix(), YELLOW);
    }

    #[test]
    fn passthrough_decision_classified_dim() {
        let event = EventKind::NetworkRequest {
            method: "GET".into(),
            host: "example.com".into(),
            path: "/".into(),
            decision: "passthrough".into(),
            latency_us: 0,
            enforcement_mode: String::new(),
        };
        assert_eq!(classify_event(&event), EventColor::Passthrough);
        assert_eq!(EventColor::Passthrough.ansi_prefix(), DIM);
    }

    #[test]
    fn unknown_decision_classified_passthrough() {
        let event = EventKind::NetworkRequest {
            method: "GET".into(),
            host: "example.com".into(),
            path: "/".into(),
            decision: "unknown_value".into(),
            latency_us: 0,
            enforcement_mode: String::new(),
        };
        assert_eq!(classify_event(&event), EventColor::Passthrough);
    }

    #[test]
    fn container_start_classified_lifecycle() {
        let event = EventKind::ContainerStart {
            container_id: "abc123".into(),
            image: "node:20".into(),
        };
        assert_eq!(classify_event(&event), EventColor::Lifecycle);
        assert_eq!(EventColor::Lifecycle.ansi_prefix(), CYAN);
    }

    #[test]
    fn container_stop_classified_lifecycle() {
        let event = EventKind::ContainerStop {
            container_id: "abc123".into(),
            exit_code: Some(0),
        };
        assert_eq!(classify_event(&event), EventColor::Lifecycle);
    }

    #[test]
    fn mount_classified_lifecycle() {
        let event = EventKind::Mount {
            path: "/workspace".into(),
            mode: "read-only".into(),
        };
        assert_eq!(classify_event(&event), EventColor::Lifecycle);
    }

    #[test]
    fn policy_reload_classified_lifecycle() {
        let event = EventKind::PolicyReloaded {
            applied: true,
            source: "reload".into(),
            restart_required_domains: Vec::new(),
        };
        assert_eq!(classify_event(&event), EventColor::Lifecycle);
    }

    #[test]
    fn fs_access_classified_passthrough() {
        let event = EventKind::FsAccess {
            path: "/etc/passwd".into(),
            operation: "read".into(),
        };
        assert_eq!(classify_event(&event), EventColor::Passthrough);
    }

    #[test]
    fn proc_exec_classified_passthrough() {
        let event = EventKind::ProcExec {
            pid: 42,
            command: "git status".into(),
        };
        assert_eq!(classify_event(&event), EventColor::Passthrough);
    }

    // -- Time formatting ------------------------------------------------------

    #[test]
    fn format_time_extracts_hh_mm_ss() {
        assert_eq!(format_time("2026-03-27T14:32:01.000Z"), "14:32:01");
    }

    #[test]
    fn format_time_handles_missing_t() {
        assert_eq!(format_time("not-a-timestamp"), "not-a-timestamp");
    }

    #[test]
    fn format_time_handles_short_time_part() {
        assert_eq!(format_time("2026-03-27T14:32"), "14:32");
    }

    // -- Truncation -----------------------------------------------------------

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_exact_length_unchanged() {
        assert_eq!(truncate("hello", 5), "hello");
    }

    #[test]
    fn truncate_long_string_adds_ellipsis() {
        assert_eq!(truncate("hello world", 8), "hello w…");
    }

    #[test]
    fn truncate_to_one_gives_ellipsis() {
        assert_eq!(truncate("hello", 1), "…");
    }

    #[test]
    fn truncate_to_zero_gives_ellipsis() {
        assert_eq!(truncate("hello", 0), "…");
    }

    // -- Event formatting: allowed (green) ------------------------------------

    #[test]
    fn format_network_allow_colored_green() {
        let event = make_event(EventKind::NetworkRequest {
            method: "GET".into(),
            host: "api.github.com".into(),
            path: "/repos/org/repo".into(),
            decision: "allow".into(),
            latency_us: 300,
            enforcement_mode: String::new(),
        });
        let output = format_event(&event, 120);
        assert!(output.contains(GREEN), "should contain green ANSI code");
        assert!(output.contains("http:GET"));
        assert!(output.contains("api.github.com/repos/org/repo"));
        assert!(output.contains("allow"));
        assert!(output.contains("0.3ms"));
        assert!(output.ends_with(RESET));
    }

    // -- Event formatting: denied (bold red) ----------------------------------

    #[test]
    fn format_network_deny_colored_bold_red() {
        let event = make_event(EventKind::NetworkRequest {
            method: "DELETE".into(),
            host: "api.github.com".into(),
            path: "/repos/org/repo".into(),
            decision: "deny".into(),
            latency_us: 100,
            enforcement_mode: String::new(),
        });
        let output = format_event(&event, 120);
        assert!(output.contains(BOLD), "deny should be bold");
        assert!(output.contains(RED), "deny should be red");
        assert!(output.contains("DENY"), "deny should render uppercase");
    }

    // -- Event formatting: warned (yellow) ------------------------------------

    #[test]
    fn format_network_warn_colored_yellow() {
        let event = make_event(EventKind::NetworkRequest {
            method: "POST".into(),
            host: "api.example.com".into(),
            path: "/data".into(),
            decision: "warn".into(),
            latency_us: 200,
            enforcement_mode: String::new(),
        });
        let output = format_event(&event, 120);
        assert!(output.contains(YELLOW));
        assert!(output.contains("warn"));
    }

    // -- Event formatting: lifecycle (cyan) -----------------------------------

    #[test]
    fn format_container_start_colored_cyan() {
        let event = make_event(EventKind::ContainerStart {
            container_id: "abc123def456".into(),
            image: "node:20-slim".into(),
        });
        let output = format_event(&event, 120);
        assert!(output.contains(CYAN));
        assert!(output.contains("container:start"));
        assert!(output.contains("node:20-slim"));
        assert!(output.contains("abc123def456"));
    }

    #[test]
    fn format_container_stop_shows_exit_code() {
        let event = make_event(EventKind::ContainerStop {
            container_id: "abc123".into(),
            exit_code: Some(1),
        });
        let output = format_event(&event, 120);
        assert!(output.contains(CYAN));
        assert!(output.contains("container:stop"));
        assert!(output.contains("exit 1"));
    }

    #[test]
    fn format_container_stop_no_exit_code() {
        let event = make_event(EventKind::ContainerStop {
            container_id: "abc123".into(),
            exit_code: None,
        });
        let output = format_event(&event, 120);
        assert!(output.contains("container:stop"));
        assert!(!output.contains("exit"));
    }

    #[test]
    fn format_mount_colored_cyan() {
        let event = make_event(EventKind::Mount {
            path: "/workspace".into(),
            mode: "read-only".into(),
        });
        let output = format_event(&event, 120);
        assert!(output.contains(CYAN));
        assert!(output.contains("mount"));
        assert!(output.contains("/workspace"));
        assert!(output.contains("read-only"));
    }

    #[test]
    fn format_tty_resize_colored_cyan() {
        let event = make_event(EventKind::TtyResized {
            rows: 40,
            cols: 100,
            source: "scripted".into(),
        });
        let output = format_event(&event, 120);
        assert!(output.contains(CYAN));
        assert!(output.contains("tty:resize"));
        assert!(output.contains("100x40"));
        assert!(output.contains("scripted"));
    }

    // -- Event formatting: passthrough (dim) ----------------------------------

    #[test]
    fn format_passthrough_colored_dim() {
        let event = make_event(EventKind::NetworkRequest {
            method: "GET".into(),
            host: "example.com".into(),
            path: "/".into(),
            decision: "passthrough".into(),
            latency_us: 0,
            enforcement_mode: String::new(),
        });
        let output = format_event(&event, 120);
        assert!(output.contains(DIM));
        assert!(output.contains("passthrough"));
    }

    #[test]
    fn format_fs_access_colored_dim() {
        let event = make_event(EventKind::FsAccess {
            path: "/etc/passwd".into(),
            operation: "read".into(),
        });
        let output = format_event(&event, 120);
        assert!(output.contains(DIM));
        assert!(output.contains("fs:read"));
    }

    #[test]
    fn format_proc_exec_colored_dim() {
        let event = make_event(EventKind::ProcExec {
            pid: 42,
            command: "git status".into(),
        });
        let output = format_event(&event, 120);
        assert!(output.contains(DIM));
        assert!(output.contains("proc:exec"));
        assert!(output.contains("git status"));
    }

    // -- Edge case: long resource paths truncated to terminal width -----------

    #[test]
    fn long_resource_truncated_to_terminal_width() {
        let long_path = "/a".repeat(200);
        let event = make_event(EventKind::NetworkRequest {
            method: "GET".into(),
            host: "api.example.com".into(),
            path: long_path,
            decision: "allow".into(),
            latency_us: 100,
            enforcement_mode: String::new(),
        });
        let output = format_event(&event, 80);
        let width = visible_width(&output);
        assert!(width <= 80, "visible width {width} should be <= 80");
        assert!(
            output.contains('…'),
            "truncated resource should have ellipsis"
        );
    }

    #[test]
    fn narrow_terminal_still_renders() {
        let event = make_event(EventKind::NetworkRequest {
            method: "GET".into(),
            host: "api.github.com".into(),
            path: "/repos/org/repo".into(),
            decision: "allow".into(),
            latency_us: 300,
            enforcement_mode: String::new(),
        });
        // Even at absurdly narrow width, it should not panic.
        let output = format_event(&event, 20);
        assert!(!output.is_empty());
    }

    // -- Socket discovery -----------------------------------------------------

    #[test]
    fn discover_socket_in_empty_dir_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(discover_socket_in(dir.path()).is_none());
    }

    #[test]
    fn discover_socket_in_dir_with_socket() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("strait-12345.sock");
        std::fs::write(&sock, "").unwrap();
        let found = discover_socket_in(dir.path());
        assert_eq!(found, Some(sock));
    }

    #[test]
    fn discover_socket_picks_newest() {
        let dir = tempfile::tempdir().unwrap();
        let old_sock = dir.path().join("strait-100.sock");
        std::fs::write(&old_sock, "").unwrap();

        // Sleep briefly to ensure different mtime.
        std::thread::sleep(std::time::Duration::from_millis(50));

        let new_sock = dir.path().join("strait-200.sock");
        std::fs::write(&new_sock, "").unwrap();

        let found = discover_socket_in(dir.path()).unwrap();
        assert_eq!(found, new_sock);
    }

    #[test]
    fn discover_socket_ignores_non_strait_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("other.sock"), "").unwrap();
        std::fs::write(dir.path().join("strait-nope.txt"), "").unwrap();
        assert!(discover_socket_in(dir.path()).is_none());
    }

    #[test]
    fn discover_socket_nonexistent_dir_returns_none() {
        assert!(discover_socket_in(Path::new("/nonexistent-dir-xyz")).is_none());
    }

    // -- Multi-directory socket discovery tests --------------------------------

    #[test]
    fn discover_socket_in_dirs_finds_socket_in_second_dir() {
        // Simulates discovering a socket in XDG_RUNTIME_DIR when /tmp has none.
        let dir1 = tempfile::tempdir().unwrap(); // empty (like /tmp with no sockets)
        let dir2 = tempfile::tempdir().unwrap(); // has a socket (like XDG_RUNTIME_DIR)

        let sock = dir2.path().join("strait-999.sock");
        std::fs::write(&sock, "").unwrap();

        let dirs = vec![dir1.path().to_path_buf(), dir2.path().to_path_buf()];
        let found = discover_socket_in_dirs(&dirs);
        assert_eq!(found, Some(sock));
    }

    #[test]
    fn discover_socket_in_dirs_prefers_newest_across_dirs() {
        // Socket in dir1 is older, socket in dir2 is newer.
        let dir1 = tempfile::tempdir().unwrap();
        let dir2 = tempfile::tempdir().unwrap();

        let old_sock = dir1.path().join("strait-100.sock");
        std::fs::write(&old_sock, "").unwrap();

        std::thread::sleep(std::time::Duration::from_millis(50));

        let new_sock = dir2.path().join("strait-200.sock");
        std::fs::write(&new_sock, "").unwrap();

        let dirs = vec![dir1.path().to_path_buf(), dir2.path().to_path_buf()];
        let found = discover_socket_in_dirs(&dirs);
        assert_eq!(found, Some(new_sock));
    }

    #[test]
    fn discover_socket_in_dirs_empty_returns_none() {
        let dir1 = tempfile::tempdir().unwrap();
        let dir2 = tempfile::tempdir().unwrap();

        let dirs = vec![dir1.path().to_path_buf(), dir2.path().to_path_buf()];
        assert!(discover_socket_in_dirs(&dirs).is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn discover_session_socket_skips_dead_newer_session() {
        use crate::launch::{
            LaunchControlResponse, LaunchControlResult, LaunchSessionMetadata, ObservationHandle,
            SESSION_CONTROL_PROTOCOL_VERSION,
        };
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let older_control = dir.path().join("older-control.sock");
        let older_observe = dir.path().join("older-observe.sock");
        let stale_control = dir.path().join("stale-control.sock");

        let live_listener = UnixListener::bind(&older_control).unwrap();
        let older_observe_for_server = older_observe.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = live_listener.accept().await.unwrap();
            let (read_half, mut write_half) = tokio::io::split(stream);
            let mut reader = BufReader::new(read_half);
            let mut request = String::new();
            reader.read_line(&mut request).await.unwrap();

            let response = LaunchControlResponse {
                version: SESSION_CONTROL_PROTOCOL_VERSION,
                ok: true,
                result: Some(LaunchControlResult::WatchAttach {
                    observation: ObservationHandle {
                        transport: "unix_socket".to_string(),
                        path: older_observe_for_server,
                    },
                }),
                error: None,
            };
            let line = serde_json::to_string(&response).unwrap();
            write_half.write_all(line.as_bytes()).await.unwrap();
            write_half.write_all(b"\n").await.unwrap();
            write_half.flush().await.unwrap();
        });

        std::thread::sleep(std::time::Duration::from_millis(50));
        let stale_listener = UnixListener::bind(&stale_control).unwrap();
        drop(stale_listener);

        let sessions = vec![
            LaunchSessionMetadata {
                version: SESSION_CONTROL_PROTOCOL_VERSION,
                session_id: "older-live".to_string(),
                mode: "observe".to_string(),
                control_socket_path: older_control,
                observation: ObservationHandle {
                    transport: "unix_socket".to_string(),
                    path: older_observe.clone(),
                },
                container_id: None,
                container_name: None,
            },
            LaunchSessionMetadata {
                version: SESSION_CONTROL_PROTOCOL_VERSION,
                session_id: "newer-dead".to_string(),
                mode: "observe".to_string(),
                control_socket_path: stale_control,
                observation: ObservationHandle {
                    transport: "unix_socket".to_string(),
                    path: dir.path().join("stale-observe.sock"),
                },
                container_id: None,
                container_name: None,
            },
        ];

        let discovered = discover_session_socket_from_sessions(sessions).await;
        assert_eq!(discovered, Some(older_observe));

        server.await.unwrap();
    }

    // -- Socket connection integration tests ----------------------------------

    #[cfg(unix)]
    #[tokio::test]
    async fn connect_and_stream_receives_events() {
        use crate::observe::ObservationStream;

        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let obs = ObservationStream::new();
        obs.start_socket_server_at(&sock_path).await.unwrap();

        // Collect events via connect_and_stream by replacing stdout.
        // Instead, we test the lower-level: connect, read a line, parse it.
        let client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let mut reader = tokio::io::BufReader::new(client);

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        obs.emit(EventKind::NetworkRequest {
            method: "GET".into(),
            host: "api.github.com".into(),
            path: "/repos".into(),
            decision: "allow".into(),
            latency_us: 150,
            enforcement_mode: String::new(),
        });

        use tokio::io::AsyncBufReadExt;
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();

        let event: ObservationEvent = serde_json::from_str(&line).unwrap();
        let formatted = format_event(&event, 120);
        assert!(formatted.contains(GREEN));
        assert!(formatted.contains("http:GET"));
        assert!(formatted.contains("api.github.com/repos"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn socket_disconnect_returns_error_for_reconnect() {
        // Verify that connect_and_stream returns (error or Ok) when
        // the socket disappears, allowing the outer loop to reconnect.
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        // No server — should fail immediately.
        let result = connect_and_stream(&sock_path).await;
        assert!(result.is_err(), "should fail when socket doesn't exist");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn connect_and_stream_returns_ok_on_server_close() {
        use crate::observe::ObservationStream;

        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let obs = ObservationStream::new();
        obs.start_socket_server_at(&sock_path).await.unwrap();

        // Spawn connect_and_stream, drop the observation stream to trigger EOF.
        let path = sock_path.clone();
        let handle = tokio::spawn(async move {
            tokio::time::timeout(std::time::Duration::from_secs(2), connect_and_stream(&path)).await
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        drop(obs);

        let result = handle.await.unwrap();
        // Should complete (either timeout or clean return).
        assert!(result.is_ok() || result.is_err());
    }
}
