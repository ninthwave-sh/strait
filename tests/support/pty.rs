#![cfg(unix)]

use serde_json::Value;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, ErrorKind};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PtySize {
    pub rows: u16,
    pub cols: u16,
}

pub struct PtySession {
    child: Child,
    master: File,
    pending: String,
    lines: VecDeque<String>,
    reached_eof: bool,
}

impl PtySession {
    pub fn spawn<S: AsRef<std::ffi::OsStr>>(
        program: impl AsRef<Path>,
        args: &[S],
        cwd: &Path,
        size: PtySize,
    ) -> io::Result<Self> {
        let (master, slave) = open_pty(size)?;
        set_nonblocking(&master)?;
        set_cloexec(&master)?;

        let stdin = Stdio::from(dup_file(&slave)?);
        let stdout = Stdio::from(dup_file(&slave)?);
        let stderr = Stdio::from(dup_file(&slave)?);
        let slave_fd = slave.as_raw_fd();

        let mut command = Command::new(program.as_ref());
        command.current_dir(cwd);
        command.args(args.iter().map(AsRef::as_ref));
        command.stdin(stdin);
        command.stdout(stdout);
        command.stderr(stderr);

        unsafe {
            command.pre_exec(move || {
                if libc::setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }

                if libc::ioctl(slave_fd, libc::TIOCSCTTY.into(), 0) == -1 {
                    return Err(io::Error::last_os_error());
                }

                Ok(())
            });
        }

        let child = command.spawn()?;
        drop(slave);

        Ok(Self {
            child,
            master,
            pending: String::new(),
            lines: VecDeque::new(),
            reached_eof: false,
        })
    }

    pub fn write_line(&mut self, line: &str) -> io::Result<()> {
        self.write_all(line.as_bytes())?;
        self.write_all(b"\n")
    }

    pub fn resize(&mut self, size: PtySize) -> io::Result<()> {
        let winsize = libc::winsize {
            ws_row: size.rows,
            ws_col: size.cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };

        let rc = unsafe {
            libc::ioctl(
                self.master.as_raw_fd(),
                libc::TIOCSWINSZ,
                &winsize as *const _,
            )
        };
        if rc == -1 {
            return Err(io::Error::last_os_error());
        }

        let signal_rc = unsafe { libc::kill(self.child.id() as i32, libc::SIGWINCH) };
        if signal_rc == -1 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    pub fn wait_for_event(&mut self, event_name: &str, timeout: Duration) -> io::Result<Value> {
        self.wait_for_json(
            |value| value.get("event").and_then(Value::as_str) == Some(event_name),
            timeout,
        )
    }

    pub fn wait_for_json<F>(&mut self, mut predicate: F, timeout: Duration) -> io::Result<Value>
    where
        F: FnMut(&Value) -> bool,
    {
        let deadline = Instant::now() + timeout;

        loop {
            while let Some(line) = self.lines.pop_front() {
                if let Ok(value) = serde_json::from_str::<Value>(&line) {
                    if predicate(&value) {
                        return Ok(value);
                    }
                }
            }

            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    ErrorKind::TimedOut,
                    "timed out waiting for PTY JSON output",
                ));
            }

            self.read_ready(deadline)?;
        }
    }

    pub fn wait_for_exit(&mut self, timeout: Duration) -> io::Result<ExitStatus> {
        let deadline = Instant::now() + timeout;

        loop {
            if let Some(status) = self.child.try_wait()? {
                return Ok(status);
            }

            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    ErrorKind::TimedOut,
                    "timed out waiting for PTY child exit",
                ));
            }

            self.read_ready(deadline)?;
        }
    }

    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        let mut offset = 0;
        while offset < bytes.len() {
            let written = unsafe {
                libc::write(
                    self.master.as_raw_fd(),
                    bytes[offset..].as_ptr().cast(),
                    bytes.len() - offset,
                )
            };

            if written == -1 {
                let err = io::Error::last_os_error();
                if err.kind() == ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }

            offset += written as usize;
        }

        Ok(())
    }

    fn read_ready(&mut self, deadline: Instant) -> io::Result<()> {
        if self.reached_eof {
            return Ok(());
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as libc::c_int;

        let mut poll_fd = libc::pollfd {
            fd: self.master.as_raw_fd(),
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };

        let ready = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
        if ready == -1 {
            let err = io::Error::last_os_error();
            if err.kind() == ErrorKind::Interrupted {
                return Ok(());
            }
            return Err(err);
        }

        if ready == 0 {
            return Ok(());
        }

        let mut buf = [0_u8; 4096];
        loop {
            let count =
                unsafe { libc::read(self.master.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };

            if count == 0 {
                self.reached_eof = true;
                self.flush_pending_line();
                return Ok(());
            }

            if count == -1 {
                let err = io::Error::last_os_error();
                match err.kind() {
                    ErrorKind::WouldBlock => return Ok(()),
                    ErrorKind::Interrupted => continue,
                    _ => {
                        if err.raw_os_error() == Some(libc::EIO) {
                            self.reached_eof = true;
                            self.flush_pending_line();
                            return Ok(());
                        }
                        return Err(err);
                    }
                }
            }

            self.push_bytes(&buf[..count as usize]);

            if (poll_fd.revents & libc::POLLIN) == 0 {
                return Ok(());
            }
        }
    }

    fn push_bytes(&mut self, bytes: &[u8]) {
        self.pending.push_str(&String::from_utf8_lossy(bytes));

        while let Some(index) = self.pending.find('\n') {
            let line = self.pending[..index].trim_end_matches('\r').to_string();
            self.lines.push_back(line);
            self.pending.drain(..=index);
        }
    }

    fn flush_pending_line(&mut self) {
        if !self.pending.is_empty() {
            self.lines.push_back(std::mem::take(&mut self.pending));
        }
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn open_pty(size: PtySize) -> io::Result<(File, File)> {
    let mut master = -1;
    let mut slave = -1;
    let mut winsize = libc::winsize {
        ws_row: size.rows,
        ws_col: size.cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut winsize,
        )
    };

    if rc == -1 {
        return Err(io::Error::last_os_error());
    }

    let master = unsafe { File::from_raw_fd(master) };
    let slave = unsafe { File::from_raw_fd(slave) };
    Ok((master, slave))
}

fn dup_file(file: &File) -> io::Result<File> {
    let duplicated = unsafe { libc::dup(file.as_raw_fd()) };
    if duplicated == -1 {
        return Err(io::Error::last_os_error());
    }

    Ok(unsafe { File::from_raw_fd(duplicated) })
}

fn set_nonblocking(file: &File) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }

    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

fn set_cloexec(file: &File) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }

    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}
