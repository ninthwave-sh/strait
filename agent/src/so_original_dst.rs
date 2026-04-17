//! Recover the pre-DNAT destination of a REDIRECT'd TCP connection.
//!
//! After an iptables `-j REDIRECT` rule bounces a locally-originated TCP
//! connection to the proxy port, the kernel stores the original destination
//! on the accepted socket. On Linux we read it via
//! `getsockopt(SOL_IP, SO_ORIGINAL_DST)`, which hands back a
//! `struct sockaddr_in` (IPv4) or `struct sockaddr_in6` (IPv6) describing
//! where the client *thought* it was connecting to.
//!
//! Without this, the proxy can't know which upstream host to forward to after
//! TLS termination — the client's TCP-level destination is just our own
//! loopback address. SNI from the ClientHello tells us the hostname, but the
//! original IP and port come from here.
//!
//! The sockaddr parsing is a pure function so it can be tested on every
//! platform; only the syscall wrapper is Linux-specific.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

/// Netinet/in.h constant for the IPv6-level `SO_ORIGINAL_DST` option on Linux.
///
/// `libc::SO_ORIGINAL_DST` exists on Linux for SOL_IP; for IPv6 the constant
/// is `IP6T_SO_ORIGINAL_DST` = 80, not exported by libc, so we hard-code it.
#[cfg(target_os = "linux")]
const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;

/// Recover the original destination of a REDIRECT'd TCP connection on Linux.
///
/// Accepts a raw file descriptor (typically from `TcpStream::as_raw_fd()`)
/// and queries the kernel for the pre-DNAT destination. Returns an error on
/// non-Linux platforms or if the socket was never REDIRECT'd.
#[cfg(target_os = "linux")]
pub fn get_original_dst(fd: std::os::unix::io::RawFd) -> io::Result<SocketAddr> {
    // Try IPv4 first. The layout of `sockaddr_in` is a u16 family + u16 port
    // (network order) + u32 address (network order) + 8 zero bytes.
    let mut v4_buf = [0u8; std::mem::size_of::<libc::sockaddr_in>()];
    let mut len: libc::socklen_t = v4_buf.len() as libc::socklen_t;
    // SAFETY: getsockopt reads into a buffer whose length matches `len`.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            v4_buf.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 {
        return parse_sockaddr_in(&v4_buf[..len as usize]);
    }

    // Fall through to IPv6 on EOPNOTSUPP / EINVAL / ENOENT etc.
    let mut v6_buf = [0u8; std::mem::size_of::<libc::sockaddr_in6>()];
    let mut len: libc::socklen_t = v6_buf.len() as libc::socklen_t;
    // SAFETY: getsockopt reads into a buffer whose length matches `len`.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IPV6,
            IP6T_SO_ORIGINAL_DST,
            v6_buf.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 {
        return parse_sockaddr_in6(&v6_buf[..len as usize]);
    }

    Err(io::Error::last_os_error())
}

/// Non-Linux stub: SO_ORIGINAL_DST is a netfilter concept and has no
/// equivalent outside Linux. Callers that need a destination on other
/// platforms should fall back to an injected test override.
#[cfg(not(target_os = "linux"))]
pub fn get_original_dst(_fd: std::os::unix::io::RawFd) -> io::Result<SocketAddr> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SO_ORIGINAL_DST is only available on Linux",
    ))
}

/// Parse a raw `struct sockaddr_in` (16 bytes on every Unix) into a
/// [`SocketAddr`].
///
/// Layout (network byte order for `sin_port` and `sin_addr`):
///
/// ```text
/// offset  size  field
///      0     2  sin_family  (AF_INET = 2, little-endian on x86/ARM)
///      2     2  sin_port    (big-endian)
///      4     4  sin_addr    (big-endian)
///      8     8  sin_zero    (reserved)
/// ```
///
/// Cross-platform pure function so it can be unit-tested without a real
/// REDIRECT'd socket. Accepts any buffer at least 8 bytes long (the tail
/// padding bytes are ignored).
pub fn parse_sockaddr_in(bytes: &[u8]) -> io::Result<SocketAddr> {
    if bytes.len() < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sockaddr_in buffer too short",
        ));
    }
    // sin_family is stored in host byte order per POSIX.
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    if family != libc::AF_INET as u16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("expected AF_INET (2), got family={family}"),
        ));
    }
    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
    let addr = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
    Ok(SocketAddr::V4(SocketAddrV4::new(addr, port)))
}

/// Parse a raw `struct sockaddr_in6` (28 bytes) into a [`SocketAddr`].
///
/// Layout (network byte order for `sin6_port`, `sin6_flowinfo`, `sin6_addr`,
/// and `sin6_scope_id`):
///
/// ```text
/// offset  size  field
///      0     2  sin6_family    (AF_INET6 = 10 on Linux)
///      2     2  sin6_port      (big-endian)
///      4     4  sin6_flowinfo  (big-endian)
///      8    16  sin6_addr      (big-endian)
///     24     4  sin6_scope_id  (big-endian)
/// ```
pub fn parse_sockaddr_in6(bytes: &[u8]) -> io::Result<SocketAddr> {
    if bytes.len() < 28 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sockaddr_in6 buffer too short",
        ));
    }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    if family != libc::AF_INET6 as u16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "expected AF_INET6 ({}), got family={}",
                libc::AF_INET6,
                family
            ),
        ));
    }
    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
    let flowinfo = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let mut addr_bytes = [0u8; 16];
    addr_bytes.copy_from_slice(&bytes[8..24]);
    let addr = Ipv6Addr::from(addr_bytes);
    let scope_id = u32::from_be_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
    Ok(SocketAddr::V6(SocketAddrV6::new(
        addr, port, flowinfo, scope_id,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canned_sockaddr_in(addr: [u8; 4], port: u16) -> [u8; 16] {
        let mut buf = [0u8; 16];
        // sin_family (AF_INET = 2, host byte order)
        let family_bytes = (libc::AF_INET as u16).to_ne_bytes();
        buf[0] = family_bytes[0];
        buf[1] = family_bytes[1];
        // sin_port (big-endian)
        let port_bytes = port.to_be_bytes();
        buf[2] = port_bytes[0];
        buf[3] = port_bytes[1];
        // sin_addr (big-endian)
        buf[4..8].copy_from_slice(&addr);
        // sin_zero (8 bytes of zero, already initialized)
        buf
    }

    #[test]
    fn parse_sockaddr_in_ipv4_loopback_443() {
        let buf = canned_sockaddr_in([127, 0, 0, 1], 443);
        let sa = parse_sockaddr_in(&buf).unwrap();
        assert_eq!(sa, "127.0.0.1:443".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parse_sockaddr_in_ipv4_public_address() {
        // 140.82.112.5 is a representative github.com IP. The point is only
        // that we recover the exact four bytes and port we fed in.
        let buf = canned_sockaddr_in([140, 82, 112, 5], 443);
        let sa = parse_sockaddr_in(&buf).unwrap();
        assert_eq!(sa, "140.82.112.5:443".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parse_sockaddr_in_ephemeral_port() {
        let buf = canned_sockaddr_in([10, 0, 0, 1], 54321);
        let sa = parse_sockaddr_in(&buf).unwrap();
        assert_eq!(sa, "10.0.0.1:54321".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parse_sockaddr_in_rejects_short_buffer() {
        let buf = [0u8; 4];
        let err = parse_sockaddr_in(&buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn parse_sockaddr_in_rejects_wrong_family() {
        let mut buf = canned_sockaddr_in([127, 0, 0, 1], 443);
        // Flip family to something non-AF_INET
        buf[0] = 0xff;
        buf[1] = 0xff;
        let err = parse_sockaddr_in(&buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn parse_sockaddr_in_accepts_trailing_padding() {
        // Real `getsockopt` returns 16 bytes; we accept anything >= 8.
        let buf = canned_sockaddr_in([192, 168, 1, 1], 80);
        let sa = parse_sockaddr_in(&buf[..]).unwrap();
        assert_eq!(sa, "192.168.1.1:80".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parse_sockaddr_in6_loopback() {
        let mut buf = [0u8; 28];
        let family_bytes = (libc::AF_INET6 as u16).to_ne_bytes();
        buf[0] = family_bytes[0];
        buf[1] = family_bytes[1];
        let port_bytes = 443u16.to_be_bytes();
        buf[2] = port_bytes[0];
        buf[3] = port_bytes[1];
        // flowinfo = 0, already zero
        // sin6_addr: ::1
        buf[23] = 1;
        // scope_id = 0, already zero

        let sa = parse_sockaddr_in6(&buf).unwrap();
        assert_eq!(sa, "[::1]:443".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parse_sockaddr_in6_rejects_short_buffer() {
        let buf = [0u8; 10];
        let err = parse_sockaddr_in6(&buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
