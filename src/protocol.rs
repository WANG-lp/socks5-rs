//! SOCKS5 wire-protocol primitives (RFC 1928 / RFC 1929).
//!
//! This module is deliberately free of any I/O policy: it only knows how to
//! read, parse, and encode the bytes that make up a SOCKS5 conversation.

use bytes::{BufMut, BytesMut};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::lookup_host;

/// The only protocol version we speak.
pub const VERSION: u8 = 0x05;

// --- Authentication methods (greeting) ---
pub const METHOD_NO_AUTH: u8 = 0x00;
pub const METHOD_USER_PASS: u8 = 0x02;
pub const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

// --- Username/password sub-negotiation (RFC 1929) ---
pub const AUTH_VERSION: u8 = 0x01;
pub const AUTH_SUCCESS: u8 = 0x00;
pub const AUTH_FAILURE: u8 = 0x01;

// --- Request commands ---
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_BIND: u8 = 0x02;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

// --- Address types ---
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

// --- Reply codes ---
pub const REP_SUCCESS: u8 = 0x00;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
pub const REP_NOT_ALLOWED: u8 = 0x02;
pub const REP_NETWORK_UNREACHABLE: u8 = 0x03;
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
pub const REP_CONNECTION_REFUSED: u8 = 0x05;
pub const REP_TTL_EXPIRED: u8 = 0x06;
pub const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// `0.0.0.0:0` — used as the BND.ADDR/BND.PORT in replies where we have no
/// meaningful address to report (e.g. error replies).
pub fn unspecified() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
}

/// A SOCKS5 target address: either a resolved socket address or a host name
/// whose resolution we defer to the moment we actually connect/send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Address {
    Socket(SocketAddr),
    Domain(String, u16),
}

impl Address {
    /// Read an ATYP-prefixed address (ADDR + PORT) from an async stream.
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Address> {
        let atyp = reader.read_u8().await?;
        match atyp {
            ATYP_IPV4 => {
                let mut octets = [0u8; 4];
                reader.read_exact(&mut octets).await?;
                let port = reader.read_u16().await?;
                Ok(Address::Socket(SocketAddr::from((octets, port))))
            }
            ATYP_IPV6 => {
                let mut octets = [0u8; 16];
                reader.read_exact(&mut octets).await?;
                let port = reader.read_u16().await?;
                Ok(Address::Socket(SocketAddr::from((octets, port))))
            }
            ATYP_DOMAIN => {
                let len = reader.read_u8().await? as usize;
                let mut domain = vec![0u8; len];
                reader.read_exact(&mut domain).await?;
                let port = reader.read_u16().await?;
                let host = String::from_utf8(domain).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid domain name")
                })?;
                Ok(Address::Domain(host, port))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported address type",
            )),
        }
    }

    /// Parse an ATYP-prefixed address from the front of an in-memory buffer
    /// (used for UDP datagram headers). Returns the address and the number of
    /// bytes it occupied.
    pub fn parse(buf: &[u8]) -> io::Result<(Address, usize)> {
        let atyp = *buf.first().ok_or_else(short)?;
        match atyp {
            ATYP_IPV4 => {
                if buf.len() < 7 {
                    return Err(short());
                }
                let octets: [u8; 4] = buf[1..5].try_into().unwrap();
                let port = u16::from_be_bytes([buf[5], buf[6]]);
                Ok((Address::Socket(SocketAddr::from((octets, port))), 7))
            }
            ATYP_IPV6 => {
                if buf.len() < 19 {
                    return Err(short());
                }
                let octets: [u8; 16] = buf[1..17].try_into().unwrap();
                let port = u16::from_be_bytes([buf[17], buf[18]]);
                Ok((Address::Socket(SocketAddr::from((octets, port))), 19))
            }
            ATYP_DOMAIN => {
                let len = *buf.get(1).ok_or_else(short)? as usize;
                let end = 2 + len;
                if buf.len() < end + 2 {
                    return Err(short());
                }
                let host = std::str::from_utf8(&buf[2..end])
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid domain name"))?
                    .to_owned();
                let port = u16::from_be_bytes([buf[end], buf[end + 1]]);
                Ok((Address::Domain(host, port), end + 2))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported address type",
            )),
        }
    }

    /// Append the ATYP + ADDR + PORT encoding of this address to `buf`.
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            Address::Socket(addr) => encode_socket_addr(*addr, buf),
            Address::Domain(host, port) => {
                buf.put_u8(ATYP_DOMAIN);
                buf.put_u8(host.len() as u8);
                buf.put_slice(host.as_bytes());
                buf.put_u16(*port);
            }
        }
    }

    /// Resolve to a single socket address, performing DNS for host names.
    pub async fn resolve_first(&self) -> Option<SocketAddr> {
        match self {
            Address::Socket(addr) => Some(*addr),
            Address::Domain(host, port) => lookup_host((host.as_str(), *port)).await.ok()?.next(),
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::Socket(addr) => write!(f, "{addr}"),
            Address::Domain(host, port) => write!(f, "{host}:{port}"),
        }
    }
}

fn short() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "truncated SOCKS5 address")
}

/// Append the ATYP + ADDR + PORT encoding of a concrete socket address.
pub fn encode_socket_addr(addr: SocketAddr, buf: &mut BytesMut) {
    match addr {
        SocketAddr::V4(a) => {
            buf.put_u8(ATYP_IPV4);
            buf.put_slice(&a.ip().octets());
            buf.put_u16(a.port());
        }
        SocketAddr::V6(a) => {
            buf.put_u8(ATYP_IPV6);
            buf.put_slice(&a.ip().octets());
            buf.put_u16(a.port());
        }
    }
}

/// Send a SOCKS5 reply: `VER REP RSV ATYP BND.ADDR BND.PORT`.
pub async fn send_reply<W: AsyncWrite + Unpin>(
    writer: &mut W,
    rep: u8,
    bnd: SocketAddr,
) -> io::Result<()> {
    let mut buf = BytesMut::with_capacity(22);
    buf.put_u8(VERSION);
    buf.put_u8(rep);
    buf.put_u8(0x00); // RSV
    encode_socket_addr(bnd, &mut buf);
    writer.write_all(&buf).await?;
    writer.flush().await
}
