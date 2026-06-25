//! Per-connection SOCKS5 state machine: method negotiation, optional
//! username/password authentication, request parsing and command dispatch.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional_with_sizes};
use tokio::net::{TcpStream, lookup_host};
use tokio::time::timeout;

use crate::protocol::*;
use crate::udp;

/// Buffer size for each direction of a CONNECT relay (64 KiB).
const RELAY_BUF: usize = 64 * 1024;

/// Runtime configuration shared by every connection.
#[derive(Clone)]
pub struct Config {
    /// `Some((user, pass))` enables RFC 1929 username/password authentication.
    pub auth: Option<(String, String)>,
    /// Time budget for the whole greeting + request exchange.
    pub handshake_timeout: Duration,
    /// Time budget for establishing the outbound CONNECT.
    pub connect_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            auth: None,
            handshake_timeout: Duration::from_secs(15),
            connect_timeout: Duration::from_secs(15),
        }
    }
}

struct Request {
    cmd: u8,
    dst: Address,
}

/// Drive a single client connection to completion.
pub async fn handle(
    mut stream: TcpStream,
    peer: SocketAddr,
    config: Arc<Config>,
) -> io::Result<()> {
    log::info!("accepted connection from {peer}");
    let _ = stream.set_nodelay(true);

    timeout(config.handshake_timeout, negotiate(&mut stream, &config))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timed out"))??;

    let request = timeout(config.handshake_timeout, read_request(&mut stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request timed out"))??;

    match request.cmd {
        CMD_CONNECT => handle_connect(&mut stream, request.dst, peer, &config).await,
        CMD_UDP_ASSOCIATE => udp::associate(&mut stream, peer).await,
        CMD_BIND => {
            log::warn!("BIND is not supported (requested by {peer})");
            send_reply(&mut stream, REP_COMMAND_NOT_SUPPORTED, unspecified()).await
        }
        other => {
            log::warn!("unsupported command {other:#04x} from {peer}");
            send_reply(&mut stream, REP_COMMAND_NOT_SUPPORTED, unspecified()).await
        }
    }
}

/// Method-selection greeting plus, if configured, the auth sub-negotiation.
async fn negotiate(stream: &mut TcpStream, config: &Config) -> io::Result<()> {
    let version = stream.read_u8().await?;
    if version != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "client is not speaking SOCKS5",
        ));
    }

    let nmethods = stream.read_u8().await? as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    let required = if config.auth.is_some() {
        METHOD_USER_PASS
    } else {
        METHOD_NO_AUTH
    };

    if !methods.contains(&required) {
        stream.write_all(&[VERSION, METHOD_NO_ACCEPTABLE]).await?;
        stream.flush().await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "no acceptable authentication method offered",
        ));
    }

    stream.write_all(&[VERSION, required]).await?;
    stream.flush().await?;

    if required == METHOD_USER_PASS {
        authenticate(stream, config).await?;
    }
    Ok(())
}

/// RFC 1929 username/password verification.
async fn authenticate(stream: &mut TcpStream, config: &Config) -> io::Result<()> {
    let version = stream.read_u8().await?;
    if version != AUTH_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported authentication version",
        ));
    }

    let ulen = stream.read_u8().await? as usize;
    let mut username = vec![0u8; ulen];
    stream.read_exact(&mut username).await?;

    let plen = stream.read_u8().await? as usize;
    let mut password = vec![0u8; plen];
    stream.read_exact(&mut password).await?;

    let (expected_user, expected_pass) = config.auth.as_ref().expect("auth configured");
    let ok = username == expected_user.as_bytes() && password == expected_pass.as_bytes();

    let status = if ok { AUTH_SUCCESS } else { AUTH_FAILURE };
    stream.write_all(&[AUTH_VERSION, status]).await?;
    stream.flush().await?;

    if ok {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid username or password",
        ))
    }
}

/// Read `VER CMD RSV ATYP DST.ADDR DST.PORT`.
async fn read_request(stream: &mut TcpStream) -> io::Result<Request> {
    let version = stream.read_u8().await?;
    if version != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad version in request",
        ));
    }
    let cmd = stream.read_u8().await?;
    let _rsv = stream.read_u8().await?;

    match Address::read_from(stream).await {
        Ok(dst) => Ok(Request { cmd, dst }),
        Err(e) => {
            // Best effort: tell the client the address could not be handled.
            let _ = send_reply(stream, REP_ADDRESS_TYPE_NOT_SUPPORTED, unspecified()).await;
            Err(e)
        }
    }
}

/// Execute a CONNECT request and, on success, splice the two streams together.
async fn handle_connect(
    stream: &mut TcpStream,
    dst: Address,
    peer: SocketAddr,
    config: &Config,
) -> io::Result<()> {
    let target = dst.to_string();

    let mut remote = match timeout(config.connect_timeout, connect_target(&dst)).await {
        Ok(Ok(remote)) => remote,
        Ok(Err(e)) => {
            log::warn!("connect to {target} failed: {e}");
            send_reply(stream, map_connect_error(&e), unspecified()).await?;
            return Ok(());
        }
        Err(_) => {
            log::warn!("connect to {target} timed out");
            send_reply(stream, REP_HOST_UNREACHABLE, unspecified()).await?;
            return Ok(());
        }
    };

    let _ = remote.set_nodelay(true);
    let bnd = remote.local_addr().unwrap_or_else(|_| unspecified());
    send_reply(stream, REP_SUCCESS, bnd).await?;
    log::info!("{peer} <-> {target} established");

    match copy_bidirectional_with_sizes(stream, &mut remote, RELAY_BUF, RELAY_BUF).await {
        Ok((up, down)) => log::info!("{peer} <-> {target} closed (up {up} B, down {down} B)"),
        Err(e) => log::debug!("{peer} <-> {target} relay ended: {e}"),
    }
    Ok(())
}

/// Connect to a target, trying every resolved address for a host name.
async fn connect_target(dst: &Address) -> io::Result<TcpStream> {
    match dst {
        Address::Socket(addr) => TcpStream::connect(addr).await,
        Address::Domain(host, port) => {
            let mut last_err = io::Error::new(
                io::ErrorKind::NotFound,
                "host name did not resolve to any address",
            );
            for addr in lookup_host((host.as_str(), *port)).await? {
                match TcpStream::connect(addr).await {
                    Ok(stream) => return Ok(stream),
                    Err(e) => last_err = e,
                }
            }
            Err(last_err)
        }
    }
}

/// Map an outbound connection error to the closest SOCKS5 reply code.
fn map_connect_error(e: &io::Error) -> u8 {
    use io::ErrorKind::*;
    match e.kind() {
        ConnectionRefused => REP_CONNECTION_REFUSED,
        NetworkUnreachable => REP_NETWORK_UNREACHABLE,
        HostUnreachable => REP_HOST_UNREACHABLE,
        TimedOut => REP_HOST_UNREACHABLE,
        _ => REP_GENERAL_FAILURE,
    }
}
