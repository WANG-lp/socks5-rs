//! UDP ASSOCIATE relay (RFC 1928 §7).
//!
//! For each association we own:
//!   * one **client-facing** socket whose address is reported back to the
//!     client as BND.ADDR/BND.PORT — the client wraps its payloads in a SOCKS5
//!     UDP header and sends them here;
//!   * up to two **remote-facing** sockets (one per IP family) used to talk to
//!     the actual targets.
//!
//! The association lives exactly as long as the TCP control connection that
//! created it: when that connection is closed by the client, we tear the relay
//! down (this is what frees the sockets and stops the task).

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::{BufMut, BytesMut};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};

use crate::protocol::{self, Address, REP_GENERAL_FAILURE, REP_SUCCESS, send_reply, unspecified};

/// Maximum size of a UDP datagram we are willing to buffer (theoretical max
/// UDP payload is 65507 bytes; round up for the SOCKS5 header).
const MAX_DATAGRAM: usize = 65_536;

/// Handle a UDP ASSOCIATE request that arrived on the control connection
/// `ctrl`. `peer` is the client's TCP address; its IP is used to accept only
/// datagrams coming from the same host.
pub async fn associate(ctrl: &mut TcpStream, peer: SocketAddr) -> io::Result<()> {
    // Bind the client-facing socket on the same local IP the client reached us
    // on, so the address we hand back is guaranteed to be routable for them.
    let local_ip = ctrl.local_addr()?.ip();
    let client_sock = UdpSocket::bind((local_ip, 0)).await?;
    let relay_addr = client_sock.local_addr()?;

    // Remote-facing sockets, one per family. A socket may legitimately fail to
    // bind (e.g. no IPv6 on the host); we only require at least one. Bind these
    // before replying so a total failure is reported as such to the client.
    let remote_v4 = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.ok();
    let remote_v6 = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).await.ok();
    if remote_v4.is_none() && remote_v6.is_none() {
        send_reply(ctrl, REP_GENERAL_FAILURE, unspecified()).await?;
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "could not bind any outbound UDP socket",
        ));
    }

    log::info!("udp associate for {peer} relaying via {relay_addr}");
    send_reply(ctrl, REP_SUCCESS, relay_addr).await?;

    // Run the relay until the control connection is closed by the client.
    let mut guard = [0u8; 256];
    let outcome = tokio::select! {
        result = relay(&client_sock, remote_v4.as_ref(), remote_v6.as_ref(), peer) => result,
        _ = wait_until_closed(ctrl, &mut guard) => Ok(()),
    };
    log::info!("udp associate for {peer} closed");
    outcome
}

/// Resolve once the control connection is half-closed or errors. The client is
/// not expected to send anything on it during the association, so any received
/// bytes are simply discarded.
async fn wait_until_closed(ctrl: &mut TcpStream, buf: &mut [u8]) {
    loop {
        match ctrl.read(buf).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

/// The bidirectional relay loop. Never returns under normal operation; it is
/// driven to completion by cancellation from [`associate`].
async fn relay(
    client_sock: &UdpSocket,
    remote_v4: Option<&UdpSocket>,
    remote_v6: Option<&UdpSocket>,
    peer: SocketAddr,
) -> io::Result<()> {
    let mut client_buf = vec![0u8; MAX_DATAGRAM];
    let mut v4_buf = vec![0u8; MAX_DATAGRAM];
    let mut v6_buf = vec![0u8; MAX_DATAGRAM];

    // The exact client UDP source (IP:port) is learned from the first datagram
    // it sends; replies are delivered back there.
    let mut client_addr: Option<SocketAddr> = None;

    loop {
        tokio::select! {
            res = client_sock.recv_from(&mut client_buf) => {
                let (n, src) = res?;
                // Only relay datagrams originating from the associated host.
                if src.ip() != peer.ip() {
                    log::debug!("udp: dropping datagram from unexpected source {src}");
                    continue;
                }
                client_addr = Some(src);
                forward_to_remote(&client_buf[..n], remote_v4, remote_v6).await;
            }
            res = recv_opt(remote_v4, &mut v4_buf) => {
                if let (Some((n, src)), Some(client)) = (res?, client_addr) {
                    forward_to_client(client_sock, client, src, &v4_buf[..n]).await;
                }
            }
            res = recv_opt(remote_v6, &mut v6_buf) => {
                if let (Some((n, src)), Some(client)) = (res?, client_addr) {
                    forward_to_client(client_sock, client, src, &v6_buf[..n]).await;
                }
            }
        }
    }
}

/// `recv_from` on an optional socket. When the socket is absent the future
/// never resolves, so it contributes nothing to the `select!`.
async fn recv_opt(
    sock: Option<&UdpSocket>,
    buf: &mut [u8],
) -> io::Result<Option<(usize, SocketAddr)>> {
    match sock {
        Some(s) => s.recv_from(buf).await.map(Some),
        None => std::future::pending().await,
    }
}

/// Parse a client datagram (`RSV RSV FRAG ATYP DST.ADDR DST.PORT DATA`) and
/// forward its payload to the requested target.
async fn forward_to_remote(
    pkt: &[u8],
    remote_v4: Option<&UdpSocket>,
    remote_v6: Option<&UdpSocket>,
) {
    // RSV(2) + FRAG(1) + at least one ATYP byte.
    if pkt.len() < 4 {
        return;
    }
    // We do not implement reassembly; per RFC a server that does not support
    // fragmentation must drop any datagram with a non-zero FRAG.
    if pkt[2] != 0x00 {
        log::debug!("udp: dropping fragmented datagram (FRAG={})", pkt[2]);
        return;
    }

    let (dst, consumed) = match Address::parse(&pkt[3..]) {
        Ok(parsed) => parsed,
        Err(_) => return,
    };
    let payload = &pkt[3 + consumed..];

    let target = match dst.resolve_first().await {
        Some(addr) => addr,
        None => {
            log::debug!("udp: could not resolve target {dst}");
            return;
        }
    };

    let sock = match target {
        SocketAddr::V4(_) => remote_v4,
        SocketAddr::V6(_) => remote_v6,
    };
    if let Some(sock) = sock {
        if let Err(e) = sock.send_to(payload, target).await {
            log::debug!("udp: send to {target} failed: {e}");
        }
    } else {
        log::debug!("udp: no outbound socket for address family of {target}");
    }
}

/// Wrap a target's reply in a SOCKS5 UDP header and deliver it to the client.
async fn forward_to_client(
    client_sock: &UdpSocket,
    client: SocketAddr,
    src: SocketAddr,
    payload: &[u8],
) {
    let mut datagram = BytesMut::with_capacity(payload.len() + 22);
    datagram.put_u16(0x0000); // RSV
    datagram.put_u8(0x00); // FRAG
    protocol::encode_socket_addr(src, &mut datagram);
    datagram.put_slice(payload);
    if let Err(e) = client_sock.send_to(&datagram, client).await {
        log::debug!("udp: send to client {client} failed: {e}");
    }
}
