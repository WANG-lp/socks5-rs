//! End-to-end tests that drive a hand-rolled SOCKS5 client against the server
//! library, relaying through local echo services.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

use socks5_rs::{Config, serve};

const VER: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const CMD_BIND: u8 = 0x02;
const CMD_UDP: u8 = 0x03;

// ----- test harness helpers -------------------------------------------------

async fn start_proxy(config: Config) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve(listener, Arc::new(config)).await;
    });
    addr
}

async fn start_tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = sock.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

async fn start_udp_echo() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, src)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(&buf[..n], src).await;
        }
    });
    addr
}

async fn greet_no_auth(stream: &mut TcpStream) {
    stream.write_all(&[VER, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [VER, 0x00], "server should accept no-auth");
}

async fn write_request_ipv4(stream: &mut TcpStream, cmd: u8, addr: SocketAddr) {
    let SocketAddr::V4(v4) = addr else {
        panic!("ipv4 expected")
    };
    let mut req = vec![VER, cmd, 0x00, 0x01];
    req.extend_from_slice(&v4.ip().octets());
    req.extend_from_slice(&v4.port().to_be_bytes());
    stream.write_all(&req).await.unwrap();
}

async fn write_request_domain(stream: &mut TcpStream, cmd: u8, host: &str, port: u16) {
    let mut req = vec![VER, cmd, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await.unwrap();
}

/// Read a reply (`VER REP RSV ATYP BND.ADDR BND.PORT`) and return (REP, BND).
async fn read_reply(stream: &mut TcpStream) -> (u8, SocketAddr) {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], VER);
    let rep = head[1];
    let bnd = match head[3] {
        0x01 => {
            let mut b = [0u8; 6];
            stream.read_exact(&mut b).await.unwrap();
            SocketAddr::from((
                Ipv4Addr::new(b[0], b[1], b[2], b[3]),
                u16::from_be_bytes([b[4], b[5]]),
            ))
        }
        0x04 => {
            let mut b = [0u8; 18];
            stream.read_exact(&mut b).await.unwrap();
            let ip: [u8; 16] = b[0..16].try_into().unwrap();
            SocketAddr::from((Ipv6Addr::from(ip), u16::from_be_bytes([b[16], b[17]])))
        }
        other => panic!("unexpected ATYP in reply: {other}"),
    };
    (rep, bnd)
}

/// Run a future with a hard deadline so a protocol bug fails fast.
async fn with_timeout<F: std::future::Future<Output = T>, T>(fut: F) -> T {
    timeout(Duration::from_secs(10), fut)
        .await
        .expect("test timed out")
}

// ----- CONNECT --------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_ipv4_relays_data() {
    with_timeout(async {
        let echo = start_tcp_echo().await;
        let proxy = start_proxy(Config::default()).await;

        let mut client = TcpStream::connect(proxy).await.unwrap();
        greet_no_auth(&mut client).await;
        write_request_ipv4(&mut client, CMD_CONNECT, echo).await;
        let (rep, _) = read_reply(&mut client).await;
        assert_eq!(rep, 0x00, "CONNECT should succeed");

        client.write_all(b"hello world").await.unwrap();
        let mut buf = [0u8; 11];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello world");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_via_domain_name() {
    with_timeout(async {
        let echo = start_tcp_echo().await;
        let proxy = start_proxy(Config::default()).await;

        let mut client = TcpStream::connect(proxy).await.unwrap();
        greet_no_auth(&mut client).await;
        write_request_domain(&mut client, CMD_CONNECT, "localhost", echo.port()).await;
        let (rep, _) = read_reply(&mut client).await;
        assert_eq!(rep, 0x00, "CONNECT to localhost should succeed");

        client.write_all(b"abc").await.unwrap();
        let mut buf = [0u8; 3];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"abc");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_refused_maps_to_reply() {
    with_timeout(async {
        // Bind then drop a listener to obtain a port nobody is listening on.
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);

        let proxy = start_proxy(Config::default()).await;
        let mut client = TcpStream::connect(proxy).await.unwrap();
        greet_no_auth(&mut client).await;
        write_request_ipv4(&mut client, CMD_CONNECT, dead_addr).await;
        let (rep, _) = read_reply(&mut client).await;
        assert_eq!(rep, 0x05, "refused connection should map to REP 0x05");
    })
    .await;
}

// ----- UDP ASSOCIATE --------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_associate_relays_datagram() {
    with_timeout(async {
        let echo = start_udp_echo().await;
        let proxy = start_proxy(Config::default()).await;

        // Establish the association over TCP.
        let mut ctrl = TcpStream::connect(proxy).await.unwrap();
        greet_no_auth(&mut ctrl).await;
        write_request_ipv4(&mut ctrl, CMD_UDP, "0.0.0.0:0".parse().unwrap()).await;
        let (rep, bnd) = read_reply(&mut ctrl).await;
        assert_eq!(rep, 0x00, "UDP ASSOCIATE should succeed");

        // The relay endpoint to send datagrams to.
        let relay = if bnd.ip().is_unspecified() {
            SocketAddr::from((Ipv4Addr::LOCALHOST, bnd.port()))
        } else {
            bnd
        };

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let SocketAddr::V4(echo_v4) = echo else {
            panic!("ipv4 echo expected")
        };

        // RSV(2) FRAG(1) ATYP=v4 DST.ADDR DST.PORT DATA
        let mut datagram = vec![0x00, 0x00, 0x00, 0x01];
        datagram.extend_from_slice(&echo_v4.ip().octets());
        datagram.extend_from_slice(&echo_v4.port().to_be_bytes());
        datagram.extend_from_slice(b"ping");
        client.send_to(&datagram, relay).await.unwrap();

        let mut buf = vec![0u8; 1024];
        let (n, _) = client.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[0..3], &[0x00, 0x00, 0x00], "RSV+FRAG must be zero");
        assert_eq!(buf[3], 0x01, "reply should carry an IPv4 source");
        assert_eq!(&buf[10..n], b"ping", "payload should round-trip");

        // Closing the control connection tears the association down.
        drop(ctrl);
    })
    .await;
}

// ----- Authentication -------------------------------------------------------

fn auth_config() -> Config {
    Config {
        auth: Some(("user".to_string(), "pass".to_string())),
        ..Config::default()
    }
}

async fn submit_credentials(stream: &mut TcpStream, user: &[u8], pass: &[u8]) -> u8 {
    // greeting offering username/password (0x02)
    stream.write_all(&[VER, 0x01, 0x02]).await.unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [VER, 0x02], "server should select user/pass");

    let mut auth = vec![0x01, user.len() as u8];
    auth.extend_from_slice(user);
    auth.push(pass.len() as u8);
    auth.extend_from_slice(pass);
    stream.write_all(&auth).await.unwrap();

    let mut status = [0u8; 2];
    stream.read_exact(&mut status).await.unwrap();
    assert_eq!(status[0], 0x01);
    status[1]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_success_then_connect() {
    with_timeout(async {
        let echo = start_tcp_echo().await;
        let proxy = start_proxy(auth_config()).await;

        let mut client = TcpStream::connect(proxy).await.unwrap();
        assert_eq!(
            submit_credentials(&mut client, b"user", b"pass").await,
            0x00,
            "valid credentials should be accepted"
        );

        write_request_ipv4(&mut client, CMD_CONNECT, echo).await;
        let (rep, _) = read_reply(&mut client).await;
        assert_eq!(rep, 0x00);
        client.write_all(b"ok").await.unwrap();
        let mut buf = [0u8; 2];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ok");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_failure_is_rejected() {
    with_timeout(async {
        let proxy = start_proxy(auth_config()).await;
        let mut client = TcpStream::connect(proxy).await.unwrap();
        assert_eq!(
            submit_credentials(&mut client, b"user", b"wrong").await,
            0x01,
            "bad credentials should be rejected"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_required_but_only_no_auth_offered() {
    with_timeout(async {
        let proxy = start_proxy(auth_config()).await;
        let mut client = TcpStream::connect(proxy).await.unwrap();
        // Offer only no-auth (0x00) when the server requires user/pass.
        client.write_all(&[VER, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [VER, 0xFF], "server must reject with NO ACCEPTABLE METHODS");
    })
    .await;
}

// ----- Unsupported commands -------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bind_command_is_not_supported() {
    with_timeout(async {
        let proxy = start_proxy(Config::default()).await;
        let mut client = TcpStream::connect(proxy).await.unwrap();
        greet_no_auth(&mut client).await;
        write_request_ipv4(&mut client, CMD_BIND, "127.0.0.1:9".parse().unwrap()).await;
        let (rep, _) = read_reply(&mut client).await;
        assert_eq!(rep, 0x07, "BIND should map to COMMAND NOT SUPPORTED");
    })
    .await;
}
