use bytes::{Buf, BufMut};
use chrono::Local;

use env_logger::Builder;
use log::LevelFilter;
use std::io::Write;
use std::net::IpAddr;
use structopt::StructOpt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// start from ATYPE, then ADDRESS and PORT
fn _socket_addr_to_vec(socket_addr: std::net::SocketAddr) -> bytes::BytesMut {
    let mut res = bytes::BytesMut::with_capacity(32);
    match socket_addr.ip() {
        IpAddr::V4(ip) => {
            res.put_u8(0x01);
            res.put_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            res.put_u8(0x04);
            res.put_slice(&ip.octets());
        }
    };
    res.put_u16(socket_addr.port());
    res
}

#[derive(Debug, PartialEq, Eq)]
enum RemoteAddr {
    V4(std::net::SocketAddrV4),
    V6(std::net::SocketAddrV6),
    Domain(String),
    Invalid,
}

impl RemoteAddr {
    fn into_inner(self) -> String {
        match self {
            RemoteAddr::V4(addr) => addr.to_string(),
            RemoteAddr::V6(addr) => addr.to_string(),
            RemoteAddr::Domain(addr) => addr,
            RemoteAddr::Invalid => "Invalid".to_string(),
        }
    }
}

async fn process(
    stream: tokio::net::TcpStream,
    peer_addr: std::net::SocketAddr,
) -> std::io::Result<()> {
    log::info!("Accepted from: {}", peer_addr);

    let (mut reader, mut writer) = stream.into_split();

    // read socks5 header
    let mut buffer = vec![0u8; 512];
    reader.read_exact(&mut buffer[0..2]).await?;
    if buffer[0] != 0x05 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "only socks5 protocol is supported!",
        )); // stream will be closed automaticly
    }
    let methods = buffer[1] as usize;
    reader.read_exact(&mut buffer[0..methods]).await?;
    let mut has_no_auth = false;
    for i in 0..methods {
        if buffer[i] == 0x00 {
            has_no_auth = true;
        }
    }
    if !has_no_auth {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "only no-auth is supported!",
        )); // stream will be closed automaticly
    }

    // server send to client accepted auth method (0x00 no-auth only yet)
    writer.write(&[0x05u8, 0x00]).await?;
    writer.flush().await?;

    // read socks5 cmd
    reader.read_exact(&mut buffer[0..4]).await?;
    let cmd = buffer[1]; // support 0x01(CONNECT) and 0x03(UDP Associate)
    let atype = buffer[3];

    // parse addr and port first
    let remote_socket_addr = match atype {
        0x01 => {
            // ipv4: 4bytes + port
            reader.read_exact(&mut buffer[0..6]).await?;
            let mut tmp_array: [u8; 4] = Default::default();
            tmp_array.copy_from_slice(&buffer[0..4]);
            let v4addr = std::net::Ipv4Addr::from(tmp_array);
            let port: u16 = buffer[4..6].as_ref().get_u16();
            let socket = std::net::SocketAddrV4::new(v4addr, port);
            RemoteAddr::V4(socket)
        }
        0x03 => {
            // domain: 1byte + domain + 2bytes port
            reader.read_exact(&mut buffer[0..1]).await?;
            let len = buffer[0] as usize;
            reader.read_exact(&mut buffer[0..len + 2]).await?;
            let port: u16 = buffer[len..len + 2].as_ref().get_u16();
            if let Ok(addr) = std::str::from_utf8(&buffer[0..len]) {
                let socket = format!("{}:{}", addr, port);
                RemoteAddr::Domain(socket)
            } else {
                RemoteAddr::Invalid
            }
        }
        0x04 => {
            // ipv6: 16bytes + port
            reader.read_exact(&mut buffer[0..18]).await?;
            let mut tmp_array: [u8; 16] = Default::default();
            tmp_array.copy_from_slice(&buffer[0..16]);
            let v6addr = std::net::Ipv6Addr::from(tmp_array);
            let port: u16 = buffer[16..18].as_ref().get_u16();
            let socket = std::net::SocketAddrV6::new(v6addr, port, 0, 0);
            RemoteAddr::V6(socket)
        }
        _ => RemoteAddr::Invalid,
    };

    if remote_socket_addr == RemoteAddr::Invalid {
        writer
            .write(&[0x05u8, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            .await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "address is not valid!".to_string(),
        ));
    }

    let addr = remote_socket_addr.into_inner();

    // parse cmd: support CONNECT(0x01) and UDP (0x03) currently
    match cmd {
        0x01 => {
            //create connection to remote server
            if let Ok(remote_stream) = tokio::net::TcpStream::connect(&addr).await {
                log::info!("connect to {} ok", addr);
                writer
                    .write(&[0x05u8, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                    .await?;
                let (mut r_reader, mut r_writer) = remote_stream.into_split();
                tokio::spawn(async move {
                    match tokio::io::copy(&mut reader, &mut r_writer).await {
                        Ok(_) => {}
                        Err(_e) => {
                            // log::warn!("broken pipe: {}", e);
                        }
                    }
                });
                tokio::io::copy(&mut r_reader, &mut writer).await?;
            } else {
                writer
                    .write(&[0x05u8, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                    .await?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    format!("cannot make connection to {}!", addr),
                )); // stream will be closed automaticly
            };
        }
        0x03 => {
            // UDP associate
            writer
                .write(&[0x05u8, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                .await?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "UDP associate is not supported yet!",
            ));
        }
        _ => {
            writer
                .write(&[0x05u8, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                .await?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "command is not supported!",
            ));
        }
    }

    log::info!("disconnect from {}", peer_addr);
    Ok(())
}

#[derive(StructOpt)]
#[structopt(name = "socks5", about = "A lightweight and fast socks5 server written in Rust", version=env!("CARGO_PKG_VERSION"))]
struct Opts {
    #[structopt(short, long, default_value = "127.0.0.1")]
    pub bind: String,
    #[structopt(short, long, default_value = "8080")]
    pub port: u16,
    #[structopt(short, long, default_value = "4")]
    pub work_threads: u16,
}

fn main() -> std::io::Result<()> {
    Builder::new()
        .format(|buf, record| {
            writeln!(
                buf,
                "{} [{}] - {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.args()
            )
        })
        .filter(None, LevelFilter::Info)
        .init();

    let opts = Opts::from_args();

    let bind_str = format!("{}:{}", opts.bind, opts.port);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(opts.work_threads as usize)
        .enable_all()
        .build()
        .expect("Failed to create runtime");

    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind(bind_str).await?;
        log::info!("Listening on {}", listener.local_addr()?);

        while let Ok((stream, addr)) = listener.accept().await {
            tokio::spawn(async move {
                if let Err(_e) = process(stream, addr).await {
                    // log::warn!("broken pipe: {}", e);
                }
            });
        }
        Ok(())
    })
}
