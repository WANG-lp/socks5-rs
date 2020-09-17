use async_std::io;
use async_std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use async_std::net::{TcpListener, TcpStream, UdpSocket};
use async_std::prelude::*;
use async_std::sync::Arc;
use async_std::task;
use bytes::{Buf, BufMut};
use chrono::Local;
use clap::{App, Arg};
use env_logger::Builder;
use log::LevelFilter;
use std::collections::HashSet;
use std::io::Write;
use std::sync::Mutex;

#[derive(Debug, Clone)]
struct BindInfo {
    addr: String,
    _port: String,
}

#[macro_use]
extern crate lazy_static;
lazy_static! {
    static ref BIND_INFO: Mutex<BindInfo> = Mutex::new(BindInfo {
        addr: String::new(),
        _port: String::new()
    });
    static ref HASHSET: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
}

// start from ATYPE, then ADDRESS and PORT
fn socket_addr_to_vec(socket_addr: std::net::SocketAddr) -> Vec<u8> {
    let mut res = Vec::new();
    let ip_bytes = match socket_addr.ip() {
        IpAddr::V4(ip) => {
            res.push(0x01);
            ip.octets().to_vec()
        }
        IpAddr::V6(ip) => {
            res.push(0x04);
            ip.octets().to_vec()
        }
    };
    for val in ip_bytes.iter() {
        res.push(*val);
    }
    res.put_u16(socket_addr.port());
    res
}

async fn process(stream: TcpStream) -> io::Result<()> {
    let peer_addr = stream.peer_addr()?;
    log::info!("Accepted from: {}", peer_addr);

    let mut reader = stream.clone();
    let mut writer = stream;

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
    writer.write(&vec![0x05u8, 0x00]).await?;
    writer.flush().await?;

    // read socks5 cmd
    reader.read_exact(&mut buffer[0..4]).await?;
    let cmd = buffer[1]; // support 0x01(CONNECT) and 0x03(UDP Associate)
    let atype = buffer[3];

    let mut addr_port = String::from("");
    let mut flag_addr_ok = true;

    // parse addr and port first
    match atype {
        0x01 => {
            // ipv4: 4bytes + port
            reader.read_exact(&mut buffer[0..6]).await?;
            let mut tmp_array: [u8; 4] = Default::default();
            tmp_array.copy_from_slice(&buffer[0..4]);
            let v4addr = Ipv4Addr::from(tmp_array);
            let port: u16 = buffer[4..6].as_ref().get_u16();
            let socket = SocketAddrV4::new(v4addr, port);
            addr_port = format!("{}", socket);
            // println!("ipv4: {}", addr_port);
        }
        0x03 => {
            reader.read_exact(&mut buffer[0..1]).await?;
            let len = buffer[0] as usize;
            reader.read_exact(&mut buffer[0..len + 2]).await?;
            let port: u16 = buffer[len..len + 2].as_ref().get_u16();
            if let Ok(addr) = std::str::from_utf8(&buffer[0..len]) {
                addr_port = format!("{}:{}", addr, port);
            } else {
                flag_addr_ok = false;
            }
            // println!("domain: {}", addr_port);
        }
        0x04 => {
            // ipv6: 16bytes + port
            reader.read_exact(&mut buffer[0..18]).await?;
            let mut tmp_array: [u8; 16] = Default::default();
            tmp_array.copy_from_slice(&buffer[0..16]);
            let v6addr = Ipv6Addr::from(tmp_array);
            let port: u16 = buffer[16..18].as_ref().get_u16();
            let socket = SocketAddrV6::new(v6addr, port, 0, 0);
            addr_port = format!("{}", socket);
            // println!("ipv6: {}", addr_port);
        }
        _ => {
            flag_addr_ok = false;
        }
    }
    if !flag_addr_ok {
        writer
            .write(&vec![
                0x05u8, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ])
            .await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            format!("address is not valid!"),
        ));
    }

    // parse cmd: support CONNECT(0x01) and UDP (0x03) currently
    match cmd {
        0x01 => {
            //create connection to remote server
            if let Ok(remote_stream) = TcpStream::connect(addr_port.as_str()).await {
                log::info!("connect to {} ok", addr_port);
                writer
                    .write(&vec![
                        0x05u8, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    ])
                    .await?;
                let mut remote_read = remote_stream.clone();
                let mut remote_write = remote_stream;
                task::spawn(async move {
                    match io::copy(&mut reader, &mut remote_write).await {
                        Ok(_) => {}
                        Err(e) => {
                            log::warn!("broken pipe: {}", e);
                        }
                    }
                });
                io::copy(&mut remote_read, &mut writer).await?;
            } else {
                writer
                    .write(&vec![
                        0x05u8, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    ])
                    .await?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    format!("cannot make connection to {}!", addr_port),
                )); // stream will be closed automaticly
            };
        }
        0x03 => {
            // UDP Associate
            log::info!("start udp associate for {}", peer_addr);
            let addr = BIND_INFO.lock().unwrap().addr.clone();
            let raw_socket = UdpSocket::bind(format!("{}:0", addr)).await?;
            let socket = Arc::new(raw_socket);
            let socket_addr = socket.local_addr();

            let mut addr_port = String::from("");

            match socket_addr {
                Ok(addr) => {
                    writer.write(&vec![0x05u8, 0x00, 0x00]).await?;

                    let content = socket_addr_to_vec(addr);
                    writer.write(&content).await?;

                    HASHSET.lock().unwrap().insert(peer_addr.to_string());

                    task::spawn(async move {
                        let mut buf = vec![0u8; 1];

                        // close connection if we read more bytes
                        match reader.read_exact(&mut buf[0..1]).await {
                            Ok(_) => {
                                // eprintln!("read something {:x?}", buf);
                            }
                            Err(_) => {
                                // eprintln!("error while reading");
                            }
                        }
                        HASHSET.lock().unwrap().remove(&peer_addr.to_string());
                        log::info!("udp-tcp disconnect from {}", peer_addr);
                    });

                    //start to transfer data
                    //recv first packet
                    let mut buf = vec![0u8; 2048];
                    let (mut n, local_peer) = socket.recv_from(&mut buf).await?;

                    let socket_remote_raw = UdpSocket::bind(format!("0.0.0.0:0")).await?;
                    let socket_remote_reader = Arc::new(socket_remote_raw);
                    let socket_remote_writer = socket_remote_reader.clone();
                    let local_socket_writer = socket.clone();
                    task::spawn(async move {
                        let mut buf = vec![0u8; 2048];

                        loop {
                            if HASHSET.lock().unwrap().contains(&peer_addr.to_string()) {
                                let res = socket_remote_reader.recv_from(&mut buf).await;
                                match res {
                                    Ok((n, remote_addr)) => {
                                        let mut write_packet = vec![0x0u8, 0, 0];

                                        let content = socket_addr_to_vec(remote_addr);
                                        for val in content.iter() {
                                            write_packet.push(*val);
                                        }
                                        for val in buf[0..n].iter() {
                                            write_packet.push(*val);
                                        }
                                        // write the udp packet at once
                                        let _ = local_socket_writer
                                            .send_to(&write_packet, local_peer)
                                            .await;
                                    }
                                    Err(e) => {
                                        HASHSET.lock().unwrap().remove(&peer_addr.to_string());
                                        log::error!("error read udp from remote: {}", e);
                                    }
                                }
                            } else {
                                break;
                            }
                        }
                    });
                    loop {
                        if HASHSET.lock().unwrap().contains(&peer_addr.to_string()) {
                            if n > 4 {
                                let mut addr_is_ok = true;
                                //processing receved packet from client
                                if buf[0] == 0x00 && buf[1] == 0x00 && buf[2] == 0x00 {
                                    let mut idx = 0usize;
                                    match buf[3] {
                                        0x01 => {
                                            if n < 4 + 4 + 2 {
                                                addr_is_ok = false;
                                            } else {
                                                let mut tmp_array: [u8; 4] = Default::default();
                                                tmp_array.copy_from_slice(&buf[4..8]);
                                                let v4addr = Ipv4Addr::from(tmp_array);
                                                let port: u16 = buf[8..10].as_ref().get_u16();
                                                let socket = SocketAddrV4::new(v4addr, port);
                                                addr_port = format!("{}", socket);
                                                idx = 10;
                                                // println!("ipv4: {}", addr_port);
                                            }
                                        }
                                        0x03 => {
                                            let len = buf[4] as usize;
                                            if n < 4 + len + 2 {
                                                addr_is_ok = false;
                                            } else {
                                                let port: u16 =
                                                    buf[5 + len..5 + 2 + len].as_ref().get_u16();
                                                if let Ok(addr) =
                                                    std::str::from_utf8(&buf[5..5 + len])
                                                {
                                                    addr_port = format!("{}:{}", addr, port);
                                                    idx = 5 + 2 + len;
                                                } else {
                                                    addr_is_ok = false;
                                                }

                                                // println!("domain: {}", addr_port);
                                            }
                                        }
                                        0x04 => {
                                            if n < 4 + 16 + 2 {
                                                addr_is_ok = false;
                                            } else {
                                                // ipv6: 16bytes + port
                                                let mut tmp_array: [u8; 16] = Default::default();
                                                tmp_array.copy_from_slice(&buf[4..20]);
                                                let v6addr = Ipv6Addr::from(tmp_array);
                                                let port: u16 = buf[20..22].as_ref().get_u16();
                                                let socket = SocketAddrV6::new(v6addr, port, 0, 0);
                                                addr_port = format!("{}", socket);
                                                idx = 22;
                                                // println!("ipv6: {}", addr_port);
                                            }
                                        }
                                        _ => {}
                                    }
                                    if addr_is_ok {
                                        log::info!("send UDP to {} for {}", addr_port, peer_addr);
                                        let _ = socket_remote_writer
                                            .send_to(&buf[idx..n], &addr_port)
                                            .await;
                                    } else {
                                        HASHSET.lock().unwrap().remove(&peer_addr.to_string());
                                    }
                                }
                            }
                            let (nn, _) = socket.recv_from(&mut buf).await?;
                            n = nn;
                        } else {
                            break;
                        }
                    }
                }
                Err(_) => {
                    writer
                        .write(&vec![
                            0x05u8, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        ])
                        .await?;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        format!("udp listen port failed {}!", addr_port),
                    )); // stream will be closed automaticly
                }
            }
        }
        _ => {
            writer
                .write(&vec![
                    0x05u8, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ])
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

fn main() -> io::Result<()> {
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
    let matches = App::new("A lightweight and fast socks5 server written in Rust")
        .version("0.2.0")
        .author("Lipeng")
        .about("A simple socks5 server")
        .arg(
            Arg::with_name("bind")
                .short("b")
                .long("bind")
                .value_name("BIND_ADDR")
                .help("bind address")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("port")
                .short("p")
                .long("port")
                .value_name("BIND_PORT")
                .help("bind port")
                .required(false)
                .takes_value(true),
        )
        .get_matches();

    let bind_addr = String::from(matches.value_of("bind").unwrap_or("127.0.0.1"));
    let bind_port = String::from(matches.value_of("port").unwrap_or("8080"));

    *BIND_INFO.lock().unwrap() = BindInfo {
        addr: bind_addr.clone(),
        _port: bind_port.clone(),
    };

    let bind_str = format!("{}:{}", bind_addr, bind_port);

    task::block_on(async {
        let listener = TcpListener::bind(bind_str).await?;
        log::info!("Listening on {}", listener.local_addr()?);

        let mut incoming = listener.incoming();

        while let Some(stream) = incoming.next().await {
            let stream = stream?;
            task::spawn(async {
                match process(stream).await {
                    Ok(()) => {}
                    Err(e) => {
                        log::warn!("broken pipe: {}", e);
                    }
                }
            });
        }
        Ok(())
    })
}
