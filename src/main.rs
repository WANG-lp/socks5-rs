use async_std::io;
use async_std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::task;
use bytes::Buf;
use clap::{App, Arg};

async fn process(stream: TcpStream) -> io::Result<()> {
    let peer_addr = stream.peer_addr()?;
    println!("Accepted from: {}", peer_addr);

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
    let cmd = buffer[1]; // only support 0x01(CONNECT)
    let atype = buffer[3];

    let mut addr_port = String::from("");
    let mut flag_addr_ok = true;
    match cmd {
        0x01 => match atype {
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
                // ipv6: 6bytes + port
                reader.read_exact(&mut buffer[0..18]).await?;
                let mut tmp_array: [u8; 16] = Default::default();
                tmp_array.copy_from_slice(&buffer[0..16]);
                let v6addr = Ipv6Addr::from(tmp_array);
                let port: u16 = buffer[4..6].as_ref().get_u16();
                let socket = SocketAddrV6::new(v6addr, port, 0, 0);
                addr_port = format!("{}", socket);
                // println!("ipv6: {}", addr_port);
            }
            _ => {
                flag_addr_ok = false;
            }
        },
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

    if flag_addr_ok {
        //create connection to remote server
        if let Ok(remote_stream) = TcpStream::connect(addr_port.as_str()).await {
            println!("connect to {} ok", addr_port);
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
                        eprintln!("broken pipe: {}", e);
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
    } else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            format!("domain is not valid!"),
        ));
    }
    println!("disconnect from {}", peer_addr);
    Ok(())
}

fn main() -> io::Result<()> {
    let matches = App::new("Socks5 server in Rust")
        .version("1.0")
        .author("Lipeng (wang.lp@outlook.com)")
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

    let bind_addr = matches.value_of("bind").unwrap_or("127.0.0.1");
    let bind_port = matches.value_of("port").unwrap_or("8080");

    task::block_on(async {
        let listener = TcpListener::bind(format!("{}:{}", bind_addr, bind_port)).await?;
        println!("Listening on {}", listener.local_addr()?);

        let mut incoming = listener.incoming();

        while let Some(stream) = incoming.next().await {
            let stream = stream?;
            task::spawn(async {
                match process(stream).await {
                    Ok(()) => {}
                    Err(e) => {
                        eprintln!("broken pipe: {}", e);
                    }
                }
            });
        }
        Ok(())
    })
}
