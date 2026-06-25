[![Build](https://github.com/WANG-lp/socks5-rs/workflows/Rust-CI/badge.svg)](https://github.com/WANG-lp/socks5-rs/actions) 

# socks5-rs

A lightweight and fast socks5 server written in Rust

Fully async I/O with Tokio! 

## Features

- `CONNECT` (TCP) and `UDP ASSOCIATE` (UDP) commands (RFC 1928)
- IPv4, IPv6 and domain-name targets
- Optional username/password authentication (RFC 1929)
- DNS resolution on the proxy side (`socks5h`), trying every resolved address
- Half-close aware, back-pressured TCP relay with large I/O buffers

Recommend to use it in a trusted network (e.g., with [wireguard](https://www.wireguard.com/)),
or enable username/password authentication when exposing it more widely.

NOTE: `BIND` is intentionally not implemented; it is rejected with
`Command not supported` (REP `0x07`).

## Compiling
install Rust toolchain: [click here to install Rust](https://www.rust-lang.org/tools/install) 


### From crates.io

```bash
cargo install socks5-rs
```

### From source

```bash
git clone git@github.com:WANG-lp/socks5-rs.git
cd socks5-rs
cargo build --release
```


## Usage

`./target/release/socks5-rs -h`

```bash
A lightweight and fast SOCKS5 server written in Rust

Usage: socks5-rs [OPTIONS]

Options:
  -b, --bind <BIND>            Address to bind [default: 127.0.0.1]
  -p, --port <PORT>            Port to listen on [default: 8080]
  -t, --work-threads <N>       Number of worker threads [default: 4]
  -u, --username <USERNAME>    Username for auth (RFC 1929); requires --password
  -P, --password <PASSWORD>    Password for auth (RFC 1929); requires --username
      --handshake-timeout <S>  Handshake/request timeout in seconds [default: 15]
      --connect-timeout <S>    Outbound CONNECT timeout in seconds [default: 15]
  -h, --help                   Print help
  -V, --version                Print version
```

Examples:

```bash
# open proxy on all interfaces
./target/release/socks5-rs -b 0.0.0.0 -p 8080

# require username/password authentication
./target/release/socks5-rs -b 0.0.0.0 -p 8080 -u alice -P s3cret
```
