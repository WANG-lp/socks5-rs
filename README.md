[![Build](https://github.com/WANG-lp/socks5-rs/workflows/Rust-CI/badge.svg)](https://github.com/WANG-lp/socks5-rs/actions) 

# socks5-rs

A lightweight and fast socks5 server written in Rust

Fully async I/O with Rust [async-std](https://github.com/async-rs/async-std)! 

Recommend to use it in a trusted network (e.g., with [wireguard](https://www.wireguard.com/)).

Support `CONNECT` and `UDP Associate`.

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
Socks5 server in Rust 1.0
Lipeng (wang.lp@outlook.com)
A simple socks5 server

USAGE:
    socks5-rs [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -b, --bind <BIND_ADDR>    bind address
    -p, --port <BIND_PORT>    bind port
```

Example: `./target/release/socks5-rs -b 0.0.0.0 -p 8080`
