use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use chrono::Local;
use clap::Parser;
use env_logger::Builder;
use log::LevelFilter;

use socks5_rs::{Config, serve};

#[derive(Parser)]
#[command(
    name = "socks5-rs",
    version,
    about = "A lightweight and fast SOCKS5 server written in Rust"
)]
struct Opts {
    /// Address to bind
    #[arg(short, long, default_value = "127.0.0.1")]
    bind: String,
    /// Port to listen on
    #[arg(short, long, default_value_t = 8080)]
    port: u16,
    /// Number of worker threads
    #[arg(short = 't', long, default_value_t = 4)]
    work_threads: u16,
    /// Username for username/password auth (RFC 1929); requires --password
    #[arg(short, long, requires = "password")]
    username: Option<String>,
    /// Password for username/password auth (RFC 1929); requires --username
    #[arg(short = 'P', long, requires = "username")]
    password: Option<String>,
    /// Handshake/request timeout in seconds
    #[arg(long, default_value_t = 15)]
    handshake_timeout: u64,
    /// Outbound CONNECT timeout in seconds
    #[arg(long, default_value_t = 15)]
    connect_timeout: u64,
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
        .parse_default_env() // honour RUST_LOG when set
        .init();

    let opts = Opts::parse();

    let config = Arc::new(Config {
        auth: match (opts.username, opts.password) {
            (Some(user), Some(pass)) => Some((user, pass)),
            _ => None,
        },
        handshake_timeout: Duration::from_secs(opts.handshake_timeout),
        connect_timeout: Duration::from_secs(opts.connect_timeout),
    });

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(opts.work_threads.max(1) as usize)
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind((opts.bind.as_str(), opts.port)).await?;
        log::info!("SOCKS5 server listening on {}", listener.local_addr()?);
        if config.auth.is_some() {
            log::info!("username/password authentication is enabled");
        }
        serve(listener, config).await
    })
}
