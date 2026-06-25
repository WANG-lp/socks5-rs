//! A lightweight, fully-async SOCKS5 server library.
//!
//! Supports the `CONNECT` and `UDP ASSOCIATE` commands (RFC 1928) and optional
//! username/password authentication (RFC 1929).

pub mod connection;
pub mod protocol;
pub mod udp;

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

pub use connection::Config;

/// Accept connections from `listener` forever, handling each one on its own
/// task. Only fatal listener errors propagate; transient `accept` failures are
/// logged and retried after a short back-off.
pub async fn serve(listener: TcpListener, config: Arc<Config>) -> std::io::Result<()> {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let config = Arc::clone(&config);
                tokio::spawn(async move {
                    if let Err(e) = connection::handle(stream, peer, config).await {
                        log::debug!("connection {peer} ended: {e}");
                    }
                });
            }
            Err(e) => {
                // e.g. EMFILE/ENFILE under load — don't spin the CPU.
                log::warn!("accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}
