//! `echo`: a trivial TCP echo server, so there is something for the exit
//! to reach (port of `allium_cli.py`'s `run_echo`/`cmd_echo`).
//!
//! Echoes each chunk straight back, prefixed with `echo:`, which is what a
//! real TCP peer would do for a stream. The prefix makes it obvious in
//! the client's output that the bytes made the full round trip.
//!
//! Python drives this with `asyncio.start_server` + `serve_forever`; this
//! uses a blocking [`std::net::TcpListener`] accept loop with a
//! [`std::thread`] per connection instead (no async runtime is vendored
//! here), polling [`crate::signals::should_stop`] between accepts so Ctrl-C/SIGTERM stop
//! the server promptly without blocking forever on `accept()`.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::time::Duration;

use crate::args::Args;
use crate::cli_error::CliExit;
use crate::helpers::{parse_addr, say};

fn handle_connection(mut stream: TcpStream) {
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break, // EOF: the peer closed its write side.
            Ok(n) => {
                say(&format!("echo: received {n} bytes, replying"));
                let mut reply = Vec::with_capacity(5 + n);
                reply.extend_from_slice(b"echo:");
                reply.extend_from_slice(&buf[..n]);
                if stream.write_all(&reply).is_err() {
                    break;
                }
            }
            // Mirrors Python's `except (ConnectionResetError,
            // asyncio.IncompleteReadError): pass` -- a reset or truncated
            // connection ends this handler quietly, not with a crash.
            Err(_) => break,
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
}

pub fn run_echo(args: &Args) -> Result<(), CliExit> {
    let bind_text = args.bind.as_deref().expect("build_parser requires --bind for the echo role");
    let bind = parse_addr(bind_text)?;

    let listener = TcpListener::bind((bind.0.as_str(), bind.1))
        .map_err(|e| CliExit::error(format!("echo: could not bind {}:{}: {e}", bind.0, bind.1)))?;
    // Non-blocking so the accept loop can poll should_stop() instead of
    // blocking forever in accept() -- see the module doc.
    listener
        .set_nonblocking(true)
        .map_err(|e| CliExit::error(format!("echo: could not configure listener: {e}")))?;

    crate::signals::install();
    say(&format!("echo: listening on ({:?}, {}) -- Ctrl-C to stop.", bind.0, bind.1));
    say("echo: this is the *destination* the exit connects to.\n");

    while !crate::signals::should_stop() {
        match listener.accept() {
            Ok((stream, _peer)) => {
                let _ = stream.set_nonblocking(false);
                std::thread::spawn(move || handle_connection(stream));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    Ok(())
}

pub fn cmd_echo(args: &Args) -> Result<(), CliExit> {
    run_echo(args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;

    /// `run_echo` itself never returns (it loops until a signal), so this
    /// exercises `handle_connection` directly against a real accepted
    /// socket pair -- the part with actual per-connection behavior to
    /// verify -- rather than the top-level accept loop.
    #[test]
    fn echoes_data_with_prefix_and_closes_on_eof() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_connection(stream);
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client.write_all(b"hello").unwrap();
        let mut buf = [0u8; 64];
        let n = client.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"echo:hello");

        client.write_all(b"world").unwrap();
        let n = client.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"echo:world");

        drop(client); // EOF on the server side
        server.join().unwrap();
    }
}
