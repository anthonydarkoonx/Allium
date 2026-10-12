//! `allium_cli.py`'s entry point, ported to Rust.
//!
//! Client build: this program only runs the end-user roles.
//!
//! * `client`  -- build a 3-hop circuit and serve a local SOCKS5 proxy over
//!   it (or `--fetch-onion` a `.allium` address once and exit).
//! * `service` -- host a `.allium` hidden service in front of a local
//!   server.
//! * `echo`    -- a trivial TCP echo server, as a demo destination.
//!
//! No async runtime is vendored in this sandbox, so every role here uses
//! blocking I/O and real OS threads instead of Python's `asyncio` -- the
//! same precedent already set
//! by `allium::socksproxy`, `allium::circuit` and `allium::handshake`.

mod apply_config;
mod args;
mod cli_error;
mod commands;
mod dirclient;
mod helpers;
mod hsclient;
mod hsserver;
mod owned_circuit;
mod pool;
mod signals;
mod transport;
mod vanguards;

use cli_error::CliExit;

fn run() -> Result<(), CliExit> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let parsed = args::parse_args(&raw)?;
    let resolved = if parsed.role == "echo" {
        // `echo` is just the demo's stand-in TCP destination, not a real
        // Allium role -- it has no [relay]/[client] shape to merge, so
        // apply_config is skipped for it rather than given an empty
        // no-op path.
        parsed
    } else {
        apply_config::apply_config(parsed)?
    };

    match resolved.role.as_str() {
        "echo" => commands::echo::cmd_echo(&resolved),
        "client" => commands::client::cmd_client(&resolved),
        "service" => hsserver::cmd_service(&resolved),
        other => Err(CliExit::error(format!("unknown role: {other}"))),
    }
}

fn main() {
    match run() {
        Ok(()) => {}
        Err(exit) => {
            if let Some(message) = &exit.message {
                eprintln!("{message}");
            }
            std::process::exit(exit.code);
        }
    }
}
