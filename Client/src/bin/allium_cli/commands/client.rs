//! `client`: build a 3-hop circuit and serve a local SOCKS5 proxy over it
//! (or `--fetch-onion` a `.allium` address once and exit). Port of
//! `allium_cli.py`'s `run_client`/`run_self_test`/`_keepalive_loop`/
//! `_hidden_service_connect_for_socks`/`cmd_client`.
//!
//! No async runtime is vendored, so every task Python spawns with
//! `asyncio.create_task` is a real `std::thread` here instead: the primary
//! circuit's return-path pump, the keepalive loop, and (inside
//! [`crate::pool::CircuitPool`]) one more pump per isolated circuit it
//! builds. `stopping: Arc<AtomicBool>` is this binary's replacement for
//! Python's `asyncio.Event` -- checked instead of awaited, and shared the
//! same way: created before `pool` and before `server` so one shutdown
//! stops every circuit's pump together.

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use allium::fragment::{encode_fragment, Fragmenter};
use allium::socks::{decode_reply, encode_request, StreamRequest, CONNECT, SUCCESS};
use allium::socksproxy::{Onion, SocksServer, SocksServerOptions};

use crate::args::Args;
use crate::cli_error::CliExit;
use crate::dirclient::{build_circuit, CircuitBuildOutcome};
use crate::helpers::{parse_addr, say, set_large_rcvbuf, sleep_or_wake, KEEPALIVE_PING};
use crate::pool::{make_onion, pump_return_path, CircuitPool};
use crate::transport::CircuitTransport;

pub fn cmd_client(args: &Args) -> Result<(), CliExit> {
    let mut args = args.clone();
    let code = run_client(&mut args)?;
    if code != 0 {
        return Err(CliExit { code, message: None });
    }
    Ok(())
}

/// Adapter wiring the interactive SOCKS5 proxy's `.allium` CONNECT path to
/// `hsclient::connect_hidden_service`, converting that function's
/// process-ending [`CliExit`] failures into an ordinary [`SocksError`] that
/// only ends the one failed connection -- see the Python original's
/// `_hidden_service_connect_for_socks` docstring for why that conversion
/// matters here specifically (this proxy may be serving other, healthy
/// connections at the same moment).
fn hidden_service_connect_for_socks(
    args: &Args,
    host: &str,
) -> Result<Arc<dyn allium::socksproxy::HiddenServiceConnection>, allium::socksproxy::SocksError> {
    crate::hsclient::connect_hidden_service(args, host).map_err(|exit| {
        if let Some(message) = &exit.message {
            say(message);
        }
        allium::socksproxy::SocksError(allium::socksproxy::REPLY_GENERAL)
    })
}

fn run_client(args: &mut Args) -> Result<i32, CliExit> {
    if let Some(address) = args.fetch_onion.clone() {
        // A hidden-service fetch is its own circuit shape entirely (an
        // introduction circuit and a rendezvous circuit, not a normal
        // guard/middle/exit one) -- see connect_hidden_service -- so this
        // branches before the ordinary circuit build below rather than
        // trying to fit it through the same path.
        return crate::hsclient::run_fetch_onion(args, &address);
    }

    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| CliExit::error(format!("client: could not bind a UDP socket: {e}")))?;
    // See CircuitTransport/pump_return_path's own docs: the receive path
    // is what actually enforces this per-call bound via short slices, so
    // the socket-level timeout only needs to be at least that long.
    set_large_rcvbuf(&sock);
    let timeout = Duration::from_secs_f64(args.timeout.unwrap_or(5.0));
    let local_addr = sock.local_addr().ok();
    say(&format!("client: bound UDP socket at {local_addr:?}\n"));

    let owned = match build_circuit(args, sock) {
        Ok(o) => o,
        Err(CircuitBuildOutcome::Exit(e)) => return Err(e),
        Err(CircuitBuildOutcome::NoReplyFromGuard) => {
            say("\nclient: no reply from the guard.  Is the guard running, and is UDP reaching it?");
            return Ok(1);
        }
        Err(CircuitBuildOutcome::Failed { kind, message }) => {
            say(&format!("\nclient: circuit build failed: {kind}: {message}"));
            return Ok(1);
        }
    };

    let transport = Arc::new(CircuitTransport::new(owned, !args.no_congestion.unwrap_or(false)));

    if args.self_test.unwrap_or(false) {
        return run_self_test(args, &transport);
    }

    // -- Interactive mode: run a real SOCKS5 proxy over the circuit. -------

    // `stopping` has to exist before `pool` (its per-circuit pump threads
    // all share it, so one Ctrl-C/shutdown stops every circuit's
    // return-path loop together) and before `server`.
    let stopping = Arc::new(AtomicBool::new(false));
    let primary_onion = make_onion(Arc::clone(&transport));

    // `--isolate-by-destination` (on unless `--no-isolate-by-destination`):
    // the pool always exists, isolation or not -- with it off, every
    // destination maps to one shared key (the primary), until a CONNECT
    // fails and `retry_onion` moves new streams to a replacement circuit.
    // SOCKS username/password scopes are folded into the key either way.
    // See `CircuitPool`'s own doc.
    let pool = Arc::new(CircuitPool::new(
        args.clone(),
        Arc::clone(&transport),
        primary_onion.clone(),
        Arc::clone(&stopping),
        args.isolate_by_destination.unwrap_or(true),
    ));

    let mtu = args.mtu.unwrap_or(256).max(1) as usize;
    let socks_port = args.socks_port.unwrap_or(9050).clamp(0, u16::MAX as i64) as u16;

    let router_pool = Arc::clone(&pool);
    let datagram_router_pool = Arc::clone(&pool);
    let retry_pool = Arc::clone(&pool);
    let started_pool = Arc::clone(&pool);
    let finished_pool = Arc::clone(&pool);
    let hs_args = args.clone();
    // UDP ASSOCIATE datagrams used to be wired straight to the primary
    // transport here (`datagram_transport =
    // Arc::clone(&transport)`, sent via a fixed `onion_datagram`
    // closure), bypassing this pool entirely -- so UDP traffic never got
    // `--isolate-by-destination` isolation and never rotated off the
    // primary circuit even after the rest of this was fixed. Route each
    // datagram through the pool instead, keyed by *its own* destination,
    // exactly like a stream's CONNECT does via `onion_router` below.
    let datagram_transport = Arc::clone(&transport);

    let options = SocksServerOptions {
        host: "127.0.0.1".to_string(),
        port: socks_port,
        allow_udp: args.allow_udp.unwrap_or(false),
        mtu,
        // `on_client_datagram` only falls back to this when
        // `onion_datagram_router` is `None` entirely -- never happens in
        // this wiring, since the router below is always set -- so this is
        // effectively unreachable here. Still wired to the primary
        // (rather than left `None`) so that stays true if the router is
        // ever made optional again, and so unit tests that build a
        // `SocksServerOptions` without a pool still see a working, if
        // unisolated, UDP path.
        onion_datagram: Some(Arc::new(move |payload: &[u8]| datagram_transport.send_datagram(payload))),
        onion_datagram_router: Some(Arc::new(move |host: &str, port: u16, scope: Option<&str>| {
            datagram_router_pool.datagram_onion_for(host, port, scope)
        })),
        // Always wired in (rather than only when --authority is set): a
        // client run without one still gets a clean, connection-scoped
        // failure message for a `.allium` CONNECT, not a silent ordinary-
        // exit attempt that would just fail DNS resolution.
        hidden_service_connect: Some(Arc::new(move |host: &str, _port: u16| hidden_service_connect_for_socks(&hs_args, host))),
        onion_router: Some(Arc::new(move |host: &str, port: u16, scope: Option<&str>| router_pool.onion_for(host, port, scope))),
        onion_retry: Some(Arc::new(
            move |host: &str, port: u16, scope: Option<&str>, failed: Option<Onion>, reason: Option<&str>| {
                retry_pool.retry_onion(host, port, scope, failed, reason)
            },
        )),
        onion_stream_started: Some(Arc::new(move |onion: &Onion| started_pool.stream_started(onion))),
        onion_stream_finished: Some(Arc::new(move |onion: &Onion| finished_pool.stream_finished(onion))),
        max_connect_attempts: args.connect_attempts.unwrap_or(3).max(1) as u32,
        connect_timeout: Duration::from_secs_f64(args.connect_timeout.unwrap_or(15.0)),
        retry_connect_timeout: None,
    };

    let server = SocksServer::new(primary_onion.clone(), options).map_err(|e| CliExit::error(format!("client: {e}")))?;
    pool.attach(Arc::clone(&server));

    let handle = match Arc::clone(&server).spawn() {
        Ok(h) => h,
        Err(e) => {
            say(&format!("client: could not bind 127.0.0.1:{socks_port}: {e}"));
            say("  something else is already listening there -- pick another port with --socks-port.");
            return Ok(1);
        }
    };

    say(&"=".repeat(68));
    say(&format!("SOCKS5 proxy listening on 127.0.0.1:{socks_port}"));
    say(&"=".repeat(68));
    say("Point an application at it, e.g.:");
    say(&format!("    curl --socks5-hostname 127.0.0.1:{socks_port} http://{}/", args.target.clone().unwrap_or_default()));
    if args.authority.is_some() {
        say("Any hostname ending in .allium is routed to that hidden service");
        say("automatically, e.g.:");
        say(&format!("    curl --socks5-hostname 127.0.0.1:{socks_port} http://ADDRESS.allium/"));
    }
    say("\nAny traffic the application sends is fragmented into cells, sent");
    say("through the 3-hop circuit, and answered by the exit.");
    say("Ctrl-C to stop.\n");

    crate::signals::install();

    // Pump return-path cells back into the SOCKS server for the primary
    // circuit -- one copy of the same loop `CircuitPool` runs for every
    // isolated circuit it builds.
    let pump_handle = {
        let transport = Arc::clone(&transport);
        let onion = primary_onion.clone();
        let server = Arc::clone(&server);
        let stopping = Arc::clone(&stopping);
        let own_stop = Arc::new(AtomicBool::new(false));
        std::thread::spawn(move || pump_return_path(transport, onion, server, timeout, stopping, own_stop, "client".to_string()))
    };

    let keepalive_interval = args.keepalive_interval.unwrap_or(90.0);
    let keepalive_handle = if keepalive_interval > 0.0 {
        say(&format!(
            "client: sending a keepalive every {keepalive_interval}s so this circuit doesn't go idle \
             and get pruned mid-session (--keepalive-interval 0 to disable)\n"
        ));
        let pool = Arc::clone(&pool);
        let stopping = Arc::clone(&stopping);
        Some(std::thread::spawn(move || {
            while !stopping.load(Ordering::SeqCst) {
                let slept = sleep_or_wake(Duration::from_secs_f64(keepalive_interval), &stopping);
                if !slept || stopping.load(Ordering::SeqCst) {
                    break;
                }
                for transport in pool.live_transports() {
                    transport.send(KEEPALIVE_PING);
                }
            }
        }))
    } else {
        None
    };

    // Runs until interrupted (Ctrl-C/SIGTERM -- see crate::signals) or
    // told to stop some other way.
    while !stopping.load(Ordering::SeqCst) && !crate::signals::should_stop() {
        std::thread::sleep(Duration::from_millis(150));
    }
    stopping.store(true, Ordering::SeqCst);

    handle.stop();
    pool.aclose();
    let _ = pump_handle.join();
    if let Some(h) = keepalive_handle {
        let _ = h.join();
    }
    Ok(0)
}

/// Sleep up to `duration`, waking early (returning `false`) if `stopping`
/// is set -- so the keepalive loop's long sleep doesn't delay shutdown by
/// a whole interval.
/// Remove every occurrence of `b"echo:"` from `data` (Python's
/// `bytes.replace(b"echo:", b"")`), for stripping the built-in `echo`
/// server's per-chunk reply prefix back out of a collected self-test
/// response.
fn strip_echo_prefix(data: &[u8]) -> Vec<u8> {
    const NEEDLE: &[u8] = b"echo:";
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i..].starts_with(NEEDLE) {
            i += NEEDLE.len();
        } else {
            out.push(data[i]);
            i += 1;
        }
    }
    out
}

/// Drive one CONNECT + data round trip through the circuit, printing each
/// step -- the scripted equivalent of pointing `curl` at the SOCKS proxy.
/// Port of `allium_cli.py`'s `run_self_test`.
fn run_self_test(args: &Args, transport: &Arc<CircuitTransport>) -> Result<i32, CliExit> {
    let target = parse_addr(args.target.as_deref().unwrap_or("127.0.0.1:9100"))?;
    let timeout = Duration::from_secs_f64(args.timeout.unwrap_or(5.0));

    say(&"=".repeat(68));
    say("SELF-TEST: CONNECT through the circuit");
    say(&"=".repeat(68));
    say(&format!("target: {target:?} (reached by the *exit*, not by this client)"));

    let request = StreamRequest::new(CONNECT, 1, target.0.clone(), target.1);
    let encoded = match encode_request(&request) {
        Ok(b) => b,
        Err(e) => return Err(CliExit::error(format!("client: could not encode CONNECT: {e}"))),
    };
    transport.send_stream_request(&encoded);
    say(&format!("client: sent CONNECT; {} cell(s) on the wire", transport.sent_cells.load(Ordering::Relaxed)));

    let received = match transport.receive(timeout) {
        Ok(r) => r,
        Err(e) => {
            say(&format!(
                "\nclient: NO REPLY from the circuit ({e}).\n  check the exit's terminal, and that \
                 --target points at the echo server.\n  if the exit denied it, look for a policy \
                 message there; a private target needs --allow-private on BOTH ends."
            ));
            return Ok(1);
        }
    };

    let reply = match decode_reply(&received.payload) {
        Ok(r) => r,
        Err(e) => {
            say(&format!("client: reply did not parse: {e}"));
            return Ok(1);
        }
    };
    if reply.status != SUCCESS {
        say(&format!("client: exit REFUSED the destination (status {}).", reply.status));
        say(
            "  That is the exit policy working: the port is not in its allow-list, or the target is \
             private and --allow-private is off.",
        );
        return Ok(1);
    }
    say(&format!("client: exit accepted it -- stream id {}", reply.stream_id));
    say("        (the CONNECTED reply travelled back through all three hops)\n");

    let body: Vec<u8> = "fragmentation-test-".repeat(40).into_bytes();
    say(&"=".repeat(68));
    say("SELF-TEST: fragmented data round trip");
    say(&"=".repeat(68));
    say(&format!(
        "client: sending {} bytes (one cell carries ~275), so this must be split into fragments ...",
        body.len()
    ));
    let mtu = args.mtu.unwrap_or(256).max(1) as usize;
    let fragmenter = match Fragmenter::new(mtu, reply.stream_id) {
        Ok(f) => f,
        Err(e) => return Err(CliExit::error(format!("client: {e}"))),
    };
    for fragment in fragmenter.fragment(&body) {
        transport.send(&encode_fragment(&fragment));
    }
    say(&format!("client: {} cell(s) sent in total", transport.sent_cells.load(Ordering::Relaxed)));

    let mut received_bytes: Vec<u8> = Vec::new();
    let deadline = Instant::now() + Duration::from_secs_f64((args.timeout.unwrap_or(5.0) * 6.0).max(15.0));
    let mut consecutive_timeouts = 0;
    while Instant::now() < deadline {
        match transport.receive(timeout) {
            Ok(r) => {
                consecutive_timeouts = 0;
                if r.payload.is_empty() {
                    continue;
                }
                received_bytes.extend_from_slice(&r.payload);
                let plain = strip_echo_prefix(&received_bytes);
                if plain.len() >= body.len() {
                    break;
                }
            }
            Err(_) => {
                consecutive_timeouts += 1;
                if consecutive_timeouts >= 3 {
                    break;
                }
                continue;
            }
        }
    }

    // The last `transport.receive()` this self-test will make for this
    // stream -- see the Python original's long comment on why this ack
    // matters: without it, the exit keeps blindly resending the
    // already-delivered tail for a real, multi-second window.
    transport.force_ack(reply.stream_id);

    let plain = strip_echo_prefix(&received_bytes);
    if received_bytes.is_empty() {
        say("client: nothing came back.  Check the exit's terminal.");
        return Ok(1);
    }
    if plain == body {
        say(&format!("client: got {} bytes back, PAYLOAD INTACT", plain.len()));
        say("        fragmentation, the return path, and exit egress all worked.");
    } else {
        say(&format!("client: MISMATCH -- {} of {} bytes came back", plain.len(), body.len()));
        return Ok(1);
    }

    say(&format!(
        "\nclient: cells sent {}, received {}",
        transport.sent_cells.load(Ordering::Relaxed),
        transport.received_cells.load(Ordering::Relaxed)
    ));
    if let Some((cwnd, loss_events)) = transport.congestion_snapshot() {
        say(&format!("client: congestion window ended at {cwnd} (started at 4), loss events {loss_events}"));
    }
    Ok(0)
}
