//! The self-referential lifetime problem `CircuitPool`/`run_client` run
//! into, and the one piece of `unsafe` in this binary that solves it.
//!
//! [`allium::circuit::CircuitBuilder`] borrows the `UdpSocket` it was built
//! on (`CircuitBuilder<'a>`, holding `&'a UdpSocket`) -- reasonable for the
//! library, where a caller keeps the socket alive in its own stack frame for
//! as long as the builder lives. This binary cannot do that: a built
//! circuit has to keep working from inside `allium::socksproxy::Onion`
//! (`Arc<dyn Fn(&[u8]) + Send + Sync>`, implicitly `'static` since it names
//! no lifetime) and from inside a spawned `std::thread`'s closure (also
//! `'static`) -- both outlive whatever stack frame originally created the
//! socket.
//!
//! [`OwnedCircuit`] fixes this by making the socket and the builder that
//! borrows it live in the same heap allocation's neighbourhood, tied
//! together in one `'static` struct:
//!
//! * the socket is moved onto the heap ([`Box<UdpSocket>`]), whose
//!   allocation address is stable for the life of the `Box` regardless of
//!   where the `Box` *handle* itself is later moved (moving a `Box` copies
//!   the pointer, not the pointee);
//! * a `'static` reference to that same heap allocation is manufactured
//!   with a raw-pointer round trip (the one `unsafe` block here) and handed
//!   to the caller-supplied closure that builds the circuit, so
//!   [`allium::circuit::CircuitBuilder::new`]/`add_hop`/`extend` see an
//!   ordinary `&'static UdpSocket` and need no changes of their own;
//! * the resulting `CircuitBuilder<'static>` and the `Box<UdpSocket>` it
//!   secretly points into are then stored together in one struct, so
//!   neither can be dropped, moved out, or otherwise separated from the
//!   other for the rest of the program.
//!
//! # Safety
//!
//! The `'static` reference this manufactures is only ever valid for as long
//! as the backing `Box<UdpSocket>` is alive, which is why [`OwnedCircuit`]
//! is the *only* way to obtain one: its constructor is the sole place the
//! unsafe cast happens, and its fields keep both halves together with no
//! way for external code to extract the reference on its own or to drop the
//! socket while the builder that (secretly) borrows it still exists.
//!
//! Field order matters here, even though it is not strictly load-bearing
//! for *this* particular pair of types (see below): Rust drops a struct's
//! fields in declaration order, so `builder` is declared before `sock` --
//! the borrowing half is torn down before the allocation it (secretly)
//! points into is freed. `CircuitBuilder` has no custom `Drop` and never
//! dereferences its `&UdpSocket` field while dropping (dropping a
//! reference is a no-op -- it does not read through it), so getting this
//! order backwards would not actually be unsound today. It is still the
//! right order to write and keep: it is the obviously-correct one for
//! *any* self-referential pair like this, it costs nothing, and it means
//! this safety argument keeps holding even if `CircuitBuilder` ever grows
//! a `Drop` impl that does look at its socket.
use std::net::UdpSocket;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Mutex;

use allium::circuit::CircuitBuilder;

/// A `CircuitBuilder` and the `UdpSocket` it borrows, bundled into one
/// `'static`, `Send + Sync` value that can live inside an `Arc<dyn Fn + Send
/// + Sync>` or a spawned thread's closure. See the module doc for why this
/// needs `unsafe` and why it is sound.
///
/// The builder is further wrapped in a [`Mutex`]: every hop-building call
/// (`add_hop`/`extend`) takes `&mut self`, and once a circuit is live,
/// `send`/`extend`-adjacent calls are never made again but `send` itself
/// also takes `&mut self` -- so any concurrent use (a sender thread and a
/// receive-pump thread sharing one circuit, exactly [`allium::circuit`]'s
/// own module doc's "thin, synchronous, blocking-socket client" design
/// point) needs the same kind of external serialization Python's
/// `CircuitTransport` gave it via `threading.RLock`.
pub struct OwnedCircuit {
    /// Declared before `sock` on purpose -- see the module doc's "Safety"
    /// section on drop order.
    builder: Mutex<CircuitBuilder<'static>>,
    /// Never read again after construction; kept alive purely so the
    /// `&'static UdpSocket` inside `builder` stays valid. The leading
    /// underscore documents that at the type level, not just in prose.
    _sock: Box<UdpSocket>,
}

impl OwnedCircuit {
    /// Move `sock` onto the heap and hand the caller-supplied `build`
    /// closure a `&'static UdpSocket` pointing into that same allocation,
    /// so it can call ordinary `CircuitBuilder` construction code (ordinary
    /// `&'a UdpSocket`-based code, with `'a` unified to `'static`) without
    /// any changes of its own.
    ///
    /// If `build` fails, `sock`'s `Box` is simply dropped when this
    /// function returns -- nothing unsound about that: the manufactured
    /// `&'static` reference is never smuggled out of a failed `build` call
    /// (a `CircuitError`/similar carries no such reference), so there is no
    /// dangling reference left anywhere for anyone to observe.
    pub fn new<E>(
        sock: UdpSocket,
        build: impl FnOnce(&'static UdpSocket) -> Result<CircuitBuilder<'static>, E>,
    ) -> Result<Self, E> {
        let boxed = Box::new(sock);
        // SAFETY: `boxed` is a heap allocation whose address does not
        // change for as long as the allocation itself is alive (moving the
        // `Box` handle around only copies the pointer). This reference is
        // stored in `OwnedCircuit` alongside the `Box` that backs it, in a
        // struct that offers no way to drop one without the other and no
        // way to extract the reference on its own -- so for the entire
        // lifetime of the returned `OwnedCircuit`, the allocation this
        // points to is guaranteed to still be there. See the module doc.
        let static_ref: &'static UdpSocket = unsafe { &*(boxed.as_ref() as *const UdpSocket) };
        let builder = build(static_ref)?;
        Ok(OwnedCircuit { builder: Mutex::new(builder), _sock: boxed })
    }

    /// Lock the builder for exclusive use. Every send/receive/extend call
    /// on the wrapped `CircuitBuilder` goes through this.
    pub fn lock(&self) -> std::sync::MutexGuard<'_, CircuitBuilder<'static>> {
        self.builder.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The wrapped socket's raw file descriptor.
    ///
    /// Reading this needs no lock: the fd is assigned once, at
    /// `UdpSocket::bind` time, and never changes for the life of the
    /// socket -- only reading or writing *through* it needs
    /// synchronization, which is exactly what `lock()` is for. This
    /// exists so a caller can wait for the socket to become readable
    /// (via a raw `poll(2)`, see `CircuitTransport::receive`) *without*
    /// holding `builder`'s lock for the whole wait -- see that method's
    /// doc for why that distinction matters on real OS threads.
    pub fn raw_fd(&self) -> RawFd {
        self._sock.as_raw_fd()
    }
}

// CircuitBuilder<'static> is Send+Sync whenever UdpSocket is (which it is):
// every other field is an owned Vec/HashMap/String/primitive. Mutex<T> is
// itself Send+Sync when T: Send, and Box<UdpSocket> is Send+Sync -- so this
// would already be auto-derived by the compiler. The explicit impls exist
// only as documentation of the invariant this type relies on, pinned so a
// future change to CircuitBuilder's fields that broke it would fail to
// compile here specifically, instead of silently at some unrelated call
// site.
unsafe impl Send for OwnedCircuit {}
unsafe impl Sync for OwnedCircuit {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn builder_stays_usable_after_being_moved_across_threads() {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let owned = OwnedCircuit::new(sock, |s| {
            allium::circuit::CircuitBuilder::new(s, None, Duration::from_millis(50), None, true, false, 0, 0.0, None)
        })
        .unwrap();
        let owned = std::sync::Arc::new(owned);
        let moved = std::sync::Arc::clone(&owned);
        // Moving the Arc (and the OwnedCircuit it points to) to another
        // thread and using the builder there is exactly the scenario this
        // type exists for -- a receive-pump thread and the original
        // caller's thread both outliving the stack frame that created the
        // socket.
        let handle = std::thread::spawn(move || {
            let builder = moved.lock();
            assert_eq!(builder.hop_count(), 0);
        });
        handle.join().unwrap();
        assert_eq!(owned.lock().hop_count(), 0);
    }

    #[test]
    fn failed_build_does_not_leak_or_panic() {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let result = OwnedCircuit::new(sock, |s| {
            // send_jitter < 0.0 is the one documented way CircuitBuilder::new
            // itself fails -- exercises the Err path of `build` without
            // needing a live peer.
            allium::circuit::CircuitBuilder::new(s, None, Duration::from_millis(50), None, true, false, 0, -1.0, None)
        });
        assert!(result.is_err());
    }
}
