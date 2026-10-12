//! Layered "vanguards" for a hidden service's own circuits.
//!
//! A hidden service builds long-lived circuits whose far end is a relay it
//! does not control and an attacker may: an introduction point (picked at
//! random from the directory, so an attacker who runs relays is picked some
//! of the time) and a rendezvous point (named by the *client*, so it is
//! whatever relay the client likes). The relay at the far end sees the hop
//! before it. If that hop were always the same relay, or a fresh random one
//! each time, an attacker running relays would soon learn it, then learn the
//! one before it, and so walk back to the service's guard, which sees the
//! service's real address.
//!
//! Vanguards make that walk slow. Instead of a fixed or fresh-each-time
//! middle, each service keeps two small, persistent, slowly rotating sets:
//!
//! ```text
//!   guard  ->  layer 2  ->  layer 3  ->  far end
//!  (fixed)    (4 relays,   (8 relays,
//!              ~3 days)     ~1 hour)
//! ```
//!
//! * The **guard** is the service's long-lived guard (kept in
//!   `--hidden-service-dir`); it is not managed here.
//! * Both layers hold only relays that can extend a circuit onward (guard
//!   and middle roles, never exit: an exit terminates its circuits).
//! * **Layer 2** is up to [`L2_TARGET`] relays, each kept for a random time
//!   between [`L2_LIFETIME_SECS`]; **layer 3** is up to [`L3_TARGET`] relays,
//!   each kept for a random time between [`L3_LIFETIME_SECS`]. Each circuit
//!   picks one relay uniformly from each set.
//! * The sets are saved to disk, so a restart does not re-roll them (a
//!   service that restarts often would otherwise hand an attacker a fresh
//!   draw every time).
//!
//! An attacker who wants to learn layer 2 first has to be *chosen into* the
//! small layer-3 set, which only turns over about hourly; to learn the guard
//! from there it has to be chosen into the layer-2 set, which turns over in
//! days. Compare a fresh random hop per circuit, where every circuit is a new
//! draw.
//!
//! Everything random or time-dependent is passed in ([`Chooser`], `now`), so
//! the rotation behaviour is unit-testable.

use std::collections::{HashMap, HashSet};

use allium::directory::{Directory, RelayDescriptor, ROLE_EXIT, ROLE_GUARD, ROLE_MIDDLE};

use crate::helpers::{hex_decode, hex_encode, say};

/// Layer-2 set size.
pub const L2_TARGET: usize = 4;
/// Layer-3 set size.
pub const L3_TARGET: usize = 8;
/// How long one layer-2 relay is kept: uniformly random in this range, so the
/// set's members do not all rotate together. Mean 3 days.
pub const L2_LIFETIME_SECS: (f64, f64) = (2.0 * 86_400.0, 4.0 * 86_400.0);
/// How long one layer-3 relay is kept. Mean 1 hour.
pub const L3_LIFETIME_SECS: (f64, f64) = (30.0 * 60.0, 90.0 * 60.0);

const FILE_HEADER: &str = "allium-vanguards 1";

/// Source of uniform random choices. A trait so tests can be deterministic.
pub trait Chooser {
    /// A uniformly random integer in `0..n`. `n` is always at least 1.
    fn below(&mut self, n: usize) -> usize;
}

/// The real thing: bytes from the operating system's CSPRNG.
pub struct OsChooser;

impl Chooser for OsChooser {
    fn below(&mut self, n: usize) -> usize {
        debug_assert!(n > 0);
        // Rejection sampling, so the choice is exactly uniform (a bare `%`
        // would be very slightly biased toward small values).
        let n = n as u64;
        let limit = u64::MAX - (u64::MAX % n);
        loop {
            let bytes = allium::osrand::bytes(8);
            let v = u64::from_le_bytes(bytes.try_into().expect("osrand::bytes(8) is always 8 bytes"));
            if v < limit {
                return (v % n) as usize;
            }
        }
    }
}

/// One relay in a layer, and when it is retired.
#[derive(Debug, Clone, PartialEq)]
pub struct Vanguard {
    pub identity: [u8; 32],
    pub expires_at: f64,
}

/// The two persistent layers.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Vanguards {
    pub l2: Vec<Vanguard>,
    pub l3: Vec<Vanguard>,
}

/// Whether two hosts sit in the same /16 (IPv4) or /32 (IPv6), the same
/// coarse "same network" test used elsewhere in path selection. Names that
/// are not IP addresses are "the same" only if they are equal.
pub fn same_network(a: &str, b: &str) -> bool {
    use std::net::IpAddr;
    match (a.parse::<IpAddr>(), b.parse::<IpAddr>()) {
        (Ok(IpAddr::V4(x)), Ok(IpAddr::V4(y))) => x.octets()[..2] == y.octets()[..2],
        (Ok(IpAddr::V6(x)), Ok(IpAddr::V6(y))) => x.segments()[..2] == y.segments()[..2],
        _ => a == b,
    }
}

/// Whether `d` can serve as a *middle* hop, i.e. will extend a circuit onward.
///
/// An exit relay cannot: it registers every circuit created on it as already
/// routed (that is how it terminates them), so it refuses any further EXTEND.
/// A circuit that puts an exit anywhere but last therefore never completes.
/// Guards and middles both extend. A relay advertising the exit role is
/// treated as an exit whatever else it says.
pub fn can_extend(d: &RelayDescriptor) -> bool {
    let has = |role: &str| d.roles.iter().any(|r| r == role);
    (has(ROLE_MIDDLE) || has(ROLE_GUARD)) && !has(ROLE_EXIT)
}

fn identity_of(d: &RelayDescriptor) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(d.identity_public.as_slice()).ok()
}

fn lifetime(range: (f64, f64), rng: &mut dyn Chooser) -> f64 {
    const STEPS: usize = 1_000_000;
    range.0 + (range.1 - range.0) * (rng.below(STEPS + 1) as f64 / STEPS as f64)
}

impl Vanguards {
    /// Bring both layers up to date against `pool` (the live relays), as of
    /// `now`: retire entries that have expired or are no longer usable, then
    /// top each layer back up with random relays. Entries that are still
    /// valid are never touched, which is the whole point -- the sets stay
    /// put between calls. Returns whether anything changed (so the caller
    /// knows to save).
    ///
    /// `guard` are the identities of the service's own guard(s), which must
    /// not appear in either layer. Relays behind NAT are never used (they
    /// cannot be dialed directly), nor are exit relays (they cannot extend a
    /// circuit; see [`can_extend`]). The two layers never share a relay.
    ///
    /// In a small network the layer sizes shrink so that both layers can be
    /// filled; with fewer than two usable relays layer 3 stays empty, and
    /// [`Vanguards::pick_path`] then finds no path.
    pub fn refresh(&mut self, now: f64, pool: &[RelayDescriptor], guard: &[[u8; 32]], rng: &mut dyn Chooser) -> bool {
        let usable: HashMap<[u8; 32], &RelayDescriptor> =
            pool.iter().filter(|d| !d.behind_nat() && can_extend(d)).filter_map(|d| identity_of(d).map(|id| (id, d))).filter(|(id, _)| !guard.contains(id)).collect();
        let before = self.clone();

        self.l2.retain(|v| v.expires_at > now && usable.contains_key(&v.identity));
        self.l3.retain(|v| v.expires_at > now && usable.contains_key(&v.identity));
        // a relay never sits in both layers (a hand-edited or old file might say it does)
        let l2_ids: HashSet<[u8; 32]> = self.l2.iter().map(|v| v.identity).collect();
        self.l3.retain(|v| !l2_ids.contains(&v.identity));

        // Sorted, so that the draw below depends only on the pool's contents
        // and the chooser, not on hash-map iteration order.
        let mut all: Vec<[u8; 32]> = usable.keys().copied().collect();
        all.sort();
        let available = all.len();
        let l2_target = L2_TARGET.min((available / 3).max(1)).min(available);
        let l3_target = L3_TARGET.min(available.saturating_sub(l2_target));

        fill(&mut self.l2, l2_target, L2_LIFETIME_SECS, now, &all, &usable, &self.l3.iter().map(|v| v.identity).collect::<HashSet<_>>(), rng);
        fill(&mut self.l3, l3_target, L3_LIFETIME_SECS, now, &all, &usable, &self.l2.iter().map(|v| v.identity).collect::<HashSet<_>>(), rng);

        *self != before
    }

    /// Choose the two middle hops of one circuit to `target`: a layer-2 relay
    /// and a layer-3 relay, each uniformly at random from its layer, such that
    /// no two hops of the path are the same relay or in the same network.
    /// `None` if no such pair exists (an empty layer, or a network too small
    /// or too clustered).
    pub fn pick_path(
        &self,
        now: f64,
        directory: &Directory,
        guard_host: &str,
        target_identity: &[u8; 32],
        target_host: &str,
        rng: &mut dyn Chooser,
    ) -> Option<(RelayDescriptor, RelayDescriptor)> {
        let resolve = |layer: &[Vanguard]| -> Vec<RelayDescriptor> {
            layer
                .iter()
                .filter(|v| v.expires_at > now && &v.identity != target_identity)
                .filter_map(|v| directory.get(&v.identity).cloned())
                .filter(|d| can_extend(d) && !d.behind_nat() && !same_network(&d.host, guard_host) && !same_network(&d.host, target_host))
                .collect()
        };
        let mut l2 = resolve(&self.l2);
        let l3 = resolve(&self.l3);
        // Try layer-2 candidates in random order until one has a compatible layer-3 relay.
        while !l2.is_empty() {
            let second = l2.swap_remove(rng.below(l2.len()));
            let mut third: Vec<&RelayDescriptor> =
                l3.iter().filter(|d| d.identity_public != second.identity_public && !same_network(&d.host, &second.host)).collect();
            if !third.is_empty() {
                let pick = third.swap_remove(rng.below(third.len())).clone();
                return Some((second, pick));
            }
        }
        None
    }

    /// The on-disk form: a header line, then one `l2`/`l3` line per relay.
    pub fn to_text(&self) -> String {
        let mut out = format!("{FILE_HEADER}\n");
        for (tag, layer) in [("l2", &self.l2), ("l3", &self.l3)] {
            for v in layer {
                out.push_str(&format!("{tag} {} {}\n", hex_encode(&v.identity), v.expires_at));
            }
        }
        out
    }

    /// Parse [`Vanguards::to_text`] output. Never fails: a missing header or
    /// a malformed line is skipped (and counted), because a damaged state
    /// file must cost at worst a re-draw, never the service. Returns the
    /// parsed layers and how many lines were skipped.
    pub fn from_text(text: &str) -> (Vanguards, usize) {
        let mut v = Vanguards::default();
        let mut skipped = 0;
        let mut lines = text.lines();
        if lines.next().map(str::trim) != Some(FILE_HEADER) {
            return (v, if text.trim().is_empty() { 0 } else { 1 });
        }
        for line in lines.filter(|l| !l.trim().is_empty()) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let parsed = (|| {
                let [tag, hex, expires] = parts.as_slice() else { return None };
                let identity = <[u8; 32]>::try_from(hex_decode(hex).ok()?.as_slice()).ok()?;
                let expires_at: f64 = expires.parse().ok().filter(|e: &f64| e.is_finite())?;
                Some((*tag, Vanguard { identity, expires_at }))
            })();
            match parsed {
                Some(("l2", entry)) => v.l2.push(entry),
                Some(("l3", entry)) => v.l3.push(entry),
                _ => skipped += 1,
            }
        }
        (v, skipped)
    }

    /// Load from `path`; an absent or damaged file gives empty layers.
    pub fn load(path: &str) -> Vanguards {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let (v, skipped) = Vanguards::from_text(&text);
                if skipped > 0 {
                    say(&format!("service: vanguard state {path}: ignored {skipped} unreadable line(s)"));
                }
                v
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vanguards::default(),
            Err(e) => {
                say(&format!("service: vanguard state {path} is unreadable ({e}); starting with fresh layers"));
                Vanguards::default()
            }
        }
    }

    /// Save atomically to `path`, mode 0600 inside a 0700 directory.
    pub fn save(&self, path: &str) -> std::io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        if let Some(parent) = std::path::Path::new(path).parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
        let tmp = format!("{path}.tmp{}", std::process::id());
        let _ = std::fs::remove_file(&tmp);
        {
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
            if let Err(e) = f.write_all(self.to_text().as_bytes()) {
                let _ = std::fs::remove_file(&tmp);
                return Err(e);
            }
        }
        std::fs::rename(&tmp, path)
    }
}

/// Top `layer` up to `target` entries with random relays from `all`, skipping
/// any in `forbidden` or already in the layer, and preferring relays whose
/// network no existing member of the layer is in (relaxed if that leaves
/// nothing, so a clustered network still fills).
#[allow(clippy::too_many_arguments)]
fn fill(
    layer: &mut Vec<Vanguard>,
    target: usize,
    life: (f64, f64),
    now: f64,
    all: &[[u8; 32]],
    usable: &HashMap<[u8; 32], &RelayDescriptor>,
    forbidden: &HashSet<[u8; 32]>,
    rng: &mut dyn Chooser,
) {
    while layer.len() < target {
        let taken: HashSet<[u8; 32]> = layer.iter().map(|v| v.identity).collect();
        let open: Vec<[u8; 32]> = all.iter().copied().filter(|id| !taken.contains(id) && !forbidden.contains(id)).collect();
        if open.is_empty() {
            break;
        }
        let member_hosts: Vec<&str> = layer.iter().filter_map(|v| usable.get(&v.identity)).map(|d| d.host.as_str()).collect();
        let spread: Vec<[u8; 32]> =
            open.iter().copied().filter(|id| !member_hosts.iter().any(|h| same_network(&usable[id].host, h))).collect();
        let pool = if spread.is_empty() { &open } else { &spread };
        let identity = pool[rng.below(pool.len())];
        layer.push(Vanguard { identity, expires_at: now + lifetime(life, rng) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use allium::directory::{CreateOptions, DirectoryOptions};
    use ed25519_dalek::SigningKey;

    /// A deterministic chooser (xorshift), so a test can replay a draw.
    struct Seeded(u64);
    impl Chooser for Seeded {
        fn below(&mut self, n: usize) -> usize {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 % n as u64) as usize
        }
    }

    fn relay(host: &str) -> RelayDescriptor {
        let seed: [u8; 32] = allium::osrand::bytes(32).try_into().unwrap();
        let identity_private = SigningKey::from_bytes(&seed).to_bytes();
        RelayDescriptor::create(&identity_private, vec![7u8; 32], host, 9001, vec!["middle".to_string()], 86_400.0, None, CreateOptions::default()).unwrap()
    }

    fn id(d: &RelayDescriptor) -> [u8; 32] {
        identity_of(d).unwrap()
    }

    /// `n` relays, each in its own /16.
    fn spread_pool(n: usize) -> Vec<RelayDescriptor> {
        (0..n).map(|i| relay(&format!("{}.{}.0.1", 10 + i / 200, i % 200 + 1))).collect()
    }

    fn directory_of(pool: &[RelayDescriptor]) -> Directory {
        let mut d = Directory::new(DirectoryOptions::default()).unwrap();
        for r in pool {
            d.publish(r.clone()).unwrap();
        }
        d
    }

    const T0: f64 = 1_000_000.0;

    #[test]
    fn refresh_fills_both_layers_disjoint_and_without_the_guard() {
        let pool = spread_pool(30);
        let guard = [id(&pool[0])];
        let mut v = Vanguards::default();
        assert!(v.refresh(T0, &pool, &guard, &mut Seeded(1)));
        assert_eq!(v.l2.len(), L2_TARGET);
        assert_eq!(v.l3.len(), L3_TARGET);
        let l2: HashSet<_> = v.l2.iter().map(|e| e.identity).collect();
        let l3: HashSet<_> = v.l3.iter().map(|e| e.identity).collect();
        assert!(l2.is_disjoint(&l3), "a relay must not be in both layers");
        assert!(!l2.contains(&guard[0]) && !l3.contains(&guard[0]), "the guard must not be a vanguard");
    }

    /// The property everything rests on: until an entry expires, repeated
    /// refreshes leave the layers exactly as they were.
    #[test]
    fn the_layers_do_not_change_until_something_expires() {
        let pool = spread_pool(40);
        let mut v = Vanguards::default();
        v.refresh(T0, &pool, &[], &mut Seeded(7));
        let snapshot = v.clone();
        for step in 1..200 {
            // always well inside the shortest layer-3 lifetime
            let changed = v.refresh(T0 + step as f64 * 10.0, &pool, &[], &mut Seeded(step));
            assert!(!changed, "refresh at +{}s changed a layer that has not expired", step * 10);
        }
        assert_eq!(v, snapshot);
    }

    #[test]
    fn layer_three_turns_over_in_about_an_hour_and_layer_two_in_days() {
        let pool = spread_pool(60);
        let mut v = Vanguards::default();
        v.refresh(T0, &pool, &[], &mut Seeded(3));
        let l2_before: HashSet<_> = v.l2.iter().map(|e| e.identity).collect();
        let l3_before: HashSet<_> = v.l3.iter().map(|e| e.identity).collect();
        // 2 hours later every layer-3 entry has expired and been replaced; layer 2 has not moved
        v.refresh(T0 + 2.0 * 3600.0, &pool, &[], &mut Seeded(4));
        let l3_after: HashSet<_> = v.l3.iter().map(|e| e.identity).collect();
        assert_eq!(v.l2.iter().map(|e| e.identity).collect::<HashSet<_>>(), l2_before, "layer 2 must outlast layer 3");
        assert_eq!(v.l3.len(), L3_TARGET);
        assert!(l3_after.iter().filter(|i| l3_before.contains(*i)).count() < L3_TARGET, "layer 3 should have turned over");
        // 5 days later layer 2 has turned over as well
        v.refresh(T0 + 5.0 * 86_400.0, &pool, &[], &mut Seeded(5));
        let l2_after: HashSet<_> = v.l2.iter().map(|e| e.identity).collect();
        assert!(l2_after.len() == L2_TARGET && l2_after != l2_before);
    }

    #[test]
    fn lifetimes_fall_in_their_ranges_and_are_not_all_equal() {
        let pool = spread_pool(60);
        let mut v = Vanguards::default();
        v.refresh(T0, &pool, &[], &mut OsChooser);
        for e in &v.l2 {
            let life = e.expires_at - T0;
            assert!(life >= L2_LIFETIME_SECS.0 && life <= L2_LIFETIME_SECS.1, "layer-2 lifetime {life}");
        }
        for e in &v.l3 {
            let life = e.expires_at - T0;
            assert!(life >= L3_LIFETIME_SECS.0 && life <= L3_LIFETIME_SECS.1, "layer-3 lifetime {life}");
        }
        let distinct: HashSet<u64> = v.l3.iter().map(|e| e.expires_at.to_bits()).collect();
        assert!(distinct.len() > 1, "members must not all rotate at the same instant");
    }

    #[test]
    fn a_relay_that_leaves_the_directory_is_replaced() {
        let mut pool = spread_pool(30);
        let mut v = Vanguards::default();
        v.refresh(T0, &pool, &[], &mut Seeded(11));
        let gone = v.l2[0].identity;
        pool.retain(|d| id(d) != gone);
        assert!(v.refresh(T0 + 60.0, &pool, &[], &mut Seeded(12)));
        assert!(!v.l2.iter().any(|e| e.identity == gone));
        assert_eq!(v.l2.len(), L2_TARGET, "the layer is topped back up");
    }

    #[test]
    fn a_small_network_shrinks_the_layers_so_both_can_be_filled() {
        let pool = spread_pool(5);
        let mut v = Vanguards::default();
        v.refresh(T0, &pool, &[], &mut Seeded(2));
        assert!(!v.l2.is_empty() && !v.l3.is_empty(), "l2={} l3={}", v.l2.len(), v.l3.len());
        assert!(v.l2.len() + v.l3.len() <= 5);
        let one = spread_pool(1);
        let mut v1 = Vanguards::default();
        v1.refresh(T0, &one, &[], &mut Seeded(2));
        assert!(v1.l3.is_empty(), "with one usable relay there is no layer 3");
    }

    #[test]
    fn relays_behind_nat_are_never_used() {
        use allium::directory::EXT_REACHABILITY;
        let mut reach = vec![allium::nat::MODE_NAT];
        reach.extend_from_slice(&[9u8; 32]);
        reach.extend_from_slice(&[0u8; 32]);
        reach.push(12);
        reach.extend_from_slice(b"203.0.113.66");
        reach.extend_from_slice(&9999u16.to_be_bytes());
        let seed: [u8; 32] = allium::osrand::bytes(32).try_into().unwrap();
        let natted = RelayDescriptor::create(
            &SigningKey::from_bytes(&seed).to_bytes(),
            vec![7u8; 32],
            "99.1.0.1",
            9001,
            vec!["middle".to_string()],
            86_400.0,
            None,
            CreateOptions { extra_extensions: vec![(EXT_REACHABILITY, reach)], ..Default::default() },
        )
        .unwrap();
        assert!(natted.behind_nat());
        let mut pool = spread_pool(10);
        pool.push(natted.clone());
        let mut v = Vanguards::default();
        v.refresh(T0, &pool, &[], &mut Seeded(5));
        assert!(!v.l2.iter().chain(v.l3.iter()).any(|e| e.identity == id(&natted)));
    }

    #[test]
    fn members_of_one_layer_prefer_different_networks() {
        // 8 relays in one /16 and 8 spread out: layer 2 should avoid doubling up while it can
        let mut pool: Vec<RelayDescriptor> = (0..8).map(|i| relay(&format!("50.50.0.{}", i + 1))).collect();
        pool.extend(spread_pool(8));
        let mut v = Vanguards::default();
        v.refresh(T0, &pool, &[], &mut Seeded(9));
        let hosts: HashMap<[u8; 32], String> = pool.iter().map(|d| (id(d), d.host.clone())).collect();
        let in_clustered = v.l2.iter().filter(|e| hosts[&e.identity].starts_with("50.50.")).count();
        assert!(in_clustered <= 1, "layer 2 put {in_clustered} members in one /16 while other networks were available");
    }

    // -- pick_path ---------------------------------------------------------

    #[test]
    fn pick_path_gives_two_distinct_relays_not_the_guard_or_target_or_their_networks() {
        let pool = spread_pool(40);
        let directory = directory_of(&pool);
        let guard = &pool[0];
        let target = &pool[1];
        let mut v = Vanguards::default();
        v.refresh(T0, &pool, &[id(guard)], &mut Seeded(21));
        for seed in 0..300 {
            let (l2, l3) = v.pick_path(T0, &directory, &guard.host, &id(target), &target.host, &mut Seeded(seed + 100)).expect("a path exists");
            let ids = [id(guard), id(target), id(&l2), id(&l3)];
            assert_eq!(ids.iter().collect::<HashSet<_>>().len(), 4, "all four hops must be different relays");
            for (a, b) in [(&l2, &l3), (&l2, guard), (&l2, target), (&l3, guard), (&l3, target)] {
                assert!(!same_network(&a.host, &b.host));
            }
        }
    }

    #[test]
    fn pick_path_only_ever_uses_members_of_the_layers() {
        let pool = spread_pool(60);
        let directory = directory_of(&pool);
        let mut v = Vanguards::default();
        v.refresh(T0, &pool, &[id(&pool[0])], &mut Seeded(31));
        let l2: HashSet<_> = v.l2.iter().map(|e| e.identity).collect();
        let l3: HashSet<_> = v.l3.iter().map(|e| e.identity).collect();
        let mut seen2 = HashSet::new();
        let mut seen3 = HashSet::new();
        for seed in 0..2000 {
            let (a, b) = v.pick_path(T0, &directory, &pool[0].host, &id(&pool[1]), &pool[1].host, &mut Seeded(seed + 1)).unwrap();
            assert!(l2.contains(&id(&a)) && l3.contains(&id(&b)));
            seen2.insert(id(&a));
            seen3.insert(id(&b));
        }
        // 2000 circuits touch at most 4 + 8 distinct middle relays: the whole point
        assert!(seen2.len() <= L2_TARGET && seen3.len() <= L3_TARGET);
        assert!(seen2.len() >= L2_TARGET - 1 && seen3.len() >= L3_TARGET - 2, "picks should spread across the layers: {} / {}", seen2.len(), seen3.len());
    }

    #[test]
    fn pick_path_ignores_expired_entries_and_returns_none_when_nothing_fits() {
        let pool = spread_pool(30);
        let directory = directory_of(&pool);
        let mut v = Vanguards::default();
        v.refresh(T0, &pool, &[], &mut Seeded(41));
        assert!(v.pick_path(T0, &directory, &pool[0].host, &id(&pool[1]), &pool[1].host, &mut Seeded(1)).is_some());
        // far in the future, with no refresh: everything has expired
        assert!(v.pick_path(T0 + 30.0 * 86_400.0, &directory, &pool[0].host, &id(&pool[1]), &pool[1].host, &mut Seeded(1)).is_none());
        assert!(Vanguards::default().pick_path(T0, &directory, "1.1.1.1", &[0u8; 32], "2.2.2.2", &mut Seeded(1)).is_none());
    }

    // -- persistence ---------------------------------------------------------

    #[test]
    fn text_round_trips() {
        let pool = spread_pool(30);
        let mut v = Vanguards::default();
        v.refresh(T0, &pool, &[], &mut Seeded(51));
        let (back, skipped) = Vanguards::from_text(&v.to_text());
        assert_eq!(skipped, 0);
        assert_eq!(back, v);
    }

    #[test]
    fn damaged_state_costs_a_redraw_never_a_crash() {
        let good = {
            let pool = spread_pool(30);
            let mut v = Vanguards::default();
            v.refresh(T0, &pool, &[], &mut Seeded(52));
            v
        };
        // wrong header -> empty
        assert_eq!(Vanguards::from_text("garbage\nl2 00 1\n").0, Vanguards::default());
        assert_eq!(Vanguards::from_text("").0, Vanguards::default());
        // damaged lines are skipped and the good ones kept
        let mut text = good.to_text();
        text.push_str("l2 nothex 5\nl2 aa 5\nl4 ");
        text.push_str(&hex_encode(&[1u8; 32]));
        text.push_str(" 5\nl3 ");
        text.push_str(&hex_encode(&[2u8; 32]));
        text.push_str(" notanumber\nl3 ");
        text.push_str(&hex_encode(&[3u8; 32]));
        text.push_str(" NaN\njust one token\n");
        let (parsed, skipped) = Vanguards::from_text(&text);
        assert_eq!(parsed, good);
        assert_eq!(skipped, 6);
    }

    #[test]
    fn save_and_load_use_private_permissions_and_survive_a_restart() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("allium-vanguards-test-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("state").join("vanguards.state");
        let path = path.to_str().unwrap();
        assert_eq!(Vanguards::load(path), Vanguards::default(), "a missing file is just empty layers");
        let pool = spread_pool(30);
        let mut v = Vanguards::default();
        v.refresh(T0, &pool, &[], &mut Seeded(53));
        v.save(path).unwrap();
        assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(std::path::Path::new(path).parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
        // a "restart": load, and the same relays are still there
        let mut reloaded = Vanguards::load(path);
        assert_eq!(reloaded, v);
        assert!(!reloaded.refresh(T0 + 30.0, &pool, &[], &mut Seeded(54)), "a restart must not re-roll layers that have not expired");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn same_network_groups_by_slash_16() {
        assert!(same_network("10.1.2.3", "10.1.250.9"));
        assert!(!same_network("10.1.2.3", "10.2.2.3"));
        assert!(same_network("2001:db8:1::1", "2001:db8:ffff::1"));
        assert!(!same_network("2001:db8::1", "2001:db9::1"));
        assert!(same_network("host-a", "host-a"));
        assert!(!same_network("host-a", "host-b"));
    }

    #[test]
    fn os_chooser_is_in_range_and_not_constant() {
        let mut c = OsChooser;
        let draws: Vec<usize> = (0..200).map(|_| c.below(7)).collect();
        assert!(draws.iter().all(|d| *d < 7));
        assert!(draws.iter().collect::<HashSet<_>>().len() > 3);
        assert_eq!(c.below(1), 0);
    }

    /// A state file edited by hand (or written by something else) might name
    /// one relay in both layers; refresh must repair that, not trust it.
    #[test]
    fn a_relay_found_in_both_layers_is_removed_from_layer_three() {
        let pool = spread_pool(30);
        let shared = id(&pool[3]);
        let mut v = Vanguards {
            l2: vec![Vanguard { identity: shared, expires_at: T0 + 100_000.0 }],
            l3: vec![Vanguard { identity: shared, expires_at: T0 + 3_000.0 }],
        };
        v.refresh(T0, &pool, &[], &mut Seeded(61));
        assert!(v.l2.iter().any(|e| e.identity == shared), "layer 2 keeps it");
        assert!(!v.l3.iter().any(|e| e.identity == shared), "layer 3 must not also hold it");
        let l2: HashSet<_> = v.l2.iter().map(|e| e.identity).collect();
        assert!(v.l3.iter().all(|e| !l2.contains(&e.identity)));
    }

    /// Relays in the same network as the guard, the target, or each other must
    /// not end up together in one path. Layers are set up by hand so the
    /// clustered relays are definitely members.
    #[test]
    fn pick_path_never_puts_two_hops_of_one_path_in_the_same_network() {
        let guard = relay("1.1.1.1");
        let target = relay("3.3.3.3");
        let near_guard = relay("1.1.200.9"); // same /16 as the guard
        let near_target = relay("3.3.7.7"); // same /16 as the target
        let good2 = relay("40.1.0.1");
        let good3 = relay("41.1.0.1");
        let near_good2 = relay("40.1.9.9"); // same /16 as good2: a bad layer-3 partner for it
        let pool = [&guard, &target, &near_guard, &near_target, &good2, &good3, &near_good2];
        let directory = directory_of(&pool.iter().map(|d| (*d).clone()).collect::<Vec<_>>());
        let v = Vanguards {
            l2: vec![&near_guard, &near_target, &good2].into_iter().map(|d| Vanguard { identity: id(d), expires_at: T0 + 1e6 }).collect(),
            l3: vec![&near_good2, &good3].into_iter().map(|d| Vanguard { identity: id(d), expires_at: T0 + 1e6 }).collect(),
        };
        for seed in 0..300 {
            let (l2, l3) = v.pick_path(T0, &directory, &guard.host, &id(&target), &target.host, &mut Seeded(seed + 1)).expect("good2 + good3 is a valid pair");
            assert_eq!(id(&l2), id(&good2), "only good2 is clear of the guard's and the target's networks");
            assert_eq!(id(&l3), id(&good3), "near_good2 shares good2's network");
        }
        // and when the only candidates are clustered with each other, there is no path at all
        let clustered = Vanguards {
            l2: vec![Vanguard { identity: id(&good2), expires_at: T0 + 1e6 }],
            l3: vec![Vanguard { identity: id(&near_good2), expires_at: T0 + 1e6 }],
        };
        assert!(clustered.pick_path(T0, &directory, &guard.host, &id(&target), &target.host, &mut Seeded(1)).is_none());
    }

    fn relay_with_roles(host: &str, roles: &[&str]) -> RelayDescriptor {
        let seed: [u8; 32] = allium::osrand::bytes(32).try_into().unwrap();
        let identity_private = SigningKey::from_bytes(&seed).to_bytes();
        RelayDescriptor::create(&identity_private, vec![7u8; 32], host, 9001, roles.iter().map(|r| r.to_string()).collect(), 86_400.0, None, CreateOptions::default()).unwrap()
    }

    /// Found by running real relays: an exit relay refuses to extend a circuit,
    /// so an exit in a middle position means the circuit never completes.
    #[test]
    fn only_relays_that_can_extend_are_ever_used_as_vanguards() {
        // far more exits than middles, so a filter that is missing is very likely to show
        let mut pool: Vec<RelayDescriptor> = (0..40).map(|i| relay_with_roles(&format!("{}.{}.0.1", 10 + i / 200, i % 200 + 1), &["exit"])).collect();
        let middles: Vec<RelayDescriptor> = (0..6).map(|i| relay_with_roles(&format!("60.{}.0.1", i + 1), &["middle"])).collect();
        let guards: Vec<RelayDescriptor> = (0..3).map(|i| relay_with_roles(&format!("70.{}.0.1", i + 1), &["guard"])).collect();
        let odd = relay_with_roles("80.1.0.1", &["exit", "middle"]); // advertises exit: treated as an exit
        let nothing = relay_with_roles("80.2.0.1", &[]);
        pool.extend(middles.iter().cloned());
        pool.extend(guards.iter().cloned());
        pool.push(odd.clone());
        pool.push(nothing.clone());
        let allowed: HashSet<[u8; 32]> = middles.iter().chain(guards.iter()).map(id).collect();
        let directory = directory_of(&pool);
        for seed in 0..40u64 {
            let mut v = Vanguards::default();
            v.refresh(T0, &pool, &[], &mut Seeded(seed + 1));
            for e in v.l2.iter().chain(v.l3.iter()) {
                assert!(allowed.contains(&e.identity), "a relay that cannot extend (an exit, or one with no relay role) was chosen");
            }
            assert!(!v.l2.is_empty() && !v.l3.is_empty());
            if let Some((l2, l3)) = v.pick_path(T0, &directory, "1.1.1.1", &[9u8; 32], "2.2.2.2", &mut Seeded(seed + 9)) {
                assert!(can_extend(&l2) && can_extend(&l3));
            }
        }
        assert!(can_extend(&middles[0]) && can_extend(&guards[0]));
        assert!(!can_extend(&odd) && !can_extend(&nothing));
    }

    /// State saved by an older build may name an exit; it must not survive.
    #[test]
    fn an_exit_relay_found_in_saved_state_is_dropped_and_replaced() {
        let exit = relay_with_roles("90.1.0.1", &["exit"]);
        let mut pool: Vec<RelayDescriptor> = (0..12).map(|i| relay_with_roles(&format!("60.{}.0.1", i + 1), &["middle"])).collect();
        pool.push(exit.clone());
        let mut v = Vanguards {
            l2: vec![Vanguard { identity: id(&exit), expires_at: T0 + 1e6 }],
            l3: vec![],
        };
        v.refresh(T0, &pool, &[], &mut Seeded(5));
        assert!(!v.l2.iter().chain(v.l3.iter()).any(|e| e.identity == id(&exit)));
        assert_eq!(v.l2.len(), L2_TARGET.min(12 / 3));
    }
}
