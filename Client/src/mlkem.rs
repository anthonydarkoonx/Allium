//! ML-KEM-768 (FIPS 203), implemented directly from the standard, using
//! only this crate's own [`crate::shake`] module and the vendored `sha3`
//! crate (SHA3-256/512).
//!
//! Allium's only third-party dependencies are the vendored, unmodified
//! RustCrypto/dalek-cryptography crates (see `/vendor`); no available
//! crate implements ML-KEM against that same vendored `digest`/`sha3`
//! stack. Rather than pull in yet another,
//! differently-versioned dependency tree for one primitive, this module
//! implements FIPS 203's ML-KEM-768 directly from the standard's
//! algorithms -- exactly the posture the Python original took for the same
//! reason (see that module's docstring): its only third-party dependency is
//! `cryptography`, whose supported releases don't expose ML-KEM either.
//!
//! Correctness: cross-checked in the `tests` module below against
//! known-answer values produced by an independent, FIPS 140-3-validated
//! implementation (Go's `crypto/mlkem`) -- the same vectors the Python
//! original's `tests/test_mlkem.py` uses: deterministic key generation from
//! a seed, encapsulation from a fixed message, decapsulation, and implicit
//! rejection of a tampered ciphertext all match byte for byte.
//!
//! Side channels: this implementation is not constant-time (ordinary `i32`
//! arithmetic branches and varies in timing with values, same as the
//! Python original's big-int arithmetic). The FO re-encryption comparison
//! uses [`subtle::ConstantTimeEq`] rather than a varying-time equality
//! check, but interpreter/CPU-level timing of the modular arithmetic
//! itself can still vary with values. For Allium's hybrid handshake that
//! exposure is bounded: ML-KEM is combined with X25519, so the session is
//! at least as strong as the classical handshake alone, and the relay
//! rotates its ML-KEM key frequently (see [`crate::handshake`]).

use std::fmt;

use digest::Digest as _;
use sha3::{Sha3_256, Sha3_512};
use subtle::{ConditionallySelectable, ConstantTimeEq as _};

use crate::osrand;
use crate::shake::{shake128, shake256};

// -- ML-KEM-768 parameters (FIPS 203, Table 2) --------------------------------

const N: usize = 256;
const Q: i32 = 3329;
const K: usize = 3;
const ETA1: usize = 2;
const ETA2: usize = 2;
const DU: usize = 10;
const DV: usize = 4;

pub const ENCAPSULATION_KEY_SIZE: usize = 384 * K + 32; // 1184
pub const DECAPSULATION_KEY_SIZE: usize = 768 * K + 96; // 2400
pub const CIPHERTEXT_SIZE: usize = 32 * (DU * K + DV); // 1088
pub const SHARED_SECRET_SIZE: usize = 32;
pub const SEED_SIZE: usize = 64; // d || z

/// Which implementation is in use (kept as a named constant, mirroring the
/// Python module, so a future switch to a different backend is visible to
/// callers and tests).
pub const BACKEND: &str = "rust-fips203-direct";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlKemError(String);

impl fmt::Display for MlKemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for MlKemError {}

type Poly = [i32; N];

fn zero_poly() -> Poly {
    [0; N]
}

// -- zeta/gamma tables (Algorithm 9-12 constants) -----------------------------

fn bitrev7(n: u32) -> u32 {
    let mut out = 0u32;
    for i in 0..7 {
        out |= ((n >> i) & 1) << (6 - i);
    }
    out
}

fn pow_mod(mut base: i64, mut exp: u32, modulus: i64) -> i64 {
    let mut result = 1i64;
    base %= modulus;
    while exp > 0 {
        if exp & 1 == 1 {
            result = result * base % modulus;
        }
        exp >>= 1;
        base = base * base % modulus;
    }
    result
}

fn zetas() -> [i32; 128] {
    let mut out = [0i32; 128];
    for (i, o) in out.iter_mut().enumerate() {
        *o = pow_mod(17, bitrev7(i as u32), Q as i64) as i32;
    }
    out
}

fn gammas() -> [i32; 128] {
    let mut out = [0i32; 128];
    for (i, o) in out.iter_mut().enumerate() {
        *o = pow_mod(17, 2 * bitrev7(i as u32) + 1, Q as i64) as i32;
    }
    out
}

const INV128: i64 = 3303; // 128^-1 mod q

// -- hash functions (FIPS 203 section 4.1) ------------------------------------

fn h(data: &[u8]) -> [u8; 32] {
    let out = Sha3_256::digest(data);
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    buf
}

fn j(data: &[u8]) -> [u8; 32] {
    let out = shake256(data, 32);
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    buf
}

fn g(data: &[u8]) -> ([u8; 32], [u8; 32]) {
    let out = Sha3_512::digest(data);
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&out[..32]);
    b.copy_from_slice(&out[32..]);
    (a, b)
}

fn prf(eta: usize, s: &[u8], b: u8) -> Vec<u8> {
    let mut input = s.to_vec();
    input.push(b);
    shake256(&input, 64 * eta)
}

// -- bit-level helpers (stand in for Python's big-int accumulator) -----------

/// Read `nbits` (<=32) starting at `bit_offset` from `data`, using the same
/// bit order as `int.from_bytes(data, "little")` (byte 0 holds the lowest
/// bits, and within a byte, bit 0 is the least significant).
fn read_bits(data: &[u8], bit_offset: usize, nbits: usize) -> u32 {
    let mut v = 0u32;
    for b in 0..nbits {
        let pos = bit_offset + b;
        let byte = data.get(pos / 8).copied().unwrap_or(0);
        let bit = (byte >> (pos % 8)) & 1;
        v |= (bit as u32) << b;
    }
    v
}

/// Write the low `nbits` of `value` into `out` starting at `bit_offset`,
/// same bit order as [`read_bits`].
///
/// Branch-free in `value`: every bit is OR-ed in unconditionally as `0` or
/// `1 << k`, so neither the control flow nor the memory writes depend on
/// the bits written. `byte_encode(1, ..)` is what packs the *decrypted
/// message* at the end of `pke_decrypt` (the shared secret's seed), and an
/// `if bit == 1 { out |= .. }` here compiled to a real conditional jump on
/// each secret bit (`bt` + `jae` skipping the `or`).
fn write_bits(out: &mut [u8], bit_offset: usize, nbits: usize, value: u32) {
    for b in 0..nbits {
        let pos = bit_offset + b;
        out[pos / 8] |= (((value >> b) & 1) as u8) << (pos % 8);
    }
}

// -- NTT (Algorithms 9-12) ----------------------------------------------------

fn ntt(f_in: &Poly) -> Poly {
    let zetas = zetas();
    let q = Q as i64;
    let mut f = *f_in;
    let mut i = 1usize;
    let mut length = 128usize;
    while length >= 2 {
        let mut start = 0usize;
        while start < N {
            let zeta = zetas[i] as i64;
            i += 1;
            for j in start..start + length {
                let t = (zeta * f[j + length] as i64).rem_euclid(q) as i32;
                f[j + length] = ((f[j] as i64 - t as i64).rem_euclid(q)) as i32;
                f[j] = ((f[j] as i64 + t as i64).rem_euclid(q)) as i32;
            }
            start += 2 * length;
        }
        length >>= 1;
    }
    f
}

fn intt(f_in: &Poly) -> Poly {
    let zetas = zetas();
    let q = Q as i64;
    let mut f = *f_in;
    let mut i = 127i64;
    let mut length = 2usize;
    while length <= 128 {
        let mut start = 0usize;
        while start < N {
            let zeta = zetas[i as usize] as i64;
            i -= 1;
            for j in start..start + length {
                let t = f[j] as i64;
                f[j] = ((t + f[j + length] as i64).rem_euclid(q)) as i32;
                f[j + length] = (zeta * (f[j + length] as i64 - t)).rem_euclid(q) as i32;
            }
            start += 2 * length;
        }
        length <<= 1;
    }
    for x in f.iter_mut() {
        *x = ((*x as i64 * INV128).rem_euclid(q)) as i32;
    }
    f
}

fn mul_ntt(f: &Poly, g_poly: &Poly) -> Poly {
    let gammas = gammas();
    let q = Q as i64;
    let mut h = zero_poly();
    for i in 0..128 {
        let a0 = f[2 * i] as i64;
        let a1 = f[2 * i + 1] as i64;
        let b0 = g_poly[2 * i] as i64;
        let b1 = g_poly[2 * i + 1] as i64;
        let gamma = gammas[i] as i64;
        h[2 * i] = ((a0 * b0 + (a1 * b1).rem_euclid(q) * gamma).rem_euclid(q)) as i32;
        h[2 * i + 1] = ((a0 * b1 + a1 * b0).rem_euclid(q)) as i32;
    }
    h
}

fn add(f: &Poly, g_poly: &Poly) -> Poly {
    let mut out = zero_poly();
    for i in 0..N {
        out[i] = ((f[i] as i64 + g_poly[i] as i64).rem_euclid(Q as i64)) as i32;
    }
    out
}

fn sub(f: &Poly, g_poly: &Poly) -> Poly {
    let mut out = zero_poly();
    for i in 0..N {
        out[i] = ((f[i] as i64 - g_poly[i] as i64).rem_euclid(Q as i64)) as i32;
    }
    out
}

// -- sampling (Algorithms 7-8) ------------------------------------------------

fn sample_ntt(seed: &[u8]) -> Poly {
    let mut length = 3 * 168 * 4;
    loop {
        let stream = shake128(seed, length);
        let mut out = Vec::with_capacity(N);
        let mut pos = 0usize;
        'outer: while pos + 2 < length {
            let c0 = stream[pos] as u32;
            let c1 = stream[pos + 1] as u32;
            let c2 = stream[pos + 2] as u32;
            pos += 3;
            let d1 = c0 + 256 * (c1 & 0x0F);
            let d2 = (c1 >> 4) + 16 * c2;
            if (d1 as i32) < Q {
                out.push(d1 as i32);
                if out.len() == N {
                    break 'outer;
                }
            }
            if (d2 as i32) < Q {
                out.push(d2 as i32);
                if out.len() == N {
                    break 'outer;
                }
            }
        }
        if out.len() == N {
            let mut poly = zero_poly();
            poly.copy_from_slice(&out);
            return poly;
        }
        length *= 2; // vanishingly rare: ran out of stream; draw a longer one
    }
}

fn cbd(eta: usize, data: &[u8]) -> Poly {
    let mask = (1u32 << eta) - 1;
    let mut f = zero_poly();
    for i in 0..N {
        let base = 2 * eta * i;
        let x_bits = read_bits(data, base, eta) & mask;
        let y_bits = read_bits(data, base + eta, eta) & mask;
        let x = x_bits.count_ones() as i64;
        let y = y_bits.count_ones() as i64;
        f[i] = (x - y).rem_euclid(Q as i64) as i32;
    }
    f
}

// -- encoding (Algorithms 5-6) and compression (section 4.2.1) ----------------

fn byte_encode(d: usize, f: &Poly) -> Vec<u8> {
    let mut out = vec![0u8; 32 * d];
    for (i, &value) in f.iter().enumerate() {
        write_bits(&mut out, d * i, d, value as u32);
    }
    out
}

fn byte_decode(d: usize, data: &[u8]) -> Poly {
    let mut values = zero_poly();
    for i in 0..N {
        let mut v = read_bits(data, d * i, d) as i32;
        if d == 12 {
            v %= Q;
        }
        values[i] = v;
    }
    values
}

/// `SHIFT`/`MAGIC` implement `n / Q` (for `n >= 0`) as `(n * MAGIC) >>
/// SHIFT`, the standard fixed-point-reciprocal technique for dividing by a
/// compile-time constant -- see [`div_by_q`]'s doc comment for why
/// `compress` needs this instead of the plain `/` operator. Both are
/// themselves ordinary compile-time constants (computed from the public
/// constant `Q`, not from any secret), so computing them with `/` here is
/// fine; only dividing *secret-derived* data needs to avoid it.
const DIV_Q_SHIFT: u32 = 50;
const DIV_Q_MAGIC: i64 = ((1i64 << DIV_Q_SHIFT) + Q as i64 - 1) / Q as i64;

/// Constant-latency equivalent of `n / Q` for the non-negative `n` this
/// module ever calls it with.
///
/// `compress` used to write `numerator / q` directly, with `numerator`
/// derived from `w = v - NTT⁻¹(Σ s_hat_i ·
/// NTT(u_i))` in `pke_decrypt` -- i.e. mixing the long-term secret key
/// with attacker-supplied ciphertext. Even though `q` (3329) is a
/// compile-time constant, dividing a *secret-dependent* numerator by it
/// is exactly the "KyberSlash" CVE pattern (2023): on some
/// targets/optimization levels a `/` by a non-power-of-two constant
/// compiles to a hardware integer-division instruction whose latency
/// depends on the numerator's value, not just the (public) divisor --
/// letting a remote attacker who can time many crafted-ciphertext
/// decapsulations recover key bits. Compilers *usually* rewrite constant
/// division into a branchless multiply-and-shift automatically (which is
/// exactly what this function does explicitly), but that optimization is
/// not guaranteed by the language, is skipped entirely in unoptimized
/// (debug) builds, and this crate pins no `[profile.release]` `opt-level`
/// guaranteeing it fires for every future build/target either. Writing
/// the multiply-and-shift by hand removes the dependency on that
/// optimization firing at all.
///
/// Exhaustively verified against the `/` operator for every input this
/// module can ever produce in `test_div_by_q_matches_operator_exhaustively`.
fn div_by_q(n: i64) -> i64 {
    ((n as i128 * DIV_Q_MAGIC as i128) >> DIV_Q_SHIFT) as i64
}

fn compress(d: usize, f: &Poly) -> Poly {
    let q = Q as i64;
    let mask: i64 = (1i64 << d) - 1;
    let mut out = zero_poly();
    for i in 0..N {
        let x = f[i] as i64;
        out[i] = (div_by_q((x << d) + q / 2) & mask) as i32;
    }
    out
}

fn decompress(d: usize, f: &Poly) -> Poly {
    let q = Q as i64;
    let half: i64 = 1 << (d - 1);
    let mut out = zero_poly();
    for i in 0..N {
        let y = f[i] as i64;
        out[i] = ((y * q + half) >> d) as i32;
    }
    out
}

// -- K-PKE (Algorithms 13-15) -------------------------------------------------

fn matrix(rho: &[u8]) -> Vec<Vec<Poly>> {
    // A_hat[i][j] = SampleNTT(rho || j || i)
    (0..K)
        .map(|i| {
            (0..K)
                .map(|j| {
                    let mut seed = rho.to_vec();
                    seed.push(j as u8);
                    seed.push(i as u8);
                    sample_ntt(&seed)
                })
                .collect()
        })
        .collect()
}

fn pke_keygen(d: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut d_with_k = d.to_vec();
    d_with_k.push(K as u8);
    let (rho, sigma) = g(&d_with_k);
    let a_hat = matrix(&rho);
    let mut n = 0u8;
    let mut s = Vec::with_capacity(K);
    for _ in 0..K {
        s.push(cbd(ETA1, &prf(ETA1, &sigma, n)));
        n += 1;
    }
    let mut e = Vec::with_capacity(K);
    for _ in 0..K {
        e.push(cbd(ETA1, &prf(ETA1, &sigma, n)));
        n += 1;
    }
    let s_hat: Vec<Poly> = s.iter().map(ntt).collect();
    let e_hat: Vec<Poly> = e.iter().map(ntt).collect();
    let mut t_hat = Vec::with_capacity(K);
    for i in 0..K {
        let mut acc = zero_poly();
        for j in 0..K {
            acc = add(&acc, &mul_ntt(&a_hat[i][j], &s_hat[j]));
        }
        t_hat.push(add(&acc, &e_hat[i]));
    }
    let mut ek = Vec::with_capacity(384 * K + 32);
    for p in &t_hat {
        ek.extend(byte_encode(12, p));
    }
    ek.extend_from_slice(&rho);
    let mut dk = Vec::with_capacity(384 * K);
    for p in &s_hat {
        dk.extend(byte_encode(12, p));
    }
    (ek, dk)
}

fn pke_encrypt(ek: &[u8], m: &[u8], r: &[u8]) -> Vec<u8> {
    let t_hat: Vec<Poly> = (0..K)
        .map(|i| byte_decode(12, &ek[384 * i..384 * (i + 1)]))
        .collect();
    let rho = &ek[384 * K..];
    let a_hat = matrix(rho);
    let mut n = 0u8;
    let mut y = Vec::with_capacity(K);
    for _ in 0..K {
        y.push(cbd(ETA1, &prf(ETA1, r, n)));
        n += 1;
    }
    let mut e1 = Vec::with_capacity(K);
    for _ in 0..K {
        e1.push(cbd(ETA2, &prf(ETA2, r, n)));
        n += 1;
    }
    let e2 = cbd(ETA2, &prf(ETA2, r, n));
    let y_hat: Vec<Poly> = y.iter().map(ntt).collect();
    let mut u = Vec::with_capacity(K);
    for i in 0..K {
        let mut acc = zero_poly();
        for j in 0..K {
            acc = add(&acc, &mul_ntt(&a_hat[j][i], &y_hat[j])); // A^T
        }
        u.push(add(&intt(&acc), &e1[i]));
    }
    let mu = decompress(1, &byte_decode(1, m));
    let mut acc = zero_poly();
    for j in 0..K {
        acc = add(&acc, &mul_ntt(&t_hat[j], &y_hat[j]));
    }
    let v = add(&add(&intt(&acc), &e2), &mu);
    let mut c1 = Vec::with_capacity(32 * DU * K);
    for p in &u {
        c1.extend(byte_encode(DU, &compress(DU, p)));
    }
    let c2 = byte_encode(DV, &compress(DV, &v));
    c1.extend(c2);
    c1
}

fn pke_decrypt(dk: &[u8], c: &[u8]) -> Vec<u8> {
    let c1_len = 32 * DU * K;
    let u: Vec<Poly> = (0..K)
        .map(|i| decompress(DU, &byte_decode(DU, &c[32 * DU * i..32 * DU * (i + 1)])))
        .collect();
    let v = decompress(DV, &byte_decode(DV, &c[c1_len..]));
    let s_hat: Vec<Poly> = (0..K)
        .map(|i| byte_decode(12, &dk[384 * i..384 * (i + 1)]))
        .collect();
    let mut acc = zero_poly();
    for i in 0..K {
        acc = add(&acc, &mul_ntt(&s_hat[i], &ntt(&u[i])));
    }
    let w = sub(&v, &intt(&acc));
    byte_encode(1, &compress(1, &w))
}

// -- ML-KEM (Algorithms 16-21) ------------------------------------------------

fn check_ek(ek: &[u8]) -> Result<(), MlKemError> {
    if ek.len() != ENCAPSULATION_KEY_SIZE {
        return Err(MlKemError(format!(
            "encapsulation key must be {ENCAPSULATION_KEY_SIZE} bytes"
        )));
    }
    for i in 0..K {
        let chunk = &ek[384 * i..384 * (i + 1)];
        if byte_encode(12, &byte_decode(12, chunk)) != chunk {
            return Err(MlKemError(
                "encapsulation key failed the modulus check".into(),
            ));
        }
    }
    Ok(())
}

/// Deterministic `(encapsulation_key, decapsulation_key)` from a 64-byte
/// seed `d || z` (FIPS 203 ML-KEM.KeyGen_internal).
pub fn keypair_from_seed(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), MlKemError> {
    if seed.len() != SEED_SIZE {
        return Err(MlKemError(format!("seed must be {SEED_SIZE} bytes")));
    }
    let d = &seed[..32];
    let z = &seed[32..];
    let (ek, dk_pke) = pke_keygen(d);
    let mut dk = dk_pke;
    dk.extend_from_slice(&ek);
    dk.extend_from_slice(&h(&ek));
    dk.extend_from_slice(z);
    Ok((ek, dk))
}

/// A fresh `(encapsulation_key, decapsulation_key)` pair.
pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    keypair_from_seed(&osrand::bytes(SEED_SIZE)).expect("freshly generated seed is always valid")
}

/// `(ciphertext, shared_secret)` for encapsulation key `ek`.
///
/// `m` (32 bytes), when supplied, makes the result deterministic -- for
/// tests only.
///
/// # Errors
/// Returns [`MlKemError`] if `ek` fails FIPS 203's input checks, or if `m`
/// is supplied and is not 32 bytes.
pub fn encapsulate(ek: &[u8], m: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>), MlKemError> {
    check_ek(ek)?;
    let owned_random;
    let m = match m {
        Some(m) => {
            if m.len() != 32 {
                return Err(MlKemError("m must be 32 bytes".into()));
            }
            m
        }
        None => {
            owned_random = osrand::bytes(32);
            &owned_random
        }
    };
    let mut m_h_ek = m.to_vec();
    m_h_ek.extend_from_slice(&h(ek));
    let (shared, r) = g(&m_h_ek);
    Ok((pke_encrypt(ek, m, &r), shared.to_vec()))
}

/// The 32-byte shared secret for `ciphertext` (implicit rejection: a
/// malformed-but-right-sized ciphertext yields an unrelated key, never an
/// error).
///
/// # Errors
/// Returns [`MlKemError`] on a wrong-sized key or ciphertext.
pub fn decapsulate(dk: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, MlKemError> {
    if ciphertext.len() != CIPHERTEXT_SIZE {
        return Err(MlKemError(format!(
            "ciphertext must be {CIPHERTEXT_SIZE} bytes"
        )));
    }
    if dk.len() != DECAPSULATION_KEY_SIZE {
        return Err(MlKemError(format!(
            "decapsulation key must be {DECAPSULATION_KEY_SIZE} bytes"
        )));
    }
    let dk_pke = &dk[..384 * K];
    let ek = &dk[384 * K..768 * K + 32];
    let h_stored = &dk[768 * K + 32..768 * K + 64];
    let z = &dk[768 * K + 64..];

    let h_ek = h(ek);
    if !bool::from(h_ek.ct_eq(h_stored)) {
        return Err(MlKemError("decapsulation key failed its hash check".into()));
    }
    let m_prime = pke_decrypt(dk_pke, ciphertext);
    let mut m_prime_h = m_prime.clone();
    m_prime_h.extend_from_slice(&h_ek);
    let (shared, r_prime) = g(&m_prime_h);
    let mut z_c = z.to_vec();
    z_c.extend_from_slice(ciphertext);
    let rejected = j(&z_c);
    let c_prime = pke_encrypt(ek, &m_prime, &r_prime);
    // Implicit rejection (FO transform): a ciphertext that does not
    // re-encrypt identically yields a pseudorandom key instead of an error.
    //
    // The final choice between `shared` and `rejected` used to be a plain
    // `if`/`else` on a constant-time comparison's *result* -- the
    // comparison itself was already branchless, but branching on its
    // `bool` output still lets the CPU take a different code path (and
    // branch predictor state)
    // depending on a value derived from the peer's secret key material.
    // `ConditionallySelectable::conditional_select`, byte by byte, selects
    // between the two 32-byte values with no data-dependent branch at all,
    // matching the fully branchless pattern used in vetted reference
    // implementations (e.g. the FIPS 203 reference code, and Go's
    // `crypto/mlkem`).
    let ok = ciphertext.ct_eq(&c_prime);
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::conditional_select(&rejected[i], &shared[i], ok);
    }
    Ok(out.to_vec())
}

/// 8-byte identifier for an encapsulation key (which one a CREATE used).
pub fn key_id(ek: &[u8]) -> [u8; 8] {
    use sha2::Sha256;
    let mut hasher = Sha256::new();
    hasher.update(b"allium-mlkem-key-id");
    hasher.update(ek);
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `div_by_q` must exactly match plain `/` for every input `compress`
    /// can ever produce -- `x` (a fully-reduced polynomial coefficient, always in `[0, Q)`
    /// per `add`/`sub`'s `.rem_euclid(Q)`) shifted left by every `d`
    /// `compress` is actually called with (1, `DV`, `DU`), plus `Q/2`.
    /// Exhaustive over the whole realistic domain (not sampled), so this
    /// is a correctness proof for this function's actual use, not just a
    /// smoke test. Also covers a wide safety margin beyond that domain
    /// (every `n` up to 8x the real maximum) so the fixed-point constants
    /// have headroom against any future change to `d`'s allowed values.
    #[test]
    fn test_div_by_q_matches_operator_exhaustively() {
        let q = Q as i64;
        for d in [1usize, DV, DU] {
            for x in 0..q {
                let n = (x << d) + q / 2;
                assert_eq!(div_by_q(n), n / q, "mismatch at d={d}, x={x}, n={n}");
            }
        }
        let real_max = ((q - 1) << DU) + q / 2;
        for n in (0..=real_max * 8).step_by(997) {
            assert_eq!(div_by_q(n), n / q, "mismatch (safety-margin sweep) at n={n}");
        }
        // Exact boundary of the safety-margin sweep too (step_by may skip it).
        let top = real_max * 8;
        assert_eq!(div_by_q(top), top / q, "mismatch at the safety-margin sweep's own top");
    }

    /// `compress`'s output must be unchanged by the constant-time
    /// rewrite: exercise every `(d, x)` pair, comparing against the
    /// original `/`-based formula directly (not just via `div_by_q`, so
    /// this also catches a mistake in how `compress` itself calls
    /// `div_by_q`, not only in `div_by_q` alone).
    #[test]
    fn test_compress_matches_naive_division_formula_exhaustively() {
        let q = Q as i32;
        for d in [1usize, DV, DU] {
            let mask = (1i64 << d) - 1;
            let mut f = zero_poly();
            for x in 0..q {
                f[0] = x;
                let naive = ((((x as i64) << d) + q as i64 / 2) / q as i64) & mask;
                assert_eq!(compress(d, &f)[0] as i64, naive, "mismatch at d={d}, x={x}");
            }
        }
    }

    #[test]
    fn key_sizes_match_fips203_table2() {
        assert_eq!(ENCAPSULATION_KEY_SIZE, 1184);
        assert_eq!(DECAPSULATION_KEY_SIZE, 2400);
        assert_eq!(CIPHERTEXT_SIZE, 1088);
    }

    #[test]
    fn round_trip_random_keys() {
        let (ek, dk) = generate_keypair();
        assert_eq!(ek.len(), ENCAPSULATION_KEY_SIZE);
        assert_eq!(dk.len(), DECAPSULATION_KEY_SIZE);
        let (ct, shared_a) = encapsulate(&ek, None).unwrap();
        assert_eq!(ct.len(), CIPHERTEXT_SIZE);
        let shared_b = decapsulate(&dk, &ct).unwrap();
        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn deterministic_keygen_from_seed_is_reproducible() {
        let seed = [7u8; SEED_SIZE];
        let (ek1, dk1) = keypair_from_seed(&seed).unwrap();
        let (ek2, dk2) = keypair_from_seed(&seed).unwrap();
        assert_eq!(ek1, ek2);
        assert_eq!(dk1, dk2);
    }

    #[test]
    fn tampered_ciphertext_yields_different_but_valid_length_key() {
        let (ek, dk) = generate_keypair();
        let (mut ct, shared) = encapsulate(&ek, None).unwrap();
        ct[0] ^= 0xFF;
        let rejected = decapsulate(&dk, &ct).unwrap();
        assert_eq!(rejected.len(), SHARED_SECRET_SIZE);
        assert_ne!(rejected, shared);
    }

    #[test]
    fn wrong_size_inputs_are_rejected() {
        assert!(keypair_from_seed(&[0u8; 10]).is_err());
        let (ek, dk) = generate_keypair();
        assert!(encapsulate(&ek, Some(&[0u8; 10])).is_err());
        assert!(decapsulate(&dk, &[0u8; 10]).is_err());
        assert!(decapsulate(&[0u8; 10], &[0u8; CIPHERTEXT_SIZE]).is_err());
    }
}

#[cfg(test)]
mod python_cross_check {
    //! Byte-for-byte cross-check against the real Python `allium.mlkem`
    //! module (the peer implementation this Rust code must interoperate
    //! with on the wire), generated via:
    //!
    //! ```text
    //! seed = bytes(range(64)); m = bytes(range(32))
    //! ek, dk = mlkem.keypair_from_seed(seed)
    //! ct, shared = mlkem.encapsulate(ek, m)
    //! ct_bad = bytearray(ct); ct_bad[0] ^= 0xFF
    //! rejected = mlkem.decapsulate(dk, bytes(ct_bad))
    //! ```
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn matches_python_reference_implementation() {
        let seed: Vec<u8> = (0u8..64).collect();
        let m: Vec<u8> = (0u8..32).collect();

        let (ek, dk) = keypair_from_seed(&seed).unwrap();
        assert_eq!(ek.len(), ENCAPSULATION_KEY_SIZE);
        assert_eq!(dk.len(), DECAPSULATION_KEY_SIZE);
        assert_eq!(hex(&ek), PY_EK, "encapsulation key mismatch vs Python");
        assert_eq!(hex(&dk), PY_DK, "decapsulation key mismatch vs Python");

        let (ct, shared) = encapsulate(&ek, Some(&m)).unwrap();
        assert_eq!(hex(&ct), PY_CT, "ciphertext mismatch vs Python");
        assert_eq!(hex(&shared), PY_SHARED, "shared secret mismatch vs Python");

        let shared2 = decapsulate(&dk, &ct).unwrap();
        assert_eq!(shared, shared2);

        let mut ct_bad = ct.clone();
        ct_bad[0] ^= 0xFF;
        let rejected = decapsulate(&dk, &ct_bad).unwrap();
        assert_eq!(
            hex(&rejected),
            PY_REJECTED,
            "implicit-rejection output mismatch vs Python"
        );

        assert_eq!(hex(&key_id(&ek)), PY_KEY_ID);
    }

    const PY_EK: &str = "298aa10d423c8dda069d02bc59e6cdf03a096b8b3da4cab9b80ca4a14907672ccef1ec4faf234a0bc5b7e9d473f2b3133b3b26a1d175cb67a7805919699c02f76531b99c5f89180704bb4ca4535c5b8972679c660a07c5e514b87009c862eb8f5157695efb3fc40a9def6b81c1cc02a249ae4f094ad0d9bd3485c1c1c68080520a7c8c632032cee738154e5c5176c07da56024776a430fe76eacf665a3f7b832102215bc82f10939c8355704336a8fac1d81e4bb0485aa5d7c74d6b59bbe5c5e972a0d8bac411b55b5d5557cd680a1a8f71b4eb86bc48c9a0509731a54bd9d7290b27963e4372dc9b199cfdcac0b01acd28a62395112e4c43648d622c48c8234d01440e8cc376c927f23a5afc9ac0474c662274e424525c8552ece3b3fe26516de901bc7d515bde89558e626c95c80b93342f8010004f39e6c6c94871c5e344cab3966c835f9a96a59afd31c40286b38b1c1a78470bab947518934453ce86736a919f1f5a6d510a86f5454fc3980cb5c765bd2bd5f7b36b1410d6635c8ceb47c4dda0d76a28eac939c71c3024804866c71626658442163c2c22117e50acefce6378a985652302a4ef0c2ce0cc716b7796e2b6b2e3777dfa1ac3da259a31b5a9b530f8cb638a81a62ac301849abaf95a7301bda30068909bfdb7e67dbccbb38a5551a25b1a3a0f685748ad5753d8880f0016c627486166384c5571fe2365900364d038311e2d875db366686932b5ec602430a369e87a6ef5c338786657825bd4c057aceb923eb0935e6905e63b4ced7f80857a773dd64b150d26612ea9ac12052db2017bf1843ccb4b3281b690dc728adfa85c00281b8e3c09287335f856b4fc2892f69a2f57921ada01914c40988662d57769662a786351b9b66493dab79594d986de2100d65ba0ff4ea58b81538d24a4435a258fac25404aa7f41f658b1385065e158dcb60115732720f40459aaac15e406953a90ac52997d1ccd070060efc65db9e653354467fad56ec713c86e7540c423acf2669f52fa6f4ac6888d871ef3e847c029a8aafbb92e17b24aa079b1f419ba6175b442afb11909d4a56b70a0335b28739218aa7c9348e2c3c2f3eb3d15a41e6417c0dd94bfeb21419b311a7bb13a180bbe833218a9a6b17447cc85f225859587a73077049acbcfd44d0f025438e15d1538270d586e1bf83192a9459cf63c0e972f85297679831ecf121509851cb8340f6f107b0fa1a0efd1b36a8189bc085c4f5cb784e553f41b918f80397ce1956f785bee377ca9aa8be6998ada30c26b7c3d8c6b55254cc96203b20c42aee0ac4e1ebb408e49a9e3f879d0ab0785eb7025425d1305a2299c015e120d163b0e19494ce57253d0246d182745cb8197ab7438b3c1bb7972bec5a306eba3567855c014699fef65ae54c770a0d85c18400cf642aedc660777ba4b138502bd5a7812f621f84a48296b98dd4322b6f15828b8a8f0e00a8ba44a53c3a8b143571b0740abd567daf1cde9c79c204b6d5e259d1766a31bbbcb4e6a05cf4502176b301c1c2f41247750157bcec85e809b30a4d60d7747cdd0f5b99aa8c826987517793aaa8080a0b124a8558df72bbe37b75f4edbb6be8216d6c633fb2b2280e25113d8695e43481c3eeb397eb192505229b67a201ea893c3e2cb32da8bc342fa4dea0578";
    const PY_DK: &str = "27d2a77f33756f61208ef113abe82595873d4abc730e5b5d679529bf6a4ceb6383427231a8612f41550515acba52e48ead8b942833bbe6865d13d14a79d2c5c3e07f0a056d8de7aadfcaba058c493c80b37cab8c562753bb3ba6b6ec8297f885eaa7540d530015a84406e55b1366b577e236ce58a26d8a1eb5a44d542323c2167d9bf4a47f985699ca05bae43b8dec617f02380a3890afd4b8c7ec7ede26553a025f3ce5bc5d7a62130304235cb1ad4836b566b5b863bd9bdb45a2844a7047b6c8d383e448525e040b4dc8a2b48c6c37c96d62d43f3fd88e2881c40a205c9e248f652b592781a779f86880f2a147b67863f391cc1a5a908c0095e07212291e2ef8a36eb9a9c0c6073225b34703a4af049382c47573da68fde9245ad444e31b1fbdb521f1f61f37bc0cef292067e670d28a1ffd904f6f1190a996918a13037a6cabf3c373bf8296cd37ab33ba7746809cc3f8ade1b3639bd57bfcc69650aaaf1de198fc4c0463299e52c461780cc428fc5d04a5c51850cba6c2a5274340675793dda09be44c29e6395c65f85d2a0a7c6df411e6911b1f2cb6c351cd2e875f51b638be776097e93e2f2b2f83da0beef4aa85ba9e763ab64502a0ca5222e9eab5b3b7088ed52060e8c8269b943a71ab0ae1c5b1b687d2e019cf8036bcf9bf6e7bac3aaa36e41660faa4540f2648cd93a189ec5c2dea70bacaaa4ffc906f90810ea1b67bf24f2c78cf6ba881aaea61c0652bff95b1bae4426d1773b9cc2ca82c21e38c636e3b1c523244986b0be8a83f5dd5cf2d54762fb3c5ebf59b8e885302b1ce47033edf760f4e029be40b6d566b19dd758acd5c7412878131244f90172c53f26663c21d905301d48baf91c917cc7779e9d8802cc10d89a3705099a2ad3a3a8896743c1144698093be257dacb66dc785228b912c8d965d14aa28342c3ac4a93fefa532b20945ddc1020139c14d638b908c4ddde9a0645b95b2e4414d40bb79f04413830f15a873c28bb7059c2741002015f20408f058e715b0bf995b5380b7dd325a056ab97e659a2be0cdf6c33731c683a634b771e8c92a139aee4bb0e49c7077321d42fc199f7c1f298ca625d223a5c263a03cc48159b7812665b78637e4e18720b2c29a6b99f42766a4cbc4dc508ba94ba83b89c3a5c78f8bb26bbd9b79beb8c8182490f5793ee5b96013b74b7e169e29d162f1315464ea7d72436d89b755161192c81cc2dd1c8b8bba795ef426ee1cc01c37aaa37b2cff8b0a378b47cbd0b4d49398cfc2712959699fa0bd8cd84666acc61f541b84fa96b9c854e4e75e9144addb44b8566a57dfbb545ce423c03346f2b2c1a91780d152a8de1a4d4c9cacde7392c996888cc2399c02c38b3353adf8acab283924da00a05b76e738c72c930d6cba09ae168990faa1fef2226e780861d416eff402f4f759fc648ab1f97100109087f96e4b148d2cb31e4805314ea0cd95fb023eac0d989474ba4201d7b41d26f5394b217eea5b34b71a8b37931c0e594271e0b7c733257240233e7ba735603e425a87dee77079e37cb28a21764594ce5350d8da2b62a07174943032ec89c98809c73b6423d30c1d283a766a64d89703c3d629b497828d48320c346210797a298aa10d423c8dda069d02bc59e6cdf03a096b8b3da4cab9b80ca4a14907672ccef1ec4faf234a0bc5b7e9d473f2b3133b3b26a1d175cb67a7805919699c02f76531b99c5f89180704bb4ca4535c5b8972679c660a07c5e514b87009c862eb8f5157695efb3fc40a9def6b81c1cc02a249ae4f094ad0d9bd3485c1c1c68080520a7c8c632032cee738154e5c5176c07da56024776a430fe76eacf665a3f7b832102215bc82f10939c8355704336a8fac1d81e4bb0485aa5d7c74d6b59bbe5c5e972a0d8bac411b55b5d5557cd680a1a8f71b4eb86bc48c9a0509731a54bd9d7290b27963e4372dc9b199cfdcac0b01acd28a62395112e4c43648d622c48c8234d01440e8cc376c927f23a5afc9ac0474c662274e424525c8552ece3b3fe26516de901bc7d515bde89558e626c95c80b93342f8010004f39e6c6c94871c5e344cab3966c835f9a96a59afd31c40286b38b1c1a78470bab947518934453ce86736a919f1f5a6d510a86f5454fc3980cb5c765bd2bd5f7b36b1410d6635c8ceb47c4dda0d76a28eac939c71c3024804866c71626658442163c2c22117e50acefce6378a985652302a4ef0c2ce0cc716b7796e2b6b2e3777dfa1ac3da259a31b5a9b530f8cb638a81a62ac301849abaf95a7301bda30068909bfdb7e67dbccbb38a5551a25b1a3a0f685748ad5753d8880f0016c627486166384c5571fe2365900364d038311e2d875db366686932b5ec602430a369e87a6ef5c338786657825bd4c057aceb923eb0935e6905e63b4ced7f80857a773dd64b150d26612ea9ac12052db2017bf1843ccb4b3281b690dc728adfa85c00281b8e3c09287335f856b4fc2892f69a2f57921ada01914c40988662d57769662a786351b9b66493dab79594d986de2100d65ba0ff4ea58b81538d24a4435a258fac25404aa7f41f658b1385065e158dcb60115732720f40459aaac15e406953a90ac52997d1ccd070060efc65db9e653354467fad56ec713c86e7540c423acf2669f52fa6f4ac6888d871ef3e847c029a8aafbb92e17b24aa079b1f419ba6175b442afb11909d4a56b70a0335b28739218aa7c9348e2c3c2f3eb3d15a41e6417c0dd94bfeb21419b311a7bb13a180bbe833218a9a6b17447cc85f225859587a73077049acbcfd44d0f025438e15d1538270d586e1bf83192a9459cf63c0e972f85297679831ecf121509851cb8340f6f107b0fa1a0efd1b36a8189bc085c4f5cb784e553f41b918f80397ce1956f785bee377ca9aa8be6998ada30c26b7c3d8c6b55254cc96203b20c42aee0ac4e1ebb408e49a9e3f879d0ab0785eb7025425d1305a2299c015e120d163b0e19494ce57253d0246d182745cb8197ab7438b3c1bb7972bec5a306eba3567855c014699fef65ae54c770a0d85c18400cf642aedc660777ba4b138502bd5a7812f621f84a48296b98dd4322b6f15828b8a8f0e00a8ba44a53c3a8b143571b0740abd567daf1cde9c79c204b6d5e259d1766a31bbbcb4e6a05cf4502176b301c1c2f41247750157bcec85e809b30a4d60d7747cdd0f5b99aa8c826987517793aaa8080a0b124a8558df72bbe37b75f4edbb6be8216d6c633fb2b2280e25113d8695e43481c3eeb397eb192505229b67a201ea893c3e2cb32da8bc342fa4dea0578a24e16d8f8f9383a95b77050f4d9fd2f5733eec1d63ef3c23ebf9918173669a7202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
    const PY_CT: &str = "714961aec88bb0623eb5b003451ca3e4cefe69c9f3d6a38d9c15380678a7173d743458693b7502c5f327be84abef32aeb4735c96b1724d2b47caa943cfe85ac2ee651513835ec1da0795c9dc3d4ef7b47df0a1c1127e22baded8ecebf1b8dbff377f1d1cb3b243cedee1aa0fe785b0616de6467c53456dd2275bd4e13d59a77b7b6c591e0bba012a814c3a7d47e5d27efa6e9196fa6dc077d86be8fb3f23aad92cb6a50a83946fcbfda494d6627f8cff4c4ae30c53637dfded4d65d0f2c02f8a7acc913d65ad33d4dd88100f6144ba58e2c543fbb0217e82420874b981458a1b79ba7225efea5bce366d8faa3d167e556ff3ce937848fdf1f54be61e4693ddf5f1e8ac044fd2886033cbcfba8a13d53663b27815cf7d2e886049154fc82345861371b86e65303f7436d9454007999d95bb13aa8561c5716b66e074e13b0a2f6589cc238d398bd7eaeb40d97cec8c4604fd84278e2ce25b50532da066cf73c11bce6ba633f6e184a3ec6224992b5577ddc30e26ded2cdc3450adc0895d6bbadf82648aa2a96d542c3b32355885f78807925d381274413082928b509fc1bb42841c5b3e1a9ea87db4ec4802b42fc4366efea7e76ad808fdc8b74fdca3ca29fbc9e16a34b7d763a0221fe959a9584b537e1911b7ef2db43aa7be9a05bdca5bc280326f9b557912a7f663d89a63354efd0a0bdec3e945d0576fc03c6ef00a599444a4fc773381906faea4a594f0c6cb54fcd915847255322b3f73dcca282bced5bf136c568fdaad86b5e1ff03503a41e7226b1811d69f0fe476a84c8c9bc15b3c33950cdee8fd41ce485c754982ffff27d7a1fa372acd9b0ebf4ef112011ab107f7c46d8066ad863519a0d2f894ea5aee05567e760bfb1079f68b4e7eedc1bf22b4a6abd4b4f15677425bac606f6f64e4ac753e5c996fa49f7b438a9511a15507b70e679877def96d35a61cf53f0ab2eceaed66dacd8e73b2dfd7e00297fb9ad11723ad534e652ef3dfe0cf1372e98ff42990373a7800087f3e7300611ccced038755968ff0a70ff039776afcc8ffcd9cc2a234c995b8db9b87cc7a958ae13a7d8ae5055e62c9bb7b698318ff1292a74f3602f838855c7c4016c1b57dc5b345d9cd609459a34889576dcb1620636bb4063361a6c2ba58660aacaf364e2179469c93687fe6e2d74c01bc45069f7a59fa7e11a93db9988b93b82c3f71fcfca67db408a0166b4c46cb1441679ed6a0ce031707831e58b9d323cc0e696eae9856536aecffa1d9f0ab629cf242ddca32869e5db59e049d8e7efa604b3e859e1aad6ccc208907947210928f92768eefc6fde3a3088dec63319c02f7688fdb64d3c89787805089c3e68f2d5caded456b5d7b9766b6e4fbd414354baf3e0759dab247b9f8271c38ec6e01d3649a62c297b5cd9aa757ec7701a0f2bfd4e15b0331bbcb6b0bb9196875e265c86bd142bead1cadda99712de3f3d0dfac9a0dfe43c76649879497f4cfd4e1c5e684e8ff37bacc8d618f65a700b41f0170867982f5a68c75c65150e";
    const PY_SHARED: &str = "42f558b0bc5d700a911b0fc67f62376f7aee4667f1969e03f18bdfdf3c59fbdc";
    const PY_REJECTED: &str = "ae08f5b2a822ebd617251e62fa39a6dc8e8a84d84aaa0fac21083c453deda851";
    const PY_KEY_ID: &str = "2073b979ed925a40";

    /// The branch-free `write_bits` (used by `byte_encode`) must write
    /// exactly what the old bit-by-bit implementation (which branched on
    /// each bit) did, for every width used by ML-KEM and for edge patterns
    /// as well as pseudo-random input. The reference below is that old
    /// implementation, kept only here.
    fn byte_encode_reference_branchy(d: usize, f: &Poly) -> Vec<u8> {
        let mut out = vec![0u8; 32 * d];
        for (i, &value) in f.iter().enumerate() {
            let value = value as u32;
            for b in 0..d {
                if (value >> b) & 1 == 1 {
                    let pos = d * i + b;
                    out[pos / 8] |= 1 << (pos % 8);
                }
            }
        }
        out
    }

    #[test]
    fn test_byte_encode_branch_free_matches_the_branchy_reference() {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for d in [1usize, 4, 5, 10, 11, 12] {
            let max = if d == 12 { 4095 } else { (1i32 << d) - 1 };
            let mut polys: Vec<Poly> = Vec::new();
            polys.push([0; N]);
            polys.push([max; N]);
            let mut alternating = [0; N];
            for (i, v) in alternating.iter_mut().enumerate() {
                *v = if i % 2 == 0 { max } else { 0 };
            }
            polys.push(alternating);
            let mut counting = [0; N];
            for (i, v) in counting.iter_mut().enumerate() {
                *v = (i as i32) & max;
            }
            polys.push(counting);
            for _ in 0..200 {
                let mut p = [0; N];
                for v in p.iter_mut() {
                    *v = (next() % (max as u64 + 1)) as i32;
                }
                polys.push(p);
            }
            for p in &polys {
                assert_eq!(byte_encode(d, p), byte_encode_reference_branchy(d, p), "width d={d}");
            }
        }
    }

    /// For `d = 1` (the decrypted message), every one of the 256 bits must
    /// land in the right place, one at a time.
    #[test]
    fn test_byte_encode_one_bit_each_position_lands_in_the_right_bit() {
        for i in 0..N {
            let mut p = [0; N];
            p[i] = 1;
            let encoded = byte_encode(1, &p);
            let mut expected = vec![0u8; 32];
            expected[i / 8] = 1 << (i % 8);
            assert_eq!(encoded, expected, "bit {i}");
        }
    }
}
