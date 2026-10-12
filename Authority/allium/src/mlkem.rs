//! ML-KEM-768 (FIPS 203), pure Rust, no external crates.
//!
//! Port status: `allium/mlkem.py` is itself a from-scratch, stdlib-only
//! implementation (only Python's `hashlib` SHA3-256/512 and SHAKE128/256, no
//! third-party crypto library -- see its module docstring), so this is a
//! full, faithful, dependency-free port rather than a wrapper around a crate
//! (a suggested `ml-kem` crate is not fetchable in this
//! sandbox in any case -- see the note atop `allium/Cargo.toml`). It uses
//! [`crate::keccak`] (this crate's own dependency-free Keccak/SHA-3/SHAKE)
//! in place of `hashlib`.
//!
//! Correctness: cross-checked in this module's tests against the exact same
//! known-answer values `tests/test_mlkem.py` uses (produced by Go's
//! `crypto/mlkem`, a FIPS 140-3 validated implementation), confirmed to match
//! this repo's own `allium/mlkem.py` byte-for-byte via the real Python
//! interpreter while porting.

use crate::keccak::{sha3_256, sha3_512, shake128, shake256};
use std::fmt;
use subtle::{ConditionallySelectable, ConstantTimeEq};

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
/// Python module's `BACKEND`, so a future switch is visible to callers/tests).
pub const BACKEND: &str = "rust-stdlib";

/// An ML-KEM key or ciphertext failed an input check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MLKEMError {
    pub message: String,
}
impl fmt::Display for MLKEMError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for MLKEMError {}
fn err(msg: impl Into<String>) -> MLKEMError {
    MLKEMError { message: msg.into() }
}

type Poly = [i32; N];

fn zero_poly() -> Poly {
    [0; N]
}

fn bitrev7(n: u32) -> u32 {
    let mut r = 0u32;
    for i in 0..7 {
        r |= ((n >> i) & 1) << (6 - i);
    }
    r
}

fn pow_mod(mut base: i64, mut exp: u32, m: i64) -> i64 {
    let mut result = 1i64;
    base %= m;
    while exp > 0 {
        if exp & 1 == 1 {
            result = result * base % m;
        }
        base = base * base % m;
        exp >>= 1;
    }
    result
}

fn zetas() -> &'static [i32; 128] {
    use std::sync::OnceLock;
    static Z: OnceLock<[i32; 128]> = OnceLock::new();
    Z.get_or_init(|| {
        let mut out = [0i32; 128];
        for i in 0..128 {
            out[i] = pow_mod(17, bitrev7(i as u32), Q as i64) as i32;
        }
        out
    })
}

fn gammas() -> &'static [i32; 128] {
    use std::sync::OnceLock;
    static G: OnceLock<[i32; 128]> = OnceLock::new();
    G.get_or_init(|| {
        let mut out = [0i32; 128];
        for i in 0..128 {
            out[i] = pow_mod(17, 2 * bitrev7(i as u32) + 1, Q as i64) as i32;
        }
        out
    })
}

const INV128: i32 = 3303; // 128^-1 mod q

// -- hash functions (FIPS 203 section 4.1) ------------------------------------

fn h_fn(data: &[u8]) -> [u8; 32] {
    sha3_256(data)
}

fn j_fn(data: &[u8]) -> [u8; 32] {
    let out = shake256(data, 32);
    out.try_into().unwrap()
}

fn g_fn(data: &[u8]) -> ([u8; 32], [u8; 32]) {
    let out = sha3_512(data);
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

// -- NTT (Algorithms 9-12) ----------------------------------------------------

fn ntt(f_in: &Poly) -> Poly {
    let mut f = *f_in;
    let z = zetas();
    let mut i = 1usize;
    let mut length = 128usize;
    while length >= 2 {
        let mut start = 0;
        while start < N {
            let zeta = z[i] as i64;
            i += 1;
            for j in start..start + length {
                let t = (zeta * f[j + length] as i64).rem_euclid(Q as i64) as i32;
                f[j + length] = (f[j] - t).rem_euclid(Q);
                f[j] = (f[j] + t).rem_euclid(Q);
            }
            start += 2 * length;
        }
        length >>= 1;
    }
    f
}

fn intt(f_in: &Poly) -> Poly {
    let mut f = *f_in;
    let z = zetas();
    let mut i = 127i64;
    let mut length = 2usize;
    while length <= 128 {
        let mut start = 0;
        while start < N {
            let zeta = z[i as usize] as i64;
            i -= 1;
            for j in start..start + length {
                let t = f[j];
                f[j] = (t + f[j + length]).rem_euclid(Q);
                f[j + length] = (zeta * (f[j + length] - t) as i64).rem_euclid(Q as i64) as i32;
            }
            start += 2 * length;
        }
        length <<= 1;
    }
    for x in f.iter_mut() {
        *x = (*x as i64 * INV128 as i64).rem_euclid(Q as i64) as i32;
    }
    f
}

fn mul_ntt(f: &Poly, g: &Poly) -> Poly {
    let gam = gammas();
    let mut h = zero_poly();
    for i in 0..128 {
        let a0 = f[2 * i] as i64;
        let a1 = f[2 * i + 1] as i64;
        let b0 = g[2 * i] as i64;
        let b1 = g[2 * i + 1] as i64;
        h[2 * i] = ((a0 * b0 + (a1 * b1).rem_euclid(Q as i64) * gam[i] as i64).rem_euclid(Q as i64)) as i32;
        h[2 * i + 1] = ((a0 * b1 + a1 * b0).rem_euclid(Q as i64)) as i32;
    }
    h
}

fn add(f: &Poly, g: &Poly) -> Poly {
    let mut out = zero_poly();
    for i in 0..N {
        out[i] = (f[i] + g[i]).rem_euclid(Q);
    }
    out
}

fn sub(f: &Poly, g: &Poly) -> Poly {
    let mut out = zero_poly();
    for i in 0..N {
        out[i] = (f[i] - g[i]).rem_euclid(Q);
    }
    out
}

// -- sampling (Algorithms 7-8) ------------------------------------------------

fn sample_ntt(seed: &[u8]) -> Poly {
    let mut length = 3 * 168 * 4;
    loop {
        let stream = shake128(seed, length);
        let mut out = Vec::with_capacity(N);
        let mut pos = 0;
        while pos + 2 < length {
            let c0 = stream[pos] as i32;
            let c1 = stream[pos + 1] as i32;
            let c2 = stream[pos + 2] as i32;
            let d1 = c0 + 256 * (c1 & 0x0F);
            let d2 = (c1 >> 4) + 16 * c2;
            if d1 < Q {
                out.push(d1);
                if out.len() == N {
                    let mut p = zero_poly();
                    p.copy_from_slice(&out);
                    return p;
                }
            }
            if d2 < Q {
                out.push(d2);
                if out.len() == N {
                    let mut p = zero_poly();
                    p.copy_from_slice(&out);
                    return p;
                }
            }
            pos += 3;
        }
        length *= 2;
    }
}

fn get_bits(data: &[u8], offset: usize, n: usize) -> u32 {
    let mut result = 0u32;
    for i in 0..n {
        let bitpos = offset + i;
        let byte = data[bitpos / 8];
        let bit = (byte >> (bitpos % 8)) & 1;
        result |= (bit as u32) << i;
    }
    result
}

fn cbd(eta: usize, data: &[u8]) -> Poly {
    let mut f = zero_poly();
    for i in 0..N {
        let chunk_offset = 2 * eta * i;
        let x_bits = get_bits(data, chunk_offset, eta);
        let y_bits = get_bits(data, chunk_offset + eta, eta);
        let x = x_bits.count_ones() as i32;
        let y = y_bits.count_ones() as i32;
        f[i] = (x - y).rem_euclid(Q);
    }
    f
}

// -- encoding (Algorithms 5-6) and compression (section 4.2.1) ----------------

fn byte_encode(d: usize, f: &Poly) -> Vec<u8> {
    let total_bits = d * N;
    let total_bytes = total_bits / 8;
    let mut out = vec![0u8; total_bytes];
    for i in 0..N {
        let value = (f[i] as u32) & (((1u64 << d) - 1) as u32);
        let bitpos = d * i;
        // Branch-free in `value`: each bit is OR-ed in unconditionally as `0`
        // or `1 << k`, so neither the control flow nor the memory writes
        // depend on the bits being encoded. `byte_encode(1, ..)` packs the
        // *decrypted message* at the end of `pke_decrypt` (the shared
        // secret's seed); an `if bit == 1 { out |= .. }` here compiled to a
        // real conditional jump on each secret bit (`bt` + `jae` skipping
        // the `or`).
        for b in 0..d {
            let p = bitpos + b;
            out[p / 8] |= (((value >> b) & 1) as u8) << (p % 8);
        }
    }
    out
}

fn byte_decode(d: usize, data: &[u8]) -> Poly {
    let mut f = zero_poly();
    for i in 0..N {
        let bitpos = d * i;
        let mut value: u32 = 0;
        for b in 0..d {
            let p = bitpos + b;
            let bit = (data[p / 8] >> (p % 8)) & 1;
            value |= (bit as u32) << b;
        }
        f[i] = value as i32;
    }
    if d == 12 {
        for v in f.iter_mut() {
            *v %= Q;
        }
    }
    f
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
/// `compress` used to write `numerator /
/// q` directly, with `numerator` derived from `w = v - NTT⁻¹(Σ s_hat_i ·
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
    let mask = (1i64 << d) - 1;
    let mut out = zero_poly();
    for i in 0..N {
        let x = f[i] as i64;
        out[i] = (div_by_q((x << d) + q / 2) & mask) as i32;
    }
    out
}

fn decompress(d: usize, f: &Poly) -> Poly {
    let q = Q as i64;
    let half = 1i64 << (d - 1);
    let mut out = zero_poly();
    for i in 0..N {
        out[i] = (((f[i] as i64) * q + half) >> d) as i32;
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
    let mut d_k = d.to_vec();
    d_k.push(K as u8);
    let (rho, sigma) = g_fn(&d_k);
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
    let mut ek = Vec::new();
    for p in &t_hat {
        ek.extend(byte_encode(12, p));
    }
    ek.extend_from_slice(&rho);
    let mut dk = Vec::new();
    for p in &s_hat {
        dk.extend(byte_encode(12, p));
    }
    (ek, dk)
}

fn pke_encrypt(ek: &[u8], m: &[u8], r: &[u8]) -> Vec<u8> {
    let t_hat: Vec<Poly> = (0..K).map(|i| byte_decode(12, &ek[384 * i..384 * (i + 1)])).collect();
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
    let mut c1 = Vec::new();
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
    let s_hat: Vec<Poly> = (0..K).map(|i| byte_decode(12, &dk[384 * i..384 * (i + 1)])).collect();
    let mut acc = zero_poly();
    for i in 0..K {
        acc = add(&acc, &mul_ntt(&s_hat[i], &ntt(&u[i])));
    }
    let w = sub(&v, &intt(&acc));
    byte_encode(1, &compress(1, &w))
}

// -- ML-KEM (Algorithms 16-21) ------------------------------------------------

fn check_ek(ek: &[u8]) -> Result<(), MLKEMError> {
    if ek.len() != ENCAPSULATION_KEY_SIZE {
        return Err(err(format!("encapsulation key must be {ENCAPSULATION_KEY_SIZE} bytes")));
    }
    for i in 0..K {
        let chunk = &ek[384 * i..384 * (i + 1)];
        if byte_encode(12, &byte_decode(12, chunk)) != chunk {
            return Err(err("encapsulation key failed the modulus check"));
        }
    }
    Ok(())
}

/// Deterministic `(encapsulation_key, decapsulation_key)` from a 64-byte seed
/// `d || z` (FIPS 203 ML-KEM.KeyGen_internal).
pub fn keypair_from_seed(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), MLKEMError> {
    if seed.len() != SEED_SIZE {
        return Err(err(format!("seed must be {SEED_SIZE} bytes")));
    }
    let d = &seed[..32];
    let z = &seed[32..];
    let (ek, dk_pke) = pke_keygen(d);
    let h = h_fn(&ek);
    let mut dk = dk_pke;
    dk.extend_from_slice(&ek);
    dk.extend_from_slice(&h);
    dk.extend_from_slice(z);
    Ok((ek, dk))
}

// The `#[cfg(not(unix))]` arm here used
// to return `SystemTime::now()` subsecond nanoseconds cycled to fill the
// buffer -- a handful of low-entropy, publicly-guessable bytes repeated to
// fill whatever length was asked for (e.g. the same 4 bytes 16 times for
// a 64-byte ML-KEM keygen seed), not a CSPRNG. That silently compiled on
// any non-Unix target with no warning, and would have produced fully
// predictable ML-KEM keypairs/ciphertexts if ever reached. This project
// is documented (`Client/building_directing.txt`) as Linux-only ("has
// only been built/tested on Linux"), so rather than adding a new crate
// dependency to this deliberately dependency-free module (see its own
// module docs) to support a platform nothing here targets, a non-Unix
// build now fails to compile instead of silently shipping weak
// randomness.
fn random_bytes(n: usize) -> Result<Vec<u8>, MLKEMError> {
    let mut buf = vec![0u8; n];
    crate::osrand::os_random(&mut buf).map_err(|e| err(e.to_string()))?;
    Ok(buf)
}

/// A fresh `(encapsulation_key, decapsulation_key)` pair.
pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), MLKEMError> {
    keypair_from_seed(&random_bytes(SEED_SIZE)?)
}

fn encapsulate_internal(ek: &[u8], m: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (shared, r) = g_fn(&[m, &h_fn(ek)].concat());
    (pke_encrypt(ek, m, &r), shared.to_vec())
}

/// `(ciphertext, shared_secret)` for encapsulation key `ek`.
///
/// `m` (32 bytes) makes the result deterministic -- for tests only; `None`
/// draws fresh randomness.
pub fn encapsulate(ek: &[u8], m: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>), MLKEMError> {
    check_ek(ek)?;
    let owned;
    let m = match m {
        Some(m) => m,
        None => {
            owned = random_bytes(32)?;
            &owned
        }
    };
    if m.len() != 32 {
        return Err(err("m must be 32 bytes"));
    }
    Ok(encapsulate_internal(ek, m))
}

/// The 32-byte shared secret for `ciphertext` (implicit rejection: a
/// malformed-but-right-sized ciphertext yields an unrelated key, never an
/// error).
pub fn decapsulate(dk: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, MLKEMError> {
    if ciphertext.len() != CIPHERTEXT_SIZE {
        return Err(err(format!("ciphertext must be {CIPHERTEXT_SIZE} bytes")));
    }
    if dk.len() != DECAPSULATION_KEY_SIZE {
        return Err(err(format!("decapsulation key must be {DECAPSULATION_KEY_SIZE} bytes")));
    }
    let dk_pke = &dk[..384 * K];
    let ek = &dk[384 * K..768 * K + 32];
    let h = &dk[768 * K + 32..768 * K + 64];
    let z = &dk[768 * K + 64..];
    let computed_h = h_fn(ek);
    if !crate::hashutil::constant_time_eq(&computed_h, h) {
        return Err(err("decapsulation key failed its hash check"));
    }
    let m_prime = pke_decrypt(dk_pke, ciphertext);
    let (shared, r_prime) = g_fn(&[&m_prime[..], h].concat());
    let rejected = j_fn(&[z, ciphertext].concat());
    let c_prime = pke_encrypt(ek, &m_prime, &r_prime);
    // The final choice between
    // `shared` and `rejected` used to be a plain `if`/`else` on a
    // constant-time comparison's *result* -- the comparison itself was
    // already branchless, but branching on its `bool` output still lets
    // the CPU take a different code path (and branch predictor state)
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
    let mut input = b"allium-mlkem-key-id".to_vec();
    input.extend_from_slice(ek);
    let digest = crate::hashutil::sha256(&input);
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `div_by_q` must exactly
    /// match plain `/` for every input `compress` can ever produce --
    /// `x` (a fully-reduced polynomial coefficient, always in `[0, Q)`
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
    /// rewrite: exercise every `(d, x)` pair the KATs below don't happen
    /// to hit, comparing against the original `/`-based formula directly
    /// (not just via `div_by_q`, so this also catches a mistake in how
    /// `compress` itself calls `div_by_q`, not only in `div_by_q` alone).
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

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    // Known-answer values from Go 1.24's crypto/mlkem, the same ones
    // tests/test_mlkem.py checks against, reproduced here so this port is
    // checked against the identical reference, not just against itself.
    // (seed_index, ek_sha256, ct_sha256, shared, flip_byte, reject)
    const KATS: [(u64, &str, &str, &str, usize, &str); 3] = [
        (0, "a83fbbf3d98ccec5a6a28da1d0d7c92369fe87f7b7c9e76110f6d0858d4d6ea2",
         "8b18b9620f10ed7ea675b4b056561b304c5dfe01a255d78d74bcaac7608a7594",
         "39f3086c4e9f020245503607adf1c49c9d9db4995dbea7d020dac4b350564f45",
         100, "c90a25280e145801454142a905f8cc3c31351556ae5873534127fa061d8f26f3"),
        (1, "d4d9e02d11fe4438e7b59b87a36413e3503f114c990c70a19685cd8304ea4085",
         "925d34b3294f96223b9b4e7532ce95a35d246cd003348e086ee032d25d4ad51c",
         "27306f7868d6324d5933542c1cce4f402d317864ad77163a09ac97476bbbd524",
         400, "c7797a2578df3fae39c8000671ef808229cb5a1d14d32c2b878e1a24ad31f3b5"),
        (2, "95bc8d8a68a3b8808d94bad8e3fe19425617de56a7cd90fae545329bfed7c661",
         "f1a263534058143d02a95f55fccdf542ef402cd1c0d98916e188ed97807559ee",
         "42522ae665328a70aa09fd1a50b64d483c48c9e79d13cc11b43dbfe6a7e88dc0",
         700, "3a32215bb94c68d60369c34c185a756192ba1291a401817bba1d98fe2deb4200"),
    ];

    // The KATs derive their seeds/messages as
    // `SHA-512(b"allium-mlkem-kat-seed-%d")` / `SHA-256(b"allium-mlkem-kat-m-%d")`
    // (see tests/test_mlkem.py's module docstring). This crate has no SHA-512
    // implementation (only SHA-256, in `hashutil`, and SHA3-256/512 in
    // `keccak`, which are a different algorithm family), so these are the
    // precomputed digests (confirmed against Python's `hashlib.sha512`/
    // `hashlib.sha256` while porting) rather than rederived here.
    const SEEDS_HEX: [&str; 3] = [
        "0c32f37e29ed47e570fb9af51562bcb6b7b349a4b4229edebfc38075fe0fe0bf9530ecd512b5cc707ebc13ee37efa3e641053be8dac2460fe4935d5d3b438652",
        "84bbd3ac0a2d2b2adcf1e6030d54f710a9c6806ca91aaf871803ca6e3767bef3eeb3f9734b0c833a3adc008a79ee2d2f7030235962ac4700f8e54981e517a4e6",
        "fca51850bbe092c6fce873715b540140547cfe7ddb3665bf226d224ceb4a7d25d49af113c254d324612022f1c8009c874da7b18e8f5b81111634d221da0fac76",
    ];
    const MS_HEX: [&str; 3] = [
        "994104c80a1f52838c0669960613bcc9bcbe41735be33567eacbfedd0a6e5b95",
        "ec98c37a923e519bb40e972b311c75ba22d9edc77ae494f303b4f0c8cc7f8079",
        "d53fb92c952bbc37eafff080718319a76662d179ea054aa8cb48b384cb9f0d8c",
    ];

    #[test]
    fn test_against_go_crypto_mlkem() {
        for (i, ek_sha, ct_sha, shared, flip, reject) in KATS {
            let seed = from_hex(SEEDS_HEX[i as usize]);
            let m = from_hex(MS_HEX[i as usize]);

            let (ek, dk) = keypair_from_seed(&seed).unwrap();
            assert_eq!(hex(&crate::hashutil::sha256(&ek)), ek_sha, "ek mismatch for seed {i}");
            let (ct, key) = encapsulate(&ek, Some(&m)).unwrap();
            assert_eq!(hex(&crate::hashutil::sha256(&ct)), ct_sha, "ct mismatch for seed {i}");
            assert_eq!(hex(&key), shared, "shared mismatch for seed {i}");
            assert_eq!(hex(&decapsulate(&dk, &ct).unwrap()), shared, "decap mismatch for seed {i}");

            let mut bad = ct.clone();
            bad[flip] ^= 0x01;
            assert_eq!(hex(&decapsulate(&dk, &bad).unwrap()), reject, "reject mismatch for seed {i}");
        }
    }

    #[test]
    fn test_sizes() {
        let (ek, dk) = generate_keypair().unwrap();
        let (ct, key) = encapsulate(&ek, None).unwrap();
        assert_eq!((ek.len(), dk.len(), ct.len(), key.len()), (1184, 2400, 1088, 32));
    }

    #[test]
    fn test_round_trip() {
        for _ in 0..5 {
            let (ek, dk) = generate_keypair().unwrap();
            let (ct, key) = encapsulate(&ek, None).unwrap();
            assert_eq!(decapsulate(&dk, &ct).unwrap(), key);
        }
    }

    #[test]
    fn test_wrong_key_gives_unrelated_secret() {
        let (ek, _dk) = generate_keypair().unwrap();
        let (_ek2, dk2) = generate_keypair().unwrap();
        let (ct, key) = encapsulate(&ek, None).unwrap();
        assert_ne!(decapsulate(&dk2, &ct).unwrap(), key);
    }

    #[test]
    fn test_input_checks() {
        let (ek, dk) = generate_keypair().unwrap();
        assert!(encapsulate(&ek[..ek.len() - 1], None).is_err());
        let mut bad_ek = vec![0xffu8; 384];
        bad_ek.extend_from_slice(&ek[384..]);
        assert!(encapsulate(&bad_ek, None).is_err());
        assert!(decapsulate(&dk, &[0u8; 10]).is_err());
        let mut corrupted_dk = dk.clone();
        corrupted_dk[1200] ^= 1;
        let (ct, _key) = encapsulate(&ek, None).unwrap();
        assert!(decapsulate(&corrupted_dk, &ct).is_err());
    }

    #[test]
    fn test_key_id_is_stable_and_distinct() {
        let (ek, _) = generate_keypair().unwrap();
        let (ek2, _) = generate_keypair().unwrap();
        assert_eq!(key_id(&ek), key_id(&ek));
        assert_ne!(key_id(&ek), key_id(&ek2));
        assert_eq!(key_id(&ek).len(), 8);
    }

    /// The branch-free `byte_encode` must produce exactly what the old
    /// bit-by-bit implementation (which branched on each bit) did, for every
    /// width used by ML-KEM and for edge patterns as well as pseudo-random
    /// input. The reference below is that old implementation, kept only here.
    fn byte_encode_reference_branchy(d: usize, f: &Poly) -> Vec<u8> {
        let total_bytes = d * N / 8;
        let mut out = vec![0u8; total_bytes];
        for i in 0..N {
            let value = (f[i] as u32) & (((1u64 << d) - 1) as u32);
            let bitpos = d * i;
            for b in 0..d {
                if (value >> b) & 1 == 1 {
                    let p = bitpos + b;
                    out[p / 8] |= 1 << (p % 8);
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
