use crate::rfc6979::generate_k;
use num_bigint::{BigInt, Sign};
use num_traits::{Zero, One};

/// Estrutura de chave privada (binária simples)
pub struct PrivateKey {
    pub d: BigInt,   // número escalar
}

/// Estrutura de chave pública (ponto da curva)
pub struct PublicKey {
    pub x: BigInt,
    pub y: BigInt,
}

/// Estrutura da assinatura ECDSA
pub struct Signature {
    pub r: BigInt,
    pub s: BigInt,
}

//
// --- CONSTANTES DA CURVA secp256k1 ---
//
lazy_static::lazy_static! {
    pub static ref P: BigInt = BigInt::parse_bytes(
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16
    ).unwrap();

    pub static ref N: BigInt = BigInt::parse_bytes(
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
    ).unwrap();

    pub static ref Gx: BigInt = BigInt::parse_bytes(
        b"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16
    ).unwrap();

    pub static ref Gy: BigInt = BigInt::parse_bytes(
        b"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16
    ).unwrap();
}

//
// --- OPERAÇÕES DE CURVA ELÍPTICA ---
//

/// Mdular inverse usando Extended Euclid
fn modinv(a: &BigInt, m: &BigInt) -> BigInt {
    let mut mn = (m.clone(), a.clone());
    let mut xy = (BigInt::zero(), BigInt::one());

    while mn.1 != BigInt::zero() {
        let q = &mn.0 / &mn.1;

        mn = (mn.1.clone(), &mn.0 - &q * &mn.1);
        xy = (
            xy.1.clone(),
            &xy.0 - &q * &xy.1
        );
    }

    while xy.0 < BigInt::zero() {
        xy.0 += m;
    }

    xy.0 % m
}

/// Soma de pontos da curva
fn point_add(x1: &BigInt, y1: &BigInt, x2: &BigInt, y2: &BigInt) -> (BigInt, BigInt) {
    if x1 == x2 && y1 == y2 {
        // Fórmula de ponto duplicado
        let s = ((BigInt::from(3) * x1 * x1) * modinv(&(BigInt::from(2) * y1), &P)) % &*P;
        let xr = (s.clone() * &s - BigInt::from(2) * x1) % &*P;
        let yr = (s * (x1 - &xr) - y1) % &*P;
        return (xr, yr);
    }

    // Fórmula de soma normal
    let s = ((y2 - y1) * modinv(&(x2 - x1), &P)) % &*P;
    let xr = (s.clone() * &s - x1 - x2) % &*P;
    let yr = (s * (x1 - &xr) - y1) % &*P;
    (xr, yr)
}

/// Multiplicação escalar (double and add)
fn point_mul(k: &BigInt, x: &BigInt, y: &BigInt) -> (BigInt, BigInt) {
    let mut k = k.clone();
    let mut rx = BigInt::zero();
    let mut ry = BigInt::zero();
    let mut px = x.clone();
    let mut py = y.clone();

    let mut started = false;

    while k > BigInt::zero() {
        if &k & BigInt::one() == BigInt::one() {
            if !started {
                rx = px.clone();
                ry = py.clone();
                started = true;
            } else {
                (rx, ry) = point_add(&rx, &ry, &px, &py);
            }
        }

        (px, py) = point_add(&px, &py, &px, &py);
        k >>= 1;
    }

    (rx, ry)
}

// --- FUNÇÃO DE ASSINATURA E VERIFICAÇÃO ---

/// Assina hash (já pronto) usando ECDSA + RFC6979
pub fn sign(private: &PrivateKey, hash: &[u8]) -> Signature {
    let z = BigInt::from_bytes_be(Sign::Plus, hash);

    // nonce determinístico k (RFC 6979)
    let k = generate_k(&private.d, &z, &N);

    // r = (kG).x mod n
    let (x, _) = point_mul(&k, &Gx, &Gy);
    let r = &x % &*N;

    let k_inv = modinv(&k, &N);

    // s = k⁻¹ (z + r·d) mod n
    let s = (&k_inv * (z + &r * &private.d)) % &*N;

    Signature { r, s }
}

/// Verifica assinatura ECDSA
pub fn verify(public: &PublicKey, hash: &[u8], sig: &Signature) -> bool {
    let z = BigInt::from_bytes_be(Sign::Plus, hash);

    if sig.r <= BigInt::zero() || sig.r >= *N { return false; }
    if sig.s <= BigInt::zero() || sig.s >= *N { return false; }

    let s_inv = modinv(&sig.s, &N);

    let u1 = (&z * &s_inv) % &*N;
    let u2 = (&sig.r * &s_inv) % &*N;

    let (x1, y1) = point_mul(&u1, &Gx, &Gy);
    let (x2, y2) = point_mul(&u2, &public.x, &public.y);

    let (xr, _) = point_add(&x1, &y1, &x2, &y2);

    (&xr % &*N) == sig.r
}
// lógica de assinatura e verificação