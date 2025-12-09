use num_bigint::{BigInt, Sign};
use num_traits::Zero;
use sha2::Sha256;
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;

fn int2octets(x: &BigInt, qlen: usize) -> Vec<u8> {
    let (_, mut bytes) = x.to_bytes_be();
    if bytes.len() > qlen {
        bytes = bytes[bytes.len() - qlen..].to_vec();
    } else if bytes.len() < qlen {
        let mut padded = vec![0u8; qlen - bytes.len()];
        padded.extend_from_slice(&bytes);
        bytes = padded;
    }
    bytes
}

fn bits2octets(x: &BigInt, q: &BigInt, qlen: usize) -> Vec<u8> {
    let (_, mut bytes) = x.to_bytes_be();
    if bytes.len() > qlen {
        bytes = bytes[bytes.len() - qlen..].to_vec();
    } else if bytes.len() < qlen {
        let mut padded = vec![0u8; qlen - bytes.len()];
        padded.extend_from_slice(&bytes);
        bytes = padded;
    }
    let z1 = BigInt::from_bytes_be(Sign::Plus, &bytes);
    let z2 = z1 % q;
    int2octets(&z2, qlen)
}

/// Gera k determinístico (RFC6979) para ECDSA
pub fn generate_k(x: &BigInt, h1: &BigInt, q: &BigInt) -> BigInt {
    let qlen = ((q.bits() + 7) / 8) as usize;
    let x_bytes = int2octets(x, qlen);
    let h1_bytes = bits2octets(h1, q, qlen);

    // Tamanho do hash (SHA-256) = 32 bytes
    let mut v = vec![0x01u8; 32];
    let mut k = vec![0x00u8; 32];

    // K = HMAC_K(V || 0x00 || x || h1)
    let mut mac = HmacSha256::new_from_slice(&k).expect("HMAC key");
    mac.update(&v);
    mac.update(&[0x00]);
    mac.update(&x_bytes);
    mac.update(&h1_bytes);
    k = mac.finalize().into_bytes().to_vec();

    // V = HMAC_K(V)
    let mut mac = HmacSha256::new_from_slice(&k).expect("HMAC key");
    mac.update(&v);
    v = mac.finalize().into_bytes().to_vec();

    // K = HMAC_K(V || 0x01 || x || h1)
    let mut mac = HmacSha256::new_from_slice(&k).expect("HMAC key");
    mac.update(&v);
    mac.update(&[0x01]);
    mac.update(&x_bytes);
    mac.update(&h1_bytes);
    k = mac.finalize().into_bytes().to_vec();

    // V = HMAC_K(V)
    let mut mac = HmacSha256::new_from_slice(&k).expect("HMAC key");
    mac.update(&v);
    v = mac.finalize().into_bytes().to_vec();

    loop {
        // V = HMAC_K(V)
        let mut mac = HmacSha256::new_from_slice(&k).expect("HMAC key");
        mac.update(&v);
        v = mac.finalize().into_bytes().to_vec();

        let t = &v;
        let mut k_candidate = BigInt::from_bytes_be(Sign::Plus, t);
        k_candidate = k_candidate % q;

        if k_candidate > BigInt::zero() && k_candidate < *q {
            return k_candidate;
        }

        // K = HMAC_K(V || 0x00)
        let mut mac = HmacSha256::new_from_slice(&k).expect("HMAC key");
        mac.update(&v);
        mac.update(&[0x00]);
        k = mac.finalize().into_bytes().to_vec();

        // V = HMAC_K(V)
        let mut mac = HmacSha256::new_from_slice(&k).expect("HMAC key");
        mac.update(&v);
        v = mac.finalize().into_bytes().to_vec();
    }
}
