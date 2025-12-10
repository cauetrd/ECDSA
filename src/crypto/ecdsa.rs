//! Assinatura e verificação ECDSA usando a curva `k256`.

use core::convert::TryFrom;

use k256::ecdsa::{
    signature::{Signer, Verifier},
    Signature as K256Signature,
};
use num_bigint::{BigInt, Sign};

use crate::crypto::key::{PrivateKey, PublicKey};

/// Assinatura ECDSA com escalares `r` e `s`.
pub struct Signature {
    pub r: BigInt,
    pub s: BigInt,
}
fn bigint_to_32_bytes(x: &BigInt) -> [u8; 32] {
    let (_, mut bytes) = x.to_bytes_be();

    if bytes.len() > 32 {
        bytes = bytes[bytes.len() - 32..].to_vec();
    }

    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

fn bytes_to_bigint(bytes: &[u8]) -> BigInt {
    BigInt::from_bytes_be(Sign::Plus, bytes)
}
pub fn sign(private: &PrivateKey, msg: &[u8]) -> Signature {
    let ksig: K256Signature = private.signing_key().sign(msg);

    let sig_bytes = ksig.to_bytes();
    let r = bytes_to_bigint(&sig_bytes[..32]);
    let s = bytes_to_bigint(&sig_bytes[32..]);

    Signature { r, s }
}
pub fn verify(public: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
    let mut sig_bytes = [0u8; 64];
    let r_bytes = bigint_to_32_bytes(&sig.r);
    let s_bytes = bigint_to_32_bytes(&sig.s);
    sig_bytes[..32].copy_from_slice(&r_bytes);
    sig_bytes[32..].copy_from_slice(&s_bytes);

    let ksig = match K256Signature::try_from(&sig_bytes[..]) {
        Ok(s) => s,
        Err(_) => return false,
    };

    public.verifying_key().verify(msg, &ksig).is_ok()
}
