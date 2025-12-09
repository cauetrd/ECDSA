use crate::crypto::key::{PrivateKey, PublicKey};
use num_bigint::{BigInt, Sign};
use k256::ecdsa::{
    Signature as K256Signature,
    signature::{Signer, Verifier},
};
use core::convert::TryFrom; // <-- adicionar

/// Estrutura da assinatura ECDSA (formato usado em arquivo)
pub struct Signature {
    pub r: BigInt,
    pub s: BigInt,
}

// Converte BigInt para 32 bytes big-endian (com zero-padding à esquerda)
fn bigint_to_32_bytes(x: &BigInt) -> [u8; 32] {
    let (_, mut bytes) = x.to_bytes_be();
    if bytes.len() > 32 {
        // mantém apenas os 32 bytes menos significativos
        bytes = bytes[bytes.len() - 32..].to_vec();
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

// Converte bytes big-endian em BigInt positivo
fn bytes_to_bigint(bytes: &[u8]) -> BigInt {
    BigInt::from_bytes_be(Sign::Plus, bytes)
}

/// Assina os bytes passados (aqui estamos assinando `hash_bytes` vindo do main)
pub fn sign(private: &PrivateKey, msg: &[u8]) -> Signature {
    // Usa a implementação ECDSA + RFC6979 do k256
    let ksig: K256Signature = private.signing_key().sign(msg);

    let sig_bytes = ksig.to_bytes(); // 64 bytes = r || s
    let r = bytes_to_bigint(&sig_bytes[..32]);
    let s = bytes_to_bigint(&sig_bytes[32..]);

    Signature { r, s }
}

/// Verifica a assinatura usando k256
pub fn verify(public: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
    // Remonta a assinatura de 64 bytes (r || s) para k256
    let mut sig_bytes = [0u8; 64];
    let r_bytes = bigint_to_32_bytes(&sig.r);
    let s_bytes = bigint_to_32_bytes(&sig.s);
    sig_bytes[..32].copy_from_slice(&r_bytes);
    sig_bytes[32..].copy_from_slice(&s_bytes);

    // usar TryFrom<&[u8]> em vez de from_bytes(&[u8; 64])
    let ksig = match K256Signature::try_from(&sig_bytes[..]) {
        Ok(s) => s,
        Err(_) => return false,
    };

    public.verifying_key().verify(msg, &ksig).is_ok()
}