//! Rotinas de assinatura e verificação ECDSA usando a curva `k256`.
//!
//! Este módulo faz a ponte entre o tipo de chave definido em `crypto::key`
//! e a implementação ECDSA da crate `k256`, expondo uma estrutura de
//! assinatura simples baseada em `BigInt`.

use core::convert::TryFrom;

use k256::ecdsa::{
    signature::{Signer, Verifier},
    Signature as K256Signature,
};
use num_bigint::{BigInt, Sign};

use crate::crypto::key::{PrivateKey, PublicKey};

/// Representa uma assinatura ECDSA no formato utilizado pelo projeto.
///
/// Os campos `r` e `s` são os inteiros grandes correspondentes à assinatura
/// gerada/validada pela biblioteca `k256`.
pub struct Signature {
    pub r: BigInt,
    pub s: BigInt,
}

/// Converte um [`BigInt`] para um array de 32 bytes em big-endian,
/// aplicando zero‑padding à esquerda quando necessário.
fn bigint_to_32_bytes(x: &BigInt) -> [u8; 32] {
    let (_, mut bytes) = x.to_bytes_be();

    // Mantém apenas os 32 bytes menos significativos, caso o número
    // ocupe mais que isso.
    if bytes.len() > 32 {
        bytes = bytes[bytes.len() - 32..].to_vec();
    }

    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// Converte um slice de bytes big-endian em um [`BigInt`] positivo.
fn bytes_to_bigint(bytes: &[u8]) -> BigInt {
    BigInt::from_bytes_be(Sign::Plus, bytes)
}

/// Assina uma mensagem arbitrária usando uma chave privada ECDSA.
///
/// A mensagem esperada normalmente é o hash (SHA‑256) de um arquivo,
/// mas qualquer slice de bytes pode ser fornecido em `msg`.
pub fn sign(private: &PrivateKey, msg: &[u8]) -> Signature {
    // Usa a implementação ECDSA + RFC6979 da crate `k256`.
    let ksig: K256Signature = private.signing_key().sign(msg);

    // A assinatura da `k256` vem como 64 bytes: r || s.
    let sig_bytes = ksig.to_bytes();
    let r = bytes_to_bigint(&sig_bytes[..32]);
    let s = bytes_to_bigint(&sig_bytes[32..]);

    Signature { r, s }
}

/// Verifica uma assinatura ECDSA para a mensagem informada.
///
/// Retorna `true` se a assinatura for válida para a chave pública
/// e mensagem fornecidas, ou `false` caso contrário.
pub fn verify(public: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
    // Remonta a assinatura de 64 bytes (r || s) para o tipo da `k256`.
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
