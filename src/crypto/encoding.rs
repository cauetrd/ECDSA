//! Camada de alto nível para assinar e verificar arquivos.
//!
//! Este módulo combina o cálculo de hash (`SHA‑256`) com as rotinas de
//! assinatura ECDSA para oferecer funções simples de "assinar arquivo" e
//! "verificar assinatura de arquivo".

use std::{io, path::Path};

use crate::crypto::{
    ecdsa,
    files::sha256_file,
    key::{PrivateKey, PublicKey},
};

/// Resultado retornado após uma operação de assinatura de arquivo.
pub struct SignResult {
    /// Hash SHA‑256 do arquivo em formato hexadecimal.
    pub hash_hex: String,
    /// Assinatura ECDSA gerada para o hash do arquivo.
    pub signature: ecdsa::Signature,
}

/// Resultado retornado após uma operação de verificação de assinatura.
pub struct VerifyResult {
    /// Hash SHA‑256 do arquivo em formato hexadecimal.
    pub hash_hex: String,
    /// Indica se a assinatura fornecida é válida para o arquivo.
    pub is_valid: bool,
}

/// Assina o conteúdo de um arquivo.
///
/// Etapas:
/// 1. Calcula o SHA‑256 do arquivo indicado por `path`.
/// 2. Usa ECDSA (via `k256`) para assinar o hash com a chave privada.
pub fn sign_file(path: &Path, private: &PrivateKey) -> io::Result<SignResult> {
    let hash_bytes = sha256_file(path)?;
    let hash_hex = hex::encode(&hash_bytes);
    let signature = ecdsa::sign(private, &hash_bytes);

    Ok(SignResult { hash_hex, signature })
}

/// Verifica a assinatura de um arquivo.
///
/// Etapas:
/// 1. Calcula o SHA‑256 do arquivo indicado por `path`.
/// 2. Verifica a assinatura ECDSA do hash usando a chave pública.
pub fn verify_file(
    path: &Path,
    public: &PublicKey,
    signature: &ecdsa::Signature,
) -> io::Result<VerifyResult> {
    let hash_bytes = sha256_file(path)?;
    let hash_hex = hex::encode(&hash_bytes);
    let is_valid = ecdsa::verify(public, &hash_bytes, signature);

    Ok(VerifyResult { hash_hex, is_valid })
}
