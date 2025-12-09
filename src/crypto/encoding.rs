use std::{io, path::Path};

use crate::crypto::{
    ecdsa,
    key::{PrivateKey, PublicKey},
    files::sha256_file,
};

/// Resultado de uma operação de assinatura
pub struct SignResult {
    pub hash_hex: String,
    pub signature: ecdsa::Signature,
}

/// Resultado de uma operação de verificação
pub struct VerifyResult {
    pub hash_hex: String,
    pub is_valid: bool,
}

/// Calcula o SHA‑256 de um arquivo e retorna em hex (minúsculo)
pub fn hash_file_hex(path: &Path) -> io::Result<String> {
    let hash_bytes = sha256_file(path)?;
    Ok(hex::encode(hash_bytes))
}

/// Assina o conteúdo de um arquivo:
/// 1. Faz SHA‑256 do arquivo
/// 2. Usa ECDSA (k256) para assinar o hash
pub fn sign_file(path: &Path, private: &PrivateKey) -> io::Result<SignResult> {
    let hash_bytes = sha256_file(path)?;
    let hash_hex = hex::encode(&hash_bytes);
    let signature = ecdsa::sign(private, &hash_bytes);
    Ok(SignResult { hash_hex, signature })
}

/// Verifica a assinatura de um arquivo:
/// 1. Faz SHA‑256 do arquivo
/// 2. Verifica assinatura ECDSA sobre o hash
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
