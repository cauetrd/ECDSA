//! Assinatura e verificação de arquivos usando ECDSA sobre SHA-256.

use std::{io, path::Path};

use crate::crypto::{
    ecdsa,
    files::sha256_file,
    key::{PrivateKey, PublicKey},
};

pub struct SignResult {
    pub hash_hex: String,
    pub signature: ecdsa::Signature,
}

pub struct VerifyResult {
    pub hash_hex: String,
    pub is_valid: bool,
}
pub fn sign_file(path: &Path, private: &PrivateKey) -> io::Result<SignResult> {
    let hash_bytes = sha256_file(path)?;
    let hash_hex = hex::encode(&hash_bytes);
    let signature = ecdsa::sign(private, &hash_bytes);

    Ok(SignResult { hash_hex, signature })
}
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
