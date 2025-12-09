//! Tipos de alto nível para chaves ECDSA baseadas em `k256`.
//!
//! Este módulo encapsula os tipos de chave privada e pública da crate
//! `k256`, oferecendo operações simples de geração, serialização e
//! persistência em disco (pasta `keys/`).

use std::fs;
use std::path::Path;

use k256::ecdsa::{SigningKey, VerifyingKey};
use k256::EncodedPoint;
use rand_core::OsRng;

/// Diretório padrão onde as chaves são gravadas e lidas.
const KEYS_DIR: &str = "keys";

/// Representa uma chave privada ECDSA.
pub struct PrivateKey {
    inner: SigningKey,
}

/// Representa uma chave pública ECDSA.
pub struct PublicKey {
    inner: VerifyingKey,
}

impl PrivateKey {
    /// Gera uma nova chave privada utilizando um gerador de números aleatórios
    /// seguro do sistema operacional.
    pub fn generate() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        Self { inner: signing_key }
    }

    /// Exporta a chave privada em um formato binário simples (32 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    /// Reconstrói uma chave privada a partir de bytes brutos.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let bytes_array: &[u8; 32] = bytes.try_into().ok()?;
        let signing_key = SigningKey::from_bytes(bytes_array.into()).ok()?;
        Some(Self { inner: signing_key })
    }

    /// Obtém a chave pública associada a esta chave privada.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            inner: *self.inner.verifying_key(),
        }
    }

    /// Salva a chave privada em um arquivo dentro da pasta `keys/`.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let keys_path = Path::new(KEYS_DIR);
        fs::create_dir_all(keys_path)?;
        let full_path = keys_path.join(path);
        fs::write(full_path, self.to_bytes())
    }

    /// Carrega uma chave privada de um arquivo dentro da pasta `keys/`.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let keys_path = Path::new(KEYS_DIR);
        let full_path = keys_path.join(path);
        let bytes = fs::read(full_path)?;

        // Em caso de corrupção no arquivo, `from_bytes` retornará `None`.
        // Aqui usamos `expect` para sinalizar claramente o erro.
        let key = Self::from_bytes(&bytes)
            .expect("Formato de chave privada inválido ao carregar do disco");

        Ok(key)
    }

    /// Exponde a [`SigningKey`] interna para uso em `crypto::ecdsa`.
    pub fn signing_key(&self) -> &SigningKey {
        &self.inner
    }
}

impl PublicKey {
    /// Exporta a chave pública em formato binário (ponto não comprimido).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_encoded_point(false).as_bytes().to_vec()
    }

    /// Reconstrói uma chave pública a partir de bytes brutos.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let encoded_point = EncodedPoint::from_bytes(bytes).ok()?;
        let verifying_key = VerifyingKey::from_encoded_point(&encoded_point).ok()?;
        Some(Self { inner: verifying_key })
    }

    /// Salva a chave pública em um arquivo dentro da pasta `keys/`.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let keys_path = Path::new(KEYS_DIR);
        fs::create_dir_all(keys_path)?;
        let full_path = keys_path.join(path);
        fs::write(full_path, self.to_bytes())
    }

    /// Carrega uma chave pública de um arquivo dentro da pasta `keys/`.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let keys_path = Path::new(KEYS_DIR);
        let full_path = keys_path.join(path);
        let bytes = fs::read(full_path)?;

        let key = Self::from_bytes(&bytes)
            .expect("Formato de chave pública inválido ao carregar do disco");

        Ok(key)
    }

    /// Exponde a [`VerifyingKey`] interna para uso em `crypto::ecdsa`.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.inner
    }
}
