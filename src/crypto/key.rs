use std::fs;
use std::path::Path;
use rand_core::OsRng;
use k256::EncodedPoint;
use k256::ecdsa::{SigningKey, VerifyingKey};

const KEYS_DIR: &str = "keys";

pub struct PrivateKey {
    inner: SigningKey,
}

pub struct PublicKey {
    inner: VerifyingKey,
}

impl PrivateKey {
    // Gera uma chave privada nova
    pub fn generate() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        Self { inner: signing_key}
    }

    // Exporta em formato binário simples
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    // Importa de formato binário simples
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let bytes_array: &[u8; 32] = bytes.try_into().ok()?;
        let signing_key = SigningKey::from_bytes(bytes_array.into()).ok()?;
        Some(Self { inner: signing_key })
    }

    // Obtém a chave pública associada
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            inner: *self.inner.verifying_key(),
        }
    }

    // Salva a chave privada em um arquivo
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let keys_path = Path::new(KEYS_DIR);
        fs::create_dir_all(keys_path)?;
        let full_path = keys_path.join(path);
        fs::write(full_path, self.to_bytes())
    }

    // Carrega a chave privada de um arquivo
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let keys_path = Path::new(KEYS_DIR);
        let full_path = keys_path.join(path);
        let bytes = fs::read(full_path)?;
        Ok(Self::from_bytes(&bytes).unwrap())
    }

    // Expor a SigningKey interna para uso em crypto::ecdsa
    pub fn signing_key(&self) -> &SigningKey {
        &self.inner
    }
}

impl PublicKey {
    // Exporta chave para formato binário simples
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_encoded_point(false).as_bytes().to_vec()
    }

    // importa chave pública de formato binário simples
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let encoded_point = EncodedPoint::from_bytes(bytes).ok()?;
        let verifying_key = VerifyingKey::from_encoded_point(&encoded_point).ok()?;
        Some(Self { inner: verifying_key})
    }

    // Salva a chave pública em um arquivo
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let keys_path = Path::new(KEYS_DIR);
        fs::create_dir_all(keys_path)?;
        let full_path = keys_path.join(path);
        fs::write(full_path, self.to_bytes())
    }

    // Carrega a chave pública de um arquivo
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let keys_path = Path::new(KEYS_DIR);
        let full_path = keys_path.join(path);
        let bytes = fs::read(full_path)?;
        Ok(Self::from_bytes(&bytes).unwrap())
    }    

    // Expor a VerifyingKey interna para uso em crypto::ecdsa
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.inner
    }
}