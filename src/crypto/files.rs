//! Utilitários para manipulação de arquivos.
//!
//! No momento, este módulo expõe apenas uma função para cálculo
//! de hash SHA‑256 de arquivos de forma eficiente em memória.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use sha2::{Digest, Sha256};

/// Calcula o hash SHA‑256 do arquivo indicado por `path`.
///
/// O arquivo é lido em blocos (buffer) para evitar carregá‑lo
/// inteiro na memória, o que é importante para arquivos grandes.
pub fn sha256_file(path: &Path) -> std::io::Result<[u8; 32]> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();

    let mut buffer = [0u8; 4096];

    loop {
        let bytes_read = reader.read(&mut buffer)?;

        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
    }

    let result = hasher.finalize();
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&result[..]);

    Ok(hash_bytes)
}
