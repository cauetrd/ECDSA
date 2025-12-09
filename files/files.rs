use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

// Retorna o hash SHA-256 de um arquivo grande sem carregar ele inteiro
pub fn sha256_file()