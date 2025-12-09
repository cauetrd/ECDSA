//! Módulo raiz do subsistema criptográfico.
//!
//! Aqui são reexportados os submódulos responsáveis por:
//! - gerenciamento de chaves (`key`)
//! - primitivas ECDSA (`ecdsa`)
//! - operações de alto nível de assinatura/verificação (`encoding`)
//! - utilitários relacionados a arquivos (`files`)

pub mod key;
pub mod ecdsa;
pub mod encoding;
pub mod files;