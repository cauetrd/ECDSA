mod crypto;

use crypto::key::{PrivateKey, PublicKey};
use std::path::Path;

fn main() {
    println!("=== Teste de Geração e Salvamento de Chaves ===\n");
    
    // Gera uma nova chave privada
    println!("Gerando chave privada...");
    let private_key = PrivateKey::generate();
    println!("✓ Chave privada gerada");
    
    // Obtém a chave pública correspondente
    let public_key = private_key.public_key();
    println!("✓ Chave pública derivada\n");
    
    // Salva as chaves em arquivos
    println!("Salvando chaves...");
    private_key.save(Path::new("private_key.bin"))
        .expect("Falha ao salvar chave privada");
    println!("✓ Chave privada salva em 'private_key.bin'");
    
    public_key.save(Path::new("public_key.bin"))
        .expect("Falha ao salvar chave pública");
    println!("✓ Chave pública salva em 'public_key.bin'\n");
    
    // Carrega as chaves dos arquivos
    println!("=== Teste de Carregamento de Chaves ===\n");
    let loaded_private = PrivateKey::load(Path::new("private_key.bin"))
        .expect("Falha ao carregar chave privada");
    println!("✓ Chave privada carregada");
    
    let loaded_public = PublicKey::load(Path::new("public_key.bin"))
        .expect("Falha ao carregar chave pública");
    println!("✓ Chave pública carregada\n");
    
    // Verifica se as chaves carregadas são iguais às originais
    println!("=== Verificação de Integridade ===\n");
    let original_pub_bytes = public_key.to_bytes();
    let loaded_pub_bytes = loaded_public.to_bytes();
    
    if original_pub_bytes == loaded_pub_bytes {
        println!("✓ Chaves públicas são idênticas");
    } else {
        println!("✗ Chaves públicas são diferentes!");
    }
    
    let derived_from_loaded = loaded_private.public_key();
    if derived_from_loaded.to_bytes() == loaded_pub_bytes {
        println!("✓ Chave pública derivada da privada carregada é válida");
    } else {
        println!("✗ Chave pública derivada não corresponde!");
    }
    
    println!("\n=== Informações das Chaves ===");
    println!("Tamanho da chave privada: {} bytes", private_key.to_pem().len());
    println!("Tamanho da chave pública: {} bytes", public_key.to_bytes().len());
    
    println!("\n✓ Todos os testes concluídos com sucesso!");
}