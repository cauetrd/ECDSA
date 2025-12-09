mod crypto;

use std::fs;
use std::path::{Path, PathBuf};
use crypto::key::{PrivateKey, PublicKey};
use crypto::{ecdsa, encoding};

fn main() {
    println!("=== Sistema de Assinatura Digital ECDSA ===\n");
    println!("Escolha uma opção:");
    println!("1. Gerar novo par de chaves");
    println!("2. Assinar um arquivo");
    println!("3. Verificar assinatura de um arquivo");
    
    let mut choice = String::new();
    std::io::stdin()
        .read_line(&mut choice)
        .expect("Falha ao ler opção");
    
    match choice.trim() {
        "1" => generate_keys(),
        "2" => sign_file(),
        "3" => verify_file(),
        _ => println!("Opção inválida!"),
    }
}

fn generate_keys() {
    println!("\n=== Gerando Par de Chaves ===");
    
    let private_key = PrivateKey::generate();
    let public_key = private_key.public_key();
    
    private_key.save(Path::new("private.key"))
        .expect("Falha ao salvar chave privada");
    public_key.save(Path::new("public.key"))
        .expect("Falha ao salvar chave pública");
    
    println!("✓ Chave privada salva em: keys/private.key");
    println!("✓ Chave pública salva em: keys/public.key");
    println!("\nPar de chaves gerado com sucesso!");
}

fn sign_file() {
    println!("\n=== Assinar Arquivo ===");
    
    let private_key = match PrivateKey::load(Path::new("private.key")) {
        Ok(key) => key,
        Err(_) => {
            println!("❌ Chave privada não encontrada!");
            println!("Execute a opção 1 para gerar um par de chaves primeiro.");
            return;
        }
    };
    
    println!("Digite o nome do arquivo a ser assinado:");
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .expect("Falha ao ler o nome do arquivo");
    let filename = input.trim();
    
    let mut filepath = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    filepath.push("files");
    filepath.push(filename);
    
    println!("Lendo arquivo: {}", filepath.display());

    // usa encoding::sign_file (hash + ECDSA)
    let result = match encoding::sign_file(&filepath, &private_key) {
        Ok(r) => r,
        Err(e) => {
            println!("❌ Erro ao processar arquivo: {}", e);
            return;
        }
    };

    println!("✓ SHA-256: {}", result.hash_hex);
    println!("✓ Arquivo assinado!");
    println!("  r: {}", result.signature.r.to_str_radix(16));
    println!("  s: {}", result.signature.s.to_str_radix(16));
    
    // Salva a assinatura em arquivo .sig
    let sig_filename = format!("{}.sig", filename);
    let mut sig_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    sig_path.push("files");
    sig_path.push(&sig_filename);
    
    let sig_content = format!(
        "{}\n{}",
        result.signature.r.to_str_radix(16),
        result.signature.s.to_str_radix(16)
    );
    
    if let Err(e) = fs::write(&sig_path, sig_content) {
        println!("❌ Falha ao salvar assinatura: {}", e);
        return;
    }
    
    println!("✓ Assinatura salva em: files/{}", sig_filename);
}

fn verify_file() {
    println!("\n=== Verificar Assinatura ===");
    
    let public_key = match PublicKey::load(Path::new("public.key")) {
        Ok(key) => key,
        Err(_) => {
            println!("❌ Chave pública não encontrada!");
            return;
        }
    };
    
    println!("Digite o nome do arquivo a ser verificado:");
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .expect("Falha ao ler o nome do arquivo");
    let filename = input.trim();
    
    let mut filepath = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    filepath.push("files");
    filepath.push(filename);
    
    let sig_filename = format!("{}.sig", filename);
    let mut sig_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    sig_path.push("files");
    sig_path.push(&sig_filename);
    
    // Lê a assinatura em texto (r e s em hex)
    let sig_content = match fs::read_to_string(&sig_path) {
        Ok(content) => content,
        Err(_) => {
            println!("❌ Arquivo de assinatura não encontrado: {}", sig_filename);
            return;
        }
    };
    
    let sig_lines: Vec<&str> = sig_content.lines().collect();
    if sig_lines.len() != 2 {
        println!("❌ Formato de assinatura inválido (esperado 2 linhas: r e s em hex)!");
        return;
    }
    
    let r_hex = sig_lines[0].trim();
    let r = match num_bigint::BigInt::parse_bytes(r_hex.as_bytes(), 16) {
        Some(v) => v,
        None => {
            println!("❌ Assinatura inválida: valor r não é hexadecimal válido: '{}'", r_hex);
            return;
        }
    };

    let s_hex = sig_lines[1].trim();
    let s = match num_bigint::BigInt::parse_bytes(s_hex.as_bytes(), 16) {
        Some(v) => v,
        None => {
            println!("❌ Assinatura inválida: valor s não é hexadecimal válido: '{}'", s_hex);
            return;
        }
    };
    
    let signature = ecdsa::Signature { r, s };

    // usa encoding::verify_file (hash + verificação)
    let result = match encoding::verify_file(&filepath, &public_key, &signature) {
        Ok(r) => r,
        Err(e) => {
            println!("❌ Erro ao processar arquivo: {}", e);
            return;
        }
    };

    println!("✓ SHA-256: {}", result.hash_hex);

    if result.is_valid {
        println!("\n✓✓✓ ASSINATURA VÁLIDA ✓✓✓");
        println!("O arquivo é autêntico e não foi modificado.");
    } else {
        println!("\n❌❌❌ ASSINATURA INVÁLIDA ❌❌❌");
        println!("O arquivo pode ter sido modificado ou a assinatura é inválida.");
    }
}
