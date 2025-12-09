use std::fs;
use std::path::{Path, PathBuf};
use std::env;
use crypto::{ecdsa, encoding};
use crypto::key::{PrivateKey, PublicKey};


fn main() {
    // Uso:
    //   ecdsa 1 <nome_chaves>
    //   ecdsa 2 <nome_chaves> <arquivo>
    //   ecdsa 3 <nome_chaves> <arquivo>
    let mut args = env::args().skip(1); // pula o nome do binário

    let op = match args.next() {
        Some(v) => v,
        None => {
            print_usage();
            return;
        }
    };

    match op.as_str() {
        "1" => {
            let nome_chaves = match args.next() {
                Some(n) => n,
                None => {
                    eprintln!("Erro: falta o parâmetro <nome_chaves>.");
                    print_usage();
                    return;
                }
            };
            generate_keys(&nome_chaves);
        }
        "2" => {
            let nome_chaves = match args.next() {
                Some(n) => n,
                None => {
                    eprintln!("Erro: falta o parâmetro <nome_chaves>.");
                    print_usage();
                    return;
                }
            };
            let nome_arquivo = match args.next() {
                Some(f) => f,
                None => {
                    eprintln!("Erro: falta o parâmetro <arquivo>.");
                    print_usage();
                    return;
                }
            };
            sign_file(&nome_chaves, &nome_arquivo);
        }
        "3" => {
            let nome_chaves = match args.next() {
                Some(n) => n,
                None => {
                    eprintln!("Erro: falta o parâmetro <nome_chaves>.");
                    print_usage();
                    return;
                }
            };
            let nome_arquivo = match args.next() {
                Some(f) => f,
                None => {
                    eprintln!("Erro: falta o parâmetro <arquivo>.");
                    print_usage();
                    return;
                }
            };
            verify_file(&nome_chaves, &nome_arquivo);
        }
        _ => {
            eprintln!("Opção inválida: {}", op);
            print_usage();
        }
    }
}

fn print_usage() {
    println!("=== Sistema de Assinatura Digital ECDSA ===\n");
    println!("Uso:");
    println!("  ecdsa 1 <nome_chaves>              # gerar chaves");
    println!("  ecdsa 2 <nome_chaves> <arquivo>    # assinar arquivo");
    println!("  ecdsa 3 <nome_chaves> <arquivo>    # verificar assinatura");
    println!();
    println!("Exemplos:");
    println!("  ecdsa 1 alice");
    println!("  ecdsa 2 alice assinar.txt");
    println!("  ecdsa 3 alice assinar.txt");
}

fn generate_keys(nome_chaves: &str) {
    println!("\n=== Gerando Par de Chaves ===");

    let private_key = PrivateKey::generate();
    let public_key = private_key.public_key();

    let private_path = format!("{}_private.key", nome_chaves);
    let public_path = format!("{}_public.key", nome_chaves);

    private_key
        .save(Path::new(&private_path))
        .expect("Falha ao salvar chave privada");
    public_key
        .save(Path::new(&public_path))
        .expect("Falha ao salvar chave pública");

    println!("✓ Chave privada salva em: keys/{}", private_path);
    println!("✓ Chave pública salva em: keys/{}", public_path);
    println!("\nPar de chaves gerado com sucesso!");
}

fn sign_file(nome_chaves: &str, nome_arquivo: &str) {
    println!("\n=== Assinar Arquivo ===");

    let priv_path = format!("{}_private.key", nome_chaves);
    let private_key = match PrivateKey::load(Path::new(&priv_path)) {
        Ok(key) => key,
        Err(_) => {
            println!(
                "❌ Chave privada '{}' não encontrada em keys/{}",
                nome_chaves, priv_path
            );
            println!("Gere um par de chaves com: ecdsa 1 {}", nome_chaves);
            return;
        }
    };

    let filename = nome_arquivo.trim();
    let mut filepath = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    filepath.push("files");
    filepath.push(filename);

    println!("Lendo arquivo: {}", filepath.display());

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

    let sig_filename = format!("{}.sig", filename);
    let mut sig_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    sig_path.push("files");
    sig_path.push(&sig_filename);

    let sig_data = format!(
        "{}\n{}",
        result.signature.r.to_str_radix(16),
        result.signature.s.to_str_radix(16),
    );

    if let Err(e) = fs::write(&sig_path, sig_data) {
        println!("❌ Falha ao salvar assinatura: {}", e);
        return;
    }

    println!("✓ Assinatura salva em: {}", sig_path.display());
}

fn verify_file(nome_chaves: &str, nome_arquivo: &str) {
    println!("\n=== Verificar Assinatura de Arquivo ===");

    let pub_path = format!("{}_public.key", nome_chaves);
    let public_key = match PublicKey::load(Path::new(&pub_path)) {
        Ok(key) => key,
        Err(_) => {
            println!(
                "❌ Chave pública '{}' não encontrada em keys/{}",
                nome_chaves, pub_path
            );
            println!("Gere um par de chaves com: ecdsa 1 {}", nome_chaves);
            return;
        }
    };

    let filename = nome_arquivo.trim();
    let mut filepath = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    filepath.push("files");
    filepath.push(filename);

    println!("Lendo arquivo: {}", filepath.display());

    let sig_filename = format!("{}.sig", filename);
    let mut sig_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    sig_path.push("files");
    sig_path.push(&sig_filename);

    let sig_content = match fs::read_to_string(&sig_path) {
        Ok(content) => content,
        Err(e) => {
            println!("❌ Falha ao ler assinatura: {}", e);
            return;
        }
    };

    let sig_lines: Vec<&str> = sig_content.lines().collect();
    if sig_lines.len() < 2 {
        println!("❌ Formato de assinatura inválido no arquivo: {}", sig_filename);
        return;
    }

    let r_hex = sig_lines[0].trim();
    let r = match num_bigint::BigInt::parse_bytes(r_hex.as_bytes(), 16) {
        Some(val) => val,
        None => {
            println!("❌ Valor inválido para r na assinatura!");
            return;
        }
    };

    let s_hex = sig_lines[1].trim();
    let s = match num_bigint::BigInt::parse_bytes(s_hex.as_bytes(), 16) {
        Some(val) => val,
        None => {
            println!("❌ Valor inválido para s na assinatura!");
            return;
        }
    };

    let signature = ecdsa::Signature { r, s };

    let result = match encoding::verify_file(&filepath, &public_key, &signature) {
        Ok(r) => r,
        Err(e) => {
            println!("❌ Erro ao processar arquivo: {}", e);
            return;
        }
    };

    println!("✓ SHA-256: {}", result.hash_hex);

    if result.is_valid {
        println!("✓ Assinatura válida!");
    } else {
        println!("❌ Assinatura inválida!");
    }
}


