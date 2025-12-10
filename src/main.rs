mod crypto;

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use crypto::{ecdsa, encoding};
use crypto::key::{PrivateKey, PublicKey};

fn main() {
    loop {
        println!("\n=== Sistema de Assinatura Digital ECDSA ===");
        println!("Use o teclado para escolher uma opção:");
        println!("  1) Gerar par de chaves");
        println!("  2) Assinar arquivo");
        println!("  3) Verificar assinatura de arquivo");
        println!("  4) Sair");
        print!("\nDigite a opção desejada: ");
        io::stdout().flush().ok();

        let opcao = match read_line_trimmed() {
            Some(v) => v,
            None => {
                println!("Entrada inválida. Tente novamente.");
                continue;
            }
        };

        match opcao.as_str() {
            "1" => {
                println!("\n=== Gerar Par de Chaves ===");
                print!("Digite o nome base para as chaves (ex: alice): ");
                io::stdout().flush().ok();

                let nome_chaves = match read_line_trimmed() {
                    Some(n) if !n.is_empty() => n,
                    _ => {
                        println!("Nome inválido. Operação cancelada.");
                        continue;
                    }
                };

                generate_keys(&nome_chaves);
            }
            "2" => {
                println!("\n=== Assinar Arquivo ===");
                print!("Digite o nome base das chaves (ex: alice): ");
                io::stdout().flush().ok();
                let nome_chaves = match read_line_trimmed() {
                    Some(n) if !n.is_empty() => n,
                    _ => {
                        println!("Nome inválido. Operação cancelada.");
                        continue;
                    }
                };

                print!("Digite o caminho do arquivo (ou nome em 'files/'): ");
                io::stdout().flush().ok();
                let nome_arquivo = match read_line_trimmed() {
                    Some(f) if !f.is_empty() => f,
                    _ => {
                        println!("Nome de arquivo inválido. Operação cancelada.");
                        continue;
                    }
                };

                sign_file(&nome_chaves, &nome_arquivo);
            }
            "3" => {
                println!("\n=== Verificar Assinatura de Arquivo ===");
                print!("Digite o nome base das chaves (ex: alice): ");
                io::stdout().flush().ok();
                let nome_chaves = match read_line_trimmed() {
                    Some(n) if !n.is_empty() => n,
                    _ => {
                        println!("Nome inválido. Operação cancelada.");
                        continue;
                    }
                };

                print!("Digite o caminho do arquivo (ou nome em 'files/'): ");
                io::stdout().flush().ok();
                let nome_arquivo = match read_line_trimmed() {
                    Some(f) if !f.is_empty() => f,
                    _ => {
                        println!("Nome de arquivo inválido. Operação cancelada.");
                        continue;
                    }
                };

                verify_file(&nome_chaves, &nome_arquivo);
            }
            "4" => {
                println!("Saindo... até a próxima!");
                break;
            }
            _ => {
                println!("Opção inválida. Use 1, 2, 3 ou 4.");
            }
        }
    }
}

fn read_line_trimmed() -> Option<String> {
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return None;
    }
    let trimmed = input.trim().to_string();
    Some(trimmed)
}

fn generate_keys(nome_chaves: &str) {
    println!("\n=== Gerando Par de Chaves ===");

    let private_key = PrivateKey::generate();
    let public_key = private_key.public_key();

    let private_path = format!("{}_private.key", nome_chaves);
    let public_path = format!("{}_public.key", nome_chaves);

    let keys_dir = Path::new("keys");
    let private_full = keys_dir.join(&private_path);
    let public_full = keys_dir.join(&public_path);

    if private_full.exists() || public_full.exists() {
        println!(
            "⚠️ Já existe um par de chaves com o nome '{}'.",
            nome_chaves
        );
        print!("Deseja sobrescrever as chaves existentes? (s/n): ");
        io::stdout().flush().ok();

        let resposta = match read_line_trimmed() {
            Some(r) => r.to_lowercase(),
            None => {
                println!("Entrada inválida. Operação cancelada.");
                return;
            }
        };

        if resposta != "s" && resposta != "sim" {
            println!("Operação cancelada. Chaves existentes foram mantidas.");
            return;
        }
    }

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

fn resolve_file_path(input: &str) -> Option<PathBuf> {
    let trimmed = input.trim();

    if trimmed.is_empty() {
        return None;
    }

    let direct = PathBuf::from(trimmed);
    if direct.is_absolute() || direct.exists() {
        return Some(direct);
    }

    let mut files_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    files_path.push("files");
    files_path.push(trimmed);

    if files_path.exists() {
        Some(files_path)
    } else {
        None
    }
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

    let filepath = match resolve_file_path(nome_arquivo) {
        Some(p) => p,
        None => {
            println!("❌ Arquivo não encontrado: {}", nome_arquivo);
            return;
        }
    };

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

    let file_name = match filepath.file_name() {
        Some(n) => n.to_string_lossy().to_string(),
        None => {
            println!("❌ Não foi possível determinar o nome do arquivo para salvar a assinatura.");
            return;
        }
    };

    let sig_filename = format!("{}.sig", file_name);
    let mut sig_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    sig_path.push("files");
    if let Err(e) = fs::create_dir_all(&sig_path) {
        println!("❌ Falha ao garantir diretório de assinaturas: {}", e);
        return;
    }
    sig_path.push(&sig_filename);

    if sig_path.exists() {
        println!(
            "⚠️ Já existe uma assinatura para este arquivo em {}.",
            sig_path.display()
        );
        print!("Deseja sobrescrever a assinatura existente? (s/n): ");
        io::stdout().flush().ok();

        let resposta = match read_line_trimmed() {
            Some(r) => r.to_lowercase(),
            None => {
                println!("Entrada inválida. Operação cancelada.");
                return;
            }
        };

        if resposta != "s" && resposta != "sim" {
            println!("Operação cancelada. Assinatura existente foi mantida.");
            return;
        }
    }

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

    let filepath = match resolve_file_path(nome_arquivo) {
        Some(p) => p,
        None => {
            println!("❌ Arquivo não encontrado: {}", nome_arquivo);
            return;
        }
    };

    println!("Lendo arquivo: {}", filepath.display());

    let file_name = match filepath.file_name() {
        Some(n) => n.to_string_lossy().to_string(),
        None => {
            println!("❌ Não foi possível determinar o nome do arquivo para localizar a assinatura.");
            return;
        }
    };

    let sig_filename = format!("{}.sig", file_name);
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


