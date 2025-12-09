mod hashfile;

use std::fs;
use std::path::PathBuf;

fn main() {
    //Sign Workflow:
    /*
    1. Ask user for filename
    2. Read file content as bytes and hash it using SHA-256
    3. Sign the hash using ECDSA with the generated private key
    4. Create a digital signature file containing the signature and public key
    */

    

    println!("Digite o nome do arquivo a ser assinado:");
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .expect("Falha ao ler o nome do arquivo");
    let filename = input.trim();
    println!("Arquivo a ser assinado: {}", filename);

    // Build path anchored to the crate root to avoid cwd issues.
    let mut filepath = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    filepath.push("files");
    filepath.push(filename);

    println!("Caminho completo do arquivo: {}", filepath.display());
    let bin_content: Vec<u8> = fs::read(&filepath).expect("Falha ao ler o arquivo");
    // println!("Conteúdo do arquivo (bytes): {:?}", bin_content);
    println!("Tamanho do arquivo (bytes): {}", bin_content.len());

    let sha256 = hashfile::hash_file(&filepath).expect("Falha ao calcular o hash");
    println!("SHA-256: {}", sha256);
}
