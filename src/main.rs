use std::fs;

fn main() {
    println!("Digite o nome do arquivo a ser assinado:");
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .expect("Falha ao ler o nome do arquivo");
    let filename = input.trim();
    println!("Arquivo a ser assinado: {}", filename);
    let filepath = format!("files\\{}", filename);
    println!("Caminho completo do arquivo: {}", filepath);
    let bin_content: Vec<u8> = fs::read(&filepath).expect("Falha ao ler o arquivo");
    // println!("Conteúdo do arquivo (bytes): {:?}", bin_content);
    println!("Tamanho do arquivo (bytes): {}", bin_content.len());  
    
}
