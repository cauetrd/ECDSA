# ECDSA

Implementação em Rust do algoritmo de assinatura digital ECDSA
usado na disciplina "Linguagens de Programação".

## Propósito do projeto

Este projeto demonstra, de forma didática, como funciona um sistema
de assinatura digital baseado em curvas elípticas (ECDSA) sobre a
curva `secp256k1` (crate `k256`).

Com ele você pode:
- gerar pares de chaves (privada/pública);
- assinar arquivos do computador;
- verificar a validade de assinaturas.

As chaves são armazenadas na pasta `keys/` e as assinaturas na
pasta `files/`, independente de onde o arquivo original esteja
no sistema de arquivos.

## Como funciona a assinatura com ECDSA

Em alto nível, o fluxo de assinatura/verificação é:

1. **Geração de chaves**: uma chave privada aleatória é gerada, e a
	 partir dela é derivada a chave pública correspondente.
2. **Hash do arquivo**: antes de assinar, o conteúdo do arquivo é
	 condensado em um hash SHA-256 (32 bytes fixos).
3. **Assinatura ECDSA**: o hash é assinado com a chave privada,
	 produzindo uma assinatura composta por dois inteiros grandes
	 $(r, s)$.
4. **Verificação**: qualquer pessoa com a chave pública pode verificar
	 se $(r, s)$ é uma assinatura válida para o hash do arquivo. Se o
	 arquivo for alterado ou a chave não corresponder, a verificação falha.

Formalmente, o ECDSA funciona sobre um grupo de pontos de uma curva
elíptica mod $p$. A chave privada é um escalar $d$, e a chave pública
é o ponto $Q = dG$, onde $G$ é o ponto gerador da curva. O algoritmo
usa operações de exponenciação escalar no grupo para garantir que,
sem conhecer $d$, seja computacionalmente inviável forjar assinaturas.

## Arquivos principais em `src/`

### `src/main.rs`

Ponto de entrada da aplicação em linha de comando. Exibe o menu
interativo e chama as funções de alto nível para:
- gerar par de chaves;
- assinar arquivo (aceitando caminhos arbitrários);
- verificar assinatura de arquivo.

Também centraliza a lógica de:
- confirmação antes de sobrescrever pares de chaves já existentes;
- confirmação antes de sobrescrever arquivos de assinatura já
	existentes em `files/`.

### `src/crypto/mod.rs`

Módulo raiz do subsistema criptográfico. Apenas reexporta os
submódulos:
- `key` — gerenciamento de chaves;
- `ecdsa` — primitivas de assinatura/verificação ECDSA;
- `encoding` — operações de alto nível para arquivos;
- `files` — utilitários de leitura e hash de arquivos.

### `src/crypto/key.rs`

Encapsula os tipos de chave privada e pública baseados em `k256`:
- `PrivateKey`: geração segura (via `OsRng`), serialização para
	bytes e salvamento/leitura em `keys/`.
- `PublicKey`: reconstrução a partir de bytes, salvamento/leitura em
	`keys/` e acesso ao tipo interno `VerifyingKey`.

Esse módulo é responsável por padronizar o formato em disco das
chaves usadas pelo restante do sistema.

### `src/crypto/ecdsa.rs`

Implementa as primitivas de assinatura/verificação ECDSA usando a
curva `k256`:
- tipo `Signature { r, s }` representando a assinatura em inteiros
	grandes;
- função `sign` para assinar um hash com uma `PrivateKey`;
- função `verify` para verificar uma assinatura com uma `PublicKey`.

Serve de ponte entre as chaves de alto nível (`key.rs`) e a
implementação de baixo nível da crate `k256`.

### `src/crypto/files.rs`

Fornece utilitários de acesso a arquivos. Atualmente expõe:
- `sha256_file(path: &Path) -> [u8; 32]`: lê o arquivo em blocos e
	calcula o hash SHA-256 sem carregar tudo em memória de uma vez.

### `src/crypto/encoding.rs`

Camada de alto nível que combina hash + ECDSA para arquivos:
- `sign_file(path, private) -> SignResult`: calcula o hash do
	arquivo, assina e retorna o hash em hexadecimal e a assinatura;
- `verify_file(path, public, signature) -> VerifyResult`: recalcula o
	hash, verifica a assinatura e informa se é válida.

Esse módulo é o que a `main` utiliza para assinar e verificar
arquivos, escondendo os detalhes de baixo nível.

## Como executar

1. Certifique-se de ter o Rust instalado.
2. No diretório do projeto, rode:

```bash
cargo run
```

3. Use o menu interativo para gerar chaves, assinar e verificar
	 arquivos. Para assinar/verificar, você pode informar:
- apenas o nome de um arquivo dentro de `files/` (por exemplo,
	`assinar.txt`); ou
- um caminho absoluto/relativo em qualquer lugar do seu computador
	(por exemplo, `/home/usuario/documentos/contrato.pdf`).

As assinaturas sempre serão gravadas em `files/`, com o nome do
arquivo original acrescido de `.sig` (por exemplo, `contrato.pdf.sig`).
