# Email Backup Manager

**Versão atual do código:** 1.18 (distribuição pública sem configurações privadas).

Aplicativo desktop para Windows voltado a **backup incremental, conversão e restauração de caixas de e-mail via IMAP**, com preservação de estrutura de pastas e metadados necessários para reconstruir a conta posteriormente.

O projeto também oferece conversão de backups para um **pacote MBOX estruturado** e restauração de **Google Takeout (MBOX)**, incluindo reconstrução de pastas a partir de `X-Gmail-Labels`.

> **Status do projeto:** em desenvolvimento ativo. Faça testes em ambiente controlado antes de utilizar em produção.

## O que o projeto faz

O Email Backup Manager reúne em uma interface gráfica os principais fluxos necessários para preservar e reconstruir uma conta de e-mail:

- gerenciamento de múltiplos perfis de servidor e múltiplas contas;
- conexão IMAP com SSL/TLS e `AUTHENTICATE LOGIN`;
- backup de uma pasta específica ou de todas as pastas selecionáveis;
- backup incremental por `UIDVALIDITY` + UID;
- armazenamento das mensagens em arquivos `.eml`;
- verificação de integridade por SHA-256;
- preservação de `FLAGS` e `INTERNALDATE`;
- retomada após interrupção usando `.ebm_state.json`;
- conversão de um backup concluído para pacote MBOX multi-pastas;
- pré-visualização da estrutura antes da conversão e da restauração;
- restauração via IMAP `CREATE` + `APPEND`;
- restauração de Google Takeout/MBOX;
- reconstrução de labels/pastas do Takeout;
- dry-run de restauração;
- prevenção de duplicação por pasta + `Message-ID` + SHA-256;
- relatórios e logs de diagnóstico.

## Por que este projeto é útil

Um arquivo MBOX isolado não representa, por si só, toda a estrutura IMAP de uma conta. Pastas, flags, datas internas e relações entre mensagens precisam ser preservadas separadamente para que uma restauração futura seja fiel.

Este projeto mantém essas informações junto do conteúdo bruto das mensagens e permite:

1. continuar backups interrompidos sem baixar novamente mensagens já preservadas;
2. conferir a integridade dos arquivos locais;
3. transportar o backup para um pacote MBOX estruturado;
4. visualizar a estrutura final antes de restaurar;
5. reconstruir pastas no servidor de destino por IMAP.

## Plataformas e requisitos

O aplicativo foi desenvolvido para **Windows** e utiliza somente módulos da biblioteca padrão do Python.

Requisitos principais:

- Windows;
- Python 3 com `tkinter`;
- acesso de rede ao servidor IMAP;
- uma conta de e-mail com IMAP habilitado.

O armazenamento opcional de senhas utiliza **Windows DPAPI**, portanto esse recurso é específico do Windows.

## Como começar

### 1. Baixe ou clone o repositório

```powershell
git clone https://github.com/frenovato/Email-Backup-Manager.git
cd Email-Backup-Manager
```

Você também pode baixar o ZIP do repositório e extraí-lo.

### 2. Execute o aplicativo

No Windows:

```powershell
python email_backup_manager.py
```

Ou execute:

```text
run.bat
```

### 3. Cadastre um servidor

Na aba **Servidores e contas**:

1. crie ou selecione um perfil;
2. informe domínio, host, porta e segurança;
3. selecione o método de autenticação;
4. adicione uma ou mais contas;
5. teste a conexão antes de iniciar qualquer operação.

Exemplo genérico:

```text
Servidor: imap.example.com
Porta: 993
Segurança: SSL/TLS
Autenticação: AUTH LOGIN
Usuário: usuario@example.com
```

Nenhuma credencial real é incluída neste repositório.

## Backup

Na aba **Backup**:

1. selecione o perfil;
2. selecione a conta;
3. aguarde o carregamento automático das pastas;
4. escolha **Pasta individual** ou **Todas as pastas**;
5. configure o diretório de destino;
6. mantenha **Backup incremental** habilitado para evitar downloads repetidos;
7. execute o backup.

### Estrutura local

O backup segue a estrutura do servidor:

```text
<diretorio-base>/
└── <host>/
    └── <conta>/
        └── INBOX/
            ├── uid_123.eml
            ├── uid_124.eml
            ├── .ebm_state.json
            └── manifest.json
```

Subpastas IMAP são materializadas como subdiretórios locais.

### Estado incremental

Cada mailbox mantém um `.ebm_state.json` próprio.

O estado registra, entre outros dados:

- mailbox original;
- delimitador IMAP;
- `UIDVALIDITY`;
- `UIDNEXT`;
- UIDs já preservados;
- SHA-256;
- FLAGS;
- INTERNALDATE.

Quando a verificação SHA-256 está habilitada, um arquivo ausente ou corrompido volta para a fila do backup.

Se `UIDVALIDITY` mudar, o processo é interrompido em segurança para evitar associar um UID antigo a outra mensagem.

## Converter para MBOX

A aba **Converter para MBOX** transforma um backup concluído em um pacote adequado para arquivamento e restauração futura.

Antes de converter, **Analisar backup** mostra uma pré-visualização da estrutura com:

- pastas;
- mensagens válidas;
- mensagens pendentes;
- arquivos inválidos;
- status de cada mailbox;
- caminho MBOX que será criado.

### Formato do pacote

```text
<conta>_MBOX/
├── manifest.json
├── mbox/
│   └── <estrutura-de-pastas>/
│       └── <pasta>.mbox
└── metadata/
    └── <estrutura-de-pastas>/
        └── <pasta>.json
```

O pacote preserva informações como:

- nome IMAP original;
- delimitador;
- UID;
- `UIDVALIDITY`;
- FLAGS;
- INTERNALDATE;
- Message-ID;
- SHA-256;
- offset e tamanho de cada mensagem dentro do MBOX.

A codificação MBOX usa quoting **mboxrd reversível** e o SHA-256 é usado para verificar a recuperação dos bytes originais.

## Restauração

A aba **Restauração** aceita:

- backup criado pelo próprio aplicativo;
- pacote MBOX convertido;
- Google Takeout (MBOX).

Use **Analisar restauração** antes de executar. A análise consulta o servidor de destino e apresenta:

- árvore final de pastas;
- pasta de origem;
- quantidade de mensagens;
- se a pasta já existe;
- ação prevista;
- nome IMAP final.

A análise não executa `CREATE` ou `APPEND`.

### Execução

A restauração usa:

- IMAP `CREATE` para pastas ausentes;
- IMAP `APPEND` para mensagens;
- FLAGS quando disponíveis;
- INTERNALDATE quando disponível;
- `Date` do cabeçalho como fallback;
- dry-run;
- retomada/idempotência;
- relatório JSON.

## Google Takeout

O projeto **não faz backup direto do Gmail**.

Google é suportado somente como origem de restauração por **Google Takeout/MBOX**.

Durante a análise/restauração, o aplicativo interpreta `X-Gmail-Labels` para reconstruir a organização da conta. Uma mensagem pode ser materializada em mais de uma pasta quando possuir múltiplos labels.

## MBOX → hMailServer

A aba **MBOX → hMailServer** usa o mesmo motor estrutural da restauração.

Fontes suportadas:

- pacote MBOX convertido pelo aplicativo;
- Google Takeout (MBOX).

Para preservar a estrutura completa, a restauração é feita por **IMAP `CREATE` + `APPEND`**. Um envio SMTP simples não consegue reconstruir de forma equivalente uma árvore de subpastas.

## Segurança e privacidade

Este repositório não deve conter dados reais de e-mail.

Não publique:

- senhas;
- tokens;
- arquivos DPAPI;
- `config.json` real;
- logs de produção;
- `.eml`;
- `.mbox`;
- `.ebm_state.json`;
- manifestos contendo dados reais;
- relatórios de restauração;
- diretórios de backup.

O arquivo `.gitignore` incluído nesta distribuição ajuda a evitar commits acidentais desses dados, mas revise sempre o conteúdo antes de fazer `git add` ou publicar uma release.

### Senhas

Quando a opção de salvar senha está habilitada, o aplicativo usa **DPAPI do Windows**. A senha protegida é vinculada ao usuário do Windows que a salvou.

Para uso público ou distribuição entre máquinas, não compartilhe arquivos de configuração que contenham `password_enc`.

## Arquivos de configuração e logs

Por padrão, os dados operacionais ficam fora do repositório:

```text
%APPDATA%\EmailBackupManager\config.json
%APPDATA%\EmailBackupManager\logs\email_backup_manager.log
```

Os backups ficam no diretório escolhido pelo usuário.

## Estrutura do repositório

```text
.
├── email_backup_manager.py
├── run.bat
├── README.md
├── config.example.json
└── .gitignore
```

## Limitações atuais

O projeto ainda está em evolução. Entre os pontos importantes:

- o caminho funcional principal de backup/restauração foi desenvolvido em torno de IMAP + SSL/TLS + `AUTHENTICATE LOGIN`;
- outros métodos exibidos na interface podem exigir validação adicional com cada provedor;
- antes de uma restauração em produção, utilize **Analisar restauração** e **Dry-run**;
- grandes caixas devem ser acompanhadas pelos logs e pelo estado incremental.

## Solução de problemas

Se ocorrer falha de conexão:

1. confirme host e porta;
2. valide SSL/TLS;
3. confirme que o usuário é o endereço completo quando o provedor exigir;
4. teste a conta no cliente de e-mail/webmail;
5. consulte **Logs / Diagnóstico**;
6. teste primeiro em uma conta de laboratório.

Para problemas com estrutura de pastas, execute a análise antes da restauração e confira o delimitador e os nomes IMAP exibidos na pré-visualização.

## Ajuda

Para relatar erro ou solicitar melhoria, abra uma **Issue** neste repositório e inclua:

- versão do aplicativo;
- versão do Python;
- versão do Windows;
- tipo de servidor IMAP;
- trecho relevante do log **sem senhas, tokens ou dados pessoais**;
- passos para reproduzir o problema.

## Contribuições

Contribuições são bem-vindas.

Antes de enviar uma alteração:

1. não inclua credenciais ou caixas reais;
2. mantenha compatibilidade com o formato de estado existente;
3. preserve o comportamento somente leitura durante backup;
4. valide que restaurações destrutivas não sejam introduzidas sem proteção;
5. execute `py_compile` antes do pull request.

Exemplo:

```powershell
python -m py_compile email_backup_manager.py
```

## Manutenção

O projeto é mantido pelo proprietário e pelos colaboradores deste repositório.

Use Issues e Pull Requests para registrar mudanças de forma rastreável.

## Licença

Este repositório contém o arquivo [LICENSE](LICENSE), com o texto da **GNU General Public License versão 3 (GPLv3)**. Consulte esse arquivo para conhecer as condições de uso, modificação e redistribuição do software.
