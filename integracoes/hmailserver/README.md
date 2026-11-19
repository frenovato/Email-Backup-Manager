# Integração MBOX → hMailServer (camada portátil)

Esta pasta contém um **adaptador CLI independente e opt-in** para validação e entrega de mensagens MBOX por SMTP local ao hMailServer. Ele complementa o Email Backup Manager, que já converte backups para MBOX e restaura via IMAP. **Ainda não está ligado à interface gráfica** do Email Backup Manager; não confundir inclusão da camada de integração com integração funcional completa.

## Como executar (Windows / PowerShell)

```powershell
py -3 --version
py -3 .\integracoes\hmailserver\migracao_mbox_portavel.py --mbox "D:\Backups\all_mail.mbox" --logs "D:\Backups\estado_migracao" --limite 10
```

A linha acima **NÃO ENVIA e-mails**: apenas abre, normaliza, corrige MIME quando preciso e valida a serialização dos primeiros 10 registros. Avalie o `erros.log` antes de continuar.

Para enviar 10 mensagens de teste à conta autorizada (envio real):

```powershell
py -3 .\integracoes\hmailserver\migracao_mbox_portavel.py --mbox "D:\Backups\all_mail.mbox" --destinatario "conta@dominio.interno" --smtp-host "127.0.0.1" --smtp-porta 25 --logs "D:\Backups\estado_migracao" --limite 10 --enviar
```

**Não executar envio real antes de conferir backup, destinatário e SMTP.** O SMTP aceita as mensagens para entrega; a confirmação da presença na caixa exige validação independente no hMailServer. A CLI usa a sintaxe `--limite 10` por padrão; não há modo "todas" nesta variante, para evitar envio integral acidental. Para lotes maiores, ajuste o limite conscientemente.

## Controle e continuidade

- `origem.json`: hash SHA-256 e tamanho da fonte MBOX usados para travar a retomada à mesma entrada.
- `processados.txt`: posições (1-based) **somente das mensagens aceitas pelo servidor SMTP**, não um controle transacional de entrega final. Em raros casos, uma falha depois de `sendmail` e antes da gravação pode resultar em duplicata ao retomar; valide a conta e o log.
- `migracao.log` e `erros.log`: privados; podem conter detalhes das operações.
- Nunca reordene/substitua o MBOX enquanto estiver usando o checkpoint; para outra fonte, escolha outra pasta de estado.
- Cópias do MBOX, EML, anexos, logs reais, `processados.txt` e credenciais são **dados privados** e não devem entrar no Git.

## Compatibilidade preservada

- Normalização de cabeçalhos não ASCII e serialização MIME;
- Tratamento de `multipart/*` com payload textual, validado no histórico para as mensagens 34682, 34769 e 35159;
- Verificação de extensão SMTPUTF8 e fallback SMTP/MIME; falhas de envio SMTPUTF8 incertas **não** são reenviadas automaticamente para evitar duplicatas;
- Sem escrita direta na pasta interna da INBOX;
- Processamento sobre cópia de cada mensagem.

**Limites de validação:** os cinco testes automatizados cobrem MIME sintético, anexos, preflight, bloqueio por checksum e não reenvio automático após falha SMTP incerta. A compatibilidade real com o servidor, dados de produção, HTML/imagens complexas, permissões SMTP, políticas antispam e casos históricos reais ainda precisa de homologação no ambiente de destino.

## Testes offline

```powershell
py -3 -m unittest discover -s testes -v
```

A implementação original e as decisões históricas encontram-se no pacote de continuidade entregue separadamente, incluindo `HISTORICO_CONTEXTO_PROJETO_MIGRACAO_MBOX_HMAILSERVER.docx`.
