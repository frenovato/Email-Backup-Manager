# Reinício em outro ambiente — Email Backup Manager

**Código:** https://github.com/frenovato/Email-Backup-Manager (público).
**Documentos e pacote v1.18:** https://drive.google.com/drive/folders/1VvQaMQ1zD456kaWTBHOJiE_AYnIi74Pp.

Python 3 / Tkinter para Windows, sem dependências Python externas conhecidas. Execute `py -3 email_backup_manager.py` ou `run.bat`. Adapte a configuração local a partir de `config.example.json`, preservando `config.json` fora do Git. O recurso DPAPI de senhas vincula-se ao Windows original: recrie credenciais no novo computador; não tente migrar segredos por commit.

A versão pública 1.18 já implementa backup IMAP incremental, conversão de backups para MBOX e restauração IMAP/Takeout. Primeiro executar análise/dry-run; depois testar com conta autorizada. Verificar FLAGS, INTERNALDATE, estrutura de pastas, checksums e prevenção de duplicidade.

**Integração MBOX/hMailServer:** o próprio repositório agora inclui `integracoes/hmailserver/migracao_mbox_portavel.py` e testes offline de SMTP com correção MIME histórica, também preservados no pacote privado. A CLI não substitui os fluxos IMAP e a interface gráfica existente ainda **não** está conectada a ela. Fica pendente projetar UI, tratamento de logs e homologação antes de incorporar definitivamente à aplicação.

Nunca publicar MBOX, EML, senhas, backups, logs ou relatórios de restauração no GitHub público.
