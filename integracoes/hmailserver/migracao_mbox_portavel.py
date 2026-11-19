"""Migracao MBOX -> hMailServer via SMTP, com preflight e retomada.

Versao portavel derivada das rotinas validadas de migracao_mbox_final.py.
Sem dependencias externas. NAO envia emails sem --enviar.
"""
from __future__ import annotations

import argparse
import copy
import email
from email import policy
from email.generator import BytesGenerator
from email.header import Header, decode_header, make_header
import hashlib
from io import BytesIO
import json
import mailbox
from pathlib import Path
import smtplib
import sys
from datetime import datetime


HEADERS = ("Subject", "From", "To", "Cc", "Reply-To", "Sender", "Organization", "Comments")


def normalizar_header(valor):
    if valor is None:
        return None
    try:
        valor = str(valor)
        try:
            return str(make_header(decode_header(valor)))
        except Exception:
            return valor
    except Exception:
        return repr(valor)


def codificar_header(valor):
    if valor is None:
        return None
    valor = str(valor).replace("\r", " ").replace("\n", " ")
    try:
        valor.encode("ascii")
        return valor
    except UnicodeEncodeError:
        return Header(valor, "utf-8").encode()


def substituir_header_seguro(msg, nome, valor):
    if valor is None:
        return
    valor = codificar_header(valor)
    try:
        if msg.get(nome) is not None:
            msg.replace_header(nome, valor)
        else:
            msg[nome] = valor
    except Exception:
        try:
            del msg[nome]
        except Exception:
            pass
        msg[nome] = valor


def corrigir_cabecalhos(msg):
    for nome in HEADERS:
        try:
            valor = msg.get(nome)
            if valor is not None:
                substituir_header_seguro(msg, nome, normalizar_header(valor))
        except Exception as exc:
            raise ValueError(f"Falha ao normalizar {nome}: {exc}") from exc
    return msg


def corrigir_multipart_malformado(msg):
    """Preserva a correcao historicamente validada dos casos 34682, 34769 e 35159."""
    corrigidos = 0
    for parte in list(msg.walk()):
        payload = parte.get_payload(decode=False)
        if parte.get_content_maintype() == "multipart" and isinstance(payload, str):
            for header in ("Content-Type", "Content-Transfer-Encoding", "Content-Disposition"):
                if header in parte:
                    del parte[header]
            parte.set_type("text/plain")
            parte.set_payload(payload, charset="utf-8")
            corrigidos += 1
    return msg, corrigidos


def preparar_mensagem(original, destinatario):
    msg = copy.deepcopy(original)
    corrigir_cabecalhos(msg)
    msg, corrigidos = corrigir_multipart_malformado(msg)
    substituir_header_seguro(msg, "To", destinatario)
    return msg, corrigidos


def gerar_bytes(msg, utf8=False):
    buffer = BytesIO()
    p = policy.SMTPUTF8.clone(utf8=True, linesep="\r\n") if utf8 else policy.SMTP.clone(utf8=False, linesep="\r\n")
    BytesGenerator(buffer, policy=p, mangle_from_=False).flatten(msg)
    return buffer.getvalue()


def enviar_mensagem(servidor, msg, destinatario):
    if servidor.has_extn("SMTPUTF8"):
        try:
            dados = gerar_bytes(msg, utf8=True)
        except (UnicodeError, ValueError):
            # Apenas uma falha LOCAL de serializacao permite fallback seguro.
            # Apos sendmail iniciar, o estado da entrega pode ser incerto.
            dados = None
        if dados is not None:
            # Excecoes de envio devem propagar. Nao reenviar automaticamente
            # em SMTP/MIME se a tentativa SMTPUTF8 pode ter sido aceita.
            recusados = servidor.sendmail(destinatario, [destinatario], dados, mail_options=["SMTPUTF8"])
            if recusados:
                raise RuntimeError(f"Destinatarios recusados: {recusados}")
            return "SMTPUTF8"
    dados = gerar_bytes(msg, utf8=False)
    recusados = servidor.sendmail(destinatario, [destinatario], dados)
    if recusados:
        raise RuntimeError(f"Destinatarios recusados: {recusados}")
    return "SMTP/MIME"


def hash_arquivo(caminho):
    h = hashlib.sha256()
    with caminho.open("rb") as arq:
        for bloco in iter(lambda: arq.read(1024 * 1024), b""):
            h.update(bloco)
    return h.hexdigest()


def registrar(caminho, texto):
    with caminho.open("a", encoding="utf-8") as f:
        f.write(f"[{datetime.now().isoformat(timespec='seconds')}] {texto}\n")


def ler_processados(caminho):
    if not caminho.exists():
        return set()
    retorno = set()
    for item in caminho.read_text(encoding="utf-8").splitlines():
        if item.strip():
            retorno.add(int(item.strip()))
    return retorno


def validar_checkpoint(pasta, mbox_sha, origem):
    manifest = pasta / "origem.json"
    dados = {"mbox_sha256": mbox_sha, "mbox_bytes": origem.stat().st_size, "controle": "posicao_1_based"}
    if manifest.exists():
        antigo = json.loads(manifest.read_text(encoding="utf-8"))
        if antigo != dados:
            raise RuntimeError("MBOX diferente do checkpoint! Use outra pasta de logs, sem reutilizar processados.txt.")
    elif (pasta / "processados.txt").exists() and (pasta / "processados.txt").stat().st_size:
        raise RuntimeError("processados.txt sem origem.json: nao e seguro associar posicoes. Confirme manualmente e crie novo estado.")
    else:
        manifest.write_text(json.dumps(dados, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def executar(args):
    origem = Path(args.mbox).expanduser().resolve()
    pasta = Path(args.logs).expanduser().resolve()
    if not origem.is_file():
        raise FileNotFoundError(f"MBOX nao localizado: {origem}")
    if args.limite is not None and args.limite < 1:
        raise ValueError("--limite deve ser >= 1")
    if args.enviar and not args.destinatario:
        raise ValueError("--destinatario e obrigatorio ao usar --enviar")
    if args.smtp_porta < 1 or args.smtp_porta > 65535:
        raise ValueError("--smtp-porta invalida")
    if not args.enviar:
        print("MODO VALIDACAO: nenhuma mensagem sera enviada e processados.txt nao sera alterado.")

    pasta.mkdir(parents=True, exist_ok=True)
    fingerprint = hash_arquivo(origem)
    # Checkpoint e manifesto so sao mantidos na pasta de controle de producao.
    if args.enviar:
        validar_checkpoint(pasta, fingerprint, origem)
    procfile, log, errlog = (pasta / n for n in ("processados.txt", "migracao.log", "erros.log"))
    processados = ler_processados(procfile) if args.enviar else set()
    totais = {"lidos": 0, "ignorados": 0, "validados": 0, "enviados": 0, "corrigidos": 0, "falhos": 0}
    print(f"MBOX SHA256: {fingerprint}")
    print(f"Destino: {args.destinatario or '(somente validacao)'}")

    servidor = None
    mbox = mailbox.mbox(str(origem), create=False)
    try:
        if args.enviar:
            servidor = smtplib.SMTP(args.smtp_host, args.smtp_porta, timeout=60)
            servidor.ehlo()
        for indice, original in enumerate(mbox, start=1):
            totais["lidos"] += 1
            if indice in processados:
                totais["ignorados"] += 1
                continue
            if args.limite is not None and totais["validados"] + totais["enviados"] >= args.limite:
                break
            try:
                msg, correcoes = preparar_mensagem(original, args.destinatario or "destino@example.invalid")
                if not args.enviar:
                    gerar_bytes(msg, utf8=False)
                    totais["validados"] += 1
                    print(f"[{indice}] VALIDADO | MIME corrigidos: {correcoes}")
                else:
                    metodo = enviar_mensagem(servidor, msg, args.destinatario)
                    # Gravar somente apos retorno de aceitacao pelo SMTP.
                    with procfile.open("a", encoding="utf-8") as f:
                        f.write(f"{indice}\n")
                        f.flush()
                    processados.add(indice)
                    totais["enviados"] += 1
                    registrar(log, f"[{indice}] OK | metodo={metodo} | MIME corrigidos={correcoes}")
                    print(f"[{indice}] ACEITO PELO SMTP ({metodo})")
                totais["corrigidos"] += correcoes
            except Exception as exc:
                totais["falhos"] += 1
                registrar(errlog, f"[{indice}] {type(exc).__name__}: {exc}")
                print(f"[{indice}] ERRO: {exc}", file=sys.stderr)
                if args.enviar:
                    try:
                        servidor.quit()
                    except Exception:
                        pass
                    try:
                        servidor = smtplib.SMTP(args.smtp_host, args.smtp_porta, timeout=60)
                        servidor.ehlo()
                    except Exception as reconnect_error:
                        registrar(errlog, f"[{indice}] reconexao: {reconnect_error}")
                        print("Nao foi possivel reconectar. Interrompido.", file=sys.stderr)
                        break
    finally:
        if servidor is not None:
            try:
                servidor.quit()
            except Exception:
                pass
        mbox.close()
    print(json.dumps(totais, ensure_ascii=False, indent=2))
    return 1 if totais["falhos"] else 0


def parser_cli():
    parser = argparse.ArgumentParser(description="Migrador MBOX -> hMailServer com validacao segura (sem envio por padrao)")
    parser.add_argument("--mbox", required=True, help="Caminho do arquivo MBOX original")
    parser.add_argument("--destinatario", help="Conta local de destino (obrigatoria apenas para envio)")
    parser.add_argument("--smtp-host", default="127.0.0.1")
    parser.add_argument("--smtp-porta", type=int, default=25)
    parser.add_argument("--logs", default="./estado_migracao", help="Pasta privada para logs/checkpoint")
    parser.add_argument("--limite", type=int, default=10, help="Quantidade a validar/enviar nesta execucao; padrao 10")
    parser.add_argument("--enviar", action="store_true", help="Habilita envio real pelo SMTP; SEM essa flag e dry-run")
    return parser


if __name__ == "__main__":
    try:
        sys.exit(executar(parser_cli().parse_args()))
    except (ValueError, FileNotFoundError, RuntimeError, smtplib.SMTPException) as exc:
        print(f"FALHA: {exc}", file=sys.stderr)
        sys.exit(2)
