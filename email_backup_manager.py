import base64
import ctypes
from ctypes import wintypes
import json
import hashlib
import re
import logging
import os
from pathlib import Path
from datetime import datetime, timezone
import queue
import socket
import ssl
import threading
import uuid
import mailbox
import csv
import io
from email import policy
from email.parser import BytesParser
import email.utils
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog

APP_NAME = "Email Backup Manager"
APP_VERSION = "1.18"

APPDATA = Path(os.environ.get("APPDATA", str(Path.home()))) / "EmailBackupManager"
CONFIG_FILE = APPDATA / "config.json"
LOG_DIR = APPDATA / "logs"
LOG_FILE = LOG_DIR / "email_backup_manager.log"

APPDATA.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(threadName)s | %(message)s",
    encoding="utf-8",
)
log = logging.getLogger("EmailBackupManager")


# ---------------------------------------------------------------------------
# DPAPI - armazenamento opcional de segredos no próprio usuário do Windows
# ---------------------------------------------------------------------------
class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


def _blob_from_bytes(data: bytes):
    buf = ctypes.create_string_buffer(data)
    blob = DATA_BLOB(
        len(data),
        ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)),
    )
    return blob, buf


def dpapi_encrypt(text: str) -> str:
    if not text:
        return ""
    if os.name != "nt":
        raise RuntimeError("DPAPI disponível apenas no Windows.")
    raw = text.encode("utf-8")
    in_blob, backing = _blob_from_bytes(raw)
    out_blob = DATA_BLOB()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    if not crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        "EmailBackupManager",
        None, None, None, 0,
        ctypes.byref(out_blob),
    ):
        raise ctypes.WinError()
    try:
        encrypted = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        return base64.b64encode(encrypted).decode("ascii")
    finally:
        kernel32.LocalFree(out_blob.pbData)


def dpapi_decrypt(token: str) -> str:
    if not token:
        return ""
    if os.name != "nt":
        raise RuntimeError("DPAPI disponível apenas no Windows.")
    raw = base64.b64decode(token)
    in_blob, backing = _blob_from_bytes(raw)
    out_blob = DATA_BLOB()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    if not crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None, None, None, None, 0,
        ctypes.byref(out_blob),
    ):
        raise ctypes.WinError()
    try:
        clear = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        return clear.decode("utf-8")
    finally:
        kernel32.LocalFree(out_blob.pbData)


# ---------------------------------------------------------------------------
# Compatibilidade / migração de configurações antigas
# ---------------------------------------------------------------------------
def normalize_account_record(account):
    """Converte formatos antigos de conta para o esquema atual."""
    if isinstance(account, str):
        email = account.strip()
        return {
            "email": email,
            "auth_user": email,
            "password_enc": "",
        }

    if isinstance(account, dict):
        email = str(
            account.get("email")
            or account.get("account")
            or account.get("user")
            or account.get("username")
            or ""
        ).strip()
        auth_user = str(
            account.get("auth_user")
            or account.get("imap_user")
            or account.get("login")
            or email
        ).strip()
        return {
            "email": email,
            "auth_user": auth_user or email,
            "password_enc": str(account.get("password_enc") or ""),
        }

    return {
        "email": str(account or "").strip(),
        "auth_user": str(account or "").strip(),
        "password_enc": "",
    }


def normalize_profile_record(profile):
    """Normaliza perfil e sua lista de contas sem perder campos desconhecidos."""
    if not isinstance(profile, dict):
        profile = {"name": str(profile or "Servidor")}

    p = dict(profile)
    p.setdefault("id", str(uuid.uuid4()))
    p.setdefault("name", "Servidor")
    p.setdefault("domain", "")
    p.setdefault("protocol", "IMAP")
    p.setdefault("host", "")
    p.setdefault("port", 993)
    p.setdefault("security", "SSL/TLS")
    p.setdefault("auth_method", "AUTH LOGIN")
    p.setdefault("timeout", 12)
    p.setdefault("save_password", False)
    p.setdefault("password_enc", "")

    raw_accounts = p.get("accounts", [])
    if isinstance(raw_accounts, (str, dict)):
        raw_accounts = [raw_accounts]
    elif not isinstance(raw_accounts, list):
        raw_accounts = []

    normalized = []
    seen = set()
    for raw in raw_accounts:
        rec = normalize_account_record(raw)
        email = rec.get("email", "").strip()
        if not email:
            continue
        key = email.casefold()
        if key in seen:
            continue
        seen.add(key)
        normalized.append(rec)

    p["accounts"] = normalized
    return p


def migrate_config(data):
    """Atualiza estruturas legadas para schema_version 2."""
    if not isinstance(data, dict):
        data = default_config()

    cfg = dict(data)
    profiles = cfg.get("profiles", [])
    if isinstance(profiles, dict):
        profiles = [profiles]
    elif not isinstance(profiles, list):
        profiles = []

    cfg["profiles"] = [
        normalize_profile_record(p)
        for p in profiles
    ]
    cfg["schema_version"] = 5

    defaults = default_config()
    for section in ("general", "backup", "converter", "restore", "mbox_restore", "legacy_mbox"):
        base = dict(defaults.get(section, {}))
        current = cfg.get(section, {})
        if isinstance(current, dict):
            base.update(current)
        cfg[section] = base

    if not cfg["profiles"]:
        cfg["profiles"] = defaults["profiles"]

    # v1.13: Google não é mais uma origem de backup/configuração.
    cfg.pop("google", None)

    return cfg


# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------
def default_config():
    return {
        "schema_version": 5,
        "general": {
            "backup_dir": str(Path.home() / "EmailBackups"),
            "connection_timeout": 12,
            "verify_sha256": True,
            "log_level": "INFO",
        },
        "profiles": [
            {
                "id": str(uuid.uuid4()),
                "name": "Servidor IMAP",
                "domain": "",
                "protocol": "IMAP",
                "host": "",
                "port": 993,
                "security": "SSL/TLS",
                "auth_method": "AUTH LOGIN",
                "timeout": 12,
                "save_password": False,
                "password_enc": "",
                "accounts": [],
            }
        ],
        "backup": {
            "incremental": True,
            "raw_eml": True,
            "manifest": True,
            "preserve_flags": True,
            "preserve_internaldate": True,
            "verify_sha256": True,
            "dedupe_message_id_sha256": True,
            "test_limit": 0,
        },
        "converter": {
            "source_path": "",
            "destination_dir": "",
            "require_complete": True,
            "verify_sha256": True,
        },
        "restore": {
            "source_type": "Backup da aplicação",
            "source_path": "",
            "profile_name": "",
            "account": "",
            "dry_run": True,
            "create_missing_folders": True,
            "preserve_flags": True,
            "preserve_internaldate": True,
            "dedupe_message_id_sha256": True,
        },
        "mbox_restore": {
            "source_type": "Pacote MBOX convertido",
            "source_path": "",
            "profile_name": "",
            "account": "",
            "dry_run": True,
            "create_missing_folders": True,
            "preserve_flags": True,
            "preserve_internaldate": True,
            "dedupe_message_id_sha256": True,
        },
        "legacy_mbox": {
            "mbox_path": "",
            "smtp_host": "localhost",
            "smtp_port": 25,
            "smtp_security": "Nenhuma",
            "recipient": "",
            "resume_file": "processados.txt",
            "test_limit": 0,
            "preserve_mime": True,
        },
    }


class ConfigStore:
    def __init__(self, path=CONFIG_FILE):
        self.path = Path(path)

    def load(self):
        if not self.path.exists():
            cfg = migrate_config(default_config())
            self.save(cfg)
            return cfg
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("configuração inválida")

            original = json.dumps(data, ensure_ascii=False, sort_keys=True)
            cfg = migrate_config(data)
            migrated = json.dumps(cfg, ensure_ascii=False, sort_keys=True)

            if original != migrated:
                backup = self.path.with_suffix(".pre_v1_8.json")
                try:
                    __import__("shutil").copy2(self.path, backup)
                except Exception:
                    pass
                self.save(cfg)
                log.info(
                    "CONFIG_MIGRATED | schema_version=%s | profiles=%s",
                    cfg.get("schema_version"),
                    len(cfg.get("profiles", [])),
                )
            return cfg
        except Exception:
            backup = self.path.with_suffix(".broken.json")
            try:
                __import__("shutil").copy2(self.path, backup)
            except Exception:
                pass
            cfg = migrate_config(default_config())
            self.save(cfg)
            return cfg

    def save(self, cfg):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(cfg, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        os.replace(tmp, self.path)


# ---------------------------------------------------------------------------
# Conector validado: socket + TLS 1.2 + AUTHENTICATE LOGIN
# ---------------------------------------------------------------------------
class RawIMAPLoginClient:
    def __init__(self, host, port=993, timeout=12):
        self.host = str(host).strip()
        self.port = int(port)
        self.timeout = int(timeout)
        self.sock = None
        self.ssl_sock = None
        self.reader = None
        self.restore_seq = 0

    def _send(self, data: bytes):
        self.ssl_sock.sendall(data)

    def _readline(self):
        line = self.reader.readline()
        if not line:
            raise RuntimeError("Servidor encerrou a conexão.")
        return line.rstrip(b"\r\n")

    def _read_tagged(self, tag: bytes):
        out = []
        prefix = tag + b" "
        while True:
            line = self._readline()
            out.append(line)
            if line.startswith(prefix):
                return out

    def connect(self):
        raw = socket.create_connection(
            (self.host, self.port),
            timeout=self.timeout,
        )
        raw.settimeout(self.timeout)

        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2

        self.sock = raw
        self.ssl_sock = ctx.wrap_socket(
            raw,
            server_hostname=self.host,
        )
        self.ssl_sock.settimeout(self.timeout)
        self.reader = self.ssl_sock.makefile("rb")

        greeting = self._readline()
        if not greeting.startswith(b"* OK"):
            raise RuntimeError(
                "Saudação IMAP inesperada: "
                + greeting.decode("utf-8", "replace")
            )

        self._send(b"A001 CAPABILITY\r\n")
        caps = self._read_tagged(b"A001")
        if b"AUTH=LOGIN" not in b" ".join(caps).upper():
            raise RuntimeError(
                "Servidor não anunciou AUTH=LOGIN."
            )

        return {
            "greeting": greeting.decode("utf-8", "replace"),
            "tls_version": self.ssl_sock.version(),
            "cipher": self.ssl_sock.cipher(),
            "capability": [
                x.decode("utf-8", "replace")
                for x in caps
            ],
        }

    def authenticate(self, user, password):
        user = str(user).strip()
        if "@" not in user:
            raise ValueError(
                "Use o endereço de e-mail completo."
            )
        if not password:
            raise ValueError("Informe a senha.")

        self._send(b"A002 AUTHENTICATE LOGIN\r\n")
        if not self._readline().startswith(b"+"):
            raise RuntimeError(
                "Servidor não solicitou usuário."
            )

        self._send(
            base64.b64encode(user.encode("utf-8"))
            + b"\r\n"
        )

        if not self._readline().startswith(b"+"):
            raise RuntimeError(
                "Servidor não solicitou senha."
            )

        encoded = base64.b64encode(
            password.encode("utf-8")
        )
        self._send(encoded + b"\r\n")
        encoded = b""

        response = self._read_tagged(b"A002")
        final = response[-1].decode(
            "utf-8",
            "replace",
        )
        parts = final.split(" ", 2)
        if (
            len(parts) < 2
            or parts[1].upper() != "OK"
        ):
            raise RuntimeError(
                "Autenticação rejeitada: " + final
            )
        return final

    @staticmethod
    def _quote_imap(value):
        value=str(value)
        return '"' + value.replace('\\','\\\\').replace('"','\\"') + '"'

    def list_folders(self):
        """Lista caixas IMAP e registra o delimitador hierárquico de cada uma."""
        self._send(b'B001 LIST "" "*"\r\n')
        resp=self._read_tagged(b"B001")
        final=resp[-1].decode("utf-8","replace")
        parts=final.split(" ",2)
        if len(parts)<2 or parts[1].upper()!="OK":
            raise RuntimeError("LIST falhou: "+final)

        folders=[]
        self.folder_delimiters={}
        self.folder_attributes={}
        self.default_folder_delimiter=None

        for line in resp[:-1]:
            text=line.decode("utf-8","replace")
            if not text.upper().startswith("* LIST "):
                continue
            m=re.match(r'^\* LIST \((.*?)\)\s+(NIL|"[^"]*")\s+(.+)$', text, re.I)
            if not m:
                continue

            attributes=[
                token.strip()
                for token in m.group(1).split()
                if token.strip()
            ]
            delimiter_token=m.group(2).strip()
            if delimiter_token.upper()=="NIL":
                delimiter=None
            else:
                delimiter=delimiter_token[1:-1].replace('\\"','"').replace('\\\\','\\')

            raw_name=m.group(3).strip()
            if raw_name.startswith('"') and raw_name.endswith('"'):
                raw_name=raw_name[1:-1].replace('\\"','"').replace('\\\\','\\')

            folders.append(raw_name)
            self.folder_delimiters[raw_name]=delimiter
            self.folder_attributes[raw_name]=attributes
            if self.default_folder_delimiter is None and delimiter:
                self.default_folder_delimiter=delimiter

        return folders, final

    def examine(self, mailbox):
        """Abre uma pasta em modo somente leitura."""
        cmd=f'B002 EXAMINE {self._quote_imap(mailbox)}\r\n'.encode("utf-8")
        self._send(cmd)
        resp=self._read_tagged(b"B002")
        final=resp[-1].decode("utf-8","replace")
        parts=final.split(" ",2)
        if len(parts)<2 or parts[1].upper()!="OK":
            raise RuntimeError("EXAMINE falhou: "+final)

        exists=None
        uidvalidity=None
        uidnext=None
        for line in resp[:-1]:
            text=line.decode("utf-8","replace")
            m=re.match(r'^\*\s+(\d+)\s+EXISTS$', text, re.I)
            if m:
                exists=int(m.group(1))
            m=re.search(r'\[UIDVALIDITY\s+(\d+)\]', text, re.I)
            if m:
                uidvalidity=int(m.group(1))
            m=re.search(r'\[UIDNEXT\s+(\d+)\]', text, re.I)
            if m:
                uidnext=int(m.group(1))
        return {
            "exists": exists,
            "uidvalidity": uidvalidity,
            "uidnext": uidnext,
            "final": final,
        }

    def search_all_uids(self):
        self._send(b"B003 UID SEARCH ALL\r\n")
        resp=self._read_tagged(b"B003")
        final=resp[-1].decode("utf-8","replace")
        parts=final.split(" ",2)
        if len(parts)<2 or parts[1].upper()!="OK":
            raise RuntimeError("UID SEARCH falhou: "+final)

        uids=[]
        for line in resp[:-1]:
            if line.upper().startswith(b"* SEARCH"):
                rest=line[len(b"* SEARCH"):].strip()
                for token in rest.split():
                    if token.isdigit():
                        uids.append(int(token))
        return uids, final

    def fetch_metadata(self, uid):
        uid=int(uid)
        tag=f"D{uid}".encode("ascii")
        cmd=(
            tag+b" UID FETCH "+str(uid).encode("ascii")+
            b" (UID FLAGS INTERNALDATE RFC822.SIZE)\r\n"
        )
        self._send(cmd)
        resp=self._read_tagged(tag)
        final=resp[-1].decode("utf-8","replace")
        parts=final.split(" ",2)
        if len(parts)<2 or parts[1].upper()!="OK":
            raise RuntimeError(f"Metadados do UID {uid} falharam: "+final)

        text=" ".join(
            x.decode("utf-8","replace")
            for x in resp[:-1]
            if b" FETCH " in x.upper()
        )
        flags_m=re.search(r'\bFLAGS\s+\((.*?)\)', text, re.I)
        date_m=re.search(r'\bINTERNALDATE\s+"([^"]+)"', text, re.I)
        size_m=re.search(r'\bRFC822\.SIZE\s+(\d+)\b', text, re.I)
        return {
            "uid": uid,
            "flags": (
                flags_m.group(1).split()
                if flags_m and flags_m.group(1).strip()
                else []
            ),
            "internaldate": date_m.group(1) if date_m else "",
            "rfc822_size": int(size_m.group(1)) if size_m else None,
            "final": final,
        }

    def fetch_message_bytes(self, uid):
        """Baixa uma mensagem com BODY.PEEK[] sem alterar \\Seen."""
        uid=int(uid)
        tag=f"C{uid}".encode("ascii")
        cmd=(
            tag+b" UID FETCH "+str(uid).encode("ascii")+
            b" (UID BODY.PEEK[])\r\n"
        )
        self._send(cmd)

        literal_data=None
        final=""
        while True:
            line=self._readline()
            if line.startswith(tag+b" "):
                final=line.decode("utf-8","replace")
                break
            literal_m=re.search(rb"\{(\d+)\}$", line)
            if literal_m:
                literal_len=int(literal_m.group(1))
                data=self.reader.read(literal_len)
                if len(data)!=literal_len:
                    raise RuntimeError(
                        f"Mensagem UID {uid} incompleta: "
                        f"esperado={literal_len}, recebido={len(data)}"
                    )
                literal_data=data

        parts=final.split(" ",2)
        if len(parts)<2 or parts[1].upper()!="OK":
            raise RuntimeError(f"BODY.PEEK do UID {uid} falhou: "+final)
        if literal_data is None:
            raise RuntimeError(f"BODY.PEEK do UID {uid} não retornou literal.")
        return literal_data, final

    def _next_restore_tag(self):
        self.restore_seq += 1
        return f"R{self.restore_seq:05d}".encode("ascii")

    def create_folder(self, mailbox):
        tag=self._next_restore_tag()
        cmd=tag+b" CREATE "+self._quote_imap(mailbox).encode("utf-8")+b"\r\n"
        self._send(cmd)
        resp=self._read_tagged(tag)
        final=resp[-1].decode("utf-8","replace")
        parts=final.split(" ",2)
        if len(parts)<2 or parts[1].upper()!="OK":
            raise RuntimeError(f"CREATE falhou para {mailbox}: {final}")
        return final

    def append_message(self, mailbox, raw, flags=None, internaldate=None):
        """APPEND sincronizante; preserva bytes da mensagem."""
        tag=self._next_restore_tag()
        prefix=tag+b" APPEND "+self._quote_imap(mailbox).encode("utf-8")
        if flags:
            prefix += b" ("+b" ".join(str(x).encode("ascii","ignore") for x in flags)+b")"
        if internaldate:
            date_text=str(internaldate).strip().strip('"')
            prefix += b' "'+date_text.encode("ascii","ignore")+b'"'
        prefix += b" {"+str(len(raw)).encode("ascii")+b"}\r\n"
        self._send(prefix)

        while True:
            line=self._readline()
            if line.startswith(b"+"):
                break
            if line.startswith(tag+b" "):
                final=line.decode("utf-8","replace")
                raise RuntimeError(f"APPEND recusado antes do literal: {final}")

        self._send(raw+b"\r\n")
        resp=self._read_tagged(tag)
        final=resp[-1].decode("utf-8","replace")
        parts=final.split(" ",2)
        if len(parts)<2 or parts[1].upper()!="OK":
            raise RuntimeError(f"APPEND falhou em {mailbox}: {final}")
        return final

    def close(self):
        try:
            if self.ssl_sock:
                self._send(b"A003 LOGOUT\r\n")
        except Exception:
            pass
        for obj in (
            self.reader,
            self.ssl_sock,
            self.sock,
        ):
            try:
                if obj:
                    obj.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Diálogo de conta
# ---------------------------------------------------------------------------
class AccountDialog(tk.Toplevel):
    def __init__(self, parent, account=None):
        super().__init__(parent)
        self.title(
            "Editar conta"
            if account
            else "Adicionar conta"
        )
        self.resizable(False, False)
        self.result = None
        account = account or {}
        self.original_password_enc = str(account.get("password_enc") or "")

        frm = ttk.Frame(self, padding=16)
        frm.pack(fill="both", expand=True)

        self.email = self._field(
            frm,
            0,
            "E-mail",
            account.get("email", ""),
        )
        self.auth_user = self._field(
            frm,
            1,
            "Usuário de autenticação",
            account.get(
                "auth_user",
                account.get("email", ""),
            ),
        )

        ttk.Label(
            frm,
            text="Senha própria (opcional)",
        ).grid(
            row=2,
            column=0,
            sticky="w",
            pady=5,
        )
        self.password = ttk.Entry(
            frm,
            show="*",
            width=38,
        )
        self.password.grid(
            row=2,
            column=1,
            sticky="ew",
            padx=(10, 0),
            pady=5,
        )

        self.save_password = tk.BooleanVar(
            value=bool(
                account.get("password_enc")
            )
        )
        ttk.Checkbutton(
            frm,
            text="Salvar senha própria com DPAPI",
            variable=self.save_password,
        ).grid(
            row=3,
            column=1,
            sticky="w",
            padx=(10, 0),
            pady=(2, 4),
        )

        ttk.Label(
            frm,
            text=(
                "Ao editar, deixe a senha vazia para manter a senha já salva."
                if self.original_password_enc
                else "Deixe vazio para usar a senha padrão do perfil."
            ),
        ).grid(
            row=4,
            column=1,
            sticky="w",
            padx=(10, 0),
            pady=(0, 10),
        )

        frm.columnconfigure(1, weight=1)

        buttons = ttk.Frame(frm)
        buttons.grid(
            row=5,
            column=0,
            columnspan=2,
            sticky="e",
        )
        ttk.Button(
            buttons,
            text="Cancelar",
            command=self.destroy,
        ).pack(
            side="right",
            padx=(6, 0),
        )
        ttk.Button(
            buttons,
            text="Salvar",
            command=self._save,
        ).pack(side="right")

        self.transient(parent)
        self.grab_set()
        self.email.focus_set()

    def _field(self, parent, row, label, value):
        ttk.Label(
            parent,
            text=label,
        ).grid(
            row=row,
            column=0,
            sticky="w",
            pady=5,
        )
        entry = ttk.Entry(
            parent,
            width=38,
        )
        entry.insert(0, value)
        entry.grid(
            row=row,
            column=1,
            sticky="ew",
            padx=(10, 0),
            pady=5,
        )
        return entry

    def _save(self):
        email = self.email.get().strip()
        auth_user = (
            self.auth_user.get().strip()
            or email
        )
        if "@" not in email:
            messagebox.showerror(
                "Conta inválida",
                "Informe o e-mail completo.",
                parent=self,
            )
            return

        password_enc = ""
        if self.save_password.get():
            pwd = self.password.get()
            if pwd:
                try:
                    password_enc = dpapi_encrypt(pwd)
                except Exception as exc:
                    messagebox.showerror(
                        "DPAPI",
                        str(exc),
                        parent=self,
                    )
                    return
            else:
                # Ao editar, manter a senha DPAPI existente se o usuário
                # não digitou uma nova senha.
                password_enc = self.original_password_enc

        self.result = {
            "email": email,
            "auth_user": auth_user,
            "password_enc": password_enc,
        }
        self.destroy()


# ---------------------------------------------------------------------------
# Restauração: backups da aplicação e Google Takeout
# ---------------------------------------------------------------------------
GMAIL_LABEL_MAP = {
    "Inbox": "INBOX",
    "Sent": "Sent",
    "Spam": "Spam",
    "Trash": "Trash",
    "Draft": "Drafts",
    "Drafts": "Drafts",
    "Starred": "Starred",
    "Important": "Important",
    "All Mail": "All Mail",
}


def parse_gmail_labels(value):
    if not value:
        return []
    try:
        return [
            x.strip()
            for x in next(csv.reader(io.StringIO(str(value)), skipinitialspace=True))
            if x.strip()
        ]
    except Exception:
        return [x.strip().strip('"') for x in str(value).split(",") if x.strip()]


def takeout_label_to_logical_folder(label):
    label=str(label).strip()
    if label.startswith("Category "):
        return "Categories/"+label[len("Category "):]
    return GMAIL_LABEL_MAP.get(label,label)


def encode_imap_modified_utf7(value):
    """Codifica nomes Unicode para Modified UTF-7 IMAP."""
    value=str(value)
    out=[]
    buf=[]
    def flush():
        if not buf:
            return
        raw="".join(buf).encode("utf-16-be")
        token=base64.b64encode(raw).decode("ascii").rstrip("=").replace("/",",")
        out.append("&"+token+"-")
        buf.clear()
    for ch in value:
        code=ord(ch)
        if 0x20 <= code <= 0x7e and ch!="&":
            flush()
            out.append(ch)
        elif ch=="&":
            flush()
            out.append("&-")
        else:
            buf.append(ch)
    flush()
    return "".join(out)


def restore_message_key(folder, raw):
    try:
        msg=BytesParser(policy=policy.default).parsebytes(raw)
        mid=str(msg.get("Message-ID","") or "").strip().lower()
    except Exception:
        mid=""
    sha=hashlib.sha256(raw).hexdigest()
    return hashlib.sha256((str(folder)+"\0"+mid+"\0"+sha).encode("utf-8")).hexdigest()


def header_internaldate(raw):
    try:
        msg=BytesParser(policy=policy.default).parsebytes(raw,headersonly=True)
        value=msg.get("Date")
        if not value:
            return None
        dt=email.utils.parsedate_to_datetime(value)
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt=dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%d-%b-%Y %H:%M:%S %z")
    except Exception:
        return None


def normalize_source_mailbox(raw_mailbox, source_delimiter, target_delimiter):
    raw_mailbox=str(raw_mailbox or "INBOX")
    if not source_delimiter or source_delimiter==target_delimiter:
        return raw_mailbox
    return target_delimiter.join(raw_mailbox.split(source_delimiter))


def takeout_folder_to_target(logical, target_delimiter, existing):
    """Materializa labels Takeout na namespace IMAP do destino."""
    logical=str(logical or "All Mail")
    if logical.upper()=="INBOX":
        return "INBOX"

    parts=[p for p in logical.replace("\\","/").split("/") if p]
    encoded=[encode_imap_modified_utf7(p) for p in parts]
    leaf=target_delimiter.join(encoded)

    # Se o destino usa namespace INBOX.<pasta>, mantém a mesma convenção.
    inbox_prefix="INBOX"+target_delimiter
    uses_inbox_namespace=any(
        str(name).upper().startswith(inbox_prefix.upper())
        for name in existing
    )
    if uses_inbox_namespace:
        return inbox_prefix+leaf
    return leaf


def restore_state_load(path):
    try:
        data=json.loads(Path(path).read_text(encoding="utf-8"))
        return data if isinstance(data,dict) else {}
    except Exception:
        return {}


def restore_state_save(path,data):
    path=Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_name(path.name+".tmp")
    with open(tmp,"w",encoding="utf-8") as fp:
        json.dump(data,fp,ensure_ascii=False,indent=2)
        fp.flush()
        os.fsync(fp.fileno())
    os.replace(tmp,path)


def scan_application_backup(source_path):
    """Retorna descritores EML do backup atual; usa .ebm_state.json como autoridade."""
    source=Path(source_path)
    if source.is_file():
        roots=[source] if source.name==".ebm_state.json" else []
    else:
        roots=sorted(source.rglob(".ebm_state.json"))

    items=[]
    for state_path in roots:
        state=restore_state_load(state_path)
        mailbox_name=state.get("mailbox")
        if not mailbox_name:
            continue
        source_delim=state.get("hierarchy_delimiter") or "."
        base=state_path.parent
        for entry in state.get("messages",[]):
            if not isinstance(entry,dict):
                continue
            fname=entry.get("file")
            if not fname:
                continue
            eml=base/fname
            if not eml.is_file():
                continue
            items.append({
                "kind":"eml",
                "source_folder":mailbox_name,
                "source_delimiter":source_delim,
                "path":str(eml),
                "flags":entry.get("flags") or [],
                "internaldate":entry.get("internaldate") or None,
                "uid":entry.get("uid"),
            })
    return items


def mboxrd_escape(raw):
    """Escapa linhas ^>*From  de forma reversível para mboxrd."""
    out=[]
    for line in raw.splitlines(keepends=True):
        if re.match(rb"^>*From ",line):
            line=b">"+line
        out.append(line)
    if raw and not raw.splitlines(keepends=True):
        return raw
    return b"".join(out)


def mboxrd_unescape(raw):
    """Reverte exatamente um nível de quoting mboxrd gerado por este aplicativo."""
    out=[]
    for line in raw.splitlines(keepends=True):
        if re.match(rb"^>+From ",line):
            line=line[1:]
        out.append(line)
    return b"".join(out)


def export_decode_modified_utf7(value):
    value=str(value)
    out=[]
    i=0
    while i<len(value):
        if value[i]!="&":
            j=value.find("&",i)
            if j<0:
                j=len(value)
            out.append(value[i:j])
            i=j
            continue
        j=value.find("-",i)
        if j<0:
            out.append(value[i:])
            break
        token=value[i+1:j]
        if token=="":
            out.append("&")
        else:
            b64=token.replace(",","/")
            b64+="="*((4-len(b64)%4)%4)
            try:
                out.append(base64.b64decode(b64).decode("utf-16-be","strict"))
            except Exception:
                out.append(value[i:j+1])
        i=j+1
    return "".join(out)


def export_safe_component(value):
    value=re.sub(r'[<>:"/\\|?*\x00-\x1f]+','_',str(value))
    value=value.strip(" ._")
    return value[:100] or "item"


def export_mailbox_parts(mailbox_name,delimiter):
    raw_parts=str(mailbox_name or "INBOX").split(delimiter) if delimiter else [str(mailbox_name or "INBOX")]
    return [
        export_safe_component(export_decode_modified_utf7(x))
        for x in raw_parts
    ]


def export_message_id(raw):
    try:
        msg=BytesParser(policy=policy.default).parsebytes(raw,headersonly=True)
        return str(msg.get("Message-ID","") or "").strip()
    except Exception:
        return ""


def analyze_backup_for_mbox(source_path,verify_sha256=True):
    source=Path(source_path)
    if not source.exists():
        raise RuntimeError("A origem do backup não existe.")

    states=sorted(source.rglob(".ebm_state.json")) if source.is_dir() else []
    if source.is_file() and source.name==".ebm_state.json":
        states=[source]
    if not states:
        raise RuntimeError(
            "Nenhum .ebm_state.json foi encontrado. Selecione a pasta da conta criada pelo backup."
        )

    accounts=set()
    folders=[]
    total_valid=0
    total_invalid=0
    total_pending=0

    for state_path in states:
        state=restore_state_load(state_path)
        account=str(state.get("account") or "").strip()
        if account:
            accounts.add(account)

        mailbox_name=state.get("mailbox")
        if not mailbox_name:
            continue
        delimiter=state.get("hierarchy_delimiter") or "."
        valid=[]
        invalid=[]

        for item in state.get("messages",[]):
            if not isinstance(item,dict):
                continue
            fname=item.get("file")
            uid=item.get("uid")
            if not fname:
                invalid.append({"uid":uid,"reason":"sem arquivo EML"})
                continue
            eml=state_path.parent/str(fname)
            if not eml.is_file():
                invalid.append({"uid":uid,"reason":"arquivo ausente","file":str(eml)})
                continue
            raw=eml.read_bytes()
            expected=str(item.get("sha256") or "")
            actual=hashlib.sha256(raw).hexdigest()
            if verify_sha256 and expected and actual.lower()!=expected.lower():
                invalid.append({"uid":uid,"reason":"SHA-256 divergente","file":str(eml)})
                continue
            valid.append({
                "state_item":item,
                "path":eml,
                "sha256":actual,
                "bytes":len(raw),
            })

        pending_before=state.get("pending_before_run")
        downloaded=state.get("downloaded_this_run")
        if isinstance(pending_before,int) and isinstance(downloaded,int):
            pending_after=max(0,pending_before-downloaded)
        else:
            try:
                server_count=int(state.get("server_uid_count") or 0)
            except Exception:
                server_count=0
            pending_after=max(0,server_count-len(valid))

        complete=(not invalid and pending_after==0)
        folders.append({
            "state_path":state_path,
            "state":state,
            "mailbox":mailbox_name,
            "delimiter":delimiter,
            "valid":valid,
            "invalid":invalid,
            "pending":pending_after,
            "complete":complete,
        })
        total_valid+=len(valid)
        total_invalid+=len(invalid)
        total_pending+=pending_after

    if len(accounts)>1:
        raise RuntimeError(
            "A pasta selecionada contém mais de uma conta. Selecione a pasta de uma única conta."
        )
    account=next(iter(accounts),"conta")
    return {
        "source":str(source),
        "account":account,
        "folders":folders,
        "folder_count":len(folders),
        "message_count":total_valid,
        "invalid_count":total_invalid,
        "pending_count":total_pending,
        "complete":(
            bool(folders)
            and total_invalid==0
            and total_pending==0
            and all(x["complete"] for x in folders)
        ),
    }


def _unique_package_root(destination,account):
    base=Path(destination)
    base.mkdir(parents=True,exist_ok=True)
    stem=export_safe_component(account)+"_MBOX"
    candidate=base/stem
    n=2
    while candidate.exists():
        candidate=base/f"{stem}_{n}"
        n+=1
    return candidate


def build_mbox_package(analysis,destination,verify_sha256=True,require_complete=True,
                       progress=None,stop_requested=None):
    if require_complete and not analysis.get("complete"):
        raise RuntimeError(
            "O backup ainda não está completo ou possui EML inválido. "
            f"Pendentes={analysis.get('pending_count',0)}, inválidos={analysis.get('invalid_count',0)}."
        )

    package=_unique_package_root(destination,analysis.get("account") or "conta")
    package.mkdir(parents=True,exist_ok=False)

    folder_entries=[]
    total=max(1,analysis.get("message_count",0))
    done=0
    used_paths=set()
    stopped=False

    for folder_index,folder in enumerate(analysis["folders"],1):
        if stop_requested and stop_requested():
            stopped=True
            break

        mailbox_name=folder["mailbox"]
        delimiter=folder["delimiter"]
        parts=export_mailbox_parts(mailbox_name,delimiter)
        rel_base=Path(*parts)

        mbox_rel=Path("mbox")/rel_base
        mbox_rel=mbox_rel.with_suffix(".mbox")
        meta_rel=Path("metadata")/rel_base
        meta_rel=meta_rel.with_suffix(".json")

        key=str(mbox_rel).casefold()
        if key in used_paths:
            suffix=hashlib.sha256(
                (mailbox_name+"\0"+str(delimiter)).encode("utf-8")
            ).hexdigest()[:8]
            mbox_rel=mbox_rel.with_name(mbox_rel.stem+"_"+suffix+".mbox")
            meta_rel=meta_rel.with_name(meta_rel.stem+"_"+suffix+".json")
        used_paths.add(str(mbox_rel).casefold())

        mbox_path=package/mbox_rel
        meta_path=package/meta_rel
        mbox_path.parent.mkdir(parents=True,exist_ok=True)
        meta_path.parent.mkdir(parents=True,exist_ok=True)

        tmp=mbox_path.with_name(mbox_path.name+".tmp")
        messages_meta=[]
        with open(tmp,"wb") as fh:
            for seq,entry in enumerate(folder["valid"],1):
                if stop_requested and stop_requested():
                    stopped=True
                    break

                raw=entry["path"].read_bytes()
                source_sha=hashlib.sha256(raw).hexdigest()
                if verify_sha256 and entry["sha256"] and source_sha!=entry["sha256"]:
                    raise RuntimeError(
                        f"SHA-256 mudou durante a conversão: {entry['path']}"
                    )

                state_item=entry["state_item"]
                envelope=(
                    "From email-backup-manager "
                    + datetime.now().ctime()
                    + "\n"
                ).encode("ascii","replace")
                fh.write(envelope)
                payload_offset=fh.tell()

                encoded=mboxrd_escape(raw)
                if hashlib.sha256(mboxrd_unescape(encoded)).hexdigest()!=source_sha:
                    raise RuntimeError(
                        f"Falha na validação reversível MBOX do UID {state_item.get('uid')}."
                    )
                fh.write(encoded)
                payload_length=len(encoded)

                # Separador físico não faz parte do payload indexado.
                if encoded.endswith(b"\n"):
                    fh.write(b"\n")
                else:
                    fh.write(b"\n\n")

                messages_meta.append({
                    "sequence":seq,
                    "uid":state_item.get("uid"),
                    "flags":state_item.get("flags") or [],
                    "internaldate":state_item.get("internaldate") or None,
                    "message_id":export_message_id(raw),
                    "sha256":source_sha,
                    "raw_bytes":len(raw),
                    "payload_offset":payload_offset,
                    "payload_length":payload_length,
                    "source_file":entry["path"].name,
                })
                done+=1
                if progress:
                    progress(done,total,mailbox_name,folder_index,len(analysis["folders"]))

            fh.flush()
            os.fsync(fh.fileno())

        if stopped:
            try:
                tmp.unlink()
            except Exception:
                pass
            break

        os.replace(tmp,mbox_path)
        metadata={
            "format":"email-backup-manager-mbox-folder-index",
            "format_version":2,
            "mailbox":mailbox_name,
            "delimiter":delimiter,
            "uidvalidity":folder["state"].get("uidvalidity"),
            "uidnext":folder["state"].get("uidnext"),
            "server_uid_count":folder["state"].get("server_uid_count"),
            "message_count":len(messages_meta),
            "messages":messages_meta,
        }
        restore_state_save(meta_path,metadata)

        folder_entries.append({
            "name":mailbox_name,
            "delimiter":delimiter,
            "file":str(mbox_rel).replace("\\","/"),
            "metadata_file":str(meta_rel).replace("\\","/"),
            "message_count":len(messages_meta),
            "uidvalidity":folder["state"].get("uidvalidity"),
            "uidnext":folder["state"].get("uidnext"),
        })

    manifest={
        "format":"email-backup-manager-mbox-package",
        "format_version":2,
        "app_version":APP_VERSION,
        "created_at_utc":datetime.now(timezone.utc).isoformat(),
        "account":analysis.get("account"),
        "source_backup":analysis.get("source"),
        "complete_backup_verified":bool(analysis.get("complete")),
        "sha256_verified_before_export":bool(verify_sha256),
        "folder_count":len(folder_entries),
        "message_count":sum(x["message_count"] for x in folder_entries),
        "stopped_by_user":stopped,
        "restore_method":"IMAP CREATE + APPEND",
        "notes":[
            "A hierarquia exata é definida por folders[].name + delimiter.",
            "FLAGS e INTERNALDATE ficam nos arquivos metadata/*.json.",
            "payload_offset/payload_length permitem restaurar os bytes originais do MBOX sem depender de parser genérico.",
            "Para hMailServer com estrutura completa, use restauração IMAP; SMTP isolado não recria subpastas.",
        ],
        "folders":folder_entries,
    }
    restore_state_save(package/"manifest.json",manifest)
    return package,manifest


def scan_legacy_manifest(manifest_path):
    """Lê pacote MBOX EBM v2 ou manifestos MBOX da solução anterior."""
    manifest_path=Path(manifest_path)
    manifest=json.loads(manifest_path.read_text(encoding="utf-8"))
    base=manifest_path.parent
    items=[]

    if manifest.get("format")=="email-backup-manager-mbox-package":
        for folder in manifest.get("folders",[]):
            mbox_file=base/str(folder.get("file",""))
            meta_file=base/str(folder.get("metadata_file",""))
            if not mbox_file.is_file() or not meta_file.is_file():
                continue
            metadata=restore_state_load(meta_file)
            with open(mbox_file,"rb") as fh:
                for meta in metadata.get("messages",[]):
                    offset=int(meta.get("payload_offset",0))
                    length=int(meta.get("payload_length",0))
                    fh.seek(offset)
                    encoded=fh.read(length)
                    if len(encoded)!=length:
                        raise RuntimeError(
                            f"Pacote MBOX truncado: {mbox_file}, sequência {meta.get('sequence')}."
                        )
                    raw=mboxrd_unescape(encoded)
                    expected=str(meta.get("sha256") or "")
                    actual=hashlib.sha256(raw).hexdigest()
                    if expected and actual.lower()!=expected.lower():
                        raise RuntimeError(
                            f"SHA-256 inválido ao ler {mbox_file}, sequência {meta.get('sequence')}."
                        )
                    items.append({
                        "kind":"raw",
                        "source_folder":folder.get("name") or metadata.get("mailbox") or "INBOX",
                        "source_delimiter":folder.get("delimiter") or metadata.get("delimiter") or "/",
                        "raw":raw,
                        "flags":meta.get("flags") or [],
                        "internaldate":meta.get("internaldate") or None,
                        "index":meta.get("sequence"),
                        "uid":meta.get("uid"),
                    })
        return items

    # Compatibilidade com o formato anterior baseado em mailbox.mbox.
    for folder in manifest.get("folders",[]):
        mbox_file=base/str(folder.get("file",""))
        if not mbox_file.is_file():
            continue
        metadata={}
        meta_file=folder.get("metadata_file")
        if meta_file and (base/meta_file).is_file():
            metadata=restore_state_load(base/meta_file)
        mb=mailbox.mbox(str(mbox_file),create=False)
        try:
            for idx,msg in enumerate(mb,1):
                raw=msg.as_bytes(policy=policy.SMTP)
                meta=metadata.get(str(idx),{}) if isinstance(metadata,dict) else {}
                items.append({
                    "kind":"raw",
                    "source_folder":folder.get("name") or "INBOX",
                    "source_delimiter":folder.get("delimiter") or "/",
                    "raw":raw,
                    "flags":meta.get("flags") or [],
                    "internaldate":meta.get("internaldate") or None,
                    "index":idx,
                })
        finally:
            mb.close()
    return items


def _aggregate_restore_plan_row(rows,target,source,count,exists,create_missing):
    row=rows.setdefault(target,{
        "target":target,
        "sources":set(),
        "messages":0,
        "exists":bool(exists),
        "action":"",
    })
    row["sources"].add(str(source or ""))
    row["messages"]+=int(count or 0)
    row["exists"]=bool(row["exists"] or exists)
    if row["exists"]:
        row["action"]="Usar pasta existente"
    elif create_missing:
        row["action"]="Criar pasta"
    else:
        row["action"]="Pasta ausente — criação desabilitada"


def analyze_restore_plan(source_type,source_path,target_delimiter,existing_folders,
                         create_missing=True):
    """Analisa a estrutura que será materializada sem gravar no servidor."""
    existing=set(existing_folders or [])
    rows={}
    source_messages=0
    append_operations=0
    source_path=Path(source_path)

    if source_type=="Google Takeout (MBOX)":
        mb=mailbox.mbox(str(source_path),create=False)
        try:
            source_messages=len(mb)
            for msg in mb:
                labels=[]
                for value in msg.get_all("X-Gmail-Labels",[]):
                    labels.extend(parse_gmail_labels(value))
                if not labels:
                    labels=["All Mail"]

                seen=set()
                logical_folders=[]
                for label in labels:
                    logical=takeout_label_to_logical_folder(label)
                    if logical and logical not in seen:
                        seen.add(logical)
                        logical_folders.append(logical)

                for logical in logical_folders:
                    target=takeout_folder_to_target(
                        logical,target_delimiter,existing
                    )
                    _aggregate_restore_plan_row(
                        rows,target,logical,1,target in existing,create_missing
                    )
                    append_operations+=1
        finally:
            mb.close()

    elif source_type=="Pacote MBOX convertido":
        manifest=json.loads(source_path.read_text(encoding="utf-8"))
        if manifest.get("format")!="email-backup-manager-mbox-package":
            raise RuntimeError(
                "O arquivo selecionado não é um pacote MBOX convertido válido."
            )
        for folder in manifest.get("folders",[]):
            source_name=folder.get("name") or "INBOX"
            source_delim=folder.get("delimiter") or "/"
            target=normalize_source_mailbox(
                source_name,source_delim,target_delimiter
            )
            count=int(folder.get("message_count") or 0)
            _aggregate_restore_plan_row(
                rows,target,source_name,count,target in existing,create_missing
            )
            source_messages+=count
            append_operations+=count

    else:
        # Backup da aplicação ou manifest.json legado.
        if source_path.is_file() and source_path.suffix.lower()==".json":
            manifest=json.loads(source_path.read_text(encoding="utf-8"))
            if manifest.get("format")=="email-backup-manager-mbox-package":
                return analyze_restore_plan(
                    "Pacote MBOX convertido",source_path,target_delimiter,
                    existing,create_missing
                )
            for folder in manifest.get("folders",[]):
                source_name=folder.get("name") or "INBOX"
                source_delim=folder.get("delimiter") or "/"
                target=normalize_source_mailbox(
                    source_name,source_delim,target_delimiter
                )
                count=int(folder.get("message_count") or 0)
                _aggregate_restore_plan_row(
                    rows,target,source_name,count,target in existing,create_missing
                )
                source_messages+=count
                append_operations+=count
        else:
            states=sorted(source_path.rglob(".ebm_state.json"))
            if source_path.is_file() and source_path.name==".ebm_state.json":
                states=[source_path]
            if not states:
                raise RuntimeError(
                    "Nenhum .ebm_state.json foi localizado na origem selecionada."
                )
            for state_path in states:
                state=restore_state_load(state_path)
                source_name=state.get("mailbox") or "INBOX"
                source_delim=state.get("hierarchy_delimiter") or "."
                target=normalize_source_mailbox(
                    source_name,source_delim,target_delimiter
                )
                count=0
                for item in state.get("messages",[]):
                    if not isinstance(item,dict):
                        continue
                    fname=item.get("file")
                    if fname and (state_path.parent/str(fname)).is_file():
                        count+=1
                _aggregate_restore_plan_row(
                    rows,target,source_name,count,target in existing,create_missing
                )
                source_messages+=count
                append_operations+=count

    folders=[]
    for target in sorted(rows,key=lambda x:x.casefold()):
        row=rows[target]
        row["sources"]=sorted(x for x in row["sources"] if x)
        folders.append(row)

    return {
        "source_type":source_type,
        "source_path":str(source_path),
        "target_delimiter":target_delimiter,
        "source_messages":source_messages,
        "append_operations":append_operations,
        "folder_count":len(folders),
        "folders":folders,
    }


# ---------------------------------------------------------------------------
# Aplicação
# ---------------------------------------------------------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(
            f"{APP_NAME} v{APP_VERSION}"
        )
        self.geometry("1220x790")
        self.minsize(1020, 680)

        self.store = ConfigStore()
        self.cfg = self.store.load()
        self.q = queue.Queue()
        self.backup_stop_event = threading.Event()
        self.restore_stop_event = threading.Event()
        self.converter_stop_event = threading.Event()
        self.hmail_stop_event = threading.Event()
        self.profile_index = None

        self._build()
        self._reload_profiles()
        self.after(100, self._poll_queue)

        log.info(
            "APP_START | version=%s",
            APP_VERSION,
        )

    # ------------------------------
    # Layout geral
    # ------------------------------
    def _build(self):
        top = ttk.Frame(
            self,
            padding=(14, 10),
        )
        top.pack(fill="x")

        ttk.Label(
            top,
            text="Email Backup Manager",
            font=("Segoe UI", 18, "bold"),
        ).pack(side="left")

        ttk.Label(
            top,
            text=(
                "Base de interface — conexão IMAP validada"
            ),
        ).pack(
            side="left",
            padx=(14, 0),
        )

        self.status_var = tk.StringVar(
            value="Pronto"
        )
        ttk.Label(
            top,
            textvariable=self.status_var,
        ).pack(side="right")

        self.tabs = ttk.Notebook(self)
        self.tabs.pack(
            fill="both",
            expand=True,
            padx=12,
            pady=(0, 12),
        )

        self.tab_profiles = ttk.Frame(
            self.tabs,
            padding=12,
        )
        self.tab_backup = ttk.Frame(
            self.tabs,
            padding=12,
        )
        self.tab_converter = ttk.Frame(
            self.tabs,
            padding=12,
        )
        self.tab_restore = ttk.Frame(
            self.tabs,
            padding=12,
        )
        self.tab_mbox = ttk.Frame(
            self.tabs,
            padding=12,
        )
        self.tab_general = ttk.Frame(
            self.tabs,
            padding=12,
        )
        self.tab_logs = ttk.Frame(
            self.tabs,
            padding=12,
        )

        self.tabs.add(
            self.tab_profiles,
            text="Servidores e contas",
        )
        self.tabs.add(
            self.tab_backup,
            text="Backup",
        )
        self.tabs.add(
            self.tab_converter,
            text="Converter para MBOX",
        )
        self.tabs.add(
            self.tab_restore,
            text="Restauração",
        )
        self.tabs.add(
            self.tab_mbox,
            text="MBOX → hMailServer",
        )
        self.tabs.add(
            self.tab_general,
            text="Configurações",
        )
        self.tabs.add(
            self.tab_logs,
            text="Logs / Diagnóstico",
        )

        self._build_profiles()
        self._build_backup()
        self._build_converter()
        self._build_restore()
        self._build_mbox()
        self._build_general()
        self._build_logs()

    # ------------------------------
    # Perfis / contas
    # ------------------------------
    def _build_profiles(self):
        pane = ttk.Panedwindow(
            self.tab_profiles,
            orient="horizontal",
        )
        pane.pack(fill="both", expand=True)

        left = ttk.Frame(pane, padding=(0,0,10,0))
        right = ttk.Frame(pane)
        pane.add(left, weight=1)
        pane.add(right, weight=3)

        ttk.Label(
            left,
            text="Perfis",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w")

        self.profile_list = tk.Listbox(
            left,
            exportselection=False,
        )
        self.profile_list.pack(
            fill="both",
            expand=True,
            pady=(6, 8),
        )
        self.profile_list.bind(
            "<<ListboxSelect>>",
            self._on_profile_select,
        )

        pbuttons = ttk.Frame(left)
        pbuttons.pack(fill="x")
        ttk.Button(
            pbuttons,
            text="Novo",
            command=self._new_profile,
        ).pack(
            side="left",
            expand=True,
            fill="x",
        )
        ttk.Button(
            pbuttons,
            text="Excluir",
            command=self._delete_profile,
        ).pack(
            side="left",
            expand=True,
            fill="x",
            padx=(6,0),
        )

        info = ttk.LabelFrame(
            right,
            text="Servidor",
            padding=12,
        )
        info.pack(fill="x")

        self.p_name = self._grid_field(
            info, 0, "Nome do perfil"
        )
        self.p_domain = self._grid_field(
            info, 1, "Domínio"
        )

        ttk.Label(
            info,
            text="Protocolo",
        ).grid(
            row=2,
            column=0,
            sticky="w",
            pady=5,
        )
        self.p_protocol = ttk.Combobox(
            info,
            values=["IMAP", "POP3"],
            state="readonly",
        )
        self.p_protocol.set("IMAP")
        self.p_protocol.grid(
            row=2,
            column=1,
            sticky="ew",
            padx=(10,0),
            pady=5,
        )

        self.p_host = self._grid_field(
            info, 3, "Servidor"
        )
        self.p_port = self._grid_field(
            info, 4, "Porta"
        )

        ttk.Label(
            info,
            text="Segurança",
        ).grid(
            row=5,
            column=0,
            sticky="w",
            pady=5,
        )
        self.p_security = ttk.Combobox(
            info,
            values=[
                "SSL/TLS",
                "STARTTLS",
                "Nenhuma",
            ],
            state="readonly",
        )
        self.p_security.set("SSL/TLS")
        self.p_security.grid(
            row=5,
            column=1,
            sticky="ew",
            padx=(10,0),
            pady=5,
        )

        ttk.Label(
            info,
            text="Autenticação",
        ).grid(
            row=6,
            column=0,
            sticky="w",
            pady=5,
        )
        self.p_auth = ttk.Combobox(
            info,
            values=[
                "AUTH LOGIN",
                "SASL PLAIN",
                "IMAP LOGIN",
            ],
            state="readonly",
        )
        self.p_auth.set("AUTH LOGIN")
        self.p_auth.grid(
            row=6,
            column=1,
            sticky="ew",
            padx=(10,0),
            pady=5,
        )

        self.p_timeout = self._grid_field(
            info, 7, "Timeout (s)"
        )

        ttk.Label(
            info,
            text="Senha padrão",
        ).grid(
            row=8,
            column=0,
            sticky="w",
            pady=5,
        )
        self.p_password = ttk.Entry(
            info,
            show="*",
        )
        self.p_password.grid(
            row=8,
            column=1,
            sticky="ew",
            padx=(10,0),
            pady=5,
        )

        self.p_save_password = tk.BooleanVar()
        ttk.Checkbutton(
            info,
            text="Salvar senha padrão com DPAPI",
            variable=self.p_save_password,
        ).grid(
            row=9,
            column=1,
            sticky="w",
            padx=(10,0),
            pady=(0,5),
        )

        info.columnconfigure(1, weight=1)

        actions = ttk.Frame(right)
        actions.pack(
            fill="x",
            pady=(8, 10),
        )
        ttk.Button(
            actions,
            text="Salvar perfil",
            command=self._save_profile,
        ).pack(side="left")
        ttk.Button(
            actions,
            text="Testar conexão",
            command=self._test_selected_account,
        ).pack(
            side="left",
            padx=(8,0),
        )
        ttk.Label(
            actions,
            text=(
                "Teste validado atualmente: IMAP + SSL/TLS + AUTH LOGIN."
            ),
        ).pack(
            side="left",
            padx=(14,0),
        )

        accounts_box = ttk.LabelFrame(
            right,
            text="Contas do perfil",
            padding=8,
        )
        accounts_box.pack(
            fill="both",
            expand=True,
        )

        # v1.14: ações ficam acima da tabela para nunca serem empurradas
        # para fora da área visível em resoluções/janelas menores.
        ab = ttk.Frame(accounts_box)
        ab.pack(
            fill="x",
            pady=(0,8),
        )
        ttk.Button(
            ab,
            text="Adicionar conta",
            command=self._add_account,
        ).pack(side="left")
        ttk.Button(
            ab,
            text="Editar conta",
            command=self._edit_account,
        ).pack(
            side="left",
            padx=(6,0),
        )
        ttk.Button(
            ab,
            text="Remover conta",
            command=self._remove_account,
        ).pack(
            side="left",
            padx=(6,0),
        )
        ttk.Label(
            ab,
            text="Dica: duplo clique em uma conta para editar.",
        ).pack(
            side="left",
            padx=(14,0),
        )

        tree_frame = ttk.Frame(accounts_box)
        tree_frame.pack(
            fill="both",
            expand=True,
        )

        self.accounts_tree = ttk.Treeview(
            tree_frame,
            columns=(
                "email",
                "auth_user",
                "own_password",
            ),
            show="headings",
            height=11,
        )
        self.accounts_tree.heading(
            "email",
            text="E-mail",
        )
        self.accounts_tree.heading(
            "auth_user",
            text="Usuário de autenticação",
        )
        self.accounts_tree.heading(
            "own_password",
            text="Senha própria",
        )
        self.accounts_tree.column(
            "email",
            width=300,
        )
        self.accounts_tree.column(
            "auth_user",
            width=300,
        )
        self.accounts_tree.column(
            "own_password",
            width=110,
            anchor="center",
        )

        account_scroll = ttk.Scrollbar(
            tree_frame,
            orient="vertical",
            command=self.accounts_tree.yview,
        )
        self.accounts_tree.configure(
            yscrollcommand=account_scroll.set,
        )

        self.accounts_tree.pack(
            side="left",
            fill="both",
            expand=True,
        )
        account_scroll.pack(
            side="right",
            fill="y",
        )

        self.accounts_tree.bind(
            "<Double-1>",
            lambda event: self._edit_account(),
        )

    def _grid_field(self, parent, row, label):
        ttk.Label(
            parent,
            text=label,
        ).grid(
            row=row,
            column=0,
            sticky="w",
            pady=5,
        )
        e = ttk.Entry(parent)
        e.grid(
            row=row,
            column=1,
            sticky="ew",
            padx=(10,0),
            pady=5,
        )
        return e

    def _reload_profiles(self):
        self.profile_list.delete(0, "end")
        for profile in self.cfg.get(
            "profiles", []
        ):
            self.profile_list.insert(
                "end",
                profile.get(
                    "name",
                    "(sem nome)",
                ),
            )

        if self.cfg.get("profiles"):
            index = (
                self.profile_index
                if self.profile_index is not None
                and self.profile_index
                < len(self.cfg["profiles"])
                else 0
            )
            self.profile_list.selection_set(index)
            self.profile_list.activate(index)
            self._load_profile(index)

        self._refresh_profile_comboboxes()

    def _on_profile_select(self, event=None):
        sel = self.profile_list.curselection()
        if not sel:
            return
        self._load_profile(sel[0])

    def _load_profile(self, index):
        self.profile_index = index
        p = self.cfg["profiles"][index]

        mapping = [
            (self.p_name, p.get("name","")),
            (self.p_domain, p.get("domain","")),
            (self.p_host, p.get("host","")),
            (self.p_port, str(p.get("port",993))),
            (
                self.p_timeout,
                str(p.get("timeout",12)),
            ),
        ]
        for widget, value in mapping:
            widget.delete(0, "end")
            widget.insert(0, value)

        self.p_protocol.set(
            p.get("protocol","IMAP")
        )
        self.p_security.set(
            p.get("security","SSL/TLS")
        )
        self.p_auth.set(
            p.get("auth_method","AUTH LOGIN")
        )

        self.p_password.delete(0, "end")
        self.p_save_password.set(
            bool(p.get("password_enc"))
        )

        self._reload_accounts()

    def _new_profile(self):
        p = {
            "id": str(uuid.uuid4()),
            "name": "Novo servidor",
            "domain": "",
            "protocol": "IMAP",
            "host": "",
            "port": 993,
            "security": "SSL/TLS",
            "auth_method": "AUTH LOGIN",
            "timeout": 12,
            "save_password": False,
            "password_enc": "",
            "accounts": [],
        }
        self.cfg.setdefault(
            "profiles", []
        ).append(p)
        self.profile_index = (
            len(self.cfg["profiles"]) - 1
        )
        self.store.save(self.cfg)
        self._reload_profiles()

    def _delete_profile(self):
        if self.profile_index is None:
            return
        p = self.cfg["profiles"][
            self.profile_index
        ]
        if not messagebox.askyesno(
            "Excluir perfil",
            f"Excluir o perfil '{p.get('name')}'?",
            parent=self,
        ):
            return
        del self.cfg["profiles"][
            self.profile_index
        ]
        self.profile_index = None
        self.store.save(self.cfg)
        self._reload_profiles()

    def _save_profile(self):
        if self.profile_index is None:
            return

        try:
            port = int(
                self.p_port.get().strip()
            )
            timeout = int(
                self.p_timeout.get().strip()
            )
        except ValueError:
            messagebox.showerror(
                "Perfil",
                "Porta e timeout devem ser numéricos.",
                parent=self,
            )
            return

        p = self.cfg["profiles"][
            self.profile_index
        ]
        p.update({
            "name": self.p_name.get().strip()
                or "Servidor",
            "domain": self.p_domain.get().strip(),
            "protocol": self.p_protocol.get(),
            "host": self.p_host.get().strip(),
            "port": port,
            "security": self.p_security.get(),
            "auth_method": self.p_auth.get(),
            "timeout": timeout,
            "save_password": bool(
                self.p_save_password.get()
            ),
        })

        pwd = self.p_password.get()
        if self.p_save_password.get():
            if pwd:
                try:
                    p["password_enc"] = (
                        dpapi_encrypt(pwd)
                    )
                except Exception as exc:
                    messagebox.showerror(
                        "DPAPI",
                        str(exc),
                        parent=self,
                    )
                    return
        else:
            p["password_enc"] = ""

        self.store.save(self.cfg)
        self.status_var.set(
            "Perfil salvo"
        )
        self._reload_profiles()
        log.info(
            "PROFILE_SAVED | name=%s | host=%s | port=%s",
            p["name"],
            p["host"],
            p["port"],
        )

    def _reload_accounts(self):
        for item in self.accounts_tree.get_children():
            self.accounts_tree.delete(item)

        if self.profile_index is None:
            return

        p = self.cfg["profiles"][
            self.profile_index
        ]
        normalized_accounts = [
            normalize_account_record(a)
            for a in p.get("accounts", [])
        ]
        if normalized_accounts != p.get("accounts", []):
            p["accounts"] = normalized_accounts
            self.store.save(self.cfg)

        for idx, account in enumerate(normalized_accounts):
            self.accounts_tree.insert(
                "",
                "end",
                iid=str(idx),
                values=(
                    account.get("email",""),
                    account.get(
                        "auth_user",
                        account.get("email",""),
                    ),
                    (
                        "Sim"
                        if account.get(
                            "password_enc"
                        )
                        else "Não"
                    ),
                ),
            )

    def _add_account(self):
        if self.profile_index is None:
            return
        dlg = AccountDialog(self)
        self.wait_window(dlg)
        if dlg.result:
            self.cfg["profiles"][
                self.profile_index
            ].setdefault(
                "accounts", []
            ).append(dlg.result)
            self.store.save(self.cfg)
            self._reload_accounts()
            self._refresh_profile_comboboxes()

    def _selected_account_index(self):
        sel = self.accounts_tree.selection()
        if not sel:
            return None
        return int(sel[0])

    def _edit_account(self):
        idx = self._selected_account_index()
        if idx is None:
            messagebox.showinfo(
                "Contas",
                "Selecione uma conta para editar.",
                parent=self,
            )
            return
        account = self.cfg["profiles"][
            self.profile_index
        ]["accounts"][idx]
        dlg = AccountDialog(
            self,
            account,
        )
        self.wait_window(dlg)
        if dlg.result:
            self.cfg["profiles"][
                self.profile_index
            ]["accounts"][idx] = dlg.result
            self.store.save(self.cfg)
            self._reload_accounts()

    def _remove_account(self):
        idx = self._selected_account_index()
        if idx is None:
            messagebox.showinfo(
                "Contas",
                "Selecione uma conta para remover.",
                parent=self,
            )
            return

        account = self.cfg["profiles"][
            self.profile_index
        ]["accounts"][idx]
        if not messagebox.askyesno(
            "Remover conta",
            f"Remover {account.get('email','')} deste perfil?",
            parent=self,
        ):
            return

        del self.cfg["profiles"][
            self.profile_index
        ]["accounts"][idx]
        self.store.save(self.cfg)
        self._reload_accounts()
        self._refresh_profile_comboboxes()

    # ------------------------------
    # Teste da conexão validada
    # ------------------------------
    def _resolve_password(
        self,
        profile,
        account,
    ):
        token = account.get(
            "password_enc", ""
        )
        if token:
            return dpapi_decrypt(token)

        token = profile.get(
            "password_enc", ""
        )
        if token:
            return dpapi_decrypt(token)

        transient = self.p_password.get()
        if transient:
            return transient

        return simpledialog.askstring(
            "Senha",
            (
                "Digite a senha para "
                f"{account.get('email','')}:"
            ),
            show="*",
            parent=self,
        )

    def _test_selected_account(self):
        idx = self._selected_account_index()
        if idx is None:
            messagebox.showinfo(
                "Teste",
                "Selecione uma conta no perfil.",
                parent=self,
            )
            return

        p = self.cfg["profiles"][
            self.profile_index
        ]
        a = p["accounts"][idx]

        if (
            p.get("protocol") != "IMAP"
            or p.get("security") != "SSL/TLS"
            or p.get("auth_method") != "AUTH LOGIN"
        ):
            messagebox.showwarning(
                "Conector validado",
                (
                    "Nesta etapa, o teste funcional está "
                    "habilitado somente para:\n\n"
                    "IMAP + SSL/TLS + AUTH LOGIN.\n\n"
                    "As demais opções já podem ser configuradas "
                    "na interface, mas serão validadas depois."
                ),
                parent=self,
            )
            return

        try:
            password = self._resolve_password(
                p,
                a,
            )
        except Exception as exc:
            messagebox.showerror(
                "Senha",
                str(exc),
                parent=self,
            )
            return

        if password is None:
            return

        self.status_var.set(
            "Testando conexão..."
        )
        self._append_diag(
            f"TESTE | {a.get('email')} | "
            f"{p.get('host')}:{p.get('port')}"
        )

        threading.Thread(
            target=self._connection_worker,
            args=(p.copy(), a.copy(), password),
            daemon=True,
        ).start()

    def _connection_worker(
        self,
        profile,
        account,
        password,
    ):
        client = None
        try:
            log.info(
                "CONNECTION_TEST_START | profile=%s | host=%s | port=%s | account=%s",
                profile.get("name"),
                profile.get("host"),
                profile.get("port"),
                account.get("email"),
            )

            client = RawIMAPLoginClient(
                profile.get("host"),
                profile.get("port"),
                profile.get("timeout", 12),
            )
            info = client.connect()
            final = client.authenticate(
                account.get(
                    "auth_user"
                )
                or account.get("email"),
                password,
            )

            self.q.put((
                "diag",
                f"TCP/TLS OK: {info['tls_version']}",
            ))
            self.q.put((
                "diag",
                "AUTH LOGIN OK: " + final,
            ))
            self.q.put((
                "connection_ok",
                account.get("email"),
            ))
            log.info(
                "CONNECTION_TEST_OK | account=%s",
                account.get("email"),
            )
        except Exception as exc:
            self.q.put((
                "diag",
                "FALHA: " + str(exc),
            ))
            self.q.put((
                "connection_error",
                str(exc),
            ))
            log.exception(
                "CONNECTION_TEST_FAILED"
            )
        finally:
            password = None
            if client:
                client.close()

    # ------------------------------
    # Backup (somente configuração)
    # ------------------------------
    def _build_backup(self):
        f = self.tab_backup

        ttk.Label(
            f,
            text="Backup",
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor="w")
        ttk.Label(
            f,
            text=(
                "Backup por lote, somente leitura, com estrutura de pastas do servidor, "
                "manifesto persistente, SHA-256 e verificação incremental."
            ),
        ).pack(anchor="w", pady=(4,14))

        source = ttk.LabelFrame(f, text="Origem", padding=12)
        source.pack(fill="x")

        self.b_profile = ttk.Combobox(source, state="readonly")
        self._label_widget(source, 0, "Perfil de origem", self.b_profile)
        self.b_profile.bind("<<ComboboxSelected>>", self._backup_profile_changed)

        self.b_account = ttk.Combobox(source, state="readonly")
        self._label_widget(source, 1, "Conta", self.b_account)
        self.b_account.bind("<<ComboboxSelected>>", self._backup_account_changed)

        ttk.Label(source,text="Escopo").grid(
            row=2,column=0,sticky="w",pady=5
        )
        self.b_scope=tk.StringVar(value="single")
        scope_frame=ttk.Frame(source)
        scope_frame.grid(row=2,column=1,columnspan=2,sticky="w",padx=(10,0),pady=5)
        ttk.Radiobutton(
            scope_frame,text="Pasta individual",
            variable=self.b_scope,value="single",
            command=self._backup_scope_changed,
        ).pack(side="left")
        ttk.Radiobutton(
            scope_frame,text="Todas as pastas",
            variable=self.b_scope,value="all",
            command=self._backup_scope_changed,
        ).pack(side="left",padx=(14,0))

        self.b_folder = ttk.Combobox(source, state="readonly")
        self.b_folder.set("INBOX")
        self._label_widget(source, 3, "Pasta IMAP", self.b_folder)
        self.b_load_folders=ttk.Button(
            source,
            text="Atualizar pastas",
            command=self._load_backup_folders,
        )
        self.b_load_folders.grid(row=3, column=2, padx=(6,0), pady=5)

        self.b_limit = ttk.Entry(source)
        self._label_widget(source, 4, "Limite por pasta (0 = todos pendentes)", self.b_limit)

        self.b_destination = ttk.Entry(source)
        self._label_widget(source, 5, "Diretório base", self.b_destination)
        ttk.Button(
            source,
            text="...",
            width=4,
            command=lambda: self._browse_into(self.b_destination, file_mode=False),
        ).grid(row=5, column=2, padx=(6,0), pady=5)

        options = ttk.LabelFrame(f, text="Formato e validação", padding=12)
        options.pack(fill="x", pady=(10,0))

        self.b_incremental = tk.BooleanVar()
        self.b_raw = tk.BooleanVar()
        self.b_manifest = tk.BooleanVar()
        self.b_flags = tk.BooleanVar()
        self.b_internaldate = tk.BooleanVar()
        self.b_hash = tk.BooleanVar()
        self.b_dedupe = tk.BooleanVar()

        checks = [
            ("Backup incremental: pular mensagens já preservadas", self.b_incremental),
            ("Salvar mensagens em EML bruto", self.b_raw),
            ("Gerar manifesto JSON", self.b_manifest),
            ("Registrar FLAGS", self.b_flags),
            ("Registrar INTERNALDATE", self.b_internaldate),
            ("Verificar SHA-256 após gravação", self.b_hash),
            ("Deduplicar Message-ID + SHA-256 (etapa posterior)", self.b_dedupe),
        ]
        for i,(label,var) in enumerate(checks):
            ttk.Checkbutton(
                options,
                text=label,
                variable=var,
            ).grid(
                row=i//2,
                column=i%2,
                sticky="w",
                padx=(0,18),
                pady=3,
            )

        actions=ttk.Frame(f)
        actions.pack(fill="x", pady=(12,0))
        ttk.Button(
            actions,
            text="Salvar configurações",
            command=self._save_backup_options,
        ).pack(side="left")

        self.backup_run = ttk.Button(
            actions,
            text="Executar backup",
            command=self._run_backup_test,
        )
        self.backup_run.pack(side="left", padx=(8,0))

        self.backup_stop = ttk.Button(
            actions,
            text="Parar após mensagem atual",
            command=self._request_backup_stop,
            state="disabled",
        )
        self.backup_stop.pack(side="left", padx=(8,0))

        self.b_progress_var=tk.DoubleVar(value=0)
        self.b_progress=ttk.Progressbar(
            f,
            variable=self.b_progress_var,
            maximum=100,
        )
        self.b_progress.pack(fill="x", pady=(14,4))

        self.b_progress_text=tk.StringVar(value="Aguardando execução.")
        ttk.Label(
            f,
            textvariable=self.b_progress_text,
        ).pack(anchor="w")

    def _profile_from_backup_selection(self):
        idx=self.b_profile.current()
        profiles=self.cfg.get("profiles",[])
        if idx<0 or idx>=len(profiles):
            return None
        return profiles[idx]

    def _backup_profile_changed(self, event=None):
        p=self._profile_from_backup_selection()
        emails=[]
        if p:
            emails=[
                a.get("email","")
                for a in p.get("accounts",[])
                if isinstance(a,dict) and a.get("email")
            ]
        self.b_account["values"]=emails
        if emails:
            if self.b_account.get() not in emails:
                self.b_account.set(emails[0])
        else:
            self.b_account.set("")
        self.b_folder["values"]=[]
        self.b_folder.set(
            self.cfg.get("backup",{}).get("folder","INBOX") or "INBOX"
        )
        self._backup_scope_changed()

    def _backup_account_changed(self,event=None):
        """Ao selecionar a conta, carregar suas pastas automaticamente."""
        self.b_folder["values"]=[]
        self.b_folder.set("INBOX")
        self._load_backup_folders(auto=True)

    def _backup_scope_changed(self):
        if self.b_scope.get()=="all":
            self.b_folder.configure(state="disabled")
        else:
            self.b_folder.configure(state="readonly")

    def _backup_selected_account(self, profile):
        email=self.b_account.get().strip()
        if not email:
            return None
        for a in profile.get("accounts",[]):
            if (
                isinstance(a,dict)
                and a.get("email","").casefold()==email.casefold()
            ):
                return a
        return None

    def _resolve_backup_password(self, profile, account):
        token=account.get("password_enc","")
        if token:
            return dpapi_decrypt(token)
        token=profile.get("password_enc","")
        if token:
            return dpapi_decrypt(token)
        return simpledialog.askstring(
            "Senha",
            f"Digite a senha para {account.get('email','')}:",
            show="*",
            parent=self,
        )

    def _validate_backup_connector(self, profile):
        if (
            profile.get("protocol")!="IMAP"
            or profile.get("security")!="SSL/TLS"
            or profile.get("auth_method")!="AUTH LOGIN"
        ):
            raise RuntimeError(
                "Nesta fase o backup funcional usa somente o conector já validado: "
                "IMAP + SSL/TLS + AUTH LOGIN."
            )

    def _load_backup_folders(self,auto=False):
        profile=self._profile_from_backup_selection()
        if not profile:
            if not auto:
                messagebox.showinfo("Backup","Selecione um perfil.",parent=self)
            return
        account=self._backup_selected_account(profile)
        if not account:
            if not auto:
                messagebox.showinfo("Backup","Selecione uma conta.",parent=self)
            return
        try:
            self._validate_backup_connector(profile)
            password=self._resolve_backup_password(profile,account)
        except Exception as exc:
            messagebox.showerror("Backup",str(exc),parent=self)
            return
        if password is None:
            return

        load_key=(str(profile.get("id") or profile.get("name")),account.get("email","").casefold())
        self._backup_folder_load_key=load_key
        self.status_var.set("Carregando pastas da conta...")
        self.b_progress_text.set(
            f"Carregando pastas de {account.get('email','')}..."
        )
        threading.Thread(
            target=self._backup_folder_worker,
            args=(profile.copy(),account.copy(),password,load_key),
            daemon=True,
        ).start()

    def _backup_folder_worker(self, profile, account, password, load_key):
        c=None
        try:
            c=RawIMAPLoginClient(
                profile.get("host"),
                profile.get("port"),
                profile.get("timeout",12),
            )
            c.connect()
            c.authenticate(
                account.get("auth_user") or account.get("email"),
                password,
            )
            folders,final=c.list_folders()
            attributes=getattr(c,"folder_attributes",{})
            selectable=[
                name for name in folders
                if "\\\\Noselect".casefold()
                not in {x.casefold() for x in attributes.get(name,[])}
            ]
            self.q.put(("backup_folders",{
                "folders": selectable,
                "all_folders": folders,
                "final": final,
                "key": load_key,
            }))
            log.info(
                "BACKUP_FOLDER_LIST_OK | account=%s | count=%s",
                account.get("email"), len(folders),
            )
        except Exception as exc:
            self.q.put(("backup_error",str(exc)))
            log.exception("BACKUP_FOLDER_LIST_FAILED")
        finally:
            password=None
            if c:
                c.close()
            self.q.put(("backup_idle",None))

    def _request_backup_stop(self):
        self.backup_stop_event.set()
        self.b_progress_text.set(
            "Parada solicitada; concluindo a mensagem atual..."
        )
        self.status_var.set("Parada do backup solicitada")
        self._append_diag("BACKUP_STOP_REQUESTED")

    def _save_backup_options(self):
        try:
            limit=int(self.b_limit.get() or "0")
        except ValueError:
            messagebox.showerror("Backup","Limite deve ser numérico.",parent=self)
            return False
        if limit<0:
            messagebox.showerror(
                "Backup",
                "Use 0 para todos os pendentes ou um número positivo.",
                parent=self,
            )
            return False

        b=self.cfg.setdefault("backup",{})
        b.update({
            "profile_name": self.b_profile.get(),
            "account": self.b_account.get(),
            "scope": self.b_scope.get(),
            "folder": self.b_folder.get().strip() or "INBOX",
            "destination": self.b_destination.get().strip(),
            "incremental": self.b_incremental.get(),
            "raw_eml": self.b_raw.get(),
            "manifest": self.b_manifest.get(),
            "preserve_flags": self.b_flags.get(),
            "preserve_internaldate": self.b_internaldate.get(),
            "verify_sha256": self.b_hash.get(),
            "dedupe_message_id_sha256": self.b_dedupe.get(),
            "test_limit": limit,
        })
        self.store.save(self.cfg)
        self.status_var.set("Configurações de backup salvas")
        return True

    @staticmethod
    def _safe_path_component(value):
        value=re.sub(r'[<>:"/\\|?*\x00-\x1f]+','_',str(value))
        value=value.strip(" ._")
        return value[:100] or "item"

    @staticmethod
    def _atomic_write_bytes(path, data):
        path=Path(path)
        path.parent.mkdir(parents=True,exist_ok=True)
        tmp=path.with_name(path.name+".tmp")
        with open(tmp,"wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp,path)

    @staticmethod
    def _atomic_write_json(path, data):
        path=Path(path)
        path.parent.mkdir(parents=True,exist_ok=True)
        tmp=path.with_name(path.name+".tmp")
        with open(tmp,"w",encoding="utf-8") as fh:
            json.dump(data,fh,ensure_ascii=False,indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp,path)

    @staticmethod
    def _decode_imap_modified_utf7(value):
        """Decodifica nomes de mailbox IMAP Modified UTF-7 apenas para o caminho local."""
        value=str(value)
        out=[]
        i=0
        while i<len(value):
            if value[i]!="&":
                j=value.find("&",i)
                if j<0:
                    j=len(value)
                out.append(value[i:j])
                i=j
                continue

            j=value.find("-",i)
            if j<0:
                out.append(value[i:])
                break

            token=value[i+1:j]
            if token=="":
                out.append("&")
            else:
                b64=token.replace(",","/")
                b64 += "="*((4-len(b64)%4)%4)
                try:
                    out.append(
                        base64.b64decode(b64).decode("utf-16-be","strict")
                    )
                except Exception:
                    out.append(value[i:j+1])
            i=j+1
        return "".join(out)

    @classmethod
    def _mailbox_local_parts(cls, mailbox, delimiter):
        """Converte a hierarquia do servidor em componentes seguros do filesystem."""
        raw_parts=(
            str(mailbox).split(delimiter)
            if delimiter
            else [str(mailbox)]
        )
        result=[]
        for raw in raw_parts:
            display=cls._decode_imap_modified_utf7(raw)
            result.append(cls._safe_path_component(display))
        return result or ["mailbox"]

    @classmethod
    def _mailbox_backup_root(cls, destination, profile, account, mailbox, delimiter):
        root=(
            Path(destination)
            / cls._safe_path_component(profile.get("host") or profile.get("name") or "Servidor")
            / cls._safe_path_component(account.get("email") or "conta")
        )
        for part in cls._mailbox_local_parts(mailbox,delimiter):
            root=root/part
        return root

    @staticmethod
    def _load_manifest(path):
        path=Path(path)
        if not path.exists():
            return None
        try:
            data=json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data,dict):
                raise ValueError("manifesto não é um objeto JSON")
            return data
        except Exception as exc:
            raise RuntimeError(
                f"Manifesto existente inválido em {path}: {exc}"
            ) from exc

    @staticmethod
    def _valid_incremental_uid_map(manifest, root, verify_sha256):
        """Retorna UIDs cuja cópia local existe e, opcionalmente, possui o SHA esperado."""
        valid={}
        if not manifest:
            return valid

        messages=manifest.get("messages",[])
        if not isinstance(messages,list):
            return valid

        for item in messages:
            if not isinstance(item,dict):
                continue
            try:
                uid=int(item.get("uid"))
            except Exception:
                continue

            file_name=item.get("file")
            expected_sha=str(item.get("sha256") or "")
            if not file_name:
                continue

            path=Path(root)/file_name
            if not path.is_file():
                continue

            if verify_sha256:
                if not expected_sha:
                    continue
                disk_sha=hashlib.sha256(path.read_bytes()).hexdigest()
                if disk_sha.lower()!=expected_sha.lower():
                    continue

            valid[uid]=item

        return valid

    def _run_backup_test(self):
        profile=self._profile_from_backup_selection()
        if not profile:
            messagebox.showinfo("Backup","Selecione um perfil.",parent=self)
            return
        account=self._backup_selected_account(profile)
        if not account:
            messagebox.showinfo("Backup","Selecione uma conta.",parent=self)
            return

        try:
            self._validate_backup_connector(profile)
            limit=int(self.b_limit.get() or "0")
            if limit<0:
                raise ValueError("Use 0 para todos os pendentes ou um número positivo.")
            password=self._resolve_backup_password(profile,account)
        except Exception as exc:
            messagebox.showerror("Backup",str(exc),parent=self)
            return
        if password is None:
            return

        scope=self.b_scope.get() or "single"
        mailbox=self.b_folder.get().strip() or "INBOX"
        destination=self.b_destination.get().strip()
        if not destination:
            destination=self.cfg.get("general",{}).get("backup_dir","")
        if not destination:
            messagebox.showerror("Backup","Informe o diretório base.",parent=self)
            return

        if not self._save_backup_options():
            return

        self.backup_stop_event.clear()
        self.backup_run.configure(state="disabled")
        self.backup_stop.configure(state="normal")
        self.b_progress_var.set(0)
        self.b_progress_text.set("Iniciando backup...")
        self.status_var.set("Backup em execução")
        self._append_diag(
            f"BACKUP_START | account={account.get('email')} | "
            f"scope={scope} | mailbox={mailbox} | limit_per_folder={limit}"
        )

        options={
            "incremental": self.b_incremental.get(),
            "raw_eml": self.b_raw.get(),
            "manifest": self.b_manifest.get(),
            "preserve_flags": self.b_flags.get(),
            "preserve_internaldate": self.b_internaldate.get(),
            "verify_sha256": self.b_hash.get(),
        }

        threading.Thread(
            target=self._backup_worker,
            args=(
                profile.copy(),account.copy(),password,
                scope,mailbox,limit,destination,options,
            ),
            daemon=True,
        ).start()

    def _backup_mailbox(
        self,c,profile,account,mailbox,delimiter,limit,destination,options,
        folder_index=1,folder_total=1,
    ):
        folder_info=c.examine(mailbox)
        uids,_=c.search_all_uids()

        root=self._mailbox_backup_root(
            destination,profile,account,mailbox,delimiter
        )
        root.mkdir(parents=True,exist_ok=True)
        state_path=root/".ebm_state.json"
        manifest_path=root/"manifest.json"

        previous=self._load_manifest(state_path)
        if previous is None:
            previous=self._load_manifest(manifest_path)

        current_uidvalidity=folder_info.get("uidvalidity")
        previous_uidvalidity=previous.get("uidvalidity") if previous else None
        if (
            options.get("incremental",True)
            and previous
            and previous_uidvalidity is not None
            and current_uidvalidity is not None
            and int(previous_uidvalidity)!=int(current_uidvalidity)
        ):
            raise RuntimeError(
                f"UIDVALIDITY mudou em {mailbox}. "
                f"Anterior={previous_uidvalidity}, atual={current_uidvalidity}."
            )

        existing_valid={}
        if options.get("incremental",True):
            existing_valid=self._valid_incremental_uid_map(
                previous,root,options.get("verify_sha256",True)
            )
            pending=[uid for uid in uids if uid not in existing_valid]
            selected=(pending if limit==0 else pending[:limit])
        else:
            pending=list(uids)
            selected=list(uids) if limit==0 else (uids[-limit:] if uids else [])

        old_items={}
        if previous and isinstance(previous.get("messages"),list):
            for item in previous["messages"]:
                if isinstance(item,dict):
                    try:
                        old_items[int(item.get("uid"))]=item
                    except Exception:
                        pass

        run_started=datetime.now(timezone.utc).isoformat()
        downloaded=0
        stopped=False
        total=max(1,len(selected))

        self.q.put(("diag",
            f"BACKUP_FOLDER_START | folder={mailbox} | "
            f"server={len(uids)} | valid_local={len(existing_valid)} | "
            f"pending={len(pending)} | selected={len(selected)}"
        ))

        for pos,uid in enumerate(selected,1):
            if self.backup_stop_event.is_set():
                stopped=True
                break

            meta=c.fetch_metadata(uid)
            raw,fetch_final=c.fetch_message_bytes(uid)
            sha=hashlib.sha256(raw).hexdigest()

            file_name=f"uid_{uid}.eml"
            file_path=root/file_name
            if options.get("raw_eml",True):
                self._atomic_write_bytes(file_path,raw)

            verified=True
            if options.get("verify_sha256",True) and options.get("raw_eml",True):
                verified=(
                    hashlib.sha256(file_path.read_bytes()).hexdigest()==sha
                )
                if not verified:
                    raise RuntimeError(
                        f"Falha SHA-256 após gravação do UID {uid} em {mailbox}."
                    )

            old_items[uid]={
                "uid":uid,
                "file":file_name if options.get("raw_eml",True) else None,
                "bytes_received":len(raw),
                "sha256":sha,
                "sha256_verified":verified,
                "rfc822_size":meta.get("rfc822_size"),
                "flags":meta.get("flags") if options.get("preserve_flags",True) else [],
                "internaldate":(
                    meta.get("internaldate")
                    if options.get("preserve_internaldate",True) else ""
                ),
                "imap_fetch_result":fetch_final,
                "last_verified_utc":datetime.now(timezone.utc).isoformat(),
            }
            downloaded+=1

            state={
                "format":"email-backup-manager-mailbox",
                "format_version":2,
                "app_version":APP_VERSION,
                "profile":{
                    "name":profile.get("name"),
                    "host":profile.get("host"),
                    "port":profile.get("port"),
                    "security":profile.get("security"),
                    "auth_method":profile.get("auth_method"),
                },
                "account":account.get("email"),
                "mailbox":mailbox,
                "hierarchy_delimiter":delimiter,
                "uidvalidity":current_uidvalidity,
                "uidnext":folder_info.get("uidnext"),
                "exists":folder_info.get("exists"),
                "server_uid_count":len(uids),
                "incremental":bool(options.get("incremental",True)),
                "last_run_started_utc":run_started,
                "last_run_updated_utc":datetime.now(timezone.utc).isoformat(),
                "messages":[old_items[k] for k in sorted(old_items)],
            }
            self._atomic_write_json(state_path,state)
            if options.get("manifest",True):
                self._atomic_write_json(manifest_path,state)

            local_percent=(pos/total) if selected else 1
            overall=((folder_index-1)+local_percent)/max(1,folder_total)*100
            self.q.put(("backup_progress",{
                "percent":overall,
                "text":(
                    f"Pasta {folder_index}/{folder_total}: {mailbox} | "
                    f"{pos}/{len(selected)} novos | "
                    f"{len(existing_valid)} já existentes"
                ),
            }))
            self.q.put(("diag",
                f"BACKUP_UID_OK | folder={mailbox} | uid={uid} | "
                f"bytes={len(raw)} | sha256={sha}"
            ))

        remaining=max(0,len(pending)-downloaded)
        final_state={
            "format":"email-backup-manager-mailbox",
            "format_version":2,
            "app_version":APP_VERSION,
            "profile":{
                "name":profile.get("name"),
                "host":profile.get("host"),
                "port":profile.get("port"),
                "security":profile.get("security"),
                "auth_method":profile.get("auth_method"),
            },
            "account":account.get("email"),
            "mailbox":mailbox,
            "hierarchy_delimiter":delimiter,
            "uidvalidity":current_uidvalidity,
            "uidnext":folder_info.get("uidnext"),
            "exists":folder_info.get("exists"),
            "server_uid_count":len(uids),
            "incremental":bool(options.get("incremental",True)),
            "last_run_started_utc":run_started,
            "last_run_completed_utc":datetime.now(timezone.utc).isoformat(),
            "valid_local_before_run":len(existing_valid),
            "pending_before_run":len(pending),
            "downloaded_this_run":downloaded,
            "stopped_by_user":stopped,
            "messages":[old_items[k] for k in sorted(old_items)],
        }
        self._atomic_write_json(state_path,final_state)
        if options.get("manifest",True):
            self._atomic_write_json(manifest_path,final_state)

        return {
            "mailbox":mailbox,
            "downloaded":downloaded,
            "skipped":len(existing_valid),
            "pending":remaining,
            "stopped":stopped,
            "path":str(root),
        }

    def _backup_worker(
        self,profile,account,password,
        scope,mailbox,limit,destination,options,
    ):
        c=None
        try:
            c=RawIMAPLoginClient(
                profile.get("host"),
                profile.get("port"),
                profile.get("timeout",12),
            )
            c.connect()
            auth_final=c.authenticate(
                account.get("auth_user") or account.get("email"),
                password,
            )
            self.q.put(("backup_progress",{
                "percent":2,
                "text":f"Autenticado: {auth_final}",
            }))

            folders,_=c.list_folders()
            attributes=getattr(c,"folder_attributes",{})
            selectable=[
                name for name in folders
                if "\\\\Noselect".casefold()
                not in {x.casefold() for x in attributes.get(name,[])}
            ]

            if scope=="all":
                mailboxes=selectable
            else:
                if mailbox not in folders:
                    raise RuntimeError(
                        f"A pasta selecionada não foi localizada no servidor: {mailbox}"
                    )
                mailboxes=[mailbox]

            if not mailboxes:
                raise RuntimeError("Nenhuma pasta selecionável foi localizada.")

            total_downloaded=0
            total_skipped=0
            total_pending=0
            results=[]
            failed_folders=[]

            for idx,current in enumerate(mailboxes,1):
                if self.backup_stop_event.is_set():
                    break
                delimiter=getattr(c,"folder_delimiters",{}).get(current)
                if delimiter is None:
                    delimiter=getattr(c,"default_folder_delimiter",None)

                self.q.put(("backup_progress",{
                    "percent":((idx-1)/len(mailboxes))*100,
                    "text":f"Pasta {idx}/{len(mailboxes)}: preparando {current}",
                }))

                try:
                    result=self._backup_mailbox(
                        c,profile,account,current,delimiter,limit,
                        destination,options,idx,len(mailboxes),
                    )
                    results.append(result)
                    total_downloaded+=result["downloaded"]
                    total_skipped+=result["skipped"]
                    total_pending+=result["pending"]
                    if result["stopped"]:
                        break
                except Exception as exc:
                    failed_folders.append({"mailbox":current,"error":str(exc)})
                    self.q.put(("diag",
                        f"BACKUP_FOLDER_FAILED | folder={current} | error={exc}"
                    ))
                    log.exception("BACKUP_FOLDER_FAILED | mailbox=%s",current)

            stopped=self.backup_stop_event.is_set() or any(
                r.get("stopped") for r in results
            )
            self.q.put(("backup_progress",{
                "percent":100 if not stopped else (
                    (len(results)/max(1,len(mailboxes)))*100
                ),
                "text":(
                    ("Interrompido: " if stopped else "Concluído: ")
                    + f"{total_downloaded} novos | "
                    + f"{total_skipped} já existentes | "
                    + f"{total_pending} pendentes | "
                    + f"{len(failed_folders)} pastas com falha"
                ),
            }))
            self.q.put(("backup_ok",{
                "messages":total_downloaded,
                "skipped":total_skipped,
                "pending":total_pending,
                "stopped":stopped,
                "scope":scope,
                "folders_total":len(mailboxes),
                "folders_done":len(results),
                "folders_failed":failed_folders,
                "path":str(
                    Path(destination)
                    / self._safe_path_component(profile.get("host") or profile.get("name"))
                    / self._safe_path_component(account.get("email"))
                ),
                "manifest":"",
                "state":"",
                "uidvalidity":None,
            }))
            log.info(
                "BACKUP_OK | account=%s | scope=%s | folders=%s | "
                "downloaded=%s | skipped=%s | pending=%s | failed_folders=%s",
                account.get("email"),scope,len(mailboxes),
                total_downloaded,total_skipped,total_pending,len(failed_folders),
            )
        except Exception as exc:
            self.q.put(("backup_error",str(exc)))
            log.exception("BACKUP_FAILED")
        finally:
            password=None
            if c:
                c.close()
            self.q.put(("backup_done",None))


    # ------------------------------
    # Pré-visualizações de estrutura
    # ------------------------------
    @staticmethod
    def _clear_tree(tree):
        for item in tree.get_children():
            tree.delete(item)

    @staticmethod
    def _tree_path(tree,root_id,parts,nodes):
        parent=root_id
        path=[]
        for part in parts:
            path.append(part)
            key=tuple(path)
            if key not in nodes:
                nodes[key]=tree.insert(
                    parent,"end",text=part,open=True,values=("","","","","")
                )
            parent=nodes[key]
        return parent

    def _populate_converter_preview(self,analysis):
        self._clear_tree(self.c_preview)
        account=analysis.get("account") or "conta"
        root=self.c_preview.insert(
            "","end",text=account,open=True,
            values=(
                analysis.get("message_count",0),
                analysis.get("pending_count",0),
                analysis.get("invalid_count",0),
                "Completo" if analysis.get("complete") else "Incompleto",
                "",
            ),
        )
        nodes={}
        for folder in sorted(
            analysis.get("folders",[]),
            key=lambda x:str(x.get("mailbox","")).casefold(),
        ):
            parts=export_mailbox_parts(
                folder.get("mailbox") or "INBOX",
                folder.get("delimiter") or ".",
            )
            leaf=self._tree_path(self.c_preview,root,parts,nodes)
            rel=Path("mbox")/Path(*parts)
            rel=rel.with_suffix(".mbox")
            self.c_preview.item(
                leaf,
                values=(
                    len(folder.get("valid",[])),
                    folder.get("pending",0),
                    len(folder.get("invalid",[])),
                    "OK" if folder.get("complete") else "Pendente/Inválido",
                    str(rel).replace("\\","/"),
                ),
            )

    def _populate_restore_preview(self,tree,plan,destination_account):
        self._clear_tree(tree)
        root=tree.insert(
            "","end",text=destination_account or "destino",open=True,
            values=(
                "",
                plan.get("append_operations",0),
                "",
                "",
                "",
            ),
        )
        nodes={}
        delimiter=plan.get("target_delimiter") or "."
        for row in plan.get("folders",[]):
            target=row.get("target") or "INBOX"
            raw_parts=target.split(delimiter) if delimiter else [target]
            parts=[export_decode_modified_utf7(x) for x in raw_parts]
            leaf=self._tree_path(tree,root,parts,nodes)
            tree.item(
                leaf,
                values=(
                    ", ".join(row.get("sources",[])),
                    row.get("messages",0),
                    "Sim" if row.get("exists") else "Não",
                    row.get("action",""),
                    target,
                ),
            )

    @staticmethod
    def _make_structure_tree(parent,mode):
        frame=ttk.Frame(parent)
        frame.pack(fill="both",expand=True,pady=(6,0))
        if mode=="converter":
            columns=("messages","pending","invalid","status","path")
            headings={
                "messages":"Mensagens",
                "pending":"Pendentes",
                "invalid":"Inválidas",
                "status":"Status",
                "path":"MBOX gerado",
            }
            widths=(90,80,80,130,320)
        else:
            columns=("source","messages","exists","action","imap")
            headings={
                "source":"Origem",
                "messages":"Mensagens",
                "exists":"Já existe",
                "action":"Ação",
                "imap":"Nome IMAP final",
            }
            widths=(260,90,80,210,300)

        tree=ttk.Treeview(
            frame,columns=columns,show="tree headings",height=11
        )
        tree.heading("#0",text="Estrutura")
        tree.column("#0",width=280,stretch=True)
        for col,width in zip(columns,widths):
            tree.heading(col,text=headings[col])
            tree.column(col,width=width,stretch=True)

        y=ttk.Scrollbar(frame,orient="vertical",command=tree.yview)
        x=ttk.Scrollbar(frame,orient="horizontal",command=tree.xview)
        tree.configure(yscrollcommand=y.set,xscrollcommand=x.set)
        tree.grid(row=0,column=0,sticky="nsew")
        y.grid(row=0,column=1,sticky="ns")
        x.grid(row=1,column=0,sticky="ew")
        frame.rowconfigure(0,weight=1)
        frame.columnconfigure(0,weight=1)
        return tree

    # ------------------------------
    # Converter backup -> pacote MBOX
    # ------------------------------
    def _build_converter(self):
        f=self.tab_converter
        ttk.Label(
            f,text="Converter backup para pacote MBOX",
            font=("Segoe UI",14,"bold"),
        ).pack(anchor="w")
        ttk.Label(
            f,
            text=(
                "Gera um MBOX por pasta + metadados + manifest.json. "
                "O pacote preserva a hierarquia necessária para futura restauração IMAP no hMailServer."
            ),
        ).pack(anchor="w",pady=(4,14))

        box=ttk.LabelFrame(f,text="Origem e destino",padding=12)
        box.pack(fill="x")

        self.c_source=ttk.Entry(box)
        self._label_widget(box,0,"Backup finalizado da conta",self.c_source)
        ttk.Button(
            box,text="...",width=4,
            command=lambda:self._browse_converter_source(),
        ).grid(row=0,column=2,padx=(6,0),pady=5)

        self.c_destination=ttk.Entry(box)
        self._label_widget(box,1,"Diretório para o pacote MBOX",self.c_destination)
        ttk.Button(
            box,text="...",width=4,
            command=lambda:self._browse_into(self.c_destination,file_mode=False),
        ).grid(row=1,column=2,padx=(6,0),pady=5)

        self.c_require_complete=tk.BooleanVar(value=True)
        self.c_verify_sha=tk.BooleanVar(value=True)
        ttk.Checkbutton(
            box,text="Exigir que o backup esteja completo",
            variable=self.c_require_complete,
        ).grid(row=2,column=0,columnspan=2,sticky="w",pady=3)
        ttk.Checkbutton(
            box,text="Verificar SHA-256 de todos os EMLs antes de converter",
            variable=self.c_verify_sha,
        ).grid(row=3,column=0,columnspan=2,sticky="w",pady=3)

        actions=ttk.Frame(f)
        actions.pack(fill="x",pady=(12,0))
        ttk.Button(
            actions,text="Analisar backup",command=self._analyze_converter_backup
        ).pack(side="left")
        self.converter_run=ttk.Button(
            actions,text="Converter para MBOX",command=self._run_converter
        )
        self.converter_run.pack(side="left",padx=(8,0))
        self.converter_stop=ttk.Button(
            actions,text="Parar após mensagem atual",
            command=self._request_converter_stop,state="disabled",
        )
        self.converter_stop.pack(side="left",padx=(8,0))

        self.c_summary=tk.StringVar(value="Nenhum backup analisado.")
        ttk.Label(f,textvariable=self.c_summary).pack(anchor="w",pady=(12,4))

        preview_box=ttk.LabelFrame(
            f,text="Pré-visualização da estrutura do pacote MBOX",padding=8
        )
        preview_box.pack(fill="both",expand=True,pady=(6,8))
        self.c_preview=self._make_structure_tree(preview_box,"converter")

        self.c_progress=tk.DoubleVar(value=0)
        ttk.Progressbar(f,variable=self.c_progress,maximum=100).pack(fill="x")
        self.c_progress_text=tk.StringVar(value="Aguardando.")
        ttk.Label(f,textvariable=self.c_progress_text).pack(anchor="w",pady=(4,0))

        ttk.Label(
            f,
            text=(
                "Observação: o pacote é MBOX, mas a reconstrução idêntica das subpastas "
                "usa o manifest.json e restauração IMAP CREATE + APPEND. "
                "O importador SMTP legado não recria subpastas."
            ),
        ).pack(anchor="w",pady=(14,0))

    def _browse_converter_source(self):
        value=filedialog.askdirectory(
            parent=self,
            title="Selecione a pasta da conta dentro do backup",
        )
        if value:
            self.c_source.delete(0,"end")
            self.c_source.insert(0,value)

    def _save_converter_options(self):
        c=self.cfg.setdefault("converter",{})
        c.update({
            "source_path":self.c_source.get().strip(),
            "destination_dir":self.c_destination.get().strip(),
            "require_complete":self.c_require_complete.get(),
            "verify_sha256":self.c_verify_sha.get(),
        })
        self.store.save(self.cfg)

    def _analyze_converter_backup(self):
        source=self.c_source.get().strip()
        if not source:
            messagebox.showerror("Converter MBOX","Selecione a origem.",parent=self)
            return
        self._save_converter_options()
        self.c_progress_text.set("Analisando EMLs e estado incremental...")
        self.status_var.set("Analisando backup para MBOX")
        threading.Thread(
            target=self._converter_analysis_worker,
            args=(source,self.c_verify_sha.get()),
            daemon=True,
        ).start()

    def _converter_analysis_worker(self,source,verify):
        try:
            analysis=analyze_backup_for_mbox(source,verify)
            self.q.put(("converter_analysis",analysis))
        except Exception as exc:
            self.q.put(("converter_error",str(exc)))

    def _request_converter_stop(self):
        self.converter_stop_event.set()
        self.c_progress_text.set("Parada solicitada; concluindo a mensagem atual...")

    def _run_converter(self):
        source=self.c_source.get().strip()
        destination=self.c_destination.get().strip()
        if not source or not Path(source).exists():
            messagebox.showerror("Converter MBOX","Selecione um backup válido.",parent=self)
            return
        if not destination:
            messagebox.showerror("Converter MBOX","Selecione o diretório de destino.",parent=self)
            return
        self._save_converter_options()
        self.converter_stop_event.clear()
        self.converter_run.configure(state="disabled")
        self.converter_stop.configure(state="normal")
        self.c_progress.set(0)
        self.c_progress_text.set("Analisando backup...")
        self.status_var.set("Conversão MBOX em execução")
        threading.Thread(
            target=self._converter_worker,
            args=(
                source,destination,
                self.c_verify_sha.get(),
                self.c_require_complete.get(),
            ),
            daemon=True,
        ).start()

    def _converter_worker(self,source,destination,verify,require_complete):
        try:
            analysis=analyze_backup_for_mbox(source,verify)
            self.q.put(("converter_analysis",analysis))

            def progress(done,total,mailbox_name,folder_index,folder_total):
                self.q.put(("converter_progress",{
                    "percent":done/max(1,total)*100,
                    "text":(
                        f"Pasta {folder_index}/{folder_total}: {mailbox_name} | "
                        f"{done}/{total} mensagens"
                    ),
                }))

            package,manifest=build_mbox_package(
                analysis,destination,
                verify_sha256=verify,
                require_complete=require_complete,
                progress=progress,
                stop_requested=self.converter_stop_event.is_set,
            )
            self.q.put(("converter_ok",{
                "path":str(package),
                "manifest":str(package/"manifest.json"),
                "folders":manifest.get("folder_count",0),
                "messages":manifest.get("message_count",0),
                "stopped":manifest.get("stopped_by_user",False),
            }))
        except Exception as exc:
            self.q.put(("converter_error",str(exc)))
            log.exception("MBOX_CONVERSION_FAILED")
        finally:
            self.q.put(("converter_done",None))

    # ------------------------------
    # Restauração
    # ------------------------------
    def _build_restore(self):
        f=self.tab_restore
        ttk.Label(
            f,
            text="Restauração",
            font=("Segoe UI",14,"bold"),
        ).pack(anchor="w")
        ttk.Label(
            f,
            text=(
                "Restaura backups da aplicação ou Google Takeout/MBOX. "
                "O Google é somente fonte de restauração; não existe backup Gmail nesta aplicação."
            ),
        ).pack(anchor="w",pady=(4,14))

        source=ttk.LabelFrame(f,text="Origem",padding=12)
        source.pack(fill="x")

        ttk.Label(source,text="Tipo de origem").grid(row=0,column=0,sticky="w",pady=5)
        self.r_source_type=ttk.Combobox(
            source,
            values=["Backup da aplicação","Pacote MBOX convertido","Google Takeout (MBOX)"],
            state="readonly",
        )
        self.r_source_type.grid(row=0,column=1,sticky="ew",padx=(10,0),pady=5)
        self.r_source_type.bind("<<ComboboxSelected>>",self._restore_source_changed)

        self.r_source_path=ttk.Entry(source)
        self._label_widget(source,1,"Origem",self.r_source_path)
        ttk.Button(
            source,text="...",width=4,command=self._browse_restore_source
        ).grid(row=1,column=2,padx=(6,0),pady=5)
        source.columnconfigure(1,weight=1)

        dest=ttk.LabelFrame(f,text="Destino",padding=12)
        dest.pack(fill="x",pady=(10,0))

        self.r_profile=ttk.Combobox(dest,state="readonly")
        self._label_widget(dest,0,"Perfil de destino",self.r_profile)
        self.r_profile.bind("<<ComboboxSelected>>",self._restore_profile_changed)

        self.r_account=ttk.Combobox(dest,state="readonly")
        self._label_widget(dest,1,"Conta de destino",self.r_account)
        ttk.Button(
            dest,text="Adicionar conta...",command=self._restore_add_account
        ).grid(row=1,column=2,padx=(6,0),pady=5)

        options=ttk.LabelFrame(f,text="Opções",padding=12)
        options.pack(fill="x",pady=(10,0))

        self.r_dry=tk.BooleanVar()
        self.r_create=tk.BooleanVar()
        self.r_flags=tk.BooleanVar()
        self.r_internal=tk.BooleanVar()
        self.r_dedupe=tk.BooleanVar()

        for i,(label,var) in enumerate([
            ("Dry-run (não grava no servidor)",self.r_dry),
            ("Criar/reconstruir pastas ausentes",self.r_create),
            ("Preservar FLAGS quando disponíveis",self.r_flags),
            ("Preservar INTERNALDATE quando disponível",self.r_internal),
            ("Retomada/idempotência por pasta + Message-ID + SHA-256",self.r_dedupe),
        ]):
            ttk.Checkbutton(options,text=label,variable=var).grid(
                row=i,column=0,columnspan=2,sticky="w",pady=3
            )

        actions=ttk.Frame(f)
        actions.pack(fill="x",pady=(12,0))
        ttk.Button(
            actions,text="Salvar configurações",command=self._save_restore_options
        ).pack(side="left")
        ttk.Button(
            actions,text="Analisar restauração",command=self._analyze_restore
        ).pack(side="left",padx=(8,0))
        self.restore_run=ttk.Button(
            actions,text="Executar restauração",command=self._run_restore
        )
        self.restore_run.pack(side="left",padx=(8,0))
        self.restore_stop=ttk.Button(
            actions,text="Parar após mensagem atual",
            command=self._request_restore_stop,state="disabled"
        )
        self.restore_stop.pack(side="left",padx=(8,0))

        self.r_summary=tk.StringVar(value="Nenhuma restauração analisada.")
        ttk.Label(f,textvariable=self.r_summary).pack(anchor="w",pady=(12,4))
        r_preview_box=ttk.LabelFrame(
            f,text="Pré-visualização da estrutura no destino",padding=8
        )
        r_preview_box.pack(fill="both",expand=True,pady=(6,8))
        self.r_preview=self._make_structure_tree(r_preview_box,"restore")

        self.r_progress_var=tk.DoubleVar(value=0)
        ttk.Progressbar(
            f,variable=self.r_progress_var,maximum=100
        ).pack(fill="x",pady=(8,4))
        self.r_progress_text=tk.StringVar(value="Aguardando restauração.")
        ttk.Label(f,textvariable=self.r_progress_text).pack(anchor="w")

    def _restore_source_changed(self,event=None):
        self._clear_tree(self.r_preview)
        kind=self.r_source_type.get()
        if kind=="Google Takeout (MBOX)":
            self.r_progress_text.set(
                "Selecione um arquivo .mbox do Google Takeout."
            )
        elif kind=="Pacote MBOX convertido":
            self.r_progress_text.set(
                "Selecione o manifest.json gerado pela aba Converter para MBOX."
            )
        else:
            self.r_progress_text.set(
                "Selecione a pasta da conta criada pelo backup desta aplicação "
                "ou um manifest.json legado."
            )

    def _browse_restore_source(self):
        if self.r_source_type.get()=="Google Takeout (MBOX)":
            value=filedialog.askopenfilename(
                parent=self,
                title="Selecione o MBOX do Google Takeout",
                filetypes=[("MBOX","*.mbox"),("Todos os arquivos","*.*")],
            )
        elif self.r_source_type.get()=="Pacote MBOX convertido":
            value=filedialog.askopenfilename(
                parent=self,
                title="Selecione o manifest.json do pacote MBOX",
                filetypes=[("Manifesto JSON","manifest.json"),("JSON","*.json")],
            )
        else:
            value=filedialog.askdirectory(
                parent=self,
                title="Selecione a pasta do backup da conta",
            )
            if not value:
                value=filedialog.askopenfilename(
                    parent=self,
                    title="Ou selecione um manifest.json legado",
                    filetypes=[("JSON","*.json"),("Todos os arquivos","*.*")],
                )
        if value:
            self.r_source_path.delete(0,"end")
            self.r_source_path.insert(0,value)

    def _restore_profile_changed(self,event=None):
        idx=self.r_profile.current()
        profiles=self.cfg.get("profiles",[])
        emails=[]
        if 0<=idx<len(profiles):
            emails=[
                a.get("email","")
                for a in profiles[idx].get("accounts",[])
                if isinstance(a,dict) and a.get("email")
            ]
        self.r_account["values"]=emails
        if emails and self.r_account.get() not in emails:
            self.r_account.set(emails[0])
        elif not emails:
            self.r_account.set("")

    def _restore_add_account(self):
        idx=self.r_profile.current()
        profiles=self.cfg.get("profiles",[])
        if idx<0 or idx>=len(profiles):
            messagebox.showinfo("Restauração","Selecione primeiro o perfil.",parent=self)
            return
        dlg=AccountDialog(self)
        self.wait_window(dlg)
        if dlg.result:
            profiles[idx].setdefault("accounts",[]).append(dlg.result)
            self.store.save(self.cfg)
            self._reload_profiles()
            self.r_profile.current(idx)
            self._restore_profile_changed()
            self.r_account.set(dlg.result["email"])

    def _save_restore_options(self):
        r=self.cfg.setdefault("restore",{})
        r.update({
            "source_type":self.r_source_type.get() or "Backup da aplicação",
            "source_path":self.r_source_path.get().strip(),
            "profile_name":self.r_profile.get(),
            "account":self.r_account.get(),
            "dry_run":self.r_dry.get(),
            "create_missing_folders":self.r_create.get(),
            "preserve_flags":self.r_flags.get(),
            "preserve_internaldate":self.r_internal.get(),
            "dedupe_message_id_sha256":self.r_dedupe.get(),
        })
        self.store.save(self.cfg)
        self.status_var.set("Configurações de restauração salvas")

    def _request_restore_stop(self):
        self.restore_stop_event.set()
        self.r_progress_text.set("Parada solicitada; concluindo a mensagem atual...")
        self._append_diag("RESTORE_STOP_REQUESTED")

    def _restore_profile_and_account(self):
        idx=self.r_profile.current()
        profiles=self.cfg.get("profiles",[])
        if idx<0 or idx>=len(profiles):
            return None,None
        profile=profiles[idx]
        email_addr=self.r_account.get().strip()
        account=None
        for a in profile.get("accounts",[]):
            if isinstance(a,dict) and a.get("email","").casefold()==email_addr.casefold():
                account=a
                break
        return profile,account

    def _resolve_restore_password(self,profile,account):
        token=account.get("password_enc","")
        if token:
            return dpapi_decrypt(token)
        token=profile.get("password_enc","")
        if token:
            return dpapi_decrypt(token)
        return simpledialog.askstring(
            "Senha",
            f"Digite a senha para {account.get('email','')}:",
            show="*",
            parent=self,
        )

    def _ensure_restore_folder(self,c,target,delimiter,existing,create_missing,dry_run):
        if target.upper()=="INBOX":
            existing.add("INBOX")
            return
        if target in existing:
            return
        if not create_missing:
            raise RuntimeError(f"Pasta de destino ausente: {target}")

        parts=target.split(delimiter) if delimiter else [target]
        for i in range(1,len(parts)+1):
            current=delimiter.join(parts[:i]) if delimiter else parts[i-1]
            if current.upper()=="INBOX" or current in existing:
                existing.add(current)
                continue
            if not dry_run:
                c.create_folder(current)
            existing.add(current)
            self.q.put(("diag",f"RESTORE_FOLDER_CREATED | {current}"))

    def _restore_source_items(self,source_type,source_path):
        if source_type=="Google Takeout (MBOX)":
            return None
        p=Path(source_path)
        if source_type=="Pacote MBOX convertido":
            return scan_legacy_manifest(p)
        if p.is_file() and p.suffix.lower()==".json":
            return scan_legacy_manifest(p)
        return scan_application_backup(p)

    def _validate_restore_profile(self,profile):
        if (
            profile.get("protocol")!="IMAP"
            or profile.get("security")!="SSL/TLS"
            or profile.get("auth_method")!="AUTH LOGIN"
        ):
            raise RuntimeError(
                "A restauração funcional usa o conector validado: "
                "IMAP + SSL/TLS + AUTH LOGIN."
            )

    def _start_restore_analysis(self,channel,source_type,source_path,
                                profile,account,password,create_missing):
        threading.Thread(
            target=self._restore_analysis_worker,
            args=(
                channel,source_type,source_path,
                profile.copy(),account.copy(),password,create_missing,
            ),
            daemon=True,
        ).start()

    def _restore_analysis_worker(self,channel,source_type,source_path,
                                 profile,account,password,create_missing):
        c=None
        try:
            c=RawIMAPLoginClient(
                profile.get("host"),profile.get("port"),profile.get("timeout",12)
            )
            c.connect()
            c.authenticate(account.get("auth_user") or account.get("email"),password)
            existing_list,_=c.list_folders()
            delimiter=getattr(c,"default_folder_delimiter",None) or "."
            plan=analyze_restore_plan(
                source_type,source_path,delimiter,existing_list,create_missing
            )
            plan["destination_account"]=account.get("email")
            plan["destination_profile"]=profile.get("name")
            self.q.put((f"{channel}_analysis",plan))
        except Exception as exc:
            self.q.put((f"{channel}_analysis_error",str(exc)))
        finally:
            password=None
            if c:
                c.close()

    def _analyze_restore(self):
        source_type=self.r_source_type.get() or "Backup da aplicação"
        source_path=self.r_source_path.get().strip()
        if not source_path or not Path(source_path).exists():
            messagebox.showerror(
                "Restauração","Selecione uma origem válida.",parent=self
            )
            return
        profile,account=self._restore_profile_and_account()
        if not profile or not account:
            messagebox.showerror(
                "Restauração","Selecione perfil e conta de destino.",parent=self
            )
            return
        try:
            self._validate_restore_profile(profile)
            password=self._resolve_restore_password(profile,account)
        except Exception as exc:
            messagebox.showerror("Restauração",str(exc),parent=self)
            return
        if password is None:
            return
        self.r_progress_text.set("Analisando estrutura de restauração...")
        self.status_var.set("Analisando restauração")
        self._start_restore_analysis(
            "restore",source_type,source_path,profile,account,password,
            self.r_create.get(),
        )

    def _run_restore(self):
        source_type=self.r_source_type.get() or "Backup da aplicação"
        source_path=self.r_source_path.get().strip()
        if not source_path or not Path(source_path).exists():
            messagebox.showerror("Restauração","Selecione uma origem válida.",parent=self)
            return
        profile,account=self._restore_profile_and_account()
        if not profile or not account:
            messagebox.showerror("Restauração","Selecione perfil e conta de destino.",parent=self)
            return
        try:
            self._validate_restore_profile(profile)
            password=self._resolve_restore_password(profile,account)
        except Exception as exc:
            messagebox.showerror("Restauração",str(exc),parent=self)
            return
        if password is None:
            return

        self._save_restore_options()
        options={
            "dry_run":self.r_dry.get(),
            "create_missing":self.r_create.get(),
            "flags":self.r_flags.get(),
            "internaldate":self.r_internal.get(),
            "dedupe":self.r_dedupe.get(),
        }
        self.restore_stop_event.clear()
        self.restore_run.configure(state="disabled")
        self.restore_stop.configure(state="normal")
        self.r_progress_var.set(0)
        self.r_progress_text.set("Preparando restauração...")
        self.status_var.set("Restauração em execução")
        threading.Thread(
            target=self._restore_worker,
            args=(source_type,source_path,profile.copy(),account.copy(),password,options,"restore",self.restore_stop_event),
            daemon=True,
        ).start()

    def _restore_worker(
        self,source_type,source_path,profile,account,password,options,
        event_prefix="restore",stop_event=None,
    ):
        c=None
        stop_event=stop_event or self.restore_stop_event
        emit=lambda suffix,value: self.q.put((f"{event_prefix}_{suffix}",value))
        state_root=Path(source_path).parent if Path(source_path).is_file() else Path(source_path)
        state_path=state_root/(
            ".restore_state_"+self._safe_path_component(account.get("email","destino"))+".json"
        )
        report_path=state_root/(
            "restore_report_"+datetime.now().strftime("%Y%m%d_%H%M%S")+".json"
        )
        state=restore_state_load(state_path)
        processed=state.setdefault("processed",{})
        report={
            "format":"email-backup-manager-restore-report",
            "version":2,
            "source_type":source_type,
            "source_path":source_path,
            "destination_account":account.get("email"),
            "started_at_utc":datetime.now(timezone.utc).isoformat(),
            "dry_run":bool(options["dry_run"]),
            "restored":0,"skipped":0,"failed":0,
            "folders":{},
        }
        try:
            c=RawIMAPLoginClient(
                profile.get("host"),profile.get("port"),profile.get("timeout",12)
            )
            c.connect()
            c.authenticate(account.get("auth_user") or account.get("email"),password)
            existing_list,_=c.list_folders()
            existing=set(existing_list)
            delimiter=getattr(c,"default_folder_delimiter",None) or "."

            done=0
            total_hint=1

            if source_type=="Google Takeout (MBOX)":
                mb=mailbox.mbox(source_path,create=False)
                total_hint=max(1,len(mb))
                try:
                    for src_index,msg in enumerate(mb,1):
                        if stop_event.is_set():
                            break
                        raw=msg.as_bytes(policy=policy.SMTP)
                        labels=[]
                        for value in msg.get_all("X-Gmail-Labels",[]):
                            labels.extend(parse_gmail_labels(value))
                        if not labels:
                            labels=["All Mail"]

                        seen=set()
                        logical_folders=[]
                        for label in labels:
                            logical=takeout_label_to_logical_folder(label)
                            if logical and logical not in seen:
                                seen.add(logical)
                                logical_folders.append(logical)

                        for logical in logical_folders:
                            target=takeout_folder_to_target(logical,delimiter,existing)
                            self._ensure_restore_folder(
                                c,target,delimiter,existing,
                                options["create_missing"],options["dry_run"]
                            )
                            key=restore_message_key(target,raw)
                            fr=report["folders"].setdefault(
                                target,{"restored":0,"skipped":0,"failed":0}
                            )
                            if options["dedupe"] and key in processed:
                                report["skipped"]+=1; fr["skipped"]+=1
                                continue
                            try:
                                dt=header_internaldate(raw) if options["internaldate"] else None
                                if not options["dry_run"]:
                                    c.append_message(target,raw,None,dt)
                                    processed[key]={
                                        "folder":target,
                                        "sha256":hashlib.sha256(raw).hexdigest(),
                                        "source_index":src_index,
                                        "restored_at_utc":datetime.now(timezone.utc).isoformat(),
                                    }
                                    restore_state_save(state_path,state)
                                report["restored"]+=1; fr["restored"]+=1
                            except Exception as exc:
                                report["failed"]+=1; fr["failed"]+=1
                                self.q.put(("diag",f"RESTORE_ITEM_FAILED | folder={target} | {exc}"))
                        done=src_index
                        if done%10==0 or done==total_hint:
                            emit("progress",{
                                "percent":(done/total_hint)*100,
                                "text":f"Takeout: {done}/{total_hint} mensagens-fonte",
                            })
                finally:
                    mb.close()
            else:
                items=self._restore_source_items(source_type,source_path)
                total_hint=max(1,len(items))
                for idx,item in enumerate(items,1):
                    if stop_event.is_set():
                        break
                    if item.get("kind")=="raw":
                        raw=item["raw"]
                    else:
                        raw=Path(item["path"]).read_bytes()

                    target=normalize_source_mailbox(
                        item.get("source_folder") or "INBOX",
                        item.get("source_delimiter"),
                        delimiter,
                    )
                    self._ensure_restore_folder(
                        c,target,delimiter,existing,
                        options["create_missing"],options["dry_run"]
                    )
                    key=restore_message_key(target,raw)
                    fr=report["folders"].setdefault(
                        target,{"restored":0,"skipped":0,"failed":0}
                    )
                    if options["dedupe"] and key in processed:
                        report["skipped"]+=1; fr["skipped"]+=1
                    else:
                        try:
                            flags=item.get("flags") if options["flags"] else None
                            dt=item.get("internaldate") if options["internaldate"] else None
                            if not dt and options["internaldate"]:
                                dt=header_internaldate(raw)
                            if not options["dry_run"]:
                                c.append_message(target,raw,flags,dt)
                                processed[key]={
                                    "folder":target,
                                    "sha256":hashlib.sha256(raw).hexdigest(),
                                    "restored_at_utc":datetime.now(timezone.utc).isoformat(),
                                }
                                restore_state_save(state_path,state)
                            report["restored"]+=1; fr["restored"]+=1
                        except Exception as exc:
                            report["failed"]+=1; fr["failed"]+=1
                            self.q.put(("diag",f"RESTORE_ITEM_FAILED | folder={target} | {exc}"))
                    done=idx
                    if done%10==0 or done==total_hint:
                        emit("progress",{
                            "percent":(done/total_hint)*100,
                            "text":f"Restauração: {done}/{total_hint}",
                        })

            stopped=stop_event.is_set()
            report["stopped_by_user"]=stopped
            report["finished_at_utc"]=datetime.now(timezone.utc).isoformat()
            restore_state_save(report_path,report)
            emit("ok",{
                "report":str(report_path),
                "state":str(state_path),
                "restored":report["restored"],
                "skipped":report["skipped"],
                "failed":report["failed"],
                "stopped":stopped,
                "dry_run":bool(options["dry_run"]),
            })
        except Exception as exc:
            emit("error",str(exc))
            log.exception("RESTORE_FAILED")
        finally:
            password=None
            if c:
                c.close()
            emit("done",None)

    # ------------------------------
    # MBOX -> hMailServer
    # ------------------------------
    def _build_mbox(self):
        f=self.tab_mbox
        ttk.Label(
            f,text="MBOX → hMailServer",
            font=("Segoe UI",14,"bold"),
        ).pack(anchor="w")
        ttk.Label(
            f,
            text=(
                "Restauração estruturada por IMAP. Usa a mesma lógica da aba Restauração "
                "para recriar pastas e preservar metadados."
            ),
        ).pack(anchor="w",pady=(4,14))

        source=ttk.LabelFrame(f,text="Origem MBOX",padding=12)
        source.pack(fill="x")
        ttk.Label(source,text="Tipo de origem").grid(
            row=0,column=0,sticky="w",pady=5
        )
        self.m_source_type=ttk.Combobox(
            source,
            values=["Pacote MBOX convertido","Google Takeout (MBOX)"],
            state="readonly",
        )
        self.m_source_type.grid(
            row=0,column=1,sticky="ew",padx=(10,0),pady=5
        )
        self.m_source_type.bind(
            "<<ComboboxSelected>>",self._mbox_source_changed
        )

        self.m_source_path=ttk.Entry(source)
        self._label_widget(source,1,"Origem",self.m_source_path)
        ttk.Button(
            source,text="...",width=4,command=self._browse_mbox_restore_source
        ).grid(row=1,column=2,padx=(6,0),pady=5)
        source.columnconfigure(1,weight=1)

        dest=ttk.LabelFrame(f,text="Destino hMailServer",padding=12)
        dest.pack(fill="x",pady=(10,0))
        self.m_profile=ttk.Combobox(dest,state="readonly")
        self._label_widget(dest,0,"Perfil de destino",self.m_profile)
        self.m_profile.bind(
            "<<ComboboxSelected>>",self._mbox_profile_changed
        )

        self.m_account=ttk.Combobox(dest,state="readonly")
        self._label_widget(dest,1,"Conta de destino",self.m_account)
        ttk.Button(
            dest,text="Adicionar conta...",command=self._mbox_add_account
        ).grid(row=1,column=2,padx=(6,0),pady=5)

        options=ttk.LabelFrame(f,text="Opções de restauração",padding=12)
        options.pack(fill="x",pady=(10,0))
        self.m_dry=tk.BooleanVar()
        self.m_create=tk.BooleanVar()
        self.m_flags=tk.BooleanVar()
        self.m_internal=tk.BooleanVar()
        self.m_dedupe=tk.BooleanVar()
        for i,(label,var) in enumerate([
            ("Dry-run (não grava no servidor)",self.m_dry),
            ("Criar/reconstruir pastas ausentes",self.m_create),
            ("Preservar FLAGS quando disponíveis",self.m_flags),
            ("Preservar INTERNALDATE quando disponível",self.m_internal),
            ("Retomada/idempotência por pasta + Message-ID + SHA-256",self.m_dedupe),
        ]):
            ttk.Checkbutton(
                options,text=label,variable=var
            ).grid(row=i,column=0,columnspan=2,sticky="w",pady=3)

        actions=ttk.Frame(f)
        actions.pack(fill="x",pady=(12,0))
        ttk.Button(
            actions,text="Salvar configurações",command=self._save_mbox_restore_options
        ).pack(side="left")
        ttk.Button(
            actions,text="Analisar restauração",command=self._analyze_mbox_restore
        ).pack(side="left",padx=(8,0))
        self.m_restore_run=ttk.Button(
            actions,text="Executar restauração",command=self._run_mbox_restore
        )
        self.m_restore_run.pack(side="left",padx=(8,0))
        self.m_restore_stop=ttk.Button(
            actions,text="Parar após mensagem atual",
            command=self._request_mbox_restore_stop,state="disabled",
        )
        self.m_restore_stop.pack(side="left",padx=(8,0))

        self.m_summary=tk.StringVar(value="Nenhuma restauração analisada.")
        ttk.Label(f,textvariable=self.m_summary).pack(anchor="w",pady=(12,4))
        m_preview_box=ttk.LabelFrame(
            f,text="Pré-visualização da estrutura no hMailServer",padding=8
        )
        m_preview_box.pack(fill="both",expand=True,pady=(6,8))
        self.m_preview=self._make_structure_tree(m_preview_box,"restore")

        self.m_progress_var=tk.DoubleVar(value=0)
        ttk.Progressbar(
            f,variable=self.m_progress_var,maximum=100
        ).pack(fill="x",pady=(8,4))
        self.m_progress_text=tk.StringVar(value="Aguardando restauração.")
        ttk.Label(f,textvariable=self.m_progress_text).pack(anchor="w")

    def _mbox_source_changed(self,event=None):
        self._clear_tree(self.m_preview)
        if self.m_source_type.get()=="Google Takeout (MBOX)":
            self.m_progress_text.set("Selecione o arquivo .mbox do Google Takeout.")
        else:
            self.m_progress_text.set(
                "Selecione o manifest.json criado pela aba Converter para MBOX."
            )

    def _browse_mbox_restore_source(self):
        if self.m_source_type.get()=="Google Takeout (MBOX)":
            value=filedialog.askopenfilename(
                parent=self,
                title="Selecione o MBOX do Google Takeout",
                filetypes=[("MBOX","*.mbox"),("Todos os arquivos","*.*")],
            )
        else:
            value=filedialog.askopenfilename(
                parent=self,
                title="Selecione o manifest.json do pacote MBOX",
                filetypes=[("Manifesto JSON","manifest.json"),("JSON","*.json")],
            )
        if value:
            self.m_source_path.delete(0,"end")
            self.m_source_path.insert(0,value)

    def _mbox_profile_and_account(self):
        idx=self.m_profile.current()
        profiles=self.cfg.get("profiles",[])
        if idx<0 or idx>=len(profiles):
            return None,None
        profile=profiles[idx]
        email_addr=self.m_account.get().strip()
        account=None
        for a in profile.get("accounts",[]):
            if (
                isinstance(a,dict)
                and a.get("email","").casefold()==email_addr.casefold()
            ):
                account=a
                break
        return profile,account

    def _mbox_profile_changed(self,event=None):
        idx=self.m_profile.current()
        profiles=self.cfg.get("profiles",[])
        emails=[]
        if 0<=idx<len(profiles):
            emails=[
                a.get("email","")
                for a in profiles[idx].get("accounts",[])
                if isinstance(a,dict) and a.get("email")
            ]
        self.m_account["values"]=emails
        if emails and self.m_account.get() not in emails:
            self.m_account.set(emails[0])
        elif not emails:
            self.m_account.set("")

    def _mbox_add_account(self):
        idx=self.m_profile.current()
        profiles=self.cfg.get("profiles",[])
        if idx<0 or idx>=len(profiles):
            messagebox.showinfo(
                "MBOX → hMailServer","Selecione primeiro o perfil.",parent=self
            )
            return
        dlg=AccountDialog(self)
        self.wait_window(dlg)
        if dlg.result:
            profiles[idx].setdefault("accounts",[]).append(dlg.result)
            self.store.save(self.cfg)
            self._reload_profiles()
            self.m_profile.current(idx)
            self._mbox_profile_changed()
            self.m_account.set(dlg.result["email"])

    def _save_mbox_restore_options(self):
        m=self.cfg.setdefault("mbox_restore",{})
        m.update({
            "source_type":self.m_source_type.get() or "Pacote MBOX convertido",
            "source_path":self.m_source_path.get().strip(),
            "profile_name":self.m_profile.get(),
            "account":self.m_account.get(),
            "dry_run":self.m_dry.get(),
            "create_missing_folders":self.m_create.get(),
            "preserve_flags":self.m_flags.get(),
            "preserve_internaldate":self.m_internal.get(),
            "dedupe_message_id_sha256":self.m_dedupe.get(),
        })
        self.store.save(self.cfg)
        self.status_var.set("Configurações MBOX → hMailServer salvas")

    def _request_mbox_restore_stop(self):
        self.hmail_stop_event.set()
        self.m_progress_text.set(
            "Parada solicitada; concluindo a mensagem atual..."
        )

    def _analyze_mbox_restore(self):
        source_type=self.m_source_type.get() or "Pacote MBOX convertido"
        source_path=self.m_source_path.get().strip()
        if not source_path or not Path(source_path).exists():
            messagebox.showerror(
                "MBOX → hMailServer","Selecione uma origem válida.",parent=self
            )
            return
        profile,account=self._mbox_profile_and_account()
        if not profile or not account:
            messagebox.showerror(
                "MBOX → hMailServer",
                "Selecione perfil e conta de destino.",
                parent=self,
            )
            return
        try:
            self._validate_restore_profile(profile)
            password=self._resolve_restore_password(profile,account)
        except Exception as exc:
            messagebox.showerror("MBOX → hMailServer",str(exc),parent=self)
            return
        if password is None:
            return
        self.m_progress_text.set("Analisando estrutura no hMailServer...")
        self.status_var.set("Analisando restauração MBOX")
        self._start_restore_analysis(
            "hmail",source_type,source_path,profile,account,password,
            self.m_create.get(),
        )

    def _run_mbox_restore(self):
        source_type=self.m_source_type.get() or "Pacote MBOX convertido"
        source_path=self.m_source_path.get().strip()
        if not source_path or not Path(source_path).exists():
            messagebox.showerror(
                "MBOX → hMailServer","Selecione uma origem válida.",parent=self
            )
            return
        profile,account=self._mbox_profile_and_account()
        if not profile or not account:
            messagebox.showerror(
                "MBOX → hMailServer",
                "Selecione perfil e conta de destino.",
                parent=self,
            )
            return
        try:
            self._validate_restore_profile(profile)
            password=self._resolve_restore_password(profile,account)
        except Exception as exc:
            messagebox.showerror("MBOX → hMailServer",str(exc),parent=self)
            return
        if password is None:
            return

        self._save_mbox_restore_options()
        options={
            "dry_run":self.m_dry.get(),
            "create_missing":self.m_create.get(),
            "flags":self.m_flags.get(),
            "internaldate":self.m_internal.get(),
            "dedupe":self.m_dedupe.get(),
        }
        self.hmail_stop_event.clear()
        self.m_restore_run.configure(state="disabled")
        self.m_restore_stop.configure(state="normal")
        self.m_progress_var.set(0)
        self.m_progress_text.set("Preparando restauração...")
        self.status_var.set("Restauração MBOX → hMailServer em execução")
        threading.Thread(
            target=self._restore_worker,
            args=(
                source_type,source_path,profile.copy(),account.copy(),password,
                options,"hmail",self.hmail_stop_event,
            ),
            daemon=True,
        ).start()

    # ------------------------------
    # Configurações gerais
    # ------------------------------
    def _build_general(self):
        f = self.tab_general
        ttk.Label(
            f,
            text="Configurações gerais",
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor="w")

        box = ttk.LabelFrame(
            f,
            text="Armazenamento e diagnóstico",
            padding=12,
        )
        box.pack(
            fill="x",
            pady=(14,0),
        )

        self.general_backup_dir = self._grid_field(
            box,
            0,
            "Diretório base dos backups",
        )
        ttk.Button(
            box,
            text="...",
            width=4,
            command=lambda: self._browse_into(
                self.general_backup_dir,
                file_mode=False,
            ),
        ).grid(
            row=0,
            column=2,
            padx=(6,0),
        )

        self.general_timeout = self._grid_field(
            box,
            1,
            "Timeout padrão (s)",
        )

        self.general_hash = tk.BooleanVar()
        ttk.Checkbutton(
            box,
            text="Verificar SHA-256 após gravação",
            variable=self.general_hash,
        ).grid(
            row=2,
            column=0,
            columnspan=2,
            sticky="w",
            pady=5,
        )

        box.columnconfigure(1, weight=1)

        ttk.Button(
            f,
            text="Salvar configurações gerais",
            command=self._save_general_options,
        ).pack(
            anchor="w",
            pady=(12,0),
        )

        ttk.Label(
            f,
            text=f"Arquivo de configuração: {CONFIG_FILE}",
        ).pack(
            anchor="w",
            pady=(18,0),
        )
        ttk.Label(
            f,
            text=f"Log: {LOG_FILE}",
        ).pack(
            anchor="w",
            pady=(4,0),
        )

    def _save_general_options(self):
        try:
            timeout = int(
                self.general_timeout.get() or "12"
            )
        except ValueError:
            messagebox.showerror(
                "Configurações",
                "Timeout deve ser numérico.",
                parent=self,
            )
            return

        g = self.cfg.setdefault(
            "general", {}
        )
        g.update({
            "backup_dir": self.general_backup_dir.get().strip(),
            "connection_timeout": timeout,
            "verify_sha256": self.general_hash.get(),
        })
        self.store.save(self.cfg)
        self.status_var.set(
            "Configurações gerais salvas"
        )

    # ------------------------------
    # Logs
    # ------------------------------
    def _build_logs(self):
        f = self.tab_logs
        toolbar = ttk.Frame(f)
        toolbar.pack(fill="x")

        ttk.Button(
            toolbar,
            text="Atualizar log",
            command=self._refresh_log,
        ).pack(side="left")
        ttk.Button(
            toolbar,
            text="Limpar diagnóstico da tela",
            command=self._clear_diag,
        ).pack(
            side="left",
            padx=(6,0),
        )
        ttk.Button(
            toolbar,
            text="Abrir pasta de logs",
            command=self._open_log_dir,
        ).pack(
            side="left",
            padx=(6,0),
        )

        self.diag = tk.Text(
            f,
            wrap="word",
            height=25,
        )
        self.diag.pack(
            fill="both",
            expand=True,
            pady=(10,0),
        )

    def _append_diag(self, text):
        self.diag.insert(
            "end",
            text + "\n",
        )
        self.diag.see("end")

    def _clear_diag(self):
        self.diag.delete(
            "1.0",
            "end",
        )

    def _refresh_log(self):
        self._clear_diag()
        if LOG_FILE.exists():
            try:
                content = LOG_FILE.read_text(
                    encoding="utf-8",
                    errors="replace",
                )
                self.diag.insert(
                    "end",
                    content[-60000:],
                )
                self.diag.see("end")
            except Exception as exc:
                self._append_diag(
                    "Erro ao ler log: "
                    + str(exc)
                )

    def _open_log_dir(self):
        try:
            os.startfile(str(LOG_DIR))
        except Exception as exc:
            messagebox.showerror(
                "Logs",
                str(exc),
                parent=self,
            )

    # ------------------------------
    # Helpers
    # ------------------------------
    def _label_widget(
        self,
        parent,
        row,
        label,
        widget,
    ):
        ttk.Label(
            parent,
            text=label,
        ).grid(
            row=row,
            column=0,
            sticky="w",
            pady=5,
        )
        widget.grid(
            row=row,
            column=1,
            sticky="ew",
            padx=(10,0),
            pady=5,
        )
        parent.columnconfigure(
            1,
            weight=1,
        )

    def _browse_into(
        self,
        entry,
        file_mode=False,
    ):
        if file_mode:
            value = filedialog.askopenfilename(
                parent=self
            )
        else:
            value = filedialog.askdirectory(
                parent=self
            )
        if value:
            entry.delete(0, "end")
            entry.insert(0, value)

    def _refresh_profile_comboboxes(self):
        names = [
            p.get("name","Servidor")
            for p in self.cfg.get(
                "profiles", []
            )
        ]
        for cb in [
            getattr(self, "b_profile", None),
            getattr(self, "r_profile", None),
            getattr(self, "m_profile", None),
        ]:
            if cb is not None:
                cb["values"] = names
                if names and not cb.get():
                    cb.set(names[0])

        if getattr(self, "b_profile", None) is not None:
            self._backup_profile_changed()
        if getattr(self, "r_profile", None) is not None:
            self._restore_profile_changed()
        if getattr(self, "m_profile", None) is not None:
            self._mbox_profile_changed()

    def _load_option_values(self):
        b = self.cfg.get(
            "backup", {}
        )
        self.b_incremental.set(
            b.get("incremental", True)
        )
        self.b_raw.set(
            b.get("raw_eml", True)
        )
        self.b_manifest.set(
            b.get("manifest", True)
        )
        self.b_flags.set(
            b.get("preserve_flags", True)
        )
        self.b_internaldate.set(
            b.get(
                "preserve_internaldate",
                True,
            )
        )
        self.b_hash.set(
            b.get("verify_sha256", True)
        )
        self.b_dedupe.set(
            b.get(
                "dedupe_message_id_sha256",
                True,
            )
        )
        self.b_limit.delete(0, "end")
        self.b_limit.insert(
            0,
            str(b.get("test_limit",0)),
        )
        self.b_destination.delete(0,"end")
        self.b_destination.insert(
            0,
            b.get("destination")
            or self.cfg.get("general",{}).get("backup_dir",""),
        )
        saved_profile=b.get("profile_name","")
        if saved_profile and saved_profile in list(self.b_profile["values"]):
            self.b_profile.set(saved_profile)
        self._backup_profile_changed()
        saved_account=b.get("account","")
        if saved_account and saved_account in list(self.b_account["values"]):
            self.b_account.set(saved_account)
        self.b_scope.set(b.get("scope","single") or "single")
        self.b_folder.set(b.get("folder","INBOX") or "INBOX")
        self._backup_scope_changed()

        conv=self.cfg.get("converter",{})
        self.c_source.delete(0,"end")
        self.c_source.insert(0,conv.get("source_path",""))
        self.c_destination.delete(0,"end")
        self.c_destination.insert(
            0,
            conv.get("destination_dir")
            or self.cfg.get("general",{}).get("backup_dir",""),
        )
        self.c_require_complete.set(conv.get("require_complete",True))
        self.c_verify_sha.set(conv.get("verify_sha256",True))

        r = self.cfg.get("restore", {})
        self.r_source_type.set(r.get("source_type","Backup da aplicação"))
        self.r_source_path.delete(0,"end")
        self.r_source_path.insert(0,r.get("source_path",""))
        self.r_dry.set(r.get("dry_run",True))
        self.r_create.set(r.get("create_missing_folders",True))
        self.r_flags.set(r.get("preserve_flags",True))
        self.r_internal.set(r.get("preserve_internaldate",True))
        self.r_dedupe.set(r.get("dedupe_message_id_sha256",True))
        saved_r_profile=r.get("profile_name","")
        if saved_r_profile and saved_r_profile in list(self.r_profile["values"]):
            self.r_profile.set(saved_r_profile)
        self._restore_profile_changed()
        saved_r_account=r.get("account","")
        if saved_r_account and saved_r_account in list(self.r_account["values"]):
            self.r_account.set(saved_r_account)

        mr=self.cfg.get("mbox_restore",{})
        self.m_source_type.set(
            mr.get("source_type","Pacote MBOX convertido")
        )
        self.m_source_path.delete(0,"end")
        self.m_source_path.insert(0,mr.get("source_path",""))
        self.m_dry.set(mr.get("dry_run",True))
        self.m_create.set(mr.get("create_missing_folders",True))
        self.m_flags.set(mr.get("preserve_flags",True))
        self.m_internal.set(mr.get("preserve_internaldate",True))
        self.m_dedupe.set(mr.get("dedupe_message_id_sha256",True))
        saved_m_profile=mr.get("profile_name","")
        if saved_m_profile and saved_m_profile in list(self.m_profile["values"]):
            self.m_profile.set(saved_m_profile)
        self._mbox_profile_changed()
        saved_m_account=mr.get("account","")
        if saved_m_account and saved_m_account in list(self.m_account["values"]):
            self.m_account.set(saved_m_account)

        gen = self.cfg.get(
            "general", {}
        )
        self.general_backup_dir.delete(
            0,
            "end",
        )
        self.general_backup_dir.insert(
            0,
            gen.get(
                "backup_dir",
                str(
                    Path.home()
                    / "EmailBackups"
                ),
            ),
        )
        self.general_timeout.delete(
            0,
            "end",
        )
        self.general_timeout.insert(
            0,
            str(
                gen.get(
                    "connection_timeout",
                    12,
                )
            ),
        )
        self.general_hash.set(
            gen.get(
                "verify_sha256",
                True,
            )
        )

    def _poll_queue(self):
        try:
            while True:
                kind, value = (
                    self.q.get_nowait()
                )
                if kind == "diag":
                    self._append_diag(value)
                elif kind == "connection_ok":
                    self.status_var.set(
                        "Conexão validada"
                    )
                    messagebox.showinfo(
                        "Conexão",
                        (
                            "Conexão e autenticação "
                            "concluídas com sucesso."
                        ),
                        parent=self,
                    )
                elif kind == "connection_error":
                    self.status_var.set(
                        "Falha na conexão"
                    )
                    messagebox.showerror(
                        "Conexão",
                        value,
                        parent=self,
                    )
                elif kind == "backup_folders":
                    if value.get("key") != getattr(self,"_backup_folder_load_key",None):
                        continue
                    folders=value.get("folders",[])
                    self.b_folder["values"]=folders
                    if folders:
                        current=self.b_folder.get().strip()
                        if current not in folders:
                            self.b_folder.set(
                                "INBOX" if "INBOX" in folders else folders[0]
                            )
                    self.b_progress_text.set(
                        f"Pastas carregadas automaticamente: {len(folders)}"
                    )
                    self.status_var.set("Pastas IMAP carregadas")
                    self._append_diag(
                        f"BACKUP_FOLDER_LIST_OK | selectable={len(folders)} | "
                        f"total={len(value.get('all_folders',folders))} | "
                        f"result={value.get('final','')}"
                    )
                elif kind == "backup_progress":
                    self.b_progress_var.set(value.get("percent",0))
                    self.b_progress_text.set(value.get("text",""))
                elif kind == "backup_ok":
                    stopped=bool(value.get("stopped"))
                    self.status_var.set(
                        "Backup interrompido com segurança"
                        if stopped else "Backup concluído"
                    )
                    self._append_diag(
                        f"BACKUP_OK | messages={value.get('messages')} | "
                        f"stopped={stopped} | path={value.get('path')} | "
                        f"uidvalidity={value.get('uidvalidity')}"
                    )
                    messagebox.showinfo(
                        "Backup",
                        (
                            "Backup interrompido com segurança.\n\n"
                            if stopped
                            else "Backup concluído com sucesso.\n\n"
                        )
                        + f"Pastas processadas: {value.get('folders_done',1)}/{value.get('folders_total',1)}\n"
                        + f"Pastas com falha: {len(value.get('folders_failed',[]))}\n"
                        + f"Baixadas nesta execução: {value.get('messages')}\n"
                        + f"Já preservadas e puladas: {value.get('skipped',0)}\n"
                        + f"Ainda pendentes: {value.get('pending',0)}\n"
                        + f"Destino: {value.get('path')}",
                        parent=self,
                    )
                elif kind == "backup_error":
                    self.status_var.set("Falha no backup")
                    self.b_progress_text.set("Falha: "+str(value))
                    self._append_diag("BACKUP_FAILED | "+str(value))
                    messagebox.showerror(
                        "Backup",
                        str(value),
                        parent=self,
                    )
                elif kind == "converter_analysis":
                    self._converter_last_analysis=value
                    complete=bool(value.get("complete"))
                    self.c_summary.set(
                        f"Conta: {value.get('account')} | "
                        f"pastas: {value.get('folder_count')} | "
                        f"mensagens válidas: {value.get('message_count')} | "
                        f"pendentes: {value.get('pending_count')} | "
                        f"inválidas: {value.get('invalid_count')} | "
                        f"completo: {'SIM' if complete else 'NÃO'}"
                    )
                    self._populate_converter_preview(value)
                    self.c_progress_text.set("Análise concluída.")
                    self.status_var.set("Backup analisado para MBOX")
                elif kind == "converter_progress":
                    self.c_progress.set(value.get("percent",0))
                    self.c_progress_text.set(value.get("text",""))
                elif kind == "converter_ok":
                    stopped=bool(value.get("stopped"))
                    self.status_var.set(
                        "Conversão MBOX interrompida" if stopped else "Conversão MBOX concluída"
                    )
                    self.c_progress_text.set(
                        f"Pacote: {value.get('folders')} pastas | {value.get('messages')} mensagens"
                    )
                    messagebox.showinfo(
                        "Converter para MBOX",
                        (
                            "Conversão interrompida. Um manifesto parcial foi criado.\n\n"
                            if stopped
                            else "Pacote MBOX criado com sucesso.\n\n"
                        )
                        + f"Pastas: {value.get('folders')}\n"
                        + f"Mensagens: {value.get('messages')}\n"
                        + f"Pacote: {value.get('path')}\n"
                        + f"Manifesto: {value.get('manifest')}",
                        parent=self,
                    )
                elif kind == "converter_error":
                    self.status_var.set("Falha na conversão MBOX")
                    self.c_progress_text.set("Falha: "+str(value))
                    messagebox.showerror("Converter para MBOX",str(value),parent=self)
                elif kind == "converter_done":
                    self.converter_run.configure(state="normal")
                    self.converter_stop.configure(state="disabled")
                    self.converter_stop_event.clear()
                elif kind == "restore_analysis":
                    self._restore_last_plan=value
                    self.r_summary.set(
                        f"Pastas finais: {value.get('folder_count')} | "
                        f"mensagens-fonte: {value.get('source_messages')} | "
                        f"operações APPEND previstas: {value.get('append_operations')}"
                    )
                    self._populate_restore_preview(
                        self.r_preview,value,value.get("destination_account")
                    )
                    self.r_progress_text.set("Análise concluída.")
                    self.status_var.set("Restauração analisada")
                elif kind == "restore_analysis_error":
                    self.r_progress_text.set("Falha na análise: "+str(value))
                    messagebox.showerror("Restauração",str(value),parent=self)
                elif kind == "hmail_analysis":
                    self._hmail_last_plan=value
                    self.m_summary.set(
                        f"Pastas finais: {value.get('folder_count')} | "
                        f"mensagens-fonte: {value.get('source_messages')} | "
                        f"operações APPEND previstas: {value.get('append_operations')}"
                    )
                    self._populate_restore_preview(
                        self.m_preview,value,value.get("destination_account")
                    )
                    self.m_progress_text.set("Análise concluída.")
                    self.status_var.set("Restauração MBOX analisada")
                elif kind == "hmail_analysis_error":
                    self.m_progress_text.set("Falha na análise: "+str(value))
                    messagebox.showerror("MBOX → hMailServer",str(value),parent=self)
                elif kind == "hmail_progress":
                    self.m_progress_var.set(value.get("percent",0))
                    self.m_progress_text.set(value.get("text",""))
                elif kind == "hmail_ok":
                    stopped=bool(value.get("stopped"))
                    dry=bool(value.get("dry_run"))
                    self.status_var.set(
                        "Dry-run MBOX concluído" if dry
                        else ("Restauração MBOX interrompida" if stopped
                              else "Restauração MBOX concluída")
                    )
                    self.m_progress_text.set(
                        f"Restauradas/validadas: {value.get('restored')} | "
                        f"puladas: {value.get('skipped')} | falhas: {value.get('failed')}"
                    )
                    messagebox.showinfo(
                        "MBOX → hMailServer",
                        (
                            "Dry-run concluído.\n\n" if dry
                            else ("Restauração interrompida com segurança.\n\n"
                                  if stopped else "Restauração concluída.\n\n")
                        )
                        + f"Processadas: {value.get('restored')}\n"
                        + f"Puladas: {value.get('skipped')}\n"
                        + f"Falhas: {value.get('failed')}\n"
                        + f"Relatório: {value.get('report')}",
                        parent=self,
                    )
                elif kind == "hmail_error":
                    self.status_var.set("Falha MBOX → hMailServer")
                    self.m_progress_text.set("Falha: "+str(value))
                    messagebox.showerror("MBOX → hMailServer",str(value),parent=self)
                elif kind == "hmail_done":
                    self.m_restore_run.configure(state="normal")
                    self.m_restore_stop.configure(state="disabled")
                    self.hmail_stop_event.clear()
                elif kind == "restore_progress":
                    self.r_progress_var.set(value.get("percent",0))
                    self.r_progress_text.set(value.get("text",""))
                elif kind == "restore_ok":
                    stopped=bool(value.get("stopped"))
                    dry=bool(value.get("dry_run"))
                    self.status_var.set(
                        "Dry-run concluído" if dry
                        else ("Restauração interrompida" if stopped else "Restauração concluída")
                    )
                    self.r_progress_text.set(
                        f"Restauradas/validadas: {value.get('restored')} | "
                        f"puladas: {value.get('skipped')} | falhas: {value.get('failed')}"
                    )
                    messagebox.showinfo(
                        "Restauração",
                        (
                            "Dry-run concluído.\n\n" if dry
                            else ("Restauração interrompida com segurança.\n\n" if stopped
                                  else "Restauração concluída.\n\n")
                        )
                        + f"Processadas: {value.get('restored')}\n"
                        + f"Puladas: {value.get('skipped')}\n"
                        + f"Falhas: {value.get('failed')}\n"
                        + f"Relatório: {value.get('report')}",
                        parent=self,
                    )
                elif kind == "restore_error":
                    self.status_var.set("Falha na restauração")
                    self.r_progress_text.set("Falha: "+str(value))
                    messagebox.showerror("Restauração",str(value),parent=self)
                elif kind == "restore_done":
                    self.restore_run.configure(state="normal")
                    self.restore_stop.configure(state="disabled")
                    self.restore_stop_event.clear()
                elif kind == "backup_done":
                    self.backup_run.configure(state="normal")
                    self.backup_stop.configure(state="disabled")
                    self.backup_stop_event.clear()
                elif kind == "backup_idle":
                    pass
        except queue.Empty:
            pass
        self.after(
            100,
            self._poll_queue,
        )

    def run(self):
        self._load_option_values()
        self._refresh_profile_comboboxes()
        self.mainloop()


if __name__ == "__main__":
    App().run()
