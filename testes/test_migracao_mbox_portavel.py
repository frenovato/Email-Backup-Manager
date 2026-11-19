"""Testes locais offline sem hMailServer e sem trafego SMTP real."""
import email
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import importlib.util
from pathlib import Path
import tempfile
import mailbox
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "integracoes" / "hmailserver" / "migracao_mbox_portavel.py"
spec = importlib.util.spec_from_file_location("migracao_mbox_portavel", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestMigracao(unittest.TestCase):
    def test_multipart_malformado(self):
        msg = email.message.Message()
        msg["Content-Type"] = 'multipart/mixed'
        msg.set_payload("Texto com acentuações legíveis")
        novo, corrigidos = mod.corrigir_multipart_malformado(msg)
        self.assertEqual(corrigidos, 1)
        self.assertEqual(novo.get_content_type(), "text/plain")
        self.assertIn(b"text/plain", mod.gerar_bytes(novo))

    def test_anexo_valido_preservado(self):
        msg = MIMEMultipart()
        msg["Subject"] = "Assunto com á"
        msg.attach(MIMEText("Texto corpo", "plain", "utf-8"))
        anexo = MIMEText("arquivo", "plain", "utf-8")
        anexo.add_header("Content-Disposition", "attachment", filename="nota.txt")
        msg.attach(anexo)
        novo, corrigidos = mod.preparar_mensagem(msg, "destino@example.invalid")
        self.assertEqual(corrigidos, 0)
        self.assertEqual(len(novo.get_payload()), 2)
        self.assertIn(b"nota.txt", mod.gerar_bytes(novo))

    def test_preflight_nao_envia_nem_processa(self):
        with tempfile.TemporaryDirectory() as temp:
            origem = Path(temp) / "amostra.mbox"
            mbox = mailbox.mbox(str(origem), create=True)
            mbox.add(email.message_from_string("From: origem@example.invalid\nTo: abc@example.invalid\nSubject: Teste\n\nOla"))
            mbox.close()
            args = mod.parser_cli().parse_args(["--mbox", str(origem), "--logs", str(Path(temp) / "estado")])
            self.assertEqual(mod.executar(args), 0)
            self.assertFalse((Path(temp) / "estado" / "processados.txt").exists())

    def test_smtp_falha_nao_reenvia_automaticamente(self):
        class SmtpIncerto:
            chamadas = 0
            def has_extn(self, extensao):
                return extensao == "SMTPUTF8"
            def sendmail(self, *args, **kwargs):
                self.chamadas += 1
                raise mod.smtplib.SMTPServerDisconnected("falha apos comando")
        servidor = SmtpIncerto()
        msg = MIMEText("Teste", "plain", "utf-8")
        with self.assertRaises(mod.smtplib.SMTPServerDisconnected):
            mod.enviar_mensagem(servidor, msg, "destino@example.invalid")
        self.assertEqual(servidor.chamadas, 1)

    def test_checkpoint_bloqueia_mbox_trocado(self):
        with tempfile.TemporaryDirectory() as temp:
            origem = Path(temp) / "msg.mbox"
            origem.write_bytes(b"mensagem original")
            estado = Path(temp) / "estado"
            estado.mkdir()
            mod.validar_checkpoint(estado, mod.hash_arquivo(origem), origem)
            origem.write_bytes(b"conteudo diferente")
            with self.assertRaises(RuntimeError):
                mod.validar_checkpoint(estado, mod.hash_arquivo(origem), origem)


if __name__ == "__main__":
    unittest.main()
