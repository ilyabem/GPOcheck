import contextlib
import io
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from argparse import Namespace

from helpers import ROOT, pol, pol_entry, dword, utf16, write_tree, make_sd, sid_bytes

import gpo_analyzer_cli as cli
import gpo_ldap
from gpo_sysvol import SmbSysvol, FsSysvol, offline_gpos

DDP = "{31B2F340-016D-11D2-945F-00C04FB984F9}"
OTHER = "{11111111-2222-3333-4444-555555555555}"
DOM = "S-1-5-21-1-2-3"
BASE = "DC=AD2012,DC=LAB"

GPTTMPL_DDP = utf16("[Unicode]\r\nUnicode=yes\r\n[System Access]\r\nMinimumPasswordLength = 7\r\n"
                    "PasswordComplexity = 1\r\nLockoutBadCount = 0\r\nMaximumPasswordAge = 42\r\n"
                    "[Version]\r\nsignature=\"$CHICAGO$\"\r\n")
GPTTMPL_OTHER = utf16("[System Access]\r\nMinimumPasswordLength = 14\r\nLockoutBadCount = 5\r\n")
GROUPS_XML = (b'<?xml version="1.0" encoding="utf-8"?><Groups><User name="local_adm">'
              b'<Properties action="U" cpassword="AAAA" userName="local_adm"/></User></Groups>')


def sysvol_tree(root):
    write_tree(root, {
        f"{DDP}/GPT.INI": b"[General]\r\nVersion=3\r\n",
        f"{DDP}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": GPTTMPL_DDP,
        f"{OTHER}/GPT.INI": "[General]\r\nVersion=7\r\ndisplayName=Политика серверов\r\n".encode("cp1251"),
        f"{OTHER}/Machine/Registry.pol": pol(
            pol_entry(r"System\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", 4, dword(1)),
            pol_entry(r"System\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1", 4, dword(0))),
        f"{OTHER}/Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf": GPTTMPL_OTHER,
        f"{OTHER}/Machine/Preferences/Groups/Groups.xml": GROUPS_XML,
        "not-a-gpo/readme.txt": b"skip me",
    })


def run_main(argv):
    out, errs = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(errs):
        code = cli.main(argv)
    return code, out.getvalue(), errs.getvalue()


class OfflineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        sysvol_tree(self.tmp.name)
        self.json = os.path.join(self.tmp.name, "report.json")

    def tearDown(self):
        self.tmp.cleanup()

    def test_offline_gpos(self):
        gpos = {g["guid"]: g for g in offline_gpos(self.tmp.name)}
        self.assertEqual(set(gpos), {DDP, OTHER})
        self.assertEqual(gpos[DDP]["name"], "Default Domain Policy")
        self.assertEqual(gpos[OTHER]["name"], "Политика серверов")
        self.assertEqual(gpos[OTHER]["version"], 7)

    def test_end_to_end(self):
        code, out, _ = run_main(["--offline", self.tmp.name, "--no-prompt", "--no-color", "--json", self.json,
                                 "--fail-on", "HIGH", "--show-files"])
        self.assertEqual(code, 2)
        self.assertIn("Найдено GPO: 2", out.replace("найдено", "Найдено"))
        self.assertIn("Слабая минимальная длина пароля (7 < 12)", out)
        self.assertIn("WDigest хранит пароли в памяти LSASS", out)
        self.assertNotIn("SMBv1", out)                                         # SMB1=0 — не уязвимость
        self.assertIn("UseLogonCredential", out)                               # --show-files вывел Registry.pol
        self.assertNotIn("\x1b[", out)                                         # --no-color
        with open(self.json, encoding="utf-8") as fh:
            report = json.load(fh)
        sev = sorted(f["severity"] for f in report["findings"])
        self.assertEqual(sev, ["CRITICAL", "HIGH", "HIGH", "HIGH"])           # cpassword, WDigest, длина, блокировка
        # пароли из GPO, не связанной с корнем, в офлайн-режиме не проверяются порогами
        self.assertFalse(any(f["gpo"] == "Политика серверов" and "пароля" in f["title"] for f in report["findings"]))

    def test_fail_on_not_triggered(self):
        code, _, _ = run_main(["--offline", self.tmp.name, "--no-prompt", "--fail-on", "CRITICAL", "--gpo", "default"])
        self.assertEqual(code, 0)

    def test_min_severity_hides(self):
        _, out, _ = run_main(["--offline", self.tmp.name, "--no-prompt", "--min-severity", "critical"])
        self.assertIn("cpassword", out)
        self.assertNotIn("WDigest", out)
        self.assertIn("Не показано замечаний ниже уровня CRITICAL: 3", out)


class LdapModeTest(unittest.TestCase):
    """Режим LDAP целиком (run) на mock-AD из ldap3 и локальной копии SYSVOL."""

    def setUp(self):
        from test_ldap_users import mock_conn, add_user, add_group
        self.tmp = tempfile.TemporaryDirectory()
        sysvol_tree(self.tmp.name)
        conn = self.conn = mock_conn()
        link = lambda guid, opt: f"[LDAP://cn={guid},cn=policies,cn=system,{BASE};{opt}]"
        conn.strategy.add_entry(BASE, {
            "objectClass": ["top", "domain"], "minPwdLength": 8, "pwdProperties": 1, "lockoutThreshold": 0,
            "maxPwdAge": -36288000000000, "objectSid": sid_bytes(DOM), "ms-DS-MachineAccountQuota": 0,
            "gPLink": link(DDP, 0) + link(OTHER, 1)}, validate=False)
        for guid, name, version, sd in (
                (DDP, "Default Domain Policy", 3, make_sd(f"{DOM}-512", [(f"{DOM}-512", 0xF01FF, 0, None)])),
                (OTHER, "Server Policy", 9, make_sd(f"{DOM}-512", [(f"{DOM}-1200", 0x40000, 0, None)]))):
            conn.strategy.add_entry(f"CN={guid},CN=Policies,CN=System,{BASE}", {
                "objectClass": ["top", "groupPolicyContainer"], "cn": guid, "displayName": name,
                "versionNumber": version, "flags": 0, "nTSecurityDescriptor": sd,
                "gPCFileSysPath": f"\\\\ad2012.lab\\SysVol\\ad2012.lab\\Policies\\{guid}"}, validate=False)
        add_group(conn, "Domain Users", 513)
        add_user(conn, "helpdesk", 1200, servicePrincipalName=["HTTP/x"])
        self._orig = gpo_ldap.connect_ad
        gpo_ldap.connect_ad = lambda args, on_fallback=None: self.conn

    def tearDown(self):
        gpo_ldap.connect_ad = self._orig
        self.tmp.cleanup()

    def test_run(self):
        js = os.path.join(self.tmp.name, "r.json")
        code, out, err = run_main(["-d", "ad2012.lab", "-dc", "dc.ad2012.lab", "-u", "x", "-p", "y", "--no-prompt",
                                   "--sysvol-path", self.tmp.name, "--users", "--min-severity", "INFO", "--json", js])
        self.assertEqual(code, 0, err)
        with open(js, encoding="utf-8") as fh:
            report = json.load(fh)
        titles = {(f["severity"], f["title"], f["gpo"]) for f in report["findings"]}
        expected = {
            ("HIGH", "Слабая минимальная длина пароля (8 < 12)", "Политика домена (действующая)"),
            ("HIGH", "Блокировка учётных записей отключена", "Политика домена (действующая)"),
            ("MEDIUM", "Делегированы права на изменение GPO", "Server Policy"),
            ("LOW", "Версия GPO в AD и SYSVOL не совпадает", "Server Policy"),
            ("INFO", "Все связи GPO отключены", "Server Policy"),
            ("INFO", "Параметры паролей в GPO не действуют для доменных учётных записей", "Server Policy"),
            ("CRITICAL", "Пароль в Group Policy Preferences (cpassword, MS14-025)", "Server Policy"),
            ("HIGH", "WDigest хранит пароли в памяти LSASS", "Server Policy"),
            ("MEDIUM", "Kerberoasting: учётные записи с SPN (1)", ""),
        }
        self.assertTrue(expected <= titles, expected - titles)
        # GptTmpl.inf Default Domain Policy не дублирует проверки действующей политики домена
        self.assertFalse(any(f["gpo"] == "Default Domain Policy" and "пароля" in f["title"] for f in report["findings"]))
        acl = next(f for f in report["findings"] if f["title"] == "Делегированы права на изменение GPO")
        self.assertEqual(acl["evidence"], f"helpdesk ({DOM}-1200): WriteDacl")
        self.assertEqual(report["users"]["total"], 1)
        self.assertIn("связь с корнем домена ОТКЛЮЧЕНА", out)


class ArgsTest(unittest.TestCase):
    def parse_error(self, argv):
        with contextlib.redirect_stderr(io.StringIO()) as e, self.assertRaises(SystemExit) as cm:
            cli.parse_args(argv)
        self.assertEqual(cm.exception.code, 2)
        return e.getvalue()

    def test_errors(self):
        self.assertIn("укажите домен", self.parse_error([]))
        self.assertIn("либо -u", self.parse_error(["-d", "x.local", "-u", "a", "-p", "b", "-k"]))
        self.assertIn("не найден", self.parse_error(["--offline", "Z:\\definitely\\missing"]))
        with tempfile.TemporaryDirectory() as d:
            self.assertIn("несовместим", self.parse_error(["--offline", d, "--users"]))
        self.parse_error(["-d", "x.local", "--min-severity", "bogus"])

    def test_defaults(self):
        a = cli.parse_args(["-d", "x.local", "-u", "a", "-p", "b", "--min-severity", "info"])
        self.assertEqual((a.dc, a.min_severity, a.kerberos), ("x.local", "INFO", False))
        if os.name == "nt":
            self.assertTrue(cli.parse_args(["-d", "x.local"]).kerberos)

    def test_help_on_legacy_console_encoding(self):
        env = dict(os.environ, PYTHONIOENCODING="cp1252")
        r = subprocess.run([sys.executable, os.path.join(ROOT, "gpo_analyzer_cli.py"), "--help"],
                           capture_output=True, env=env, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr.decode(errors="replace"))
        self.assertIn("Подключение", r.stdout.decode("utf-8"))

    def test_noninteractive_does_not_prompt(self):
        with tempfile.TemporaryDirectory() as d:
            sysvol_tree(d)
            r = subprocess.run([sys.executable, os.path.join(ROOT, "gpo_analyzer_cli.py"), "--offline", d],
                               capture_output=True, stdin=subprocess.DEVNULL, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr.decode(errors="replace"))
        self.assertNotIn("Настройка порогов", r.stdout.decode("utf-8"))


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class SmbTest(unittest.TestCase):
    """SmbSysvol против локального SMB-сервера impacket (127.0.0.1, тестовая учётная запись)."""

    @classmethod
    def setUpClass(cls):
        from impacket import smbserver
        from Crypto.Hash import MD4

        cls.tmp = tempfile.TemporaryDirectory()
        root = os.path.join(cls.tmp.name, "ad2012.lab", "Policies")
        sysvol_tree(root)
        # SMB-сервер impacket на Windows читает файлы в текстовом режиме (\r\n -> \n), что искажает
        # сравнение байт; клиентская сторона тут ни при чём — уберём CR из тестовых файлов
        for dirpath, _, names in os.walk(root):
            for n in names:
                p = os.path.join(dirpath, n)
                with open(p, "rb") as fh:
                    data = fh.read().replace(b"\r", b"")
                with open(p, "wb") as fh:
                    fh.write(data)
        cls.user, cls.password = "gpotest", secrets.token_urlsafe(16)
        nthash = MD4.new(cls.password.encode("utf-16-le")).hexdigest()
        cls.port = _free_port()
        cls.server = smbserver.SimpleSMBServer(listenAddress="127.0.0.1", listenPort=cls.port)
        cls.server.addShare("SYSVOL", cls.tmp.name, readOnly="yes")
        cls.server.addCredential(cls.user, 0, "aad3b435b51404eeaad3b435b51404ee", nthash)
        cls.server.setSMB2Support(True)
        cls.server.getServer().daemon_threads = True    # иначе процесс ждёт открытые соединения при выходе
        cls.thread = threading.Thread(target=cls.server.start, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        # server.stop() на Windows зависает в select(); поток-демон завершится вместе с процессом
        cls.tmp.cleanup()

    def args(self, password):
        return Namespace(dc="127.0.0.1", smb_port=self.port, timeout=10, kerberos=False,
                         username=f"AD2012\\{self.user}", password=password, domain="ad2012.lab")

    def gpo(self, guid):
        return {"guid": guid, "path": f"\\\\ad2012.lab\\SysVol\\ad2012.lab\\Policies\\{guid}"}

    def test_read_matches_filesystem(self):
        reader = SmbSysvol(self.args(self.password))
        try:
            smb_files, smb_errors = reader.read_gpo(self.gpo(OTHER))
            again, _ = reader.read_gpo(self.gpo(DDP))                 # то же соединение
        finally:
            reader.close()
        fs_files, _ = FsSysvol(root=os.path.join(self.tmp.name, "ad2012.lab", "Policies")).read_gpo(self.gpo(OTHER))
        self.assertEqual(smb_errors, [])
        self.assertEqual({k.replace("/", "\\"): v for k, v in fs_files.items()}, smb_files)
        self.assertIn(r"Machine\Preferences\Groups\Groups.xml", smb_files)
        self.assertIn(r"MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf", again)

    def test_wrong_password_raises(self):
        reader = SmbSysvol(self.args("wrong-" + self.password))
        with self.assertRaises(Exception):
            reader.read_gpo(self.gpo(OTHER))

    def test_missing_gpo_folder_is_reported(self):
        reader = SmbSysvol(self.args(self.password))
        try:
            files, errors = reader.read_gpo(self.gpo("{00000000-0000-0000-0000-000000000000}"))
        finally:
            reader.close()
        self.assertEqual(files, {})
        self.assertTrue(errors)


if __name__ == "__main__":
    unittest.main()
