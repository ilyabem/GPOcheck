"""
gpo_sysvol.py — чтение файлов GPO из SYSVOL.

  - FsSysvol  : локальный каталог (офлайн-копия) или UNC-путь Windows от имени текущего пользователя
  - SmbSysvol : SMB через impacket, одно соединение на весь прогон
"""

from __future__ import annotations

import io
import os
import re

from gpo_decoders import decode_text, parse_inf, inf_get

MAX_FILE_SIZE = 10 * 1024 * 1024

# Стандартные GPO: в их GPT.INI обычно нет displayName
WELL_KNOWN_GPOS = {
    "{31B2F340-016D-11D2-945F-00C04FB984F9}": "Default Domain Policy",
    "{6AC1786C-016F-11D2-945F-00C04FB984F9}": "Default Domain Controllers Policy",
}


def split_username(username: str, domain: str):
    """'DOM\\user' / 'user@dom.local' / 'user' -> (user, domain)."""
    if "\\" in username:
        dom, user = username.split("\\", 1)
        return user, dom
    if "@" in username:
        user, dom = username.rsplit("@", 1)
        return user, dom
    return username, domain


class FsSysvol:
    """Чтение файлов GPO из локального каталога Policies или по UNC-пути через DC."""

    def __init__(self, root: str | None = None, dc: str | None = None):
        self.root = root
        self.dc = dc

    def gpo_dir(self, gpo: dict):
        if self.root:
            guid = gpo["guid"].upper()
            try:
                for name in os.listdir(self.root):
                    if name.upper() == guid:
                        return os.path.join(self.root, name)
            except OSError:
                return None
            return None
        # \\domain\SysVol\domain\Policies\{GUID} -> \\dc\SysVol\domain\Policies\{GUID}
        # (DFS-имя домена может не разрешаться, а имя DC — разрешается всегда)
        parts = gpo["path"].lstrip("\\").split("\\", 1)
        return f"\\\\{self.dc}\\{parts[1]}" if len(parts) == 2 and self.dc else gpo["path"]

    def read_gpo(self, gpo: dict):
        files, errors = {}, []
        base = self.gpo_dir(gpo)
        if not base or not os.path.isdir(base):
            return files, [f"каталог GPO недоступен: {base or gpo['guid']}"]
        for dirpath, _, names in os.walk(base, onerror=lambda e: errors.append(str(e))):
            for n in names:
                full = os.path.join(dirpath, n)
                rel = os.path.relpath(full, base)
                try:
                    if os.path.getsize(full) > MAX_FILE_SIZE:
                        errors.append(f"{rel}: файл больше {MAX_FILE_SIZE // 1048576} МБ, пропущен")
                        continue
                    with open(full, "rb") as fh:
                        files[rel] = fh.read()
                except OSError as e:
                    errors.append(f"{rel}: {e}")
        return files, errors

    def close(self):
        pass


class SmbSysvol:
    """Чтение SYSVOL по SMB (impacket)."""

    def __init__(self, args):
        self.args = args
        self.smb = None

    def _connect(self):
        from impacket.smbconnection import SMBConnection
        a = self.args
        smb = SMBConnection(a.dc, a.dc, sess_port=a.smb_port, timeout=a.timeout)
        if a.kerberos:
            smb.kerberosLogin("", "", a.domain, kdcHost=a.dc, useCache=True)
        else:
            user, dom = split_username(a.username, a.domain)
            smb.login(user, a.password, dom)
        self.smb = smb

    def read_gpo(self, gpo: dict):
        if self.smb is None:
            self._connect()   # ошибка входа пробрасывается вызывающему — это не «пустая GPO»
        files, errors = {}, []
        parts = gpo["path"].lstrip("\\").split("\\")
        if len(parts) < 3:
            return files, [f"некорректный gPCFileSysPath: {gpo['path']}"]
        share, folder = parts[1], "\\".join(parts[2:])

        def walk(path):
            try:
                listing = self.smb.listPath(share, path + "\\*")
            except Exception as e:
                errors.append(f"{path}: {e}")
                return
            for f in listing:
                name = f.get_longname()
                if name in (".", ".."):
                    continue
                full = path + "\\" + name
                rel = full[len(folder):].lstrip("\\")
                if f.is_directory():
                    walk(full)
                elif f.get_filesize() > MAX_FILE_SIZE:
                    errors.append(f"{rel}: файл больше {MAX_FILE_SIZE // 1048576} МБ, пропущен")
                else:
                    buf = io.BytesIO()
                    try:
                        self.smb.getFile(share, full, buf.write)
                        files[rel] = buf.getvalue()
                    except Exception as e:
                        errors.append(f"{rel}: {e}")

        walk(folder)
        return files, errors

    def close(self):
        if self.smb is not None:
            try:
                self.smb.logoff()
            except Exception:
                pass


def offline_gpos(root: str) -> list:
    """GPO из локальной копии каталога Policies; имя и версия берутся из GPT.INI."""
    gpos = []
    for name in sorted(os.listdir(root)):
        full = os.path.join(root, name)
        if not (os.path.isdir(full) and re.fullmatch(r"\{[0-9A-Fa-f-]{36}\}", name)):
            continue
        display, version = WELL_KNOWN_GPOS.get(name.upper(), name), 0
        ini = next((os.path.join(full, n) for n in os.listdir(full) if n.lower() == "gpt.ini"), None)
        if ini:
            with open(ini, "rb") as fh:
                sec = parse_inf(decode_text(fh.read()))
            display = inf_get(sec, "General", "displayName") or display
            try:
                version = int(inf_get(sec, "General", "Version") or 0)
            except ValueError:
                pass
        gpos.append({"name": display, "guid": name.upper(), "path": full, "version": version,
                     "flags": 0, "created": None, "changed": None, "sd": None})
    return gpos
