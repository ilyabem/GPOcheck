"""
gpo_checks.py — проверки безопасности содержимого GPO.

Все функции чистые (без сети): на вход — разобранные файлы, на выход — список Finding.
Проверки реестра учитывают ЗНАЧЕНИЕ параметра, а не просто упоминание имени,
и одинаково применяются к Registry.pol, секции [Registry Values] файла GptTmpl.inf
и к Registry.xml из Group Policy Preferences.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict

from gpo_decoders import (
    decode_text, parse_inf, inf_get, inf_int, read_registry_pol, reg_type_from_name,
)

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Finding:
    severity: str
    title: str
    description: str
    gpo: str = ""
    path: str = ""
    evidence: str = ""
    category: str = "GPO"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RegSetting:
    """Нормализованная настройка реестра из любого источника GPO."""
    key: str          # путь без куста, например System\CurrentControlSet\Control\Lsa
    name: str         # имя значения
    value: object     # int | str | list | bytes | None
    hive: str = ""    # MACHINE / USER
    source: str = ""  # Registry.pol / GptTmpl.inf / Registry.xml


# ─────────────────────────────────────────────────────────────────────────────
# Хорошо известные SID
# ─────────────────────────────────────────────────────────────────────────────

WELL_KNOWN_SIDS = {
    "S-1-0-0": "Nobody", "S-1-1-0": "Everyone", "S-1-3-0": "Creator Owner",
    "S-1-5-2": "Network", "S-1-5-4": "Interactive", "S-1-5-6": "Service",
    "S-1-5-7": "Anonymous Logon", "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Self", "S-1-5-11": "Authenticated Users", "S-1-5-18": "SYSTEM",
    "S-1-5-19": "Local Service", "S-1-5-20": "Network Service",
    "S-1-5-32-544": "BUILTIN\\Administrators", "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-546": "BUILTIN\\Guests", "S-1-5-32-547": "BUILTIN\\Power Users",
    "S-1-5-32-548": "BUILTIN\\Account Operators", "S-1-5-32-549": "BUILTIN\\Server Operators",
    "S-1-5-32-550": "BUILTIN\\Print Operators", "S-1-5-32-551": "BUILTIN\\Backup Operators",
    "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
    "S-1-5-32-555": "BUILTIN\\Remote Desktop Users", "S-1-5-32-559": "BUILTIN\\Performance Log Users",
    "S-1-5-32-562": "BUILTIN\\Distributed COM Users", "S-1-5-32-580": "BUILTIN\\Remote Management Users",
    "S-1-5-90-0": "Window Manager Group",
}
DOMAIN_RIDS = {
    498: "Enterprise Read-only Domain Controllers", 500: "Administrator", 501: "Guest",
    502: "krbtgt", 512: "Domain Admins", 513: "Domain Users", 514: "Domain Guests",
    515: "Domain Computers", 516: "Domain Controllers", 517: "Cert Publishers",
    518: "Schema Admins", 519: "Enterprise Admins", 520: "Group Policy Creator Owners",
    521: "Read-only Domain Controllers", 525: "Protected Users", 526: "Key Admins",
    527: "Enterprise Key Admins", 553: "RAS and IAS Servers",
}

# Широкие группы: любой пользователь домена (или вообще любой) в них состоит
BROAD_SIDS = {"S-1-1-0", "S-1-5-7", "S-1-5-11", "S-1-5-32-545", "S-1-5-32-546", "S-1-5-2", "S-1-5-4"}
BROAD_RIDS = {513, 514, 515}
BROAD_NAMES = {"everyone", "все", "authenticated users", "прошедшие проверку",
               "domain users", "пользователи домена", "users", "пользователи",
               "guests", "гости", "domain computers", "anonymous logon"}

# Привилегированные субъекты (право на изменение GPO у них штатное)
PRIVILEGED_SIDS = {"S-1-5-18", "S-1-5-32-544", "S-1-5-9", "S-1-3-0", "S-1-5-10"}
PRIVILEGED_RIDS = {500, 512, 516, 518, 519}


def sid_rid(sid: str):
    m = re.match(r"^S-1-5-21-\d+-\d+-\d+-(\d+)$", sid or "", re.IGNORECASE)
    return int(m.group(1)) if m else None


def sid_name(sid: str, resolver: dict | None = None) -> str:
    sid = sid.strip().lstrip("*")
    if resolver and sid in resolver:
        return resolver[sid]
    if sid.upper() in WELL_KNOWN_SIDS:
        return WELL_KNOWN_SIDS[sid.upper()]
    rid = sid_rid(sid)
    if rid in DOMAIN_RIDS:
        return DOMAIN_RIDS[rid]
    return sid


def is_broad_principal(p: str) -> bool:
    p = p.strip().lstrip("*")
    if p.upper() in BROAD_SIDS or sid_rid(p) in BROAD_RIDS:
        return True
    name = p.split("\\")[-1].lower()
    return name in BROAD_NAMES


def is_privileged_principal(sid: str) -> bool:
    sid = sid.strip().lstrip("*").upper()
    return sid in PRIVILEGED_SIDS or sid_rid(sid) in PRIVILEGED_RIDS


def principal_label(p: str, resolver: dict | None = None) -> str:
    p = p.strip()
    if p.startswith("*"):
        name = sid_name(p, resolver)
        return f"{name} ({p[1:]})" if name != p[1:] else p[1:]
    if p.upper().startswith("S-1-"):
        name = sid_name(p, resolver)
        return f"{name} ({p})" if name != p else p
    return p


# ─────────────────────────────────────────────────────────────────────────────
# Правила реестра
# ─────────────────────────────────────────────────────────────────────────────

def _as_int(v):
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        s = v.strip().strip('"')
        try:
            return int(s, 0) if s.lower().startswith("0x") else int(s)
        except ValueError:
            return None
    return None


def _eq(n):
    return lambda v: _as_int(v) == n


def _lt(n):
    return lambda v: (x := _as_int(v)) is not None and x < n


def _not_in(*vals):
    return lambda v: (x := _as_int(v)) is not None and x not in vals


def _nonempty(v):
    if isinstance(v, (list, bytes)):
        return len(v) > 0
    return v is not None and str(v).strip() != ""


def _str_in(*vals):
    low = {x.lower() for x in vals}
    return lambda v: isinstance(v, str) and v.strip().lower() in low


_LSA = r"System\CurrentControlSet\Control\Lsa"
_LANSRV = r"System\CurrentControlSet\Services\LanManServer\Parameters"
_LANWKS = r"System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
_NETLOGON = r"System\CurrentControlSet\Services\Netlogon\Parameters"
_TS = r"Software\Policies\Microsoft\Windows NT\Terminal Services"
_UAC = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
_DEF = r"Software\Policies\Microsoft\Windows Defender"
_FW = r"Software\Policies\Microsoft\WindowsFirewall"
_WINRM = r"Software\Policies\Microsoft\Windows\WinRM"
_PNP = r"Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"

# (ключ, имя значения | '*' для любого, условие, severity, заголовок, описание)
REGISTRY_RULES = [
    # ── Хеши и учётные данные ────────────────────────────────────────────────
    (_LSA, "NoLMHash", _eq(0), "HIGH", "Хранение LM-хешей разрешено",
     "NoLMHash=0: Windows сохраняет LM-хеши паролей, которые подбираются за минуты."),
    (_LSA, "LmCompatibilityLevel", _lt(3), "HIGH", "Разрешена аутентификация LM/NTLMv1",
     "LmCompatibilityLevel<3: клиенты отправляют LM/NTLMv1-ответы (relay и перебор). Рекомендуется 5."),
    (_LSA, "LmCompatibilityLevel", lambda v: _as_int(v) in (3, 4), "LOW", "NTLMv1 не отклоняется",
     "LmCompatibilityLevel 3–4: клиенты используют NTLMv2, но сервер ещё принимает LM/NTLMv1. Рекомендуется 5."),
    (r"System\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", _eq(1), "HIGH",
     "WDigest хранит пароли в памяти LSASS",
     "UseLogonCredential=1: пароли пользователей хранятся в LSASS в открытом виде и извлекаются дампом памяти."),
    (_LSA, "RestrictAnonymous", _eq(0), "LOW", "Анонимное перечисление не ограничено",
     "RestrictAnonymous=0: анонимные сессии получают дополнительную информацию о системе."),
    (_LSA, "RestrictAnonymousSAM", _eq(0), "MEDIUM", "Анонимное перечисление учётных записей SAM",
     "RestrictAnonymousSAM=0: анонимный пользователь может получить список учётных записей."),
    (_LSA, "EveryoneIncludesAnonymous", _eq(1), "MEDIUM", "Анонимные пользователи входят в Everyone",
     "EveryoneIncludesAnonymous=1: все права группы Everyone получает анонимный вход."),
    (_LSA, "RunAsPPL", _eq(0), "LOW", "Защита LSA (RunAsPPL) отключена",
     "RunAsPPL=0: процесс LSASS не защищён, дамп учётных данных проще."),
    (_LSA, "DisableDomainCreds", _eq(0), "LOW", "Разрешено сохранение доменных учётных данных",
     "DisableDomainCreds=0: Credential Manager хранит пароли для сетевой аутентификации."),
    (r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "DefaultPassword", _nonempty, "CRITICAL",
     "Пароль автовхода в GPO в открытом виде",
     "DefaultPassword задан политикой: файлы SYSVOL доступны на чтение любому пользователю домена."),
    (r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon", _eq(1), "HIGH",
     "Включён автоматический вход (AutoAdminLogon)",
     "AutoAdminLogon=1: учётные данные автовхода хранятся на компьютере (LSA secrets / реестр)."),
    (r"Software\Policies\Microsoft\Windows\CredentialsDelegation", "AllowDefCredentialsWhenNTLMOnly", _eq(1),
     "MEDIUM", "Делегирование учётных данных CredSSP при NTLM",
     "AllowDefCredentialsWhenNTLMOnly=1: учётные данные передаются серверу без взаимной аутентификации."),
    (r"Software\Policies\Microsoft\Windows\CredentialsDelegation", "AllowDefaultCredentials", _eq(1),
     "LOW", "Делегирование учётных данных CredSSP по умолчанию",
     "AllowDefaultCredentials=1: проверьте список серверов, получающих учётные данные пользователя."),
    # ── SMB ──────────────────────────────────────────────────────────────────
    (_LANSRV, "SMB1", _eq(1), "HIGH", "Сервер SMBv1 включён",
     "SMB1=1: устаревший протокол SMBv1 (MS17-010 / EternalBlue). Отключите SMBv1."),
    (r"System\CurrentControlSet\Services\mrxsmb10", "Start", _not_in(4), "MEDIUM", "Клиент SMBv1 включён",
     "mrxsmb10 Start≠4: драйвер клиента SMBv1 загружается."),
    (_LANSRV, "RequireSecuritySignature", _eq(0), "MEDIUM", "Подпись SMB на сервере не обязательна",
     "RequireSecuritySignature=0 (сервер): возможен NTLM relay на SMB."),
    (_LANWKS, "RequireSecuritySignature", _eq(0), "MEDIUM", "Подпись SMB на клиенте не обязательна",
     "RequireSecuritySignature=0 (клиент): возможен перехват/подмена SMB-сессий."),
    (_LANWKS, "EnablePlainTextPassword", _eq(1), "HIGH", "Отправка пароля SMB открытым текстом",
     "EnablePlainTextPassword=1: клиент отправляет пароль сторонним SMB-серверам открытым текстом."),
    (_LANSRV, "RestrictNullSessAccess", _eq(0), "MEDIUM", "Null-сессии к общим ресурсам разрешены",
     "RestrictNullSessAccess=0: анонимный доступ к именованным каналам и общим ресурсам."),
    (_LANSRV, "NullSessionShares", _nonempty, "MEDIUM", "Общие ресурсы доступны null-сессии",
     "NullSessionShares не пуст: перечисленные ресурсы доступны анонимно."),
    (_LANSRV, "NullSessionPipes", _nonempty, "LOW", "Именованные каналы доступны null-сессии",
     "NullSessionPipes не пуст: проверьте, что список каналов минимален."),
    # ── LDAP / Netlogon ──────────────────────────────────────────────────────
    (r"System\CurrentControlSet\Services\NTDS\Parameters", "LDAPServerIntegrity", _lt(2), "MEDIUM",
     "Подпись LDAP на контроллере домена не обязательна",
     "LDAPServerIntegrity<2: DC принимает неподписанные LDAP-привязки (NTLM relay на LDAP). Должно быть 2."),
    (r"System\CurrentControlSet\Services\NTDS\Parameters", "LdapEnforceChannelBinding", _eq(0), "MEDIUM",
     "Привязка канала LDAPS отключена",
     "LdapEnforceChannelBinding=0: возможен relay на LDAPS. Рекомендуется 2 (Always)."),
    (r"System\CurrentControlSet\Services\LDAP", "LDAPClientIntegrity", _eq(0), "MEDIUM",
     "Подпись LDAP на клиенте отключена",
     "LDAPClientIntegrity=0: клиенты не запрашивают подпись LDAP."),
    (_NETLOGON, "RequireSignOrSeal", _eq(0), "HIGH", "Netlogon не требует подписи/шифрования канала",
     "RequireSignOrSeal=0: безопасный канал Netlogon может работать без защиты."),
    (_NETLOGON, "SealSecureChannel", _eq(0), "MEDIUM", "Шифрование канала Netlogon отключено",
     "SealSecureChannel=0."),
    (_NETLOGON, "SignSecureChannel", _eq(0), "MEDIUM", "Подпись канала Netlogon отключена",
     "SignSecureChannel=0."),
    (_NETLOGON, "RequireStrongKey", _eq(0), "MEDIUM", "Netlogon не требует стойкого ключа",
     "RequireStrongKey=0."),
    (_NETLOGON, "FullSecureChannelProtection", _eq(0), "HIGH", "Защита от ZeroLogon ослаблена",
     "FullSecureChannelProtection=0 (CVE-2020-1472)."),
    (_NETLOGON, "VulnerableChannelAllowList", _nonempty, "HIGH", "Исключения из защиты ZeroLogon",
     "VulnerableChannelAllowList задан: перечисленным учётным записям разрешён уязвимый канал Netlogon (CVE-2020-1472)."),
    # ── Kerberos ─────────────────────────────────────────────────────────────
    (_UAC + r"\Kerberos\Parameters", "SupportedEncryptionTypes",
     lambda v: (x := _as_int(v)) is not None and x & 0x3 != 0, "MEDIUM",
     "Kerberos разрешает шифрование DES",
     "SupportedEncryptionTypes включает DES_CBC_CRC/DES_CBC_MD5."),
    (_UAC + r"\Kerberos\Parameters", "SupportedEncryptionTypes",
     lambda v: (x := _as_int(v)) is not None and x & 0x4 != 0, "LOW",
     "Kerberos разрешает шифрование RC4",
     "SupportedEncryptionTypes включает RC4_HMAC_MD5 (облегчает Kerberoasting)."),
    # ── Повышение привилегий / UAC ───────────────────────────────────────────
    (r"Software\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated", _eq(1), "CRITICAL",
     "AlwaysInstallElevated включён",
     "MSI-пакеты устанавливаются с правами SYSTEM. Эксплуатируется, если задано и в Computer, и в User Configuration."),
    (_UAC, "EnableLUA", _eq(0), "HIGH", "UAC отключён",
     "EnableLUA=0: все администраторы работают с полным токеном."),
    (_UAC, "ConsentPromptBehaviorAdmin", _eq(0), "MEDIUM", "UAC повышает права без запроса",
     "ConsentPromptBehaviorAdmin=0: повышение прав администратора происходит молча."),
    (_UAC, "LocalAccountTokenFilterPolicy", _eq(1), "MEDIUM", "Удалённый UAC отключён",
     "LocalAccountTokenFilterPolicy=1: локальные администраторы получают полный токен по сети (pass-the-hash)."),
    (_UAC, "FilterAdministratorToken", _eq(0), "LOW", "Режим одобрения администратором для Administrator выключен",
     "FilterAdministratorToken=0."),
    (_PNP, "RestrictDriverInstallationToAdministrators", _eq(0), "HIGH",
     "Установка драйверов принтеров разрешена не только администраторам",
     "RestrictDriverInstallationToAdministrators=0: уязвимость PrintNightmare (CVE-2021-34527)."),
    (_PNP, "NoWarningNoElevationOnInstall", _eq(1), "HIGH", "Point and Print без запроса повышения прав",
     "NoWarningNoElevationOnInstall=1: PrintNightmare (CVE-2021-34527)."),
    (_PNP, "UpdatePromptSettings", lambda v: _as_int(v) in (1, 2), "HIGH",
     "Point and Print обновляет драйверы без запроса",
     "UpdatePromptSettings≠0: PrintNightmare (CVE-2021-34527)."),
    # ── RDP ──────────────────────────────────────────────────────────────────
    (_TS, "UserAuthentication", _eq(0), "HIGH", "RDP без NLA (Network Level Authentication)",
     "UserAuthentication=0: сеанс создаётся до аутентификации (BlueKeep-класс атак, перебор)."),
    (_TS, "SecurityLayer", _eq(0), "MEDIUM", "RDP использует RDP Security Layer вместо TLS",
     "SecurityLayer=0: сервер не аутентифицируется, возможен MitM."),
    (_TS, "MinEncryptionLevel", _eq(1), "MEDIUM", "Низкий уровень шифрования RDP",
     "MinEncryptionLevel=1 (Low)."),
    (_TS, "fPromptForPassword", _eq(0), "LOW", "RDP не запрашивает пароль при подключении",
     "fPromptForPassword=0: допускается вход с сохранёнными в клиенте учётными данными."),
    (_TS, "fAllowUnsolicited", _eq(1), "LOW", "Удалённый помощник без запроса разрешён",
     "fAllowUnsolicited=1."),
    (_TS, "fDisableCdm", _eq(0), "LOW", "Перенаправление дисков в RDP разрешено",
     "fDisableCdm=0."),
    # ── Защитные механизмы ───────────────────────────────────────────────────
    (_DEF, "DisableAntiSpyware", _eq(1), "HIGH", "Microsoft Defender отключён политикой",
     "DisableAntiSpyware=1."),
    (_DEF + r"\Real-Time Protection", "DisableRealtimeMonitoring", _eq(1), "HIGH",
     "Защита Defender в реальном времени отключена", "DisableRealtimeMonitoring=1."),
    (_DEF + r"\Real-Time Protection", "DisableBehaviorMonitoring", _eq(1), "MEDIUM",
     "Поведенческий мониторинг Defender отключён", "DisableBehaviorMonitoring=1."),
    (_DEF + r"\Exclusions\Paths", "*", lambda v: True, "LOW", "Исключение Defender (путь)",
     "Исключённые пути не сканируются; проверьте, что туда не может писать обычный пользователь."),
    (_DEF + r"\Exclusions\Processes", "*", lambda v: True, "LOW", "Исключение Defender (процесс)",
     "Файлы, открываемые этим процессом, не сканируются."),
    (_DEF + r"\Exclusions\Extensions", "*", lambda v: True, "LOW", "Исключение Defender (расширение)",
     "Файлы с этим расширением не сканируются."),
    (_FW + r"\DomainProfile", "EnableFirewall", _eq(0), "HIGH", "Брандмауэр отключён (доменный профиль)", "EnableFirewall=0."),
    (_FW + r"\PrivateProfile", "EnableFirewall", _eq(0), "HIGH", "Брандмауэр отключён (частный профиль)", "EnableFirewall=0."),
    (_FW + r"\PublicProfile", "EnableFirewall", _eq(0), "HIGH", "Брандмауэр отключён (публичный профиль)", "EnableFirewall=0."),
    (_FW + r"\StandardProfile", "EnableFirewall", _eq(0), "HIGH", "Брандмауэр отключён (стандартный профиль)", "EnableFirewall=0."),
    # ── WinRM ────────────────────────────────────────────────────────────────
    (_WINRM + r"\Service", "AllowUnencryptedTraffic", _eq(1), "HIGH", "WinRM-сервер принимает незашифрованный трафик",
     "AllowUnencryptedTraffic=1."),
    (_WINRM + r"\Service", "AllowBasic", _eq(1), "MEDIUM", "WinRM-сервер разрешает Basic-аутентификацию", "AllowBasic=1."),
    (_WINRM + r"\Client", "AllowUnencryptedTraffic", _eq(1), "HIGH", "WinRM-клиент отправляет незашифрованный трафик",
     "AllowUnencryptedTraffic=1."),
    (_WINRM + r"\Client", "AllowBasic", _eq(1), "MEDIUM", "WinRM-клиент использует Basic-аутентификацию", "AllowBasic=1."),
    # ── Сеть / журналирование ────────────────────────────────────────────────
    (r"Software\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast", _eq(1), "LOW",
     "LLMNR включён", "EnableMulticast=1: возможен перехват имён (LLMNR poisoning)."),
    (r"Software\Policies\Microsoft\Windows\PowerShell", "ExecutionPolicy", _str_in("Unrestricted", "Bypass"),
     "LOW", "Политика выполнения PowerShell не ограничивает скрипты", "ExecutionPolicy Unrestricted/Bypass."),
    (r"Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging", _eq(0),
     "LOW", "Журналирование блоков скриптов PowerShell отключено", "EnableScriptBlockLogging=0."),
    (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun", _eq(0),
     "LOW", "Автозапуск со всех типов носителей разрешён", "NoDriveTypeAutoRun=0."),
]


def _norm_key(key: str) -> str:
    k = key.strip().strip("\\").replace("/", "\\")
    k = re.sub(r"\\+", r"\\", k)
    for prefix in ("hkey_local_machine\\", "hkey_current_user\\", "hklm\\", "hkcu\\", "machine\\", "user\\"):
        if k.lower().startswith(prefix):
            k = k[len(prefix):]
            break
    return k.lower()


_RULE_INDEX: dict = {}
for _r in REGISTRY_RULES:
    _RULE_INDEX.setdefault((_norm_key(_r[0]), _r[1].lower()), []).append(_r)


def _display_value(name: str, value) -> str:
    if name.lower() == "defaultpassword" and isinstance(value, str):
        return f"<скрыто, длина {len(value)}>"
    if isinstance(value, bytes):
        return value[:32].hex(" ") + (" ..." if len(value) > 32 else "")
    if isinstance(value, list):
        return " | ".join(map(str, value))
    return str(value)


def check_registry_settings(settings: list, gpo: str = "", path: str = "") -> list:
    """Применить REGISTRY_RULES к списку RegSetting."""
    findings = []
    for s in settings:
        if s.name.startswith("**"):      # служебные записи (**del., **delvals.) — значение не задаётся
            continue
        key = _norm_key(s.key)
        rules = _RULE_INDEX.get((key, s.name.lower()), []) + _RULE_INDEX.get((key, "*"), [])
        for _, rname, cond, sev, title, desc in rules:
            try:
                hit = cond(s.value)
            except Exception:
                hit = False
            if not hit:
                continue
            hive = f"{s.hive}\\" if s.hive else ""
            evidence = f"{hive}{s.key}\\{s.name} = {_display_value(s.name, s.value)}"
            if rname == "*":
                title = f"{title}: {s.name}"
            findings.append(Finding(sev, title, desc, gpo, path, evidence))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Источники настроек реестра
# ─────────────────────────────────────────────────────────────────────────────

def hive_from_path(rel_path: str) -> str:
    first = rel_path.replace("/", "\\").split("\\", 1)[0].lower()
    return {"machine": "MACHINE", "user": "USER"}.get(first, "")


def registry_pol_settings(raw: bytes, rel_path: str):
    """Registry.pol -> ([RegSetting], [предупреждения])."""
    _, entries, warnings = read_registry_pol(raw)
    hive = hive_from_path(rel_path)
    return [RegSetting(e.key, e.value, e.parsed, hive, "Registry.pol") for e in entries], warnings


def _inf_reg_value(raw_value: str):
    """'4,1' -> 1 ; '1,"text"' -> 'text' ; '7,a,b' -> ['a', 'b']."""
    reg_type, _, data = raw_value.partition(",")
    try:
        t = int(reg_type)
    except ValueError:
        return raw_value
    if t in (4, 5, 11):
        try:
            return int(data.strip(), 0)
        except ValueError:
            return data
    if t == 7:
        return [p for p in (x.strip().strip('"') for x in data.split(",")) if p]
    return data.strip().strip('"')


def inf_registry_settings(sections: dict) -> list:
    """Секция [Registry Values] GptTmpl.inf -> [RegSetting]."""
    out = []
    for full, raw_value in sections.get("registry values", []):
        if raw_value is None or "\\" not in full:
            continue
        hive, _, rest = full.partition("\\")
        key, _, name = rest.rpartition("\\")
        out.append(RegSetting(key, name, _inf_reg_value(raw_value), hive.upper(), "GptTmpl.inf"))
    return out


def _gpp_reg_value(type_name: str, value: str):
    t = reg_type_from_name(type_name)
    if t in (4, 5, 11):
        try:
            return int(value, 16)
        except ValueError:
            return _as_int(value)
    return value


def gpp_registry_settings(root) -> list:
    """Registry.xml (Group Policy Preferences) -> [RegSetting]. Удаляемые элементы (action=D) пропускаются."""
    out = []
    for props in root.iter("Properties"):
        a = props.attrib
        if "key" not in a or a.get("action", "U").upper() == "D":
            continue
        hive = {"HKEY_LOCAL_MACHINE": "MACHINE", "HKEY_CURRENT_USER": "USER"}.get(a.get("hive", "").upper(), a.get("hive", ""))
        out.append(RegSetting(a["key"], a.get("name", ""), _gpp_reg_value(a.get("type", "REG_SZ"), a.get("value", "")),
                              hive, "Registry.xml"))
    return out


# ─────────────────────────────────────────────────────────────────────────────
# GptTmpl.inf
# ─────────────────────────────────────────────────────────────────────────────

DANGEROUS_PRIVILEGES = {
    "SeDebugPrivilege": "отладка любых процессов (дамп LSASS)",
    "SeTcbPrivilege": "действовать как часть ОС",
    "SeBackupPrivilege": "чтение любых файлов в обход ACL (NTDS.dit, SAM)",
    "SeRestorePrivilege": "запись любых файлов в обход ACL",
    "SeTakeOwnershipPrivilege": "смена владельца любых объектов",
    "SeLoadDriverPrivilege": "загрузка драйверов ядра",
    "SeImpersonatePrivilege": "олицетворение токенов (Potato-атаки)",
    "SeAssignPrimaryTokenPrivilege": "замена токена процесса",
    "SeCreateTokenPrivilege": "создание токенов",
    "SeManageVolumePrivilege": "низкоуровневый доступ к томам",
    "SeSecurityPrivilege": "управление журналом аудита",
    "SeEnableDelegationPrivilege": "настройка делегирования Kerberos",
    "SeSystemEnvironmentPrivilege": "изменение переменных прошивки",
    "SeRelabelPrivilege": "изменение меток целостности",
    "SeTrustedCredManAccessPrivilege": "доступ к Credential Manager",
}

PRIVILEGED_LOCAL_GROUPS = {
    "S-1-5-32-544": "Administrators", "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators", "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators", "S-1-5-32-555": "Remote Desktop Users",
    "S-1-5-32-580": "Remote Management Users", "S-1-5-32-562": "Distributed COM Users",
}

# Ключи [System Access] -> поле нормализованной политики паролей
INF_PASSWORD_KEYS = {
    "MinimumPasswordLength": "min_length",
    "PasswordComplexity": "complexity",
    "MaximumPasswordAge": "max_age_days",
    "MinimumPasswordAge": "min_age_days",
    "PasswordHistorySize": "history",
    "LockoutBadCount": "lockout_threshold",
    "LockoutDuration": "lockout_duration_min",
    "ResetLockoutCount": "lockout_window_min",
    "ClearTextPassword": "reversible",
}


def inf_password_policy(sections: dict) -> dict:
    """Политика паролей из [System Access] в нормализованном виде (только заданные ключи)."""
    policy = {}
    for key, field_name in INF_PASSWORD_KEYS.items():
        v = inf_int(sections, "System Access", key)
        if v is not None:
            policy[field_name] = v
    # В secedit -1 означает «никогда» / «до разблокировки администратором»
    if policy.get("max_age_days") in (-1, 0):
        policy["max_age_days"] = None
    if policy.get("lockout_duration_min") == -1:
        policy["lockout_duration_min"] = 0
    return policy


def check_gpttmpl(sections: dict, gpo: str = "", path: str = "", resolver: dict | None = None) -> list:
    findings = []

    def add(sev, title, desc, evidence=""):
        findings.append(Finding(sev, title, desc, gpo, path, evidence))

    # [System Access] — кроме политики паролей (её проверяет check_password_policy)
    if inf_int(sections, "System Access", "ClearTextPassword") == 1:
        add("CRITICAL", "Пароли хранятся с обратимым шифрованием",
            "ClearTextPassword=1: пароли восстанавливаются в открытом виде из базы AD.",
            "ClearTextPassword = 1")
    if inf_int(sections, "System Access", "EnableGuestAccount") == 1:
        add("HIGH", "Учётная запись Guest включена", "EnableGuestAccount=1.", "EnableGuestAccount = 1")
    if inf_int(sections, "System Access", "LSAAnonymousNameLookup") == 1:
        add("MEDIUM", "Разрешено анонимное преобразование SID в имя",
            "LSAAnonymousNameLookup=1: анонимный пользователь перечисляет учётные записи.",
            "LSAAnonymousNameLookup = 1")

    # [Kerberos Policy]
    v = inf_int(sections, "Kerberos Policy", "MaxTicketAge")
    if v is not None and v > 10:
        add("LOW", f"Большое время жизни билета Kerberos ({v} ч > 10)", "MaxTicketAge > 10 ч.",
            f"MaxTicketAge = {v}")
    if inf_int(sections, "Kerberos Policy", "TicketValidateClient") == 0:
        add("LOW", "KDC не проверяет ограничения входа пользователя", "TicketValidateClient=0.",
            "TicketValidateClient = 0")
    v = inf_int(sections, "Kerberos Policy", "MaxClockSkew")
    if v is not None and v > 5:
        add("LOW", f"Большой допуск рассинхронизации часов Kerberos ({v} мин)", "MaxClockSkew > 5 мин.",
            f"MaxClockSkew = {v}")

    # [Privilege Rights]
    for priv, value in sections.get("privilege rights", []):
        if priv not in DANGEROUS_PRIVILEGES or not value:
            continue
        for p in (x.strip() for x in value.split(",")):
            if not p:
                continue
            label = principal_label(p, resolver)
            sid = p.lstrip("*")
            if is_broad_principal(p):
                add("HIGH", f"{priv} выдана широкой группе", f"{DANGEROUS_PRIVILEGES[priv]}: {label}.",
                    f"{priv} = {value}")
            elif (rid := sid_rid(sid)) is not None and rid >= 1000:
                add("MEDIUM", f"{priv} выдана учётной записи/группе домена",
                    f"{DANGEROUS_PRIVILEGES[priv]}: {label}. Проверьте необходимость.",
                    f"{priv} = {value}")

    # [Group Membership] (Restricted Groups)
    for key, value in sections.get("group membership", []):
        if not value or "__" not in key:
            continue
        group, _, kind = key.rpartition("__")
        gsid = group.lstrip("*").upper()
        members = [m.strip() for m in value.split(",") if m.strip()]
        if kind.lower() == "members" and gsid in PRIVILEGED_LOCAL_GROUPS:
            gname = PRIVILEGED_LOCAL_GROUPS[gsid]
            for m in members:
                if is_broad_principal(m):
                    add("HIGH", f"Широкая группа добавлена в локальную группу {gname}",
                        f"Restricted Groups: {principal_label(m, resolver)} -> {gname}.", f"{key} = {value}")
            add("INFO", f"Restricted Groups задаёт состав {gname}",
                ", ".join(principal_label(m, resolver) for m in members) or "(пусто)", f"{key} = {value}")
        elif kind.lower() == "memberof":
            for g in members:
                if g.lstrip("*").upper() in PRIVILEGED_LOCAL_GROUPS and is_broad_principal(group):
                    add("HIGH", "Широкая группа добавлена в привилегированную группу",
                        f"{principal_label(group, resolver)} -> {principal_label(g, resolver)}.", f"{key} = {value}")

    findings += check_registry_settings(inf_registry_settings(sections), gpo, path)
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Group Policy Preferences (XML)
# ─────────────────────────────────────────────────────────────────────────────

_ACCOUNT_ATTRS = ("userName", "runAs", "accountName", "newName", "username")


def parse_xml(raw: bytes):
    text = decode_text(raw)
    text = re.sub(r"^\s*<\?xml[^>]*\?>", "", text)   # кодировка уже применена
    return ET.fromstring(text)


def check_gpp_xml(raw: bytes, gpo: str = "", path: str = "") -> list:
    findings = []
    try:
        root = parse_xml(raw)
    except ET.ParseError as e:
        return [Finding("INFO", "Не удалось разобрать XML", str(e), gpo, path)]

    fname = path.replace("/", "\\").rsplit("\\", 1)[-1].lower()

    # cpassword (MS14-025): ключ AES опубликован Microsoft, пароль расшифровывается любым пользователем
    for el in root.iter():
        cpw = el.attrib.get("cpassword")
        if cpw:
            account = next((el.attrib[a] for a in _ACCOUNT_ATTRS if el.attrib.get(a)), "?")
            item = el.attrib.get("name") or ""
            findings.append(Finding(
                "CRITICAL", "Пароль в Group Policy Preferences (cpassword, MS14-025)",
                "Пароль зашифрован общеизвестным ключом и читается любым пользователем домена. "
                "Удалите элемент и смените пароль учётной записи.",
                gpo, path, f"учётная запись: {account}" + (f", элемент: {item}" if item else "")))

    if fname == "groups.xml":
        for props in root.iter("Properties"):
            gname = props.attrib.get("groupName") or props.attrib.get("groupSid", "")
            gsid = props.attrib.get("groupSid", "").upper()
            is_priv = gsid in PRIVILEGED_LOCAL_GROUPS or any(
                n.lower() in gname.lower() for n in ("administrators", "администраторы"))
            members = props.find("Members")
            if not is_priv or members is None:
                continue
            for m in members.iter("Member"):
                if m.attrib.get("action", "ADD").upper() != "ADD":
                    continue
                mname = m.attrib.get("name", "")
                msid = m.attrib.get("sid", "")
                label = f"{mname} ({msid})" if msid else mname
                if is_broad_principal(mname) or (msid and is_broad_principal(msid)):
                    findings.append(Finding("HIGH", f"Широкая группа добавляется в {gname}",
                                            f"GPP Local Users and Groups: {label}.", gpo, path, label))
                else:
                    findings.append(Finding("INFO", f"GPP добавляет участника в {gname}", label, gpo, path, label))

    elif fname == "scheduledtasks.xml":
        for task in root:
            props = task.find("Properties")
            if props is None or props.attrib.get("action", "U").upper() == "D":
                continue
            run_as = props.attrib.get("runAs", "")
            cmds = []
            for ex in props.iter("Exec"):
                cmd = (ex.findtext("Command") or "").strip()
                args = (ex.findtext("Arguments") or "").strip()
                cmds.append(f"{cmd} {args}".strip())
            if props.attrib.get("appName"):
                cmds.append(f"{props.attrib['appName']} {props.attrib.get('args', '')}".strip())
            name = props.attrib.get("name") or task.attrib.get("name", "")
            findings.append(Finding("INFO", f"Задача планировщика: {name}",
                                    f"Запуск от: {run_as or '—'}. Убедитесь, что исполняемые файлы "
                                    f"недоступны на запись обычным пользователям.",
                                    gpo, path, "; ".join(cmds) or "(нет команды)"))

    elif fname == "registry.xml":
        findings += check_registry_settings(gpp_registry_settings(root), gpo, path)

    return findings


def check_scripts_ini(text: str, gpo: str = "", path: str = "") -> list:
    """scripts.ini / psscripts.ini — сценарии входа/запуска."""
    findings = []
    sections = parse_inf(text)
    for section, items in sections.items():
        cmds = {k[:-len("CmdLine")]: v for k, v in items if v and k.lower().endswith("cmdline")}
        params = {k[:-len("Parameters")]: v for k, v in items if v and k.lower().endswith("parameters")}
        for idx, cmd in cmds.items():
            full = f"{cmd} {params.get(idx, '')}".strip()
            findings.append(Finding("INFO", f"Сценарий GPO ({section})",
                                    "Сценарий выполняется на клиентах; проверьте права на запись к файлу.",
                                    gpo, path, full))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Политика паролей
# ─────────────────────────────────────────────────────────────────────────────

def default_thresholds(**overrides) -> dict:
    t = {
        "min_password_length": 12,
        "require_complexity": 1,
        "min_password_age": 1,
        "max_password_age": 90,
        "password_history": 10,
        "lockout_threshold": 5,
        "lockout_duration": 15,
        "reset_lockout_count": 15,
    }
    t.update({k: v for k, v in overrides.items() if v is not None})
    return t


def check_password_policy(policy: dict, t: dict, source: str = "", path: str = "") -> list:
    """
    Проверить нормализованную политику паролей.
    Поля: min_length, complexity, max_age_days (None = никогда), min_age_days, history,
          lockout_threshold, lockout_duration_min (0 = до разблокировки), lockout_window_min, reversible.
    Отсутствующие поля не проверяются.
    """
    findings = []

    def add(sev, title, desc, evidence=""):
        findings.append(Finding(sev, title, desc, source, path, evidence, "Политика паролей"))

    if policy.get("reversible") == 1:
        add("CRITICAL", "Пароли хранятся с обратимым шифрованием",
            "Пароли восстанавливаются в открытом виде из базы AD.", "reversible encryption = on")

    if policy.get("complexity") == 0 and t.get("require_complexity", 1):
        add("HIGH", "Сложность пароля отключена",
            "Пользователи могут задавать простые пароли без цифр, спецсимволов и смешанного регистра.",
            "PasswordComplexity = 0")

    v = policy.get("min_length")
    if v is not None and v < t["min_password_length"]:
        add("HIGH", f"Слабая минимальная длина пароля ({v} < {t['min_password_length']})",
            f"Рекомендуется не меньше {t['min_password_length']} символов.", f"MinimumPasswordLength = {v}")

    v = policy.get("min_age_days")
    if v is not None and v < t["min_password_age"]:
        add("MEDIUM", f"Минимальный возраст пароля слишком мал ({v} дн < {t['min_password_age']})",
            "Пользователь может сразу сменить пароль несколько раз и вернуться к старому.",
            f"MinimumPasswordAge = {v}")

    if "max_age_days" in policy:
        v = policy["max_age_days"]
        if v is None:
            if t["max_password_age"] > 0:
                add("MEDIUM", "Срок действия пароля не ограничен",
                    "Пароли никогда не истекают. Допустимо только при длинных паролях и MFA (NIST 800-63B).",
                    "MaximumPasswordAge = 0 (никогда)")
        elif t["max_password_age"] > 0 and v > t["max_password_age"]:
            add("MEDIUM", f"Слишком долгий срок действия пароля ({v} дн > {t['max_password_age']})",
                f"Рекомендуется не больше {t['max_password_age']} дней.", f"MaximumPasswordAge = {v}")

    v = policy.get("history")
    if v is not None and v < t["password_history"]:
        add("MEDIUM", f"Маленькая история паролей ({v} < {t['password_history']})",
            "Пользователи быстро возвращаются к старым паролям.", f"PasswordHistorySize = {v}")

    v = policy.get("lockout_threshold")
    if v is not None:
        if v == 0:
            add("HIGH", "Блокировка учётных записей отключена",
                "Неограниченный перебор паролей (brute-force, password spraying).", "LockoutBadCount = 0")
        elif v > t["lockout_threshold"]:
            add("MEDIUM", f"Высокий порог блокировки ({v} > {t['lockout_threshold']})",
                f"Рекомендуется не больше {t['lockout_threshold']} попыток.", f"LockoutBadCount = {v}")

    # Длительность и окно сброса имеют смысл, только если блокировка включена
    if policy.get("lockout_threshold"):
        v = policy.get("lockout_duration_min")
        if v is not None and v != 0 and t["lockout_duration"] > 0 and v < t["lockout_duration"]:
            add("MEDIUM", f"Короткая длительность блокировки ({v} мин < {t['lockout_duration']})",
                f"Рекомендуется ≥{t['lockout_duration']} мин или 0 (до разблокировки администратором).",
                f"LockoutDuration = {v}")
        v = policy.get("lockout_window_min")
        if v is not None and v < t["reset_lockout_count"]:
            add("LOW", f"Быстрый сброс счётчика попыток ({v} мин < {t['reset_lockout_count']})",
                f"Рекомендуется ≥{t['reset_lockout_count']} мин.", f"ResetLockoutCount = {v}")

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Диспетчер по файлам GPO
# ─────────────────────────────────────────────────────────────────────────────

def check_gpo_file(rel_path: str, raw: bytes, gpo: str = "", resolver: dict | None = None) -> list:
    """Запустить все применимые проверки для одного файла GPO."""
    fl = rel_path.lower().replace("/", "\\")
    try:
        if fl.endswith("gpttmpl.inf"):
            return check_gpttmpl(parse_inf(decode_text(raw)), gpo, rel_path, resolver)
        if fl.endswith("registry.pol"):
            settings, warnings = registry_pol_settings(raw, rel_path)
            out = check_registry_settings(settings, gpo, rel_path)
            for w in warnings:
                out.append(Finding("INFO", "Registry.pol разобран с ошибками", w, gpo, rel_path))
            return out
        if fl.endswith(".xml") and "\\preferences\\" in f"\\{fl}":
            return check_gpp_xml(raw, gpo, rel_path)
        if fl.endswith(("\\scripts.ini", "\\psscripts.ini")) or fl in ("scripts.ini", "psscripts.ini"):
            return check_scripts_ini(decode_text(raw), gpo, rel_path)
    except Exception as e:  # одна битая запись не должна ронять весь анализ
        return [Finding("INFO", "Ошибка анализа файла", f"{type(e).__name__}: {e}", gpo, rel_path)]
    return []


def sort_findings(findings: list) -> list:
    return sorted(findings, key=lambda f: (SEV_ORDER.get(f.severity, 99), f.category, f.gpo, f.title))
