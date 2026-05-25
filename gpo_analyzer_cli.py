#!/usr/bin/env python3
"""
GPOHunter — Active Directory GPO Security Analyzer
https://github.com/YOUR_USERNAME/GPOHunter
"""

import argparse
import sys
import re
import struct
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
from ldap3.core.exceptions import LDAPException

from gpo_decoders import (
    decode_gpttmpl, parse_registry_pol, decode_certificate,
    display_gpo_file, is_binary, hexdump,
)
from gpo_users import (
    get_all_users, get_all_groups, build_user_report, print_user_report,
)

VERSION = "1.0.0"

# ── ANSI цвета ────────────────────────────────────────────────────────────────
class C:
    OK   = "\033[92m"
    WARN = "\033[93m"
    ERR  = "\033[91m"
    INFO = "\033[94m"
    BOLD = "\033[1m"
    DIM  = "\033[2m"
    RST  = "\033[0m"

def ok(msg):   print(f"{C.OK}[+]{C.RST} {msg}")
def warn(msg): print(f"{C.WARN}[!]{C.RST} {msg}")
def err(msg):  print(f"{C.ERR}[-]{C.RST} {msg}")
def info(msg): print(f"{C.INFO}[*]{C.RST} {msg}")
def dim(msg):  print(f"{C.DIM}{msg}{C.RST}")


# ── Интерактивный ввод порогов ────────────────────────────────────────────────
def _ask_int(prompt: str, default: int, lo: int = 0, hi: int = 99999) -> int:
    while True:
        try:
            raw = input(f"  {prompt} [{default}]: ").strip()
            if raw == "":
                return default
            v = int(raw)
            if lo <= v <= hi:
                return v
            print(f"    Введите число от {lo} до {hi}")
        except ValueError:
            print("    Ожидается целое число")
        except (EOFError, KeyboardInterrupt):
            print()
            return default


def ask_thresholds() -> dict:
    print(f"\n{C.BOLD}=== Настройка порогов политики безопасности ==={C.RST}")
    print(f"  {C.DIM}Нажмите Enter чтобы принять значение по умолчанию{C.RST}\n")

    print(f"  {C.BOLD}— Политика паролей —{C.RST}")
    t = {}
    t["min_password_length"] = _ask_int(
        "Минимальная длина пароля            (предупреждение если МЕНЬШЕ)",  12, 0, 128)
    t["require_complexity"]  = _ask_int(
        "Требовать сложность пароля          (1=да, 0=нет — предупреждение если 0)",  1, 0, 1)
    t["min_password_age"]    = _ask_int(
        "Минимальный возраст пароля (дни)    (предупреждение если МЕНЬШЕ)",   1, 0, 998)
    t["max_password_age"]    = _ask_int(
        "Максимальный возраст пароля (дни)   (предупреждение если БОЛЬШЕ, 0=без лимита)", 90, 0, 999)
    t["password_history"]    = _ask_int(
        "История паролей                     (предупреждение если МЕНЬШЕ)",  10, 0, 24)

    print(f"\n  {C.BOLD}— Политика блокировки —{C.RST}")
    t["lockout_threshold"]   = _ask_int(
        "Попыток до блокировки               (предупреждение если БОЛЬШЕ или 0=откл)",  5, 0, 999)
    t["lockout_duration"]    = _ask_int(
        "Длительность блокировки (мин)       (предупреждение если МЕНЬШЕ, 0=навсегда)", 15, 0, 99999)
    t["reset_lockout_count"] = _ask_int(
        "Сброс счётчика попыток (мин)        (предупреждение если МЕНЬШЕ)",  15, 0, 99999)
    print()
    return t


def _default_thresholds(**overrides) -> dict:
    t = {
        "min_password_length": 12,
        "require_complexity":   1,
        "min_password_age":     1,
        "max_password_age":    90,
        "password_history":    10,
        "lockout_threshold":    5,
        "lockout_duration":    15,
        "reset_lockout_count": 15,
    }
    t.update({k: v for k, v in overrides.items() if v is not None})
    return t


# ── Парсинг значений из GptTmpl.inf ──────────────────────────────────────────
def _inf_val(content: str, key: str) -> int | None:
    m = re.search(rf"^\s*{re.escape(key)}\s*=\s*(\d+)", content,
                  re.MULTILINE | re.IGNORECASE)
    return int(m.group(1)) if m else None


def _reg_dword(content: str, value_name: str) -> int | None:
    m = re.search(
        rf"Value\s*:\s*{re.escape(value_name)}.*?Data\s*:\s*(\d+)",
        content, re.IGNORECASE | re.DOTALL,
    )
    return int(m.group(1)) if m else None


# ── Сводка политики паролей (информационный блок) ────────────────────────────
def _password_policy_summary(filename: str, content: str) -> list[tuple]:
    """
    Возвращает список (label, value, status) для информационной таблицы
    политики паролей. Вызывается один раз на весь прогон.
    """
    if not filename.lower().endswith("gpttmpl.inf"):
        return []

    rows = []

    # Сложность пароля — всегда показываем явно
    complexity = _inf_val(content, "PasswordComplexity")
    if complexity is not None:
        if complexity == 1:
            rows.append(("Сложность пароля", "Включена ✓", "ok"))
        else:
            rows.append(("Сложность пароля", "ОТКЛЮЧЕНА ✗", "warn"))
    else:
        rows.append(("Сложность пароля", "не задана в GPO", "dim"))

    for key, label in [
        ("MinimumPasswordLength",  "Мин. длина пароля"),
        ("MaximumPasswordAge",     "Макс. возраст (дни)"),
        ("MinimumPasswordAge",     "Мин. возраст (дни)"),
        ("PasswordHistorySize",    "История паролей"),
        ("LockoutBadCount",        "Порог блокировки (попыток)"),
        ("LockoutDuration",        "Длительность блокировки (мин)"),
        ("ResetLockoutCount",      "Сброс счётчика (мин)"),
        ("ClearTextPassword",      "Хранить пароли открыто"),
        ("NoLMHash",               "Отключить LM-хеши"),
    ]:
        v = _inf_val(content, key)
        if v is not None:
            rows.append((label, str(v), "info"))

    return rows


def print_policy_summary(summaries: list[tuple], C) -> None:
    """Красиво вывести сводную таблицу политики паролей."""
    if not summaries:
        return
    print(f"\n{C.BOLD}=== Сводка политики паролей ==={C.RST}")
    print(f"  {'─'*50}")
    for label, value, status in summaries:
        if status == "ok":
            val_str = f"{C.OK}{value}{C.RST}"
        elif status == "warn":
            val_str = f"{C.WARN}{value}{C.RST}"
        elif status == "dim":
            val_str = f"{C.DIM}{value}{C.RST}"
        else:
            val_str = f"{C.INFO}{value}{C.RST}"
        print(f"  {label:<35} {val_str}")
    print()


# ── Статические security checks ───────────────────────────────────────────────
_STATIC_CHECKS = [
    ("LM hashes enabled",      "gpttmpl.inf",  "NoLMHash=4,0",            "HIGH",
     "Хранение LM-хешей включено — уязвимость для Pass-the-Hash атак"),
    ("ClearText passwords",    "gpttmpl.inf",  "ClearTextPassword = 1",   "CRITICAL",
     "Пароли хранятся в обратимом шифровании (равносильно открытому тексту)"),
    ("Autologon configured",   "registry.pol", "AutoAdminLogon",          "CRITICAL",
     "Настроен автовход — проверьте DefaultPassword в реестре"),
    ("WDigest enabled",        "registry.pol", "UseLogonCredential",      "HIGH",
     "WDigest хранит пароли в открытом виде в LSASS — уязвимость для Mimikatz"),
    ("SMBv1 enabled",          "registry.pol", "SMB1",                    "HIGH",
     "Устаревший протокол SMBv1 активен (EternalBlue, WannaCry)"),
    ("AlwaysInstallElevated",  "registry.pol", "AlwaysInstallElevated",   "CRITICAL",
     "MSI-пакеты запускаются с привилегиями SYSTEM — локальное повышение привилегий"),
    ("LDAP signing weak",      "gpttmpl.inf",  "LDAPServerIntegrity=4,1", "MEDIUM",
     "LDAP подпись запрашивается но не обязательна (должно быть =4,2)"),
    ("Netlogon signing off",   "gpttmpl.inf",  "RequireSignOrSeal=4,0",   "HIGH",
     "Netlogon не требует подписи — уязвимость ZeroLogon"),
]


def run_static_checks(filename: str, content: str) -> list:
    issues = []
    fl = filename.lower()
    for name, suffix, pattern, severity, desc in _STATIC_CHECKS:
        if not fl.endswith(suffix):
            continue
        if pattern.lower() not in content.lower():
            continue
        # RDP NLA: UserAuthentication должен быть именно 0
        if pattern == "UserAuthentication":
            if _reg_dword(content, "UserAuthentication") != 0:
                continue
        # fPromptForPassword = 0 → проблема
        if pattern == "fPromptForPassword":
            if _reg_dword(content, "fPromptForPassword") != 0:
                continue
        issues.append((severity, name, desc))
    return issues


# ── Пороговые security checks ─────────────────────────────────────────────────
def run_threshold_checks(filename: str, content: str, t: dict) -> list:
    issues = []
    if not filename.lower().endswith("gpttmpl.inf"):
        return issues

    # Сложность пароля
    complexity = _inf_val(content, "PasswordComplexity")
    if complexity is not None:
        if complexity == 0 and t.get("require_complexity", 1) == 1:
            issues.append((
                "HIGH",
                "Сложность пароля отключена (PasswordComplexity=0)",
                "Пользователи могут устанавливать простые пароли без спецсимволов, "
                "цифр и смешанного регистра",
            ))
    else:
        # Параметр вообще не задан в GPO — тоже потенциальный риск
        issues.append((
            "LOW",
            "Политика сложности пароля не определена в GPO",
            "PasswordComplexity не найден — применяются настройки по умолчанию ОС",
        ))

    # Минимальная длина
    v = _inf_val(content, "MinimumPasswordLength")
    if v is not None and v < t["min_password_length"]:
        issues.append((
            "HIGH",
            f"Слабая минимальная длина пароля ({v} < {t['min_password_length']})",
            f"MinimumPasswordLength={v}, требуется ≥{t['min_password_length']}",
        ))

    # Минимальный возраст
    v = _inf_val(content, "MinimumPasswordAge")
    if v is not None and v < t["min_password_age"]:
        issues.append((
            "MEDIUM",
            f"Минимальный возраст пароля слишком мал ({v} дн < {t['min_password_age']})",
            f"MinimumPasswordAge={v} — пользователи могут менять пароль сразу обратно",
        ))

    # Максимальный возраст
    v = _inf_val(content, "MaximumPasswordAge")
    if v is not None:
        if v == 0:
            issues.append((
                "HIGH",
                "Срок действия пароля не ограничен (MaximumPasswordAge=0)",
                "Пароль никогда не истекает — скомпрометированный пароль действует вечно",
            ))
        elif t["max_password_age"] > 0 and v > t["max_password_age"]:
            issues.append((
                "MEDIUM",
                f"Слишком долгий срок действия пароля ({v} дн > {t['max_password_age']})",
                f"MaximumPasswordAge={v}, рекомендуется ≤{t['max_password_age']}",
            ))

    # История паролей
    v = _inf_val(content, "PasswordHistorySize")
    if v is not None and v < t["password_history"]:
        issues.append((
            "MEDIUM",
            f"Маленькая история паролей ({v} < {t['password_history']})",
            f"PasswordHistorySize={v} — пользователи быстро возвращаются к старым паролям",
        ))

    # Порог блокировки
    v = _inf_val(content, "LockoutBadCount")
    if v is not None:
        if v == 0:
            issues.append((
                "HIGH",
                "Блокировка учётной записи отключена (LockoutBadCount=0)",
                "Возможен неограниченный перебор пароля (brute-force)",
            ))
        elif v > t["lockout_threshold"]:
            issues.append((
                "MEDIUM",
                f"Высокий порог блокировки ({v} попыток > {t['lockout_threshold']})",
                f"LockoutBadCount={v}, рекомендуется ≤{t['lockout_threshold']}",
            ))

    # Длительность блокировки
    v = _inf_val(content, "LockoutDuration")
    if v is not None and t["lockout_duration"] > 0 and 0 < v < t["lockout_duration"]:
        issues.append((
            "MEDIUM",
            f"Короткая длительность блокировки ({v} мин < {t['lockout_duration']})",
            f"LockoutDuration={v}, рекомендуется ≥{t['lockout_duration']} или 0 (навсегда)",
        ))

    # Сброс счётчика
    v = _inf_val(content, "ResetLockoutCount")
    if v is not None and v < t["reset_lockout_count"]:
        issues.append((
            "LOW",
            f"Быстрый сброс счётчика попыток ({v} мин < {t['reset_lockout_count']})",
            f"ResetLockoutCount={v}, рекомендуется ≥{t['reset_lockout_count']}",
        ))

    return issues


def run_all_checks(filename: str, content: str, thresholds: dict) -> list:
    return run_static_checks(filename, content) + \
           run_threshold_checks(filename, content, thresholds)


# ── LDAP / AD ─────────────────────────────────────────────────────────────────
def connect_ad(dc: str, domain: str, username: str, password: str) -> Connection:
    server = Server(dc, get_info=ALL)
    conn = Connection(
        server, user=f"{domain}\\{username}", password=password,
        authentication=NTLM, auto_bind=True,
    )
    return conn


def get_base_dn(domain: str) -> str:
    return ",".join(f"DC={p}" for p in domain.split("."))


def get_gpos(conn: Connection, base_dn: str) -> list:
    conn.search(
        search_base=f"CN=Policies,CN=System,{base_dn}",
        search_filter="(objectClass=groupPolicyContainer)",
        search_scope=SUBTREE,
        attributes=["displayName", "cn", "gPCFileSysPath",
                    "versionNumber", "flags", "whenCreated", "whenChanged"],
    )
    return conn.entries


# ── SYSVOL через SMB ──────────────────────────────────────────────────────────
def read_sysvol_files(gpo_entry, dc: str, domain: str,
                      username: str, password: str) -> dict:
    files = {}
    try:
        from impacket.smbconnection import SMBConnection
        import io

        smb = SMBConnection(dc, dc)
        smb.login(username, password, domain)

        sysvol_path = str(gpo_entry.gPCFileSysPath)
        parts  = sysvol_path.replace("\\\\", "").split("\\")
        share  = parts[1]
        folder = "\\".join(parts[2:])

        def list_dir(path):
            try:
                for f in smb.listPath(share, path + "\\*"):
                    name = f.get_longname()
                    if name in (".", ".."):
                        continue
                    full = path + "\\" + name
                    if f.is_directory():
                        list_dir(full)
                    else:
                        buf = io.BytesIO()
                        smb.getFile(share, full, buf.write)
                        rel = full[len(folder):].lstrip("\\")
                        files[rel] = buf.getvalue()
            except Exception:
                pass

        list_dir(folder)
        smb.logoff()
    except ImportError:
        pass
    except Exception:
        pass
    return files


# ── CLI аргументы ─────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        description=f"GPOHunter v{VERSION} — Active Directory GPO Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  # Анализ GPO с интерактивным вводом порогов:
  python gpo_analyzer_cli.py -u admin -p 'Pass123!' -d corp.local -dc 192.168.1.1 --show-xml

  # Быстрый анализ с дефолтами + статистика пользователей:
  python gpo_analyzer_cli.py -u admin -p 'Pass123!' -d corp.local -dc 192.168.1.1 \\
    --no-prompt --users --show-members

  # Задать пороги через аргументы:
  python gpo_analyzer_cli.py -u admin -p 'Pass123!' -d corp.local -dc 192.168.1.1 \\
    --no-prompt --min-pwd-len 14 --max-pwd-age 60 --lockout-count 3
        """,
    )
    p.add_argument("-u",  "--username",     required=True,  help="Имя пользователя AD")
    p.add_argument("-p",  "--password",     required=True,  help="Пароль")
    p.add_argument("-d",  "--domain",       required=True,  help="Домен (например corp.local)")
    p.add_argument("-dc", "--dc",           required=True,  help="IP или hostname контроллера домена")
    p.add_argument("--show-xml",            action="store_true",
                   help="Показать содержимое файлов GPO")
    p.add_argument("--gpo",                 default=None,
                   help="Фильтровать по имени GPO (substring)")
    p.add_argument("--users",               action="store_true",
                   help="Показать статистику пользователей и групп")
    p.add_argument("--show-members",        action="store_true",
                   help="Показать участников каждой группы (используется с --users)")
    p.add_argument("--no-prompt",           action="store_true",
                   help="Не задавать интерактивных вопросов, использовать дефолты")
    p.add_argument("--no-color",            action="store_true",
                   help="Отключить ANSI-цвета")
    p.add_argument("--version",             action="version", version=f"GPOHunter {VERSION}")
    # Пороги через аргументы
    g = p.add_argument_group("Пороги (переопределяют интерактивный ввод)")
    g.add_argument("--min-pwd-len",    type=int, metavar="N",
                   help="Минимальная длина пароля (по умолч. 12)")
    g.add_argument("--max-pwd-age",    type=int, metavar="N",
                   help="Максимальный возраст пароля в днях (по умолч. 90)")
    g.add_argument("--min-pwd-age",    type=int, metavar="N",
                   help="Минимальный возраст пароля в днях (по умолч. 1)")
    g.add_argument("--lockout-count",  type=int, metavar="N",
                   help="Порог неверных попыток до блокировки (по умолч. 5)")
    return p.parse_args()


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    args = parse_args()

    if args.no_color:
        for attr in vars(C):
            if not attr.startswith("_"):
                setattr(C, attr, "")

    print(f"\n{C.BOLD}GPOHunter v{VERSION}{C.RST} — Active Directory GPO Security Analyzer\n")

    # ── Пороги ───────────────────────────────────────────────────────────────
    if args.no_prompt:
        thresholds = _default_thresholds(
            min_password_length=args.min_pwd_len,
            min_password_age=args.min_pwd_age,
            max_password_age=args.max_pwd_age,
            lockout_threshold=args.lockout_count,
        )
    else:
        thresholds = ask_thresholds()
        if args.min_pwd_len   is not None: thresholds["min_password_length"] = args.min_pwd_len
        if args.min_pwd_age   is not None: thresholds["min_password_age"]    = args.min_pwd_age
        if args.max_pwd_age   is not None: thresholds["max_password_age"]    = args.max_pwd_age
        if args.lockout_count is not None: thresholds["lockout_threshold"]   = args.lockout_count

    info(
        f"Пороги: длина≥{thresholds['min_password_length']}  "
        f"сложность={'вкл' if thresholds['require_complexity'] else 'выкл'}  "
        f"макс.возраст≤{thresholds['max_password_age']}дн  "
        f"блокировка≤{thresholds['lockout_threshold']} попыток"
    )

    # ── Подключение к AD ──────────────────────────────────────────────────────
    try:
        conn = connect_ad(args.dc, args.domain, args.username, args.password)
        ok("Подключено к Active Directory")
    except LDAPException as e:
        err(f"LDAP ошибка подключения: {e}")
        sys.exit(1)

    base_dn = get_base_dn(args.domain)

    # ── Перечисление GPO ──────────────────────────────────────────────────────
    gpos = get_gpos(conn, base_dn)
    ok(f"Найдено GPO: {len(gpos)}")

    if args.gpo:
        gpos = [g for g in gpos
                if args.gpo.lower() in str(getattr(g, "displayName", "")).lower()]
        info(f"Фильтр: {len(gpos)} GPO совпадают с '{args.gpo}'")

    all_issues   = []   # [(gpo_name, filepath, severity, name, desc)]
    all_summaries = []  # [(label, value, status)]  — для сводки политики

    if args.show_xml:
        print(f"\n{C.BOLD}=== GPO File Contents ==={C.RST}")

    for gpo_entry in gpos:
        gpo_name = str(gpo_entry.displayName) if hasattr(gpo_entry, "displayName") else "Unknown"
        gpo_guid = str(gpo_entry.cn)          if hasattr(gpo_entry, "cn")          else "Unknown"

        if args.show_xml:
            print(f"\n{C.BOLD}{'='*60}{C.RST}")
            ok(f"GPO: {gpo_name} ({gpo_guid})")

        sysvol_files = read_sysvol_files(
            gpo_entry, args.dc, args.domain, args.username, args.password,
        )

        if not sysvol_files:
            if args.show_xml:
                warn("Файлы SYSVOL недоступны (нет impacket или прав доступа)")
            continue

        for rel_path, raw_bytes in sorted(sysvol_files.items()):
            if args.show_xml:
                display_gpo_file(rel_path, raw_bytes)

            fl = rel_path.lower()
            if fl.endswith("gpttmpl.inf"):
                decoded = decode_gpttmpl(raw_bytes)
            elif fl.endswith("registry.pol"):
                decoded = parse_registry_pol(raw_bytes)
            else:
                decoded = raw_bytes.decode("utf-8", errors="replace")

            # Сводка политики паролей (только из GptTmpl.inf)
            rows = _password_policy_summary(rel_path, decoded)
            if rows:
                all_summaries.extend(rows)

            # Security checks
            for severity, issue_name, desc in run_all_checks(rel_path, decoded, thresholds):
                all_issues.append((gpo_name, rel_path, severity, issue_name, desc))

    # ── Сводка политики паролей ───────────────────────────────────────────────
    if all_summaries:
        # Дедупликация: оставить первое вхождение каждого label
        seen = set()
        deduped = []
        for row in all_summaries:
            if row[0] not in seen:
                seen.add(row[0])
                deduped.append(row)
        print_policy_summary(deduped, C)

    # ── Security report ───────────────────────────────────────────────────────
    print(f"{C.BOLD}=== Security Analysis ==={C.RST}")

    if not all_issues:
        ok("Проблем безопасности не обнаружено")
    else:
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        all_issues.sort(key=lambda x: sev_order.get(x[2], 9))

        sev_color = {
            "CRITICAL": C.ERR,
            "HIGH":     C.WARN,
            "MEDIUM":   C.INFO,
            "LOW":      C.OK,
        }
        counts = {}
        for gpo_name, path, severity, issue_name, desc in all_issues:
            counts[severity] = counts.get(severity, 0) + 1
            col = sev_color.get(severity, "")
            print(f"\n  {col}[{severity}]{C.RST} {C.BOLD}{issue_name}{C.RST}")
            print(f"    GPO  : {gpo_name}")
            print(f"    Файл : {path}")
            print(f"    Инфо : {desc}")

        print(f"\n{C.BOLD}  Итого:{C.RST}", end="  ")
        parts = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if counts.get(sev, 0):
                parts.append(f"{sev_color[sev]}{counts[sev]} {sev}{C.RST}")
        print("  |  ".join(parts))

    # ── Отчёт по пользователям ────────────────────────────────────────────────
    if args.users:
        info("Загружаю пользователей и группы из AD...")
        all_users  = get_all_users(conn, base_dn)
        all_groups = get_all_groups(conn, base_dn)
        report = build_user_report(all_users, all_groups)
        report["all_users"] = all_users
        print_user_report(report, C, show_members=args.show_members)

    conn.unbind()
    print()


if __name__ == "__main__":
    main()
