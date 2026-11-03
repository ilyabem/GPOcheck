#!/usr/bin/env python3
"""
GPOCheck — Active Directory GPO Security Analyzer
https://github.com/ilyabem/GPOCheck
"""

from __future__ import annotations

import argparse
import getpass
import os
import re
import sys
from datetime import datetime, timezone

from gpo_decoders import decode_text, parse_inf, inf_get, render_gpo_file
from gpo_checks import (
    Finding, SEVERITIES, SEV_ORDER, check_gpo_file, check_password_policy, default_thresholds,
    inf_password_policy, sort_findings,
)
from gpo_report import (
    C, setup_streams, setup_colors, ok, warn, err, info, ask_thresholds, is_interactive, print_policy, gpo_status,
    print_findings, write_json,
)
from gpo_sysvol import FsSysvol, SmbSysvol, offline_gpos

VERSION = "2.0.0"
DEFAULT_DOMAIN_POLICY_GUID = "{31B2F340-016D-11D2-945F-00C04FB984F9}"

EPILOG = """
Примеры:
  # Пароль будет запрошен без отображения:
  python gpo_analyzer_cli.py -d corp.local -dc dc01.corp.local -u auditor

  # Windows, текущий сеанс домена (Kerberos/SSPI), SYSVOL читается по UNC-пути:
  python gpo_analyzer_cli.py -d corp.local -dc dc01.corp.local -k --users

  # Linux, билет Kerberos из kinit (KRB5CCNAME):
  python gpo_analyzer_cli.py -d corp.local -dc dc01.corp.local -k

  # Офлайн-анализ копии каталога SYSVOL\\<домен>\\Policies:
  python gpo_analyzer_cli.py --offline ./Policies

  # Без вопросов, свои пороги, отчёт в JSON:
  python gpo_analyzer_cli.py -d corp.local -dc 10.0.0.1 -u auditor --no-prompt \\
      --min-pwd-len 14 --lockout-count 5 --json report.json
"""


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="gpo_analyzer_cli.py",
        description=f"GPOCheck v{VERSION} — анализ безопасности групповых политик Active Directory",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=EPILOG)

    a = p.add_argument_group("Подключение")
    a.add_argument("-d", "--domain", help="DNS-имя домена (например corp.local)")
    a.add_argument("-dc", "--dc", help="IP или имя контроллера домена (по умолчанию — имя домена)")
    a.add_argument("-u", "--username", help="Пользователь: user, DOMAIN\\user или user@domain")
    a.add_argument("-p", "--password", help="Пароль (если не указан — будет запрошен)")
    a.add_argument("-k", "--kerberos", action="store_true",
                   help="Kerberos: текущий сеанс Windows или билет KRB5CCNAME (Linux)")
    a.add_argument("--ldaps", action="store_true", help="Подключаться по LDAPS (636)")
    a.add_argument("--ldap-port", type=int, help="Нестандартный порт LDAP")
    a.add_argument("--smb-port", type=int, default=445, help="Порт SMB (по умолчанию 445)")
    a.add_argument("--timeout", type=int, default=10, help="Таймаут подключения, сек (по умолчанию 10)")
    a.add_argument("--sysvol-path", metavar="DIR",
                   help="Читать файлы GPO из каталога Policies (локальная копия или UNC) вместо SMB")
    a.add_argument("--offline", metavar="DIR", help="Офлайн-анализ каталога Policies без подключения к AD")

    o = p.add_argument_group("Что проверять и выводить")
    o.add_argument("--gpo", help="Фильтр по имени или GUID GPO (подстрока)")
    o.add_argument("--show-xml", "--show-files", dest="show_files", action="store_true",
                   help="Показать декодированное содержимое файлов GPO")
    o.add_argument("--users", action="store_true", help="Пользователи и группы + проверки учётных записей")
    o.add_argument("--show-members", action="store_true", help="Показать участников групп (с --users)")
    o.add_argument("--stale-days", type=int, default=90, help="Порог неактивности учётных записей, дни (90)")
    o.add_argument("--no-acl", action="store_true", help="Не проверять права на объекты GPO")
    o.add_argument("--min-severity", type=str.upper, choices=SEVERITIES, default="LOW",
                   help="Минимальный уровень выводимых замечаний (по умолчанию LOW)")
    o.add_argument("--json", metavar="FILE", help="Сохранить полный отчёт в JSON")
    o.add_argument("--fail-on", type=str.upper, choices=SEVERITIES,
                   help="Код возврата 2, если есть замечания этого уровня или выше (для CI)")
    o.add_argument("--no-prompt", action="store_true", help="Не задавать вопросов, пороги по умолчанию")
    o.add_argument("--no-color", action="store_true", help="Отключить цвета")
    o.add_argument("--version", action="version", version=f"GPOCheck {VERSION}")

    t = p.add_argument_group("Пороги (переопределяют значения по умолчанию и интерактивный ввод)")
    t.add_argument("--min-pwd-len", type=int, metavar="N", help="Минимальная длина пароля (12)")
    t.add_argument("--max-pwd-age", type=int, metavar="N", help="Макс. возраст пароля, дни; 0 — не проверять (90)")
    t.add_argument("--min-pwd-age", type=int, metavar="N", help="Мин. возраст пароля, дни (1)")
    t.add_argument("--pwd-history", type=int, metavar="N", help="История паролей (10)")
    t.add_argument("--lockout-count", type=int, metavar="N", help="Порог неверных попыток до блокировки (5)")
    t.add_argument("--lockout-duration", type=int, metavar="N", help="Длительность блокировки, мин (15)")
    t.add_argument("--lockout-reset", type=int, metavar="N", help="Сброс счётчика попыток, мин (15)")

    args = p.parse_args(argv)

    if args.offline:
        if not os.path.isdir(args.offline):
            p.error(f"--offline: каталог не найден: {args.offline}")
        if args.users:
            p.error("--users требует подключения к AD и несовместим с --offline")
        return args

    if not args.domain:
        p.error("укажите домен (-d) или --offline DIR")
    args.dc = args.dc or args.domain
    if args.username and args.kerberos:
        p.error("укажите либо -u (NTLM), либо -k (Kerberos)")
    if not args.username and not args.kerberos:
        if os.name == "nt":
            args.kerberos = True          # текущий сеанс Windows
        else:
            p.error("укажите -u USER (NTLM) или -k (Kerberos, нужен kinit)")
    if args.username and args.password is None:
        args.password = getpass.getpass(f"Пароль для {args.username}: ")
    return args


def collect_thresholds(args) -> dict:
    t = default_thresholds()
    if not args.no_prompt and is_interactive():
        t = ask_thresholds(t)
    t.update({k: v for k, v in {
        "min_password_length": args.min_pwd_len, "max_password_age": args.max_pwd_age,
        "min_password_age": args.min_pwd_age, "password_history": args.pwd_history,
        "lockout_threshold": args.lockout_count, "lockout_duration": args.lockout_duration,
        "reset_lockout_count": args.lockout_reset,
    }.items() if v is not None})
    return t


class Context:
    """Данные, собранные из AD (в офлайн-режиме остаются пустыми)."""

    def __init__(self):
        self.conn = None
        self.base_dn = ""
        self.links: dict = {}
        self.resolver: dict = {}
        self.domain_policy: dict | None = None
        self.fgpp: list = []


def load_from_ad(args, ctx: Context, findings: list, thresholds: dict):
    """Подключиться к AD и собрать GPO, связи, политику паролей. -> список GPO или None при ошибке."""
    from gpo_ldap import (ConnectError, connect_ad, get_base_dn, get_domain_info, get_fgpp, get_gpos,
                          get_gpo_links, gpo_acl_writers, resolve_sids)

    if args.kerberos and re.fullmatch(r"[\d.]+|[0-9a-fA-F:]+", args.dc):
        warn("Для Kerberos укажите имя DC (FQDN), а не IP-адрес: SPN строится по имени")
    try:
        ctx.conn = connect_ad(args, on_fallback=lambda: warn(
            "Контроллер домена требует подпись LDAP — переключаюсь на LDAPS (636)"))
    except ConnectError as e:
        err(f"Не удалось подключиться к LDAP {args.dc}: {e}")
        if "invalidCredentials" in str(e):
            err("Неверное имя пользователя или пароль")
        return None
    except OSError as e:
        err(f"Сетевая ошибка: {e}")
        return None

    who = (ctx.conn.extend.standard.who_am_i() or "").replace("u:", "")
    ok(f"Подключено к {args.dc} ({'LDAPS' if args.ldaps else 'LDAP'}, "
       f"{'Kerberos' if args.kerberos else 'NTLM'}) как {who}")

    other = ctx.conn.server.info.other if ctx.conn.server.info else {}
    ctx.base_dn = (other.get("defaultNamingContext") or [get_base_dn(args.domain)])[0]
    config_nc = (other.get("configurationNamingContext") or [None])[0]

    ctx.domain_policy, _, maq = get_domain_info(ctx.conn, ctx.base_dn)
    ctx.fgpp = get_fgpp(ctx.conn, ctx.base_dn)
    gpos = get_gpos(ctx.conn, ctx.base_dn)
    ctx.links = get_gpo_links(ctx.conn, ctx.base_dn, config_nc)
    ok(f"Найдено GPO: {len(gpos)}, связей (gPLink): {sum(len(v) for v in ctx.links.values())}")

    if ctx.domain_policy:
        findings += check_password_policy(ctx.domain_policy, thresholds, "Политика домена (действующая)")
    for pso in ctx.fgpp:
        findings += check_password_policy(pso["policy"], thresholds, f"FGPP: {pso['name']}")
    if maq:
        findings.append(Finding("LOW", f"Пользователи могут добавлять компьютеры в домен (квота {maq})",
                                "ms-DS-MachineAccountQuota > 0: любой пользователь создаёт учётные записи "
                                "компьютеров (используется в атаках RBCD/noPac). Рекомендуется 0.",
                                "", "", f"ms-DS-MachineAccountQuota = {maq}", "Домен"))

    if not args.no_acl:
        sids = set()
        for g in gpos:
            if g["sd"]:
                try:
                    owner, writers = gpo_acl_writers(g["sd"])
                    sids |= set(writers) | {owner}
                except Exception:
                    pass
        ctx.resolver = resolve_sids(ctx.conn, ctx.base_dn, sids)
    return gpos


def gpo_link_findings(g: dict, g_links: list) -> list:
    if g["flags"] == 3:
        return [Finding("INFO", "GPO полностью отключена", "Политика не применяется.", g["name"])]
    if not g_links:
        return [Finding("INFO", "GPO не связана ни с одним контейнером",
                        "Политика не применяется; удалите её, если она не нужна.", g["name"])]
    if not any(en for _, en, _ in g_links):
        return [Finding("INFO", "Все связи GPO отключены", "Политика не применяется.", g["name"])]
    return []


def run(args) -> int:
    print(f"\n{C.BOLD}GPOCheck v{VERSION}{C.RST} — Active Directory GPO Security Analyzer\n")
    thresholds = collect_thresholds(args)
    info(f"Пороги: длина≥{thresholds['min_password_length']}  "
         f"макс. возраст≤{thresholds['max_password_age'] or '∞'} дн  история≥{thresholds['password_history']}  "
         f"блокировка≤{thresholds['lockout_threshold']} попыток / ≥{thresholds['lockout_duration']} мин")

    findings: list = []
    ctx = Context()
    report = {"tool": "GPOCheck", "version": VERSION, "generated": datetime.now(timezone.utc),
              "thresholds": thresholds, "gpos": []}

    if args.offline:
        report["mode"] = "offline"
        reader = FsSysvol(root=args.offline)
        gpos = offline_gpos(args.offline)
        ok(f"Офлайн-режим: {args.offline}, найдено GPO: {len(gpos)}")
    else:
        report.update(mode="ldap", domain=args.domain, dc=args.dc)
        gpos = load_from_ad(args, ctx, findings, thresholds)
        if gpos is None:
            return 1
        report["base_dn"] = ctx.base_dn
        if args.sysvol_path:
            reader = FsSysvol(root=args.sysvol_path)
        elif args.kerberos and os.name == "nt":
            reader = FsSysvol(dc=args.dc)          # UNC-путь от имени текущего пользователя
        else:
            reader = SmbSysvol(args)

    if args.gpo:
        flt = args.gpo.lower()
        gpos = [g for g in gpos if flt in g["name"].lower() or flt in g["guid"].lower()]
        info(f"Фильтр '{args.gpo}': {len(gpos)} GPO")

    # ── Обработка GPO ─────────────────────────────────────────────────────────
    gpo_policies = []        # [(gpo, связи, политика паролей из GptTmpl.inf, путь)]
    unreadable = 0
    try:
        for g in gpos:
            g_links = ctx.links.get(g["guid"], [])
            entry = {"name": g["name"], "guid": g["guid"], "path": g["path"], "status": gpo_status(g),
                     "links": [{"dn": dn, "enabled": en, "enforced": enf} for dn, en, enf in g_links]}
            report["gpos"].append(entry)

            if args.show_files:
                print(f"\n{C.BOLD}{'═' * 70}{C.RST}")
                ok(f"GPO: {g['name']} {g['guid']}  [{gpo_status(g)}]")

            if not args.offline:
                findings += gpo_link_findings(g, g_links)
                if not args.no_acl:
                    from gpo_ldap import check_gpo_acl
                    findings += check_gpo_acl(g, ctx.resolver)

            try:
                files, errors = reader.read_gpo(g)
            except Exception as e:
                err(f"Не удалось прочитать SYSVOL ({args.dc}): {type(e).__name__}: {e}")
                return 1
            entry["files"], entry["errors"] = sorted(files), errors
            if errors and not files:
                unreadable += 1
            if args.show_files:
                for e in errors:
                    warn(e)

            gpt_ini = next((files[k] for k in files if k.lower() == "gpt.ini"), None)
            if gpt_ini and not args.offline:
                try:
                    fs_version = int(inf_get(parse_inf(decode_text(gpt_ini)), "General", "Version") or 0)
                except ValueError:
                    fs_version = None
                if fs_version is not None and fs_version != g["version"]:
                    findings.append(Finding("LOW", "Версия GPO в AD и SYSVOL не совпадает",
                                            "Возможна незавершённая репликация SYSVOL (DFSR) или повреждение GPO.",
                                            g["name"], "GPT.INI",
                                            f"AD versionNumber={g['version']}, GPT.INI Version={fs_version}"))

            for rel in sorted(files):
                raw = files[rel]
                if args.show_files:
                    print(f"\n  {C.BOLD}── {rel}{C.RST} ({len(raw)} байт)")
                    print(render_gpo_file(rel, raw))
                findings += check_gpo_file(rel, raw, g["name"], ctx.resolver)
                if rel.lower().endswith("gpttmpl.inf"):
                    pol = inf_password_policy(parse_inf(decode_text(raw)))
                    if pol:
                        gpo_policies.append((g, g_links, pol, rel))
    finally:
        reader.close()

    if unreadable:
        warn(f"Файлы SYSVOL недоступны для {unreadable} GPO (права или путь; подробности: --show-files)")

    # ── Политика паролей ──────────────────────────────────────────────────────
    print(f"\n{C.BOLD}=== Политика паролей ==={C.RST}")
    if ctx.domain_policy:
        print_policy("Действующая политика домена (атрибуты объекта домена)", ctx.domain_policy)
    for pso in ctx.fgpp:
        print_policy(f"FGPP «{pso['name']}» (приоритет {pso['precedence']}, объектов: {len(pso['applies_to'])})",
                     pso["policy"])
    if not args.offline and not ctx.fgpp:
        print(f"\n  {C.DIM}FGPP (Fine-Grained Password Policies) не найдены или нет прав на чтение{C.RST}")

    root = ctx.base_dn.lower()
    for g, g_links, pol, rel in gpo_policies:
        at_root = [en for dn, en, _ in g_links if dn.lower() == root]
        if args.offline:
            note = ""
        elif any(at_root):
            note = " — связана с корнем домена"
        elif at_root:
            note = " — связь с корнем домена ОТКЛЮЧЕНА"
        else:
            note = " — не связана с корнем домена"
        print_policy(f"GPO «{g['name']}»{note}", pol)
        if args.offline:
            if g["guid"] == DEFAULT_DOMAIN_POLICY_GUID:
                findings += check_password_policy(pol, thresholds, g["name"], rel)
        elif not any(at_root):
            findings.append(Finding("INFO", "Параметры паролей в GPO не действуют для доменных учётных записей",
                                    "Политику паролей домена задают только GPO, связанные с корнем домена; "
                                    "здесь параметры влияют лишь на локальные учётные записи компьютеров.",
                                    g["name"], rel, ", ".join(f"{k}={v}" for k, v in pol.items())))
    if args.offline and not any(g["guid"] == DEFAULT_DOMAIN_POLICY_GUID for g, *_ in gpo_policies):
        print(f"\n  {C.DIM}Default Domain Policy не найдена — пороговые проверки паролей пропущены{C.RST}")

    # ── Пользователи ──────────────────────────────────────────────────────────
    if args.users and ctx.conn is not None:
        from gpo_users import (get_all_users, get_all_groups, get_privileged_members, build_user_report,
                               check_accounts, print_user_report)
        info("Загружаю пользователей и группы...")
        users = get_all_users(ctx.conn, ctx.base_dn)
        groups = get_all_groups(ctx.conn, ctx.base_dn)
        ur = build_user_report(users, groups, get_privileged_members(ctx.conn, ctx.base_dn, groups),
                               args.stale_days)
        findings += check_accounts(ur)
        print_user_report(ur, C, show_members=args.show_members)
        report["users"] = {
            "total": ur["total"], "enabled": ur["enabled"], "disabled": ur["disabled"],
            "stale": sorted(u["sam"] for u in ur["stale"]), "privileged": ur["privileged"],
            "groups": [{k: g[k] for k in ("name", "type", "user_count", "users")} for g in ur["groups"]],
        }

    if ctx.conn is not None:
        ctx.conn.unbind()

    findings = sort_findings(findings)
    print_findings(findings, args.min_severity)
    report["password_policy"] = {"domain": ctx.domain_policy, "fgpp": ctx.fgpp}
    report["findings"] = [f.to_dict() for f in findings]
    if args.json:
        write_json(args.json, report)
        ok(f"JSON-отчёт сохранён: {args.json}")
    print()

    if args.fail_on and any(SEV_ORDER[f.severity] <= SEV_ORDER[args.fail_on] for f in findings):
        return 2
    return 0


def main(argv=None) -> int:
    setup_streams()
    args = parse_args(argv)
    setup_colors(args.no_color)
    try:
        return run(args)
    except KeyboardInterrupt:
        err("Прервано пользователем")
        return 130


if __name__ == "__main__":
    sys.exit(main())
