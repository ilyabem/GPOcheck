"""
gpo_users.py — пользователи и группы Active Directory.

  - постраничный поиск (AD отдаёт не больше 1000 объектов за запрос)
  - учёт основной группы (primaryGroupID): «Domain Users» не попадает в memberOf
  - рекурсивный состав привилегированных групп (LDAP_MATCHING_RULE_IN_CHAIN)
  - проверки учётных записей: AS-REP roasting, Kerberoasting, делегирование и т.п.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

from ldap3 import SUBTREE, BASE
from ldap3.utils.conv import escape_filter_chars

from gpo_checks import Finding, sid_rid

# userAccountControl
UAC_ACCOUNTDISABLE = 0x0002
UAC_PASSWD_NOTREQD = 0x0020
UAC_ENCRYPTED_TEXT_PWD_ALLOWED = 0x0080
UAC_DONT_EXPIRE_PASSWORD = 0x10000
UAC_TRUSTED_FOR_DELEGATION = 0x80000
UAC_NOT_DELEGATED = 0x100000
UAC_USE_DES_KEY_ONLY = 0x200000
UAC_DONT_REQ_PREAUTH = 0x400000
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000

PRIVILEGED_GROUP_RIDS = {512: "Domain Admins", 519: "Enterprise Admins", 518: "Schema Admins", 526: "Key Admins",
                         527: "Enterprise Key Admins"}
PRIVILEGED_BUILTIN = {"S-1-5-32-544": "Administrators", "S-1-5-32-548": "Account Operators",
                      "S-1-5-32-549": "Server Operators", "S-1-5-32-550": "Print Operators",
                      "S-1-5-32-551": "Backup Operators"}
EXTRA_PRIVILEGED_CN = ("DnsAdmins", "Group Policy Creator Owners")

_EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)


# ─────────────────────────────────────────────────────────────────────────────
# LDAP-утилиты
# ─────────────────────────────────────────────────────────────────────────────

def paged_search(conn, base: str, flt: str, attributes: list, scope=SUBTREE, page_size: int = 500,
                 controls=None) -> list:
    """Постраничный поиск. Возвращает [{'dn', 'attributes', 'raw_attributes'}]."""
    results = conn.extend.standard.paged_search(
        search_base=base, search_filter=flt, search_scope=scope, attributes=attributes,
        paged_size=page_size, controls=controls, generator=True)
    return [r for r in results if r.get("type") == "searchResEntry"]


def first(attrs: dict, name: str, default=None):
    v = attrs.get(name, default)
    if isinstance(v, list):
        return v[0] if v else default
    return v if v not in (None, "") else default


def as_list(attrs: dict, name: str) -> list:
    v = attrs.get(name)
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def filetime_to_dt(v):
    """FILETIME (int или datetime от ldap3) -> datetime UTC или None (0 / никогда)."""
    if isinstance(v, datetime):
        if v.year <= 1601:
            return None
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    try:
        v = int(v)
    except (TypeError, ValueError):
        return None
    if v <= 0 or v >= 0x7FFFFFFFFFFFFFFF:
        return None
    return _EPOCH_1601 + timedelta(microseconds=v // 10)


def _cn_from_dn(dn: str) -> str:
    """Извлечь значение первого RDN (CN=...) с учётом экранированных запятых."""
    part, i = [], 0
    while i < len(dn):
        ch = dn[i]
        if ch == "\\" and i + 1 < len(dn):
            part.append(dn[i + 1])
            i += 2
            continue
        if ch == ",":
            break
        part.append(ch)
        i += 1
    rdn = "".join(part)
    return rdn.split("=", 1)[1] if "=" in rdn else rdn


def _group_type(gtype: int) -> str:
    """Декодировать битовую маску groupType."""
    security = bool(gtype & 0x80000000)
    scope = "Unknown"
    if gtype & 0x1:
        scope = "Builtin"
    elif gtype & 0x2:
        scope = "Global"
    elif gtype & 0x4:
        scope = "Domain Local"
    elif gtype & 0x8:
        scope = "Universal"
    return f"{'Security' if security else 'Distribution'} / {scope}"


# ─────────────────────────────────────────────────────────────────────────────
# Получение данных
# ─────────────────────────────────────────────────────────────────────────────

USER_ATTRS = ["sAMAccountName", "displayName", "cn", "userAccountControl", "memberOf", "primaryGroupID",
              "lastLogonTimestamp", "pwdLastSet", "adminCount", "servicePrincipalName", "objectSid",
              "whenCreated", "msDS-AllowedToDelegateTo", "mail"]


def get_all_users(conn, base_dn: str) -> list:
    users = []
    for r in paged_search(conn, base_dn, "(&(objectCategory=person)(objectClass=user))", USER_ATTRS):
        a = r["attributes"]
        # userAccountControl может быть недоступен на чтение (ограниченные ACL) — тогда состояние неизвестно
        raw_uac = first(a, "userAccountControl")
        uac = int(raw_uac) if raw_uac is not None else 0
        sam = str(first(a, "sAMAccountName", "") or "")
        users.append({
            "dn": r["dn"],
            "sam": sam,
            "name": str(first(a, "displayName") or first(a, "cn") or sam),
            "uac": uac,
            "uac_known": raw_uac is not None,
            "enabled": raw_uac is not None and not uac & UAC_ACCOUNTDISABLE,
            "created": filetime_to_dt(first(a, "whenCreated")),
            "groups_dn": [str(g) for g in as_list(a, "memberOf")],
            "primary_group_id": int(first(a, "primaryGroupID", 0) or 0),
            "last_logon": filetime_to_dt(first(a, "lastLogonTimestamp")),
            "pwd_last_set": filetime_to_dt(first(a, "pwdLastSet")),
            "admin_count": int(first(a, "adminCount", 0) or 0),
            "spns": [str(s) for s in as_list(a, "servicePrincipalName")],
            "sid": str(first(a, "objectSid", "") or ""),
            "delegate_to": [str(s) for s in as_list(a, "msDS-AllowedToDelegateTo")],
            "mail": str(first(a, "mail", "") or ""),
        })
    return users


def get_all_groups(conn, base_dn: str) -> list:
    groups = []
    for r in paged_search(conn, base_dn, "(objectClass=group)",
                          ["cn", "sAMAccountName", "member", "description", "groupType", "objectSid"]):
        a = r["attributes"]
        groups.append({
            "dn": r["dn"],
            "name": str(first(a, "cn") or first(a, "sAMAccountName") or _cn_from_dn(r["dn"])),
            "sam": str(first(a, "sAMAccountName", "") or ""),
            "description": str(first(a, "description", "") or ""),
            "members_dn": [str(m) for m in as_list(a, "member")],
            "type": _group_type(int(first(a, "groupType", 0) or 0)),
            "sid": str(first(a, "objectSid", "") or ""),
        })
    return groups


def get_privileged_members(conn, base_dn: str, groups: list) -> dict:
    """Рекурсивный состав привилегированных групп: {имя группы: [sAMAccountName, ...]}."""
    targets = []
    for g in groups:
        rid = sid_rid(g["sid"])
        if rid in PRIVILEGED_GROUP_RIDS or g["sid"].upper() in PRIVILEGED_BUILTIN or g["name"] in EXTRA_PRIVILEGED_CN:
            targets.append(g)
    result = {}
    for g in targets:
        flt = (f"(&(objectCategory=person)(objectClass=user)"
               f"(memberOf:1.2.840.113556.1.4.1941:={escape_filter_chars(g['dn'])}))")
        members = paged_search(conn, base_dn, flt, ["sAMAccountName"])
        result[g["name"]] = sorted(str(first(m["attributes"], "sAMAccountName", m["dn"])) for m in members)
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Сборка отчёта
# ─────────────────────────────────────────────────────────────────────────────

def build_user_report(users: list, groups: list, privileged: dict | None = None,
                      stale_days: int = 90, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    user_by_dn = {u["dn"].lower(): u for u in users}
    group_by_rid = {sid_rid(g["sid"]): g for g in groups if sid_rid(g["sid"]) is not None}

    group_stats = []
    for g in groups:
        members = [user_by_dn[m.lower()]["sam"] for m in g["members_dn"] if m.lower() in user_by_dn]
        rid = sid_rid(g["sid"])
        primary = [u["sam"] for u in users if rid is not None and u["primary_group_id"] == rid]
        group_stats.append({
            "name": g["name"], "sam": g["sam"], "type": g["type"], "description": g["description"],
            "users": sorted(set(members) | set(primary)),
            "user_count": len(set(members) | set(primary)),
            "nested_groups": sum(1 for m in g["members_dn"] if m.lower() not in user_by_dn),
        })
    group_stats.sort(key=lambda x: (-x["user_count"], x["name"].lower()))

    for u in users:
        names = [_cn_from_dn(d) for d in u["groups_dn"]]
        pg = group_by_rid.get(u["primary_group_id"])
        if pg and pg["name"] not in names:
            names.insert(0, pg["name"])
        u["groups"] = names

    stale_before = now - timedelta(days=stale_days)
    never = datetime.min.replace(tzinfo=timezone.utc)
    enabled = [u for u in users if u["enabled"]]
    disabled = [u for u in users if u["uac_known"] and not u["enabled"]]
    return {
        "total": len(users),
        "enabled": len(enabled),
        "disabled": len(disabled),
        "unknown": len(users) - len(enabled) - len(disabled),
        "stale_days": stale_days,
        # без входа ни разу — считаем от даты создания, чтобы не помечать только что созданные учётки
        "stale": [u for u in enabled if (u["last_logon"] or u.get("created") or never) < stale_before],
        "groups": group_stats,
        "only_primary_group": [u for u in users if not u["groups_dn"]],
        "disabled_users": disabled,
        "privileged": privileged or {},
        "all_users": users,
    }


def check_accounts(report: dict, now: datetime | None = None) -> list:
    """Проверки гигиены учётных записей. Отключённые учётки не учитываются (кроме krbtgt)."""
    now = now or datetime.now(timezone.utc)
    findings = []
    privileged_sams = {s.lower() for members in report["privileged"].values() for s in members}

    def add(sev, title, desc, users_list):
        if users_list:
            sams = sorted(u["sam"] for u in users_list)
            shown = ", ".join(sams[:15]) + (f" (+{len(sams) - 15})" if len(sams) > 15 else "")
            findings.append(Finding(sev, f"{title} ({len(sams)})", desc, "", "", shown, "Учётные записи"))

    active = [u for u in report["all_users"] if u["enabled"]]
    add("HIGH", "Не требуется предварительная аутентификация Kerberos",
        "DONT_REQ_PREAUTH: хеш пароля можно получить без учётных данных (AS-REP roasting).",
        [u for u in active if u["uac"] & UAC_DONT_REQ_PREAUTH])
    add("HIGH", "Обратимое шифрование пароля у учётной записи",
        "ENCRYPTED_TEXT_PWD_ALLOWED: пароль восстанавливается в открытом виде.",
        [u for u in active if u["uac"] & UAC_ENCRYPTED_TEXT_PWD_ALLOWED])
    add("HIGH", "Неограниченное делегирование Kerberos у пользователя",
        "TRUSTED_FOR_DELEGATION: сервис получает TGT любого подключившегося пользователя.",
        [u for u in active if u["uac"] & UAC_TRUSTED_FOR_DELEGATION])
    add("MEDIUM", "Ограниченное делегирование с переходом протокола",
        "TRUSTED_TO_AUTH_FOR_DELEGATION (S4U2Self) — проверьте msDS-AllowedToDelegateTo.",
        [u for u in active if u["uac"] & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION])
    add("MEDIUM", "Пароль не обязателен (PASSWD_NOTREQD)",
        "Учётной записи может быть задан пустой пароль.",
        [u for u in active if u["uac"] & UAC_PASSWD_NOTREQD])
    add("MEDIUM", "Только DES-шифрование Kerberos", "USE_DES_KEY_ONLY.",
        [u for u in active if u["uac"] & UAC_USE_DES_KEY_ONLY])

    kerberoastable = [u for u in active if u["spns"] and u["sam"].lower() != "krbtgt"]
    add("HIGH", "Kerberoasting: привилегированные учётные записи с SPN",
        "Любой пользователь домена может запросить билет и подобрать пароль офлайн.",
        [u for u in kerberoastable if u["sam"].lower() in privileged_sams or u["admin_count"]])
    add("MEDIUM", "Kerberoasting: учётные записи с SPN",
        "Любой пользователь домена может запросить билет и подобрать пароль офлайн. Используйте gMSA или пароль 25+ символов.",
        [u for u in kerberoastable if not (u["sam"].lower() in privileged_sams or u["admin_count"])])

    priv_users = [u for u in active if u["sam"].lower() in privileged_sams]
    add("MEDIUM", "Привилегированные учётные записи с бессрочным паролем",
        "DONT_EXPIRE_PASSWORD у членов административных групп.",
        [u for u in priv_users if u["uac"] & UAC_DONT_EXPIRE_PASSWORD])
    add("MEDIUM", f"Неактивные привилегированные учётные записи (>{report['stale_days']} дн)",
        "Отключите или удалите неиспользуемые административные учётные записи.",
        [u for u in report["stale"] if u["sam"].lower() in privileged_sams])
    add("LOW", "Привилегированные учётные записи без флага «не делегируется»",
        "Рекомендуется NOT_DELEGATED или группа Protected Users для администраторов.",
        [u for u in priv_users if not u["uac"] & UAC_NOT_DELEGATED])
    add("LOW", f"Неактивные учётные записи (>{report['stale_days']} дн)",
        "Включённые учётные записи без входа в течение заданного срока.",
        [u for u in report["stale"] if u["sam"].lower() not in privileged_sams])

    for u in report["all_users"]:
        if u["sam"].lower() == "krbtgt" and u["pwd_last_set"]:
            age = (now - u["pwd_last_set"]).days
            if age > 180:
                findings.append(Finding("MEDIUM", f"Пароль krbtgt не менялся {age} дн",
                                        "Рекомендуется менять дважды не реже раза в 180 дней (защита от Golden Ticket).",
                                        "", "", f"pwdLastSet = {u['pwd_last_set']:%Y-%m-%d}", "Учётные записи"))
        if u["sam"].lower() == "guest" and u["enabled"]:
            findings.append(Finding("HIGH", "Учётная запись Guest включена", "", "", "", "Guest",
                                    "Учётные записи"))
    return findings


def get_machine_account_quota(conn, base_dn: str):
    conn.search(base_dn, "(objectClass=*)", BASE, attributes=["ms-DS-MachineAccountQuota"])
    if conn.entries:
        v = conn.entries[0]["ms-DS-MachineAccountQuota"].value
        return int(v) if v is not None else None
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Форматированный вывод
# ─────────────────────────────────────────────────────────────────────────────

def print_user_report(report: dict, C, show_members: bool = False) -> None:
    print(f"\n{C.BOLD}=== Пользователи и группы ==={C.RST}\n")
    print(f"  {C.BOLD}Пользователи:{C.RST}")
    print(f"    Всего       : {C.BOLD}{report['total']}{C.RST}")
    print(f"    Активные    : {C.OK}{report['enabled']}{C.RST}")
    print(f"    Отключённые : {C.WARN if report['disabled'] else ''}{report['disabled']}{C.RST}")
    if report.get("unknown"):
        print(f"    Состояние неизвестно (нет прав на userAccountControl): {report['unknown']}")
    print(f"    Неактивные >{report['stale_days']} дн (включённые): {len(report['stale'])}")

    if report["privileged"]:
        print(f"\n  {C.BOLD}Привилегированные группы (с учётом вложенности):{C.RST}")
        for gname, members in sorted(report["privileged"].items()):
            print(f"    {gname:<30} {len(members):>4}")
            if show_members:
                for sam in members:
                    print(f"      {C.INFO}·{C.RST} {sam}")

    groups = report["groups"]
    non_empty = [g for g in groups if g["user_count"] > 0]
    empty = [g for g in groups if g["user_count"] == 0]
    print(f"\n  {C.BOLD}Группы:{C.RST} всего {len(groups)}, с пользователями {len(non_empty)}, "
          f"без пользователей {len(empty)}")

    if non_empty:
        w = min(max(len(g["name"]) for g in non_empty), 35)
        print(f"\n  {'Группа':<{w}}  {'Тип':<26}  {'Польз.':>6}")
        print(f"  {'─' * w}  {'─' * 26}  {'─' * 6}")
        max_count = max(g["user_count"] for g in non_empty)
        for g in non_empty:
            bar = "█" * max(1, round(g["user_count"] / max_count * 30))
            print(f"  {g['name'][:w]:<{w}}  {g['type']:<26}  {g['user_count']:>6}  {C.INFO}{bar}{C.RST}")
            if show_members:
                for sam in g["users"]:
                    print(f"      {C.INFO}·{C.RST} {sam}")

    if empty and show_members:
        print(f"\n  {C.BOLD}Группы без пользователей ({len(empty)}):{C.RST}")
        for g in sorted(empty, key=lambda x: x["name"].lower()):
            nested = f", вложенных групп: {g['nested_groups']}" if g["nested_groups"] else ""
            print(f"    · {g['name']}  ({g['type']}{nested})")

    only_primary = report["only_primary_group"]
    if only_primary:
        print(f"\n  {C.BOLD}Только в основной группе ({len(only_primary)}):{C.RST}")
        for u in sorted(only_primary, key=lambda x: x["sam"].lower()):
            status = (f"{C.OK}активен{C.RST}" if u["enabled"] else
                      f"{C.WARN}отключён{C.RST}" if u["uac_known"] else "неизвестно")
            print(f"    · {u['sam']:<24} [{status}]  {', '.join(u['groups']) or '—'}")

    disabled = report["disabled_users"]
    if disabled:
        print(f"\n  {C.WARN}Отключённые учётные записи ({len(disabled)}):{C.RST}")
        for u in sorted(disabled, key=lambda x: x["sam"].lower()):
            grp = ", ".join(u["groups"][:3]) + (f" (+{len(u['groups']) - 3})" if len(u["groups"]) > 3 else "")
            print(f"    · {u['sam']:<24} группы: {grp or '—'}")
    print()
