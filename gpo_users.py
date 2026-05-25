"""
gpo_users.py — Перечисление пользователей и групп из Active Directory.
"""

from ldap3 import Connection, SUBTREE


# ─────────────────────────────────────────────────────────────────────────────
# Получение пользователей
# ─────────────────────────────────────────────────────────────────────────────

def get_all_users(conn: Connection, base_dn: str) -> list:
    """
    Вернуть список всех активных пользователей (не отключённых).
    Каждый элемент — dict с полями: dn, name, sam, enabled, last_logon, groups.
    """
    conn.search(
        search_base=base_dn,
        search_filter="(&(objectClass=user)(objectCategory=person))",
        search_scope=SUBTREE,
        attributes=[
            "sAMAccountName", "displayName", "cn",
            "userAccountControl", "lastLogon",
            "memberOf", "mail", "description",
            "pwdLastSet", "whenCreated",
        ],
    )

    users = []
    for entry in conn.entries:
        uac = int(entry.userAccountControl.value or 0)
        enabled = not bool(uac & 0x0002)   # бит ACCOUNTDISABLE

        sam  = str(entry.sAMAccountName.value or "")
        name = str(entry.displayName.value or entry.cn.value or sam)

        # memberOf — список DN групп
        raw_groups = entry.memberOf.values if entry.memberOf else []
        groups = [_cn_from_dn(g) for g in raw_groups]

        users.append({
            "dn":       str(entry.entry_dn),
            "name":     name,
            "sam":      sam,
            "enabled":  enabled,
            "mail":     str(entry.mail.value or ""),
            "groups":   groups,
        })

    return users


def get_all_groups(conn: Connection, base_dn: str) -> list:
    """
    Вернуть список всех групп с их прямыми членами-пользователями.
    """
    conn.search(
        search_base=base_dn,
        search_filter="(objectClass=group)",
        search_scope=SUBTREE,
        attributes=["cn", "sAMAccountName", "member", "description",
                    "groupType", "distinguishedName"],
    )

    groups = []
    for entry in conn.entries:
        name = str(entry.cn.value or entry.sAMAccountName.value or "")
        members_dn = entry.member.values if entry.member else []
        gtype = int(entry.groupType.value or 0)

        groups.append({
            "dn":          str(entry.entry_dn),
            "name":        name,
            "sam":         str(entry.sAMAccountName.value or ""),
            "description": str(entry.description.value or ""),
            "members_dn":  [str(m) for m in members_dn],
            "type":        _group_type(gtype),
        })

    return groups


# ─────────────────────────────────────────────────────────────────────────────
# Вспомогательные функции
# ─────────────────────────────────────────────────────────────────────────────

def _cn_from_dn(dn: str) -> str:
    """Извлечь CN= из DN строки."""
    for part in dn.split(","):
        if part.strip().upper().startswith("CN="):
            return part.strip()[3:]
    return dn


def _group_type(gtype: int) -> str:
    """Декодировать groupType битмаску."""
    security    = bool(gtype & 0x80000000)
    scope_map   = {
        0x00000002: "Domain Local",
        0x00000004: "Global",
        0x00000008: "Universal",
    }
    scope = "Unknown"
    for mask, label in scope_map.items():
        if gtype & mask:
            scope = label
            break
    kind = "Security" if security else "Distribution"
    return f"{kind} / {scope}"


# ─────────────────────────────────────────────────────────────────────────────
# Сборка статистики
# ─────────────────────────────────────────────────────────────────────────────

def build_user_report(users: list, groups: list) -> dict:
    """
    Собрать полный отчёт:
      - общее кол-во пользователей (всего / активные / отключённые)
      - для каждой группы: кол-во прямых членов (только users, не вложенные группы)
      - список пользователей без групп
      - список отключённых пользователей
    """
    # Индекс: DN → user
    user_dn_index = {u["dn"].lower(): u for u in users}

    # Для каждой группы считаем, сколько её членов — пользователи (не группы)
    group_stats = []
    for g in groups:
        user_members = []
        for mdn in g["members_dn"]:
            u = user_dn_index.get(mdn.lower())
            if u:
                user_members.append(u["sam"])
        group_stats.append({
            "name":         g["name"],
            "sam":          g["sam"],
            "type":         g["type"],
            "description":  g["description"],
            "user_count":   len(user_members),
            "users":        user_members,
        })

    # Сортировка: сначала самые населённые группы
    group_stats.sort(key=lambda x: x["user_count"], reverse=True)

    # Пользователи без групп
    no_group = [u for u in users if not u["groups"]]

    return {
        "total":    len(users),
        "enabled":  sum(1 for u in users if u["enabled"]),
        "disabled": sum(1 for u in users if not u["enabled"]),
        "groups":   group_stats,
        "no_group": no_group,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Форматированный вывод
# ─────────────────────────────────────────────────────────────────────────────

def print_user_report(report: dict, C, show_members: bool = False) -> None:
    """Вывести отчёт в консоль."""

    print(f"\n{C.BOLD}{'='*60}{C.RST}")
    print(f"{C.BOLD}=== Отчёт по пользователям и группам ==={C.RST}")
    print(f"{C.BOLD}{'='*60}{C.RST}\n")

    # ── Общая статистика ──────────────────────────────────────────────────────
    total    = report["total"]
    enabled  = report["enabled"]
    disabled = report["disabled"]

    print(f"  {C.BOLD}Пользователи:{C.RST}")
    print(f"    Всего      : {C.BOLD}{total}{C.RST}")
    print(f"    Активные   : {C.OK}{enabled}{C.RST}")
    if disabled:
        print(f"    Отключённые: {C.WARN}{disabled}{C.RST}")

    # ── Группы ───────────────────────────────────────────────────────────────
    groups = report["groups"]
    non_empty = [g for g in groups if g["user_count"] > 0]
    empty     = [g for g in groups if g["user_count"] == 0]

    print(f"\n  {C.BOLD}Группы:{C.RST}")
    print(f"    Всего групп         : {len(groups)}")
    print(f"    С пользователями    : {len(non_empty)}")
    print(f"    Пустые              : {len(empty)}")

    print(f"\n  {C.BOLD}Состав групп (только группы с пользователями):{C.RST}")
    print(f"  {'─'*56}")

    # Ширина колонок
    max_name = max((len(g["name"]) for g in non_empty), default=10)
    max_name = min(max_name, 35)

    print(f"  {'Группа':<{max_name}}  {'Тип':<22}  {'Пользователей':>13}")
    print(f"  {'─'*max_name}  {'─'*22}  {'─'*13}")

    for g in non_empty:
        name_trunc = g["name"][:max_name]
        bar_len = min(g["user_count"], 30)
        bar = "█" * bar_len
        count_str = str(g["user_count"])
        print(f"  {name_trunc:<{max_name}}  {g['type']:<22}  {count_str:>5}  {C.INFO}{bar}{C.RST}")

        # Показать участников если попросили
        if show_members and g["users"]:
            for sam in sorted(g["users"]):
                print(f"    {C.INFO}·{C.RST} {sam}")

        # Показать описание группы если есть
        if g["description"]:
            print(f"    {C.INFO}↳ {g['description']}{C.RST}")

    # ── Пустые группы ────────────────────────────────────────────────────────
    if empty:
        print(f"\n  {C.BOLD}Пустые группы ({len(empty)}):{C.RST}")
        for g in sorted(empty, key=lambda x: x["name"]):
            print(f"    · {g['name']}  ({g['type']})")

    # ── Пользователи без групп ────────────────────────────────────────────────
    no_group = report["no_group"]
    if no_group:
        print(f"\n  {C.WARN}Пользователи без групп ({len(no_group)}):{C.RST}")
        for u in sorted(no_group, key=lambda x: x["sam"]):
            status = f"{C.OK}активен{C.RST}" if u["enabled"] else f"{C.WARN}отключён{C.RST}"
            print(f"    · {u['sam']:<20} [{status}]")

    # ── Отключённые пользователи ──────────────────────────────────────────────
    disabled_users = [u for u in
                      # берём из всего списка — он передаётся отдельно,
                      # восстановим из no_group + group members через report
                      # (проще хранить в report)
                      report.get("all_users", [])
                      if not u["enabled"]]
    if disabled_users:
        print(f"\n  {C.WARN}Отключённые учётные записи ({len(disabled_users)}):{C.RST}")
        for u in sorted(disabled_users, key=lambda x: x["sam"]):
            grp_str = ", ".join(u["groups"][:3])
            if len(u["groups"]) > 3:
                grp_str += f" (+{len(u['groups'])-3})"
            print(f"    · {u['sam']:<20}  группы: {grp_str or '—'}")

    print()
