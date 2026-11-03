"""
gpo_ldap.py — работа с Active Directory по LDAP.

  - подключение (NTLM / Kerberos, LDAP / LDAPS, автопереход на LDAPS при обязательной подписи)
  - перечисление GPO и их связей (gPLink), действующая политика паролей домена и FGPP
  - анализ прав (nTSecurityDescriptor) на объекты GPO
"""

from __future__ import annotations

import re
import ssl

from gpo_checks import Finding, is_broad_principal, is_privileged_principal, sid_name
from gpo_sysvol import split_username
from gpo_users import paged_search, first


class ConnectError(Exception):
    pass


def get_base_dn(domain: str) -> str:
    return ",".join(f"DC={p}" for p in domain.split(".") if p)


def connect_ldap(args, use_ssl: bool):
    from ldap3 import Server, Connection, ALL, NTLM, SASL, KERBEROS, Tls
    from ldap3.core.exceptions import LDAPException

    port = args.ldap_port or (636 if use_ssl else 389)
    tls = Tls(validate=ssl.CERT_NONE) if use_ssl else None
    server = Server(args.dc, port=port, use_ssl=use_ssl, get_info=ALL, tls=tls, connect_timeout=args.timeout)
    try:
        if args.kerberos:
            conn = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS,
                              receive_timeout=args.timeout * 6, raise_exceptions=False)
        else:
            user, dom = split_username(args.username, args.domain)
            conn = Connection(server, user=f"{dom}\\{user}", password=args.password, authentication=NTLM,
                              receive_timeout=args.timeout * 6, raise_exceptions=False)
        if not conn.bind():
            res = conn.result or {}
            raise ConnectError(f"{res.get('description', 'bind failed')}: {res.get('message', '').strip()}")
    except LDAPException as e:
        raise ConnectError(f"{type(e).__name__}: {e}") from e
    return conn


def connect_ad(args, on_fallback=None):
    """Подключиться к LDAP; если DC требует подпись (strongerAuthRequired) — перейти на LDAPS."""
    try:
        return connect_ldap(args, args.ldaps)
    except ConnectError as e:
        msg = str(e)
        if args.ldaps or args.ldap_port:
            raise
        if "strongerAuthRequired" in msg or "integrity" in msg.lower():
            if on_fallback:
                on_fallback()
            args.ldaps = True
            return connect_ldap(args, True)
        raise


def resolve_sids(conn, base_dn: str, sids) -> dict:
    """SID домена -> sAMAccountName (через LDAP). Известные SID разрешаются в gpo_checks.sid_name."""
    out = {}
    pending = sorted({s for s in sids if s and s.upper().startswith("S-1-5-21-")})
    for i in range(0, len(pending), 40):
        flt = "(|" + "".join(f"(objectSid={s})" for s in pending[i:i + 40]) + ")"
        try:
            for r in paged_search(conn, base_dn, flt, ["sAMAccountName", "objectSid"]):
                a = r["attributes"]
                out[str(first(a, "objectSid"))] = str(first(a, "sAMAccountName", r["dn"]))
        except Exception:
            pass
    return out


def parse_gplinks(entries) -> dict:
    """[(dn, gPLink)] -> {GUID upper: [(dn контейнера, связь включена, принудительная)]}."""
    links = {}
    for dn, gplink in entries:
        for path, opts in re.findall(r"\[LDAP://([^;\]]+);(\d+)\]", gplink or "", re.IGNORECASE):
            m = re.search(r"cn=(\{[0-9a-f-]+\})", path, re.IGNORECASE)
            if not m:
                continue
            o = int(opts)
            links.setdefault(m.group(1).upper(), []).append((dn, not o & 1, bool(o & 2)))
    return links


def get_gpo_links(conn, base_dn: str, config_nc: str | None) -> dict:
    rows = []
    for base in [base_dn] + ([f"CN=Sites,{config_nc}"] if config_nc else []):
        try:
            for r in paged_search(conn, base, "(gPLink=*)", ["gPLink"]):
                rows.append((r["dn"], first(r["attributes"], "gPLink")))
        except Exception:
            pass
    return parse_gplinks(rows)


GPO_ATTRS = ["displayName", "cn", "gPCFileSysPath", "versionNumber", "flags", "whenCreated", "whenChanged",
             "nTSecurityDescriptor"]


def get_gpos(conn, base_dn: str) -> list:
    from ldap3.protocol.microsoft import security_descriptor_control
    # sdflags=OWNER|DACL: без этого контроля непривилегированный пользователь не получает дескриптор
    rows = paged_search(conn, f"CN=Policies,CN=System,{base_dn}", "(objectClass=groupPolicyContainer)",
                        GPO_ATTRS, controls=security_descriptor_control(sdflags=0x05))
    gpos = []
    for r in rows:
        a, raw = r["attributes"], r.get("raw_attributes", {})
        sd = raw.get("nTSecurityDescriptor")
        gpos.append({
            "name": str(first(a, "displayName") or first(a, "cn") or "?"),
            "guid": str(first(a, "cn") or "").upper(),
            "path": str(first(a, "gPCFileSysPath") or ""),
            "version": int(first(a, "versionNumber", 0) or 0),
            "flags": int(first(a, "flags", 0) or 0),
            "created": first(a, "whenCreated"),
            "changed": first(a, "whenChanged"),
            "sd": sd[0] if isinstance(sd, list) and sd else None,
        })
    gpos.sort(key=lambda g: g["name"].lower())
    return gpos


# ── Политика паролей домена и FGPP ────────────────────────────────────────────
_TICKS_DAY = 864_000_000_000
_TICKS_MIN = 600_000_000
_NEVER = -0x8000000000000000
_MISSING = object()


def _raw_int(raw_attrs: dict, name: str):
    v = raw_attrs.get(name)
    if isinstance(v, list):
        v = v[0] if v else None
    if v is None:
        return None
    try:
        return int(v.decode() if isinstance(v, bytes) else v)
    except ValueError:
        return None


def _interval(v, unit):
    """Отрицательный интервал AD в 100-нс тиках -> дни/минуты; None = «никогда»."""
    if v is None:
        return _MISSING
    if v in (0, _NEVER):
        return None
    return abs(v) // unit


def normalize_ad_policy(raw: dict, pso: bool = False) -> dict:
    """Политика из объекта домена (pso=False) или PSO (pso=True) в формат gpo_checks.check_password_policy."""
    i = 1 if pso else 0
    policy = {}
    for field, pair in (("min_length", ("minPwdLength", "msDS-MinimumPasswordLength")),
                        ("history", ("pwdHistoryLength", "msDS-PasswordHistoryLength")),
                        ("lockout_threshold", ("lockoutThreshold", "msDS-LockoutThreshold"))):
        v = _raw_int(raw, pair[i])
        if v is not None:
            policy[field] = v
    for field, pair, unit in (("max_age_days", ("maxPwdAge", "msDS-MaximumPasswordAge"), _TICKS_DAY),
                              ("min_age_days", ("minPwdAge", "msDS-MinimumPasswordAge"), _TICKS_DAY),
                              ("lockout_duration_min", ("lockoutDuration", "msDS-LockoutDuration"), _TICKS_MIN),
                              ("lockout_window_min", ("lockOutObservationWindow", "msDS-LockoutObservationWindow"), _TICKS_MIN)):
        v = _interval(_raw_int(raw, pair[i]), unit)
        if v is not _MISSING:
            policy[field] = v
    if "lockout_duration_min" in policy and policy["lockout_duration_min"] is None:
        policy["lockout_duration_min"] = 0          # «до разблокировки администратором»
    if "lockout_window_min" in policy and policy["lockout_window_min"] is None:
        del policy["lockout_window_min"]
    if pso:
        for field, attr in (("complexity", "msDS-PasswordComplexityEnabled"),
                            ("reversible", "msDS-PasswordReversibleEncryptionEnabled")):
            v = raw.get(attr)
            v = v[0] if isinstance(v, list) and v else v
            if v is not None:
                policy[field] = int((v.decode() if isinstance(v, bytes) else str(v)).upper() == "TRUE")
    else:
        props = _raw_int(raw, "pwdProperties")
        if props is not None:
            policy["complexity"] = int(bool(props & 0x1))
            policy["reversible"] = int(bool(props & 0x10))
    return policy


def get_domain_info(conn, base_dn: str):
    """-> (политика паролей домена, SID домена, ms-DS-MachineAccountQuota)."""
    from ldap3 import BASE
    attrs = ["minPwdLength", "pwdProperties", "maxPwdAge", "minPwdAge", "pwdHistoryLength", "lockoutThreshold",
             "lockoutDuration", "lockOutObservationWindow", "objectSid", "ms-DS-MachineAccountQuota"]
    rows = paged_search(conn, base_dn, "(objectClass=domain)", attrs, scope=BASE)
    if not rows:
        return {}, None, None
    a, raw = rows[0]["attributes"], rows[0]["raw_attributes"]
    sid = first(a, "objectSid")
    return normalize_ad_policy(raw), (str(sid) if sid else None), _raw_int(raw, "ms-DS-MachineAccountQuota")


def get_fgpp(conn, base_dn: str) -> list:
    """Fine-Grained Password Policies (по умолчанию читаются только администраторами)."""
    attrs = ["cn", "msDS-PasswordSettingsPrecedence", "msDS-PSOAppliesTo", "msDS-MinimumPasswordLength",
             "msDS-PasswordComplexityEnabled", "msDS-MaximumPasswordAge", "msDS-MinimumPasswordAge",
             "msDS-PasswordHistoryLength", "msDS-LockoutThreshold", "msDS-LockoutDuration",
             "msDS-LockoutObservationWindow", "msDS-PasswordReversibleEncryptionEnabled"]
    try:
        rows = paged_search(conn, f"CN=Password Settings Container,CN=System,{base_dn}",
                            "(objectClass=msDS-PasswordSettings)", attrs)
    except Exception:
        return []
    out = []
    for r in rows:
        a = r["attributes"]
        out.append({
            "name": str(first(a, "cn", "?")),
            "precedence": first(a, "msDS-PasswordSettingsPrecedence"),
            "applies_to": [str(x) for x in (a.get("msDS-PSOAppliesTo") or [])],
            "policy": normalize_ad_policy(r["raw_attributes"], pso=True),
        })
    return sorted(out, key=lambda x: x["precedence"] or 0)


# ── Права на объекты GPO ──────────────────────────────────────────────────────
_GENERIC_ALL, _GENERIC_WRITE = 0x10000000, 0x40000000
_WRITE_DAC, _WRITE_OWNER, _WRITE_PROP = 0x00040000, 0x00080000, 0x00000020
# schemaIDGUID атрибутов, изменение которых даёт контроль над тем, что применяет GPO
GPO_SENSITIVE_ATTRS = {
    "f30e3bc1-9ff0-11d1-b603-0000f80367c1": "gPCFileSysPath",
    "32ff8ecc-783f-11d2-9916-0000f87a57d4": "gPCMachineExtensionNames",
    "42a75fc6-783f-11d2-9916-0000f87a57d4": "gPCUserExtensionNames",
}


def gpo_acl_writers(sd_bytes: bytes):
    """
    Разобрать nTSecurityDescriptor GPO.
    -> (SID владельца, {SID: [права]}) — только субъекты, которые могут изменить GPO.
    """
    from impacket.ldap import ldaptypes
    from impacket.uuid import bin_to_string

    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_bytes)
    owner = sd["OwnerSid"].formatCanonical() if sd["OwnerSid"] else None
    if not sd["Dacl"]:
        return owner, {"S-1-1-0": ["NULL DACL"]}
    writers = {}
    for ace in sd["Dacl"].aces:
        # только ACCESS_ALLOWED / ACCESS_ALLOWED_OBJECT, без INHERIT_ONLY
        if ace["AceType"] not in (0x00, 0x05) or ace["AceFlags"] & 0x08:
            continue
        mask = ace["Ace"]["Mask"]["Mask"]
        rights = [name for bit, name in ((_GENERIC_ALL, "GenericAll"), (_GENERIC_WRITE, "GenericWrite"),
                                         (_WRITE_DAC, "WriteDacl"), (_WRITE_OWNER, "WriteOwner")) if mask & bit]
        if mask & _WRITE_PROP:
            obj = None
            if ace["AceType"] == 0x05 and ace["Ace"]["Flags"] & 0x1:
                obj = bin_to_string(ace["Ace"]["ObjectType"]).lower()
            if obj is None:
                rights.append("WriteProperty")
            elif obj in GPO_SENSITIVE_ATTRS:
                rights.append(f"WriteProperty({GPO_SENSITIVE_ATTRS[obj]})")
        if rights:
            writers.setdefault(ace["Ace"]["Sid"].formatCanonical(), []).extend(rights)
    return owner, writers


def check_gpo_acl(gpo: dict, resolver: dict) -> list:
    if not gpo.get("sd"):
        return []
    try:
        owner, writers = gpo_acl_writers(gpo["sd"])
    except ImportError:
        return []
    except Exception as e:
        return [Finding("INFO", "Не удалось разобрать права на GPO", str(e), gpo["name"], category="Права на GPO")]

    def label(sid):
        name = resolver.get(sid) or sid_name(sid)
        return f"{name} ({sid})" if name != sid else sid

    out = []
    for sid, rights in writers.items():
        if is_privileged_principal(sid):
            continue
        r = ", ".join(sorted(set(rights)))
        if is_broad_principal(sid):
            out.append(Finding("CRITICAL", "Широкая группа может изменять GPO",
                               "Любой участник группы может добавить в политику свои настройки "
                               "и получить контроль над компьютерами в области её действия.",
                               gpo["name"], "", f"{label(sid)}: {r}", "Права на GPO"))
        else:
            out.append(Finding("MEDIUM", "Делегированы права на изменение GPO",
                               "Убедитесь, что субъект должен управлять политикой: его компрометация "
                               "даёт контроль над компьютерами в области действия GPO.",
                               gpo["name"], "", f"{label(sid)}: {r}", "Права на GPO"))
    if owner and not is_privileged_principal(owner):
        out.append(Finding("HIGH" if is_broad_principal(owner) else "LOW",
                           "Владелец GPO — непривилегированный субъект",
                           "Владелец объекта неявно может менять его права (DACL).",
                           gpo["name"], "", label(owner), "Права на GPO"))
    return out
