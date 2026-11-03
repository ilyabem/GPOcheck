import unittest
from datetime import datetime, timedelta, timezone

from helpers import make_sd, sid_bytes

from ldap3 import Server, Connection, MOCK_SYNC, OFFLINE_AD_2012_R2

from gpo_ldap import (parse_gplinks, normalize_ad_policy, gpo_acl_writers, check_gpo_acl, GPO_SENSITIVE_ATTRS,
                      get_domain_info, get_gpos, get_gpo_links, resolve_sids)
from gpo_sysvol import split_username
from gpo_users import (get_all_users, get_all_groups, build_user_report, check_accounts, filetime_to_dt,
                       _cn_from_dn, _group_type)

DOM = "S-1-5-21-1-2-3"
BASE = "DC=AD2012,DC=LAB"
GA, GW, WD, RP = 0x10000000, 0x40000000, 0x00040000, 0x00020094   # GenericAll, GenericWrite, WriteDacl, Read


def mock_conn():
    server = Server("dc", get_info=OFFLINE_AD_2012_R2)
    conn = Connection(server, user=f"CN=admin,{BASE}", password="x", client_strategy=MOCK_SYNC)
    conn.strategy.add_entry(f"CN=admin,{BASE}", {"userPassword": "x", "objectClass": "user"})
    conn.bind()
    return conn


def add_user(conn, sam, rid, uac=512, groups=(), pgid=513, **extra):
    attrs = {"objectClass": ["top", "person", "user"], "objectCategory": "person", "sAMAccountName": sam,
             "userAccountControl": uac, "primaryGroupID": pgid, "objectSid": sid_bytes(f"{DOM}-{rid}"),
             "memberOf": list(groups), "whenCreated": "20200101000000.0Z"}
    if uac is None:
        del attrs["userAccountControl"]
    attrs.update(extra)
    conn.strategy.add_entry(f"CN={sam},CN=Users,{BASE}", attrs, validate=False)


def add_group(conn, name, rid, members=(), sid=None):
    conn.strategy.add_entry(f"CN={name},CN=Users,{BASE}", {
        "objectClass": ["top", "group"], "cn": name, "sAMAccountName": name, "member": list(members),
        "groupType": -2147483646, "objectSid": sid_bytes(sid or f"{DOM}-{rid}")}, validate=False)


class GpLinkTest(unittest.TestCase):
    def test_parse(self):
        links = parse_gplinks([
            (BASE, "[LDAP://cn={AAAAAAAA-0000-0000-0000-000000000001},cn=policies,cn=system,DC=x;0]"
                   "[LDAP://CN={AAAAAAAA-0000-0000-0000-000000000002},CN=Policies,CN=System,DC=x;1]"),
            (f"OU=Srv,{BASE}", "[LDAP://cn={aaaaaaaa-0000-0000-0000-000000000001},cn=policies,cn=system,DC=x;2]"),
            (f"OU=Bad,{BASE}", "garbage"), (f"OU=None,{BASE}", None),
        ])
        self.assertEqual(links["{AAAAAAAA-0000-0000-0000-000000000001}"],
                         [(BASE, True, False), (f"OU=Srv,{BASE}", True, True)])
        self.assertEqual(links["{AAAAAAAA-0000-0000-0000-000000000002}"], [(BASE, False, False)])


class AdPolicyTest(unittest.TestCase):
    def test_domain_object(self):
        raw = {"minPwdLength": [b"7"], "pwdProperties": [b"17"], "maxPwdAge": [b"-36288000000000"],
               "minPwdAge": [b"-864000000000"], "pwdHistoryLength": [b"24"], "lockoutThreshold": [b"0"],
               "lockoutDuration": [b"-6000000000"], "lockOutObservationWindow": [b"-6000000000"]}
        self.assertEqual(normalize_ad_policy(raw), {
            "min_length": 7, "history": 24, "lockout_threshold": 0, "max_age_days": 42, "min_age_days": 1,
            "lockout_duration_min": 10, "lockout_window_min": 10, "complexity": 1, "reversible": 1})

    def test_never_and_forever(self):
        raw = {"maxPwdAge": [b"-9223372036854775808"], "lockoutDuration": [b"-9223372036854775808"],
               "minPwdAge": [b"0"]}
        self.assertEqual(normalize_ad_policy(raw), {"max_age_days": None, "lockout_duration_min": 0, "min_age_days": None})

    def test_pso(self):
        raw = {"msDS-MinimumPasswordLength": [b"15"], "msDS-PasswordComplexityEnabled": [b"TRUE"],
               "msDS-PasswordReversibleEncryptionEnabled": [b"FALSE"], "msDS-LockoutThreshold": [b"3"]}
        self.assertEqual(normalize_ad_policy(raw, pso=True),
                         {"min_length": 15, "lockout_threshold": 3, "complexity": 1, "reversible": 0})


class AclTest(unittest.TestCase):
    def gpo(self, sd):
        return {"name": "Test GPO", "sd": sd}

    def test_default_like_acl_is_clean(self):
        sd = make_sd(f"{DOM}-512", [
            (f"{DOM}-512", 0x000F01FF, 0, None), (f"{DOM}-519", 0x000F01FF, 0, None),
            ("S-1-5-18", 0x000F01FF, 0, None), ("S-1-3-0", 0x000F01FF, 0x0A, None),   # Creator Owner, inherit-only
            ("S-1-5-11", RP, 0, None), ("S-1-5-9", RP, 0, None),
            ("S-1-5-11", 0x100, 0, "edacfd8f-ffb3-11d1-b41d-00a0c968f939"),          # Apply Group Policy
        ])
        owner, writers = gpo_acl_writers(sd)
        self.assertEqual(owner, f"{DOM}-512")
        self.assertEqual(set(writers), {f"{DOM}-512", f"{DOM}-519", "S-1-5-18"})
        self.assertEqual(check_gpo_acl(self.gpo(sd), {}), [])

    def test_broad_and_delegated_writers(self):
        sd = make_sd(f"{DOM}-1300", [
            ("S-1-5-11", GW, 0, None),
            (f"{DOM}-1200", WD, 0, None),
            (f"{DOM}-1201", 0x20, 0, "f30e3bc1-9ff0-11d1-b603-0000f80367c1"),     # WriteProperty(gPCFileSysPath)
            (f"{DOM}-1202", 0x20, 0, "bf967950-0de6-11d0-a285-00aa003049e2"),     # WriteProperty(description) — неопасно
            (f"{DOM}-1203", GA, 0x08, None),                                      # inherit-only — не действует на объект
        ])
        f = check_gpo_acl(self.gpo(sd), {f"{DOM}-1200": "helpdesk"})
        got = sorted((x.severity, x.evidence) for x in f)
        self.assertEqual(got, [
            ("CRITICAL", "Authenticated Users (S-1-5-11): GenericWrite"),
            ("LOW", f"{DOM}-1300"),
            ("MEDIUM", f"{DOM}-1201: WriteProperty(gPCFileSysPath)"),
            ("MEDIUM", f"helpdesk ({DOM}-1200): WriteDacl"),
        ])

    def test_missing_or_broken_sd(self):
        self.assertEqual(check_gpo_acl({"name": "x", "sd": None}, {}), [])
        self.assertEqual(check_gpo_acl({"name": "x", "sd": b"\x01\x00garbage"}, {})[0].severity, "INFO")

    def test_sensitive_attr_guids_are_lowercase(self):
        self.assertTrue(all(k == k.lower() for k in GPO_SENSITIVE_ATTRS))


class MockLdapTest(unittest.TestCase):
    def setUp(self):
        self.conn = mock_conn()
        c = self.conn
        c.strategy.add_entry(BASE, {
            "objectClass": ["top", "domain"], "minPwdLength": 7, "pwdProperties": 1,
            "maxPwdAge": -36288000000000, "lockoutThreshold": 0, "lockoutDuration": -9223372036854775808,
            "objectSid": sid_bytes(DOM), "ms-DS-MachineAccountQuota": 10,
            "gPLink": f"[LDAP://cn={{31B2F340-016D-11D2-945F-00C04FB984F9}},cn=policies,cn=system,{BASE};0]",
        }, validate=False)
        c.strategy.add_entry(f"CN={{31B2F340-016D-11D2-945F-00C04FB984F9}},CN=Policies,CN=System,{BASE}", {
            "objectClass": ["top", "container", "groupPolicyContainer"], "cn": "{31B2F340-016D-11D2-945F-00C04FB984F9}",
            "displayName": "Default Domain Policy", "versionNumber": 3, "flags": 0,
            "gPCFileSysPath": r"\\ad2012.lab\sysvol\ad2012.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}",
            "nTSecurityDescriptor": make_sd(f"{DOM}-512", [("S-1-5-11", GW, 0, None)]),
        }, validate=False)

    def test_domain_info(self):
        policy, sid, maq = get_domain_info(self.conn, BASE)
        self.assertEqual(sid, DOM)
        self.assertEqual(maq, 10)
        self.assertEqual(policy["lockout_duration_min"], 0)
        self.assertEqual(policy["max_age_days"], 42)

    def test_gpos_and_links(self):
        gpos = get_gpos(self.conn, BASE)
        self.assertEqual(len(gpos), 1)
        g = gpos[0]
        self.assertEqual((g["name"], g["version"], g["guid"]),
                         ("Default Domain Policy", 3, "{31B2F340-016D-11D2-945F-00C04FB984F9}"))
        self.assertEqual(check_gpo_acl(g, {})[0].severity, "CRITICAL")
        self.assertEqual(get_gpo_links(self.conn, BASE, None),
                         {"{31B2F340-016D-11D2-945F-00C04FB984F9}": [(BASE, True, False)]})

    def test_resolve_sids(self):
        add_user(self.conn, "helpdesk", 1200)
        self.assertEqual(resolve_sids(self.conn, BASE, {f"{DOM}-1200", "S-1-5-11", None}), {f"{DOM}-1200": "helpdesk"})


class UsersTest(unittest.TestCase):
    NOW = datetime(2026, 11, 1, tzinfo=timezone.utc)

    def setUp(self):
        c = self.conn = mock_conn()
        recent = int((self.NOW - timedelta(days=5) - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10 ** 7)
        old = int((self.NOW - timedelta(days=400) - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10 ** 7)
        da = f"CN=Domain Admins,CN=Users,{BASE}"
        add_group(c, "Domain Users", 513)
        add_group(c, "Domain Admins", 512, members=[f"CN=adm,CN=Users,{BASE}", f"CN=svc_sql,CN=Users,{BASE}"])
        add_group(c, "Empty", 1500)
        add_user(c, "adm", 1100, uac=0x10200, groups=[da], lastLogonTimestamp=old)
        add_user(c, "svc_sql", 1101, groups=[da], servicePrincipalName=["MSSQLSvc/db:1433"], lastLogonTimestamp=recent)
        add_user(c, "svc_web", 1102, servicePrincipalName=["HTTP/web"], lastLogonTimestamp=recent)
        add_user(c, "roast", 1103, uac=0x400200, lastLogonTimestamp=recent)
        add_user(c, "off", 1104, uac=0x202, groups=[da])
        add_user(c, "hidden", 1105, uac=None)                      # userAccountControl не читается
        add_user(c, "krbtgt", 502, uac=0x202, servicePrincipalName=["kadmin/changepw"], pwdLastSet=old)
        add_user(c, "guest", 501, uac=0x222, pgid=514)
        for i in range(1100):                                        # больше лимита AD (1000) на один запрос
            add_user(c, f"bulk{i}", 3000 + i, lastLogonTimestamp=recent)
        self.users = get_all_users(c, BASE)
        self.groups = get_all_groups(c, BASE)
        self.report = build_user_report(self.users, self.groups, {"Domain Admins": ["adm", "off", "svc_sql"]},
                                        90, now=self.NOW)

    def test_paging_and_counts(self):
        r = self.report
        self.assertEqual(r["total"], 1108)
        self.assertEqual(r["disabled"], 3)             # off, krbtgt, guest
        self.assertEqual(r["unknown"], 1)              # hidden
        self.assertEqual(r["enabled"], 1104)

    def test_primary_group_counted(self):
        du = next(g for g in self.report["groups"] if g["name"] == "Domain Users")
        self.assertEqual(du["user_count"], 1107)
        adm = next(u for u in self.users if u["sam"] == "adm")
        self.assertEqual(adm["groups"], ["Domain Users", "Domain Admins"])
        self.assertEqual(self.report["groups"][0]["name"], "Domain Users")

    def test_account_findings(self):
        f = {x.title: x for x in check_accounts(self.report, now=self.NOW)}
        self.assertEqual(f["Не требуется предварительная аутентификация Kerberos (1)"].evidence, "roast")
        self.assertEqual(f["Kerberoasting: привилегированные учётные записи с SPN (1)"].evidence, "svc_sql")
        self.assertEqual(f["Kerberoasting: учётные записи с SPN (1)"].evidence, "svc_web")
        self.assertEqual(f["Привилегированные учётные записи с бессрочным паролем (1)"].evidence, "adm")
        self.assertEqual(f["Неактивные привилегированные учётные записи (>90 дн) (1)"].evidence, "adm")
        self.assertIn("Пароль krbtgt не менялся 400 дн", f)
        self.assertNotIn("Учётная запись Guest включена", f)       # guest отключён
        self.assertFalse(any("hidden" in x.evidence for x in f.values()))   # неизвестное состояние не считается активным

    def test_unknown_uac_not_reported_as_enabled_guest(self):
        users = [{"sam": "Guest", "enabled": False, "uac_known": False, "uac": 0, "spns": [], "admin_count": 0,
                  "pwd_last_set": None}]
        report = {"all_users": users, "privileged": {}, "stale": [], "stale_days": 90}
        self.assertEqual(check_accounts(report), [])


class UtilTest(unittest.TestCase):
    def test_split_username(self):
        self.assertEqual(split_username("TEST\\bob", "corp.local"), ("bob", "TEST"))
        self.assertEqual(split_username("bob@test.local", "corp.local"), ("bob", "test.local"))
        self.assertEqual(split_username("bob", "corp.local"), ("bob", "corp.local"))

    def test_filetime(self):
        self.assertIsNone(filetime_to_dt(0))
        self.assertIsNone(filetime_to_dt("9223372036854775807"))
        self.assertIsNone(filetime_to_dt(datetime(1601, 1, 1)))
        self.assertEqual(filetime_to_dt(116444736000000000), datetime(1970, 1, 1, tzinfo=timezone.utc))

    def test_dn_helpers(self):
        self.assertEqual(_cn_from_dn(r"CN=Smith\, John,OU=Users,DC=x"), "Smith, John")
        self.assertEqual(_group_type(-2147483646), "Security / Global")
        self.assertEqual(_group_type(-2147483643), "Security / Builtin")
        self.assertEqual(_group_type(8), "Distribution / Universal")


if __name__ == "__main__":
    unittest.main()
