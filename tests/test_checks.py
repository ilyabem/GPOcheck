import unittest

from helpers import pol, pol_entry, dword, sz, utf16

from gpo_checks import (
    RegSetting, check_registry_settings, check_gpttmpl, check_gpp_xml, check_scripts_ini, check_gpo_file,
    check_password_policy, default_thresholds, inf_password_policy, inf_registry_settings, sort_findings,
    is_broad_principal, is_privileged_principal, principal_label,
)
from gpo_decoders import parse_inf

TS = r"Software\Policies\Microsoft\Windows NT\Terminal Services"
DOM = "S-1-5-21-1601711706-4134303832-3741856697"


def titles(findings):
    return [f.title for f in findings]


def reg(key, name, value, hive="MACHINE"):
    return check_registry_settings([RegSetting(key, name, value, hive)])


class RegistryRulesTest(unittest.TestCase):
    def test_value_matters_not_just_name(self):
        """v1.0 помечал SMB1/WDigest/AlwaysInstallElevated как уязвимость, даже когда они ВЫКЛЮЧЕНЫ."""
        cases = [
            (r"System\CurrentControlSet\Services\LanManServer\Parameters", "SMB1", "Сервер SMBv1 включён"),
            (r"System\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", "WDigest"),
            (r"Software\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated", "AlwaysInstallElevated"),
            (r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon", "AutoAdminLogon"),
        ]
        for key, name, title in cases:
            with self.subTest(name):
                self.assertEqual(reg(key, name, 0), [])
                found = reg(key, name, 1)
                self.assertEqual(len(found), 1)
                self.assertIn(title, found[0].title)

    def test_rdp(self):
        self.assertEqual(reg(TS, "UserAuthentication", 0)[0].severity, "HIGH")
        self.assertEqual(reg(TS, "UserAuthentication", 1), [])
        self.assertEqual(reg(TS, "fPromptForPassword", 1), [])
        self.assertEqual(reg(TS, "SecurityLayer", 2), [])

    def test_key_normalization(self):
        for key in (r"HKEY_LOCAL_MACHINE\software\policies\microsoft\windows nt\terminal services",
                    r"MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\\",
                    r"HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services"):
            with self.subTest(key):
                self.assertEqual(len(reg(key, "userauthentication", 0)), 1)

    def test_lm_compat_levels(self):
        lsa = r"System\CurrentControlSet\Control\Lsa"
        self.assertEqual(reg(lsa, "LmCompatibilityLevel", 1)[0].severity, "HIGH")
        self.assertEqual(reg(lsa, "LmCompatibilityLevel", 3)[0].severity, "LOW")
        self.assertEqual(reg(lsa, "LmCompatibilityLevel", 5), [])
        self.assertEqual(reg(lsa, "NoLMHash", 1), [])
        self.assertEqual(reg(lsa, "NoLMHash", 0)[0].severity, "HIGH")

    def test_default_password_is_redacted(self):
        f = reg(r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "DefaultPassword", "P@ssw0rd!")
        self.assertEqual(f[0].severity, "CRITICAL")
        self.assertNotIn("P@ssw0rd", f[0].evidence)
        self.assertIn("длина 9", f[0].evidence)
        self.assertEqual(reg(r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "DefaultPassword", ""), [])

    def test_wildcard_and_special_entries(self):
        f = reg(r"Software\Policies\Microsoft\Windows Defender\Exclusions\Paths", r"C:\Temp", "0")
        self.assertEqual(titles(f), [r"Исключение Defender (путь): C:\Temp"])
        self.assertEqual(reg(TS, "**del.UserAuthentication", " "), [])
        self.assertEqual(reg(TS, "**delvals.", " "), [])

    def test_kerberos_enc_types_bits(self):
        k = r"Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
        self.assertEqual(reg(k, "SupportedEncryptionTypes", 0x18), [])               # AES only
        self.assertEqual([f.severity for f in reg(k, "SupportedEncryptionTypes", 0x1C)], ["LOW"])
        self.assertEqual(sorted(f.severity for f in reg(k, "SupportedEncryptionTypes", 0x7FFFFFFF)),
                         ["LOW", "MEDIUM"])

    def test_string_values_are_compared_as_numbers(self):
        self.assertEqual(len(reg(r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon", "1")), 1)
        self.assertEqual(reg(r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon", "0"), [])
        self.assertEqual(reg(TS, "UserAuthentication", "garbage"), [])


class GptTmplTest(unittest.TestCase):
    def check(self, text):
        return check_gpttmpl(parse_inf(text), "GPO", "GptTmpl.inf")

    def test_registry_values_section(self):
        f = self.check("[Registry Values]\n"
                       "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\NoLMHash=4,1\n"
                       "MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity=4,1\n"
                       "MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\RequireSignOrSeal=4,1\n"
                       "MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\RequireSecuritySignature=4,0\n")
        self.assertEqual(sorted(titles(f)), ["Подпись LDAP на контроллере домена не обязательна",
                                             "Подпись SMB на сервере не обязательна"])
        self.assertTrue(all(fi.evidence.startswith("MACHINE\\") for fi in f))

    def test_inf_reg_value_types(self):
        s = inf_registry_settings(parse_inf("[Registry Values]\nMACHINE\\A\\B\\Str=1,\"x\"\n"
                                           "MACHINE\\A\\B\\Multi=7,a,b\nMACHINE\\A\\B\\Dw=4,900\n"))
        self.assertEqual([(x.key, x.name, x.value) for x in s],
                         [("A\\B", "Str", "x"), ("A\\B", "Multi", ["a", "b"]), ("A\\B", "Dw", 900)])

    def test_system_access(self):
        f = self.check("[System Access]\nClearTextPassword = 1\nEnableGuestAccount = 1\nLSAAnonymousNameLookup = 0\n")
        self.assertEqual(sorted(x.severity for x in f), ["CRITICAL", "HIGH"])
        self.assertEqual(self.check("[System Access]\nClearTextPassword = 0\nEnableGuestAccount = 0\n"), [])

    def test_privileges(self):
        f = self.check("[Privilege Rights]\n"
                       "SeDebugPrivilege = *S-1-5-32-544,*S-1-1-0\n"
                       f"SeBackupPrivilege = *S-1-5-32-544,*{DOM}-1105\n"
                       f"SeImpersonatePrivilege = *{DOM}-513\n"
                       "SeChangeNotifyPrivilege = *S-1-1-0\n"
                       "SeRemoteInteractiveLogonRight = *S-1-1-0,Te\n")
        self.assertEqual(sorted((x.severity, x.title) for x in f), [
            ("HIGH", "SeDebugPrivilege выдана широкой группе"),
            ("HIGH", "SeImpersonatePrivilege выдана широкой группе"),
            ("MEDIUM", "SeBackupPrivilege выдана учётной записи/группе домена"),
        ])

    def test_restricted_groups(self):
        f = self.check("[Group Membership]\n*S-1-5-32-544__Memberof =\n"
                       f"*S-1-5-32-544__Members = *{DOM}-512,*S-1-5-11\n")
        self.assertIn("Широкая группа добавлена в локальную группу Administrators", titles(f))
        info = [x for x in f if x.severity == "INFO"][0]
        self.assertIn("Domain Admins", info.description)
        self.assertIn("Authenticated Users", info.description)

    def test_kerberos_policy(self):
        self.assertEqual(self.check("[Kerberos Policy]\nMaxTicketAge = 10\nTicketValidateClient = 1\nMaxClockSkew = 5\n"), [])
        self.assertEqual(len(self.check("[Kerberos Policy]\nMaxTicketAge = 24\nTicketValidateClient = 0\n")), 2)

    def test_real_default_domain_controllers_policy(self):
        """Фрагмент реального GptTmpl.inf стандартной политики контроллеров домена: только LDAP signing."""
        f = self.check("[Registry Values]\n"
                       "MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity=4,1\n"
                       "MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\RequireSignOrSeal=4,1\n"
                       "MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\RequireSecuritySignature=4,1\n"
                       "MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\EnableSecuritySignature=4,1\n"
                       "[Privilege Rights]\n"
                       "SeAssignPrimaryTokenPrivilege = *S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003,*S-1-5-19,*S-1-5-20\n"
                       "SeBackupPrivilege = *S-1-5-32-544,*S-1-5-32-551,*S-1-5-32-549\n"
                       "SeChangeNotifyPrivilege = *S-1-1-0,*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-11\n"
                       "SeMachineAccountPrivilege = *S-1-5-11\n"
                       "SeNetworkLogonRight = *S-1-1-0,*S-1-5-32-544,*S-1-5-11,*S-1-5-9,*S-1-5-32-554\n")
        self.assertEqual(titles(f), ["Подпись LDAP на контроллере домена не обязательна"])


class GppTest(unittest.TestCase):
    def test_cpassword(self):
        xml = ('<?xml version="1.0" encoding="utf-8"?><Groups clsid="{x}"><User clsid="{y}" name="Administrator (built-in)">'
               '<Properties action="U" newName="" fullName="" cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw" '
               'userName="Administrator (built-in)"/></User></Groups>')
        f = check_gpp_xml(xml.encode(), "GPO", r"Machine\Preferences\Groups\Groups.xml")
        self.assertEqual(f[0].severity, "CRITICAL")
        self.assertIn("Administrator (built-in)", f[0].evidence)
        self.assertNotIn("j1Uyj3", f[0].evidence + f[0].description)

    def test_empty_cpassword_ignored(self):
        xml = '<Groups><User><Properties cpassword="" userName="x"/></User></Groups>'
        self.assertEqual(check_gpp_xml(xml.encode(), "", r"Machine\Preferences\Groups\Groups.xml"), [])

    def test_groups_membership(self):
        xml = ('<Groups><Group name="Administrators (built-in)"><Properties action="U" groupSid="S-1-5-32-544" '
               'groupName="Administrators (built-in)"><Members>'
               f'<Member name="TEST\\Domain Users" action="ADD" sid="{DOM}-513"/>'
               f'<Member name="TEST\\helpdesk" action="ADD" sid="{DOM}-1200"/>'
               '<Member name="TEST\\old" action="REMOVE" sid=""/>'
               '</Members></Properties></Group></Groups>')
        f = check_gpp_xml(utf16(xml), "", r"Machine\Preferences\Groups\Groups.xml")
        self.assertEqual(sorted(x.severity for x in f), ["HIGH", "INFO"])

    def test_scheduled_task(self):
        xml = ('<ScheduledTasks><TaskV2 name="t"><Properties action="U" name="clear DNS" runAs="NT AUTHORITY\\System">'
               '<Task><Actions><Exec><Command>cmd.exe</Command><Arguments>/c del x</Arguments></Exec></Actions></Task>'
               '</Properties></TaskV2><ImmediateTaskV2 name="gone"><Properties action="D" name="gone"/></ImmediateTaskV2>'
               '</ScheduledTasks>')
        f = check_gpp_xml(xml.encode(), "", r"Machine\Preferences\ScheduledTasks\ScheduledTasks.xml")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].evidence, "cmd.exe /c del x")
        self.assertIn("NT AUTHORITY\\System", f[0].description)

    def test_registry_xml(self):
        xml = ('<RegistrySettings><Registry><Properties action="U" hive="HKEY_LOCAL_MACHINE" '
               'key="SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" name="UseLogonCredential" '
               'type="REG_DWORD" value="00000001"/></Registry>'
               '<Registry><Properties action="D" hive="HKEY_LOCAL_MACHINE" key="SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" '
               'name="SMB1" type="REG_DWORD" value="00000001"/></Registry></RegistrySettings>')
        f = check_gpp_xml(xml.encode(), "", r"Machine\Preferences\Registry\Registry.xml")
        self.assertEqual(titles(f), ["WDigest хранит пароли в памяти LSASS"])

    def test_broken_xml(self):
        f = check_gpp_xml(b"<Groups><User>", "", r"Machine\Preferences\Groups\Groups.xml")
        self.assertEqual(f[0].severity, "INFO")

    def test_scripts_ini(self):
        text = "[Startup]\n0CmdLine=\\\\srv\\share\\run.bat\n0Parameters=/q\n1CmdLine=setup.ps1\n"
        f = check_scripts_ini(text, "", r"Machine\Scripts\scripts.ini")
        self.assertEqual(sorted(x.evidence for x in f), ["\\\\srv\\share\\run.bat /q", "setup.ps1"])


class PasswordPolicyTest(unittest.TestCase):
    T = default_thresholds()

    def test_weak_policy(self):
        f = check_password_policy({"min_length": 7, "complexity": 0, "lockout_threshold": 0, "history": 5,
                                   "max_age_days": None, "min_age_days": 0, "reversible": 1}, self.T)
        self.assertEqual(sorted(x.severity for x in f), ["CRITICAL", "HIGH", "HIGH", "HIGH", "MEDIUM", "MEDIUM", "MEDIUM"])

    def test_good_policy(self):
        f = check_password_policy({"min_length": 14, "complexity": 1, "lockout_threshold": 5, "history": 24,
                                   "max_age_days": 60, "min_age_days": 1, "lockout_duration_min": 0,
                                   "lockout_window_min": 15, "reversible": 0}, self.T)
        self.assertEqual(f, [])

    def test_lockout_duration_ignored_when_lockout_disabled(self):
        f = check_password_policy({"lockout_threshold": 0, "lockout_duration_min": 1, "lockout_window_min": 1}, self.T)
        self.assertEqual(titles(f), ["Блокировка учётных записей отключена"])

    def test_thresholds_applied(self):
        t = default_thresholds(min_password_length=7, max_password_age=0)
        self.assertEqual(check_password_policy({"min_length": 7, "max_age_days": None}, t), [])

    def test_inf_policy_normalization(self):
        s = parse_inf("[System Access]\nMaximumPasswordAge = -1\nLockoutDuration = -1\nMinimumPasswordLength = 8\n")
        self.assertEqual(inf_password_policy(s), {"min_length": 8, "max_age_days": None, "lockout_duration_min": 0})
        self.assertEqual(inf_password_policy(parse_inf("[Version]\nsignature=x\n")), {})


class DispatchTest(unittest.TestCase):
    def test_user_hive_registry_pol(self):
        raw = pol(pol_entry(r"Software\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated", 4, dword(1)))
        f = check_gpo_file(r"User\Registry.pol", raw, "GPO")
        self.assertTrue(f[0].evidence.startswith("USER\\"))

    def test_registry_pol_warnings_become_info(self):
        raw = pol(pol_entry("K", "A", 4, dword(1))) + b"\x01\x02\x03"
        f = check_gpo_file(r"Machine\Registry.pol", raw, "GPO")
        self.assertEqual([x.severity for x in f], ["INFO"])

    def test_non_preferences_xml_ignored(self):
        self.assertEqual(check_gpo_file(r"Machine\comment.cmtx", b"<x/>", "GPO"), [])
        self.assertEqual(check_gpo_file(r"Machine\Microsoft\Windows NT\Audit\audit.csv", b"a,b", "GPO"), [])

    def test_sort(self):
        f = sort_findings(reg(TS, "fPromptForPassword", 0) + reg(TS, "UserAuthentication", 0))
        self.assertEqual([x.severity for x in f], ["HIGH", "LOW"])


class PrincipalTest(unittest.TestCase):
    def test_broad(self):
        for p in ("*S-1-1-0", "S-1-5-11", f"*{DOM}-513", "TEST\\Domain Users", "Everyone"):
            self.assertTrue(is_broad_principal(p), p)
        for p in ("*S-1-5-32-544", f"{DOM}-1105", "TEST\\helpdesk"):
            self.assertFalse(is_broad_principal(p), p)

    def test_privileged(self):
        self.assertTrue(is_privileged_principal(f"{DOM}-512"))
        self.assertTrue(is_privileged_principal("S-1-5-18"))
        self.assertFalse(is_privileged_principal(f"{DOM}-520"))

    def test_label(self):
        self.assertEqual(principal_label("*S-1-5-32-544"), "BUILTIN\\Administrators (S-1-5-32-544)")
        self.assertEqual(principal_label(f"*{DOM}-1105", {f"{DOM}-1105": "svc_backup"}), f"svc_backup ({DOM}-1105)")
        self.assertEqual(principal_label("Te"), "Te")


if __name__ == "__main__":
    unittest.main()
