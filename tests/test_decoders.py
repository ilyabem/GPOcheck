import unittest

from helpers import pol, pol_entry, dword, sz, make_cert_der, utf16

from gpo_decoders import (
    decode_text, parse_inf, inf_get, inf_int, read_registry_pol, parse_registry_pol, format_reg_value,
    decode_certificate, find_certificates, is_binary, hexdump, render_gpo_file,
)

INI = "[System Access]\r\nMinimumPasswordLength = 8\r\nLockoutDuration = -1\r\n"


class DecodeTextTest(unittest.TestCase):
    def test_encodings(self):
        cases = {
            "utf-16-le bom": b"\xff\xfe" + INI.encode("utf-16-le"),
            "utf-16-be bom": b"\xfe\xff" + INI.encode("utf-16-be"),
            "utf-8 bom": b"\xef\xbb\xbf" + INI.encode("utf-8"),
            "ascii": INI.encode("ascii"),
            "utf-16-le без BOM": INI.encode("utf-16-le"),
        }
        for name, raw in cases.items():
            with self.subTest(name):
                text = decode_text(raw)
                self.assertIn("MinimumPasswordLength = 8", text)
                self.assertFalse(text.startswith("﻿"))

    def test_cp1251(self):
        raw = "[General]\r\ndisplayName=Тестовая политика\r\n".encode("cp1251")
        self.assertIn("Тестовая политика", decode_text(raw))

    def test_utf8_cyrillic(self):
        raw = "displayName=тест".encode("utf-8")
        self.assertEqual(decode_text(raw), "displayName=тест")


class InfTest(unittest.TestCase):
    def test_parse(self):
        text = ("[Unicode]\nUnicode=yes\n[System Access]\nMinimumPasswordLength = 7\n"
                "LockoutDuration = -1\n; comment\n[Service General Setting]\n\"SCardSvr\",2,\"\"\n"
                "[Privilege Rights]\nSeDebugPrivilege = *S-1-5-32-544,*S-1-1-0\n")
        s = parse_inf(text)
        self.assertEqual(inf_int(s, "system access", "minimumpasswordlength"), 7)
        self.assertEqual(inf_int(s, "System Access", "LockoutDuration"), -1)
        self.assertIsNone(inf_int(s, "System Access", "Missing"))
        self.assertEqual(s["service general setting"], [('"SCardSvr",2,""', None)])
        self.assertEqual(inf_get(s, "Privilege Rights", "SeDebugPrivilege"), "*S-1-5-32-544,*S-1-1-0")

    def test_value_with_equals(self):
        s = parse_inf("[Registry Values]\nMACHINE\\A\\B=1,\"a=b\"\n")
        self.assertEqual(s["registry values"], [("MACHINE\\A\\B", '1,"a=b"')])


class RegistryPolTest(unittest.TestCase):
    def test_all_types(self):
        raw = pol(
            pol_entry(r"Software\Policies\Test", "Str", 1, sz("HelloWorld")),
            pol_entry(r"Software\Policies\Test", "Exp", 2, sz("%SystemRoot%")),
            pol_entry(r"Software\Policies\Test", "Dw", 4, dword(42)),
            pol_entry(r"Software\Policies\Test", "DwBE", 5, (42).to_bytes(4, "big")),
            pol_entry(r"Software\Policies\Test", "Qw", 11, (2 ** 40).to_bytes(8, "little")),
            pol_entry(r"Software\Policies\Test", "Multi", 7, "foo\x00bar\x00\x00".encode("utf-16-le")),
            pol_entry(r"Software\Policies\Test", "Bin", 3, b"\x01\x02\x03"),
            pol_entry(r"Software\Policies\Test", "", 0, b""),
        )
        version, entries, warnings = read_registry_pol(raw)
        self.assertEqual(version, 1)
        self.assertEqual(warnings, [])
        self.assertEqual([e.parsed for e in entries],
                         ["HelloWorld", "%SystemRoot%", 42, 42, 2 ** 40, ["foo", "bar"], b"\x01\x02\x03", None])

    def test_odd_binary_does_not_lose_following_entries(self):
        """Регрессия v1.0: после REG_BINARY нечётной длины записи терялись (на реальных файлах — до половины)."""
        raw = pol(
            pol_entry(r"Software\Policies\Microsoft\SystemCertificates\EFS", "EFSBlob", 3, b"\x30" * 961),
            pol_entry(r"Software\Policies\Microsoft\Windows NT\Terminal Services", "UserAuthentication", 4, dword(0)),
            pol_entry(r"Software\Policies\Microsoft\Windows NT\Terminal Services", "fPromptForPassword", 4, dword(0)),
        )
        _, entries, warnings = read_registry_pol(raw)
        self.assertEqual(warnings, [])
        self.assertEqual([e.value for e in entries], ["EFSBlob", "UserAuthentication", "fPromptForPassword"])
        self.assertEqual(entries[1].parsed, 0)

    def test_data_containing_brackets_and_separators(self):
        data = "[x];]".encode("utf-16-le") + b"\x00\x00"
        raw = pol(pol_entry("K", "V", 1, data), pol_entry("K", "W", 4, dword(7)))
        _, entries, warnings = read_registry_pol(raw)
        self.assertEqual(warnings, [])
        self.assertEqual([e.parsed for e in entries], ["[x];]", 7])

    def test_resync_after_garbage(self):
        raw = pol(pol_entry("K", "A", 4, dword(1)), version=1) + b"\x11\x22\x33" + pol_entry("K", "B", 4, dword(2))
        _, entries, warnings = read_registry_pol(raw)
        self.assertEqual([e.value for e in entries], ["A", "B"])
        self.assertTrue(any("пропущено 3 байт" in w for w in warnings))

    def test_truncated(self):
        full = pol(pol_entry("K", "A", 4, dword(1)), pol_entry("K", "B", 4, dword(2)))
        _, entries, warnings = read_registry_pol(full[:-5])
        self.assertEqual([e.value for e in entries], ["A"])
        self.assertTrue(warnings)

    def test_size_beyond_eof(self):
        e = bytearray(pol_entry("K", "A", 3, b"\x01\x02"))
        size_pos = e.index(b"\x02\x00\x00\x00;\x00")
        e[size_pos:size_pos + 4] = (10 ** 6).to_bytes(4, "little")
        _, entries, warnings = read_registry_pol(pol(bytes(e)))
        self.assertEqual(entries, [])
        self.assertTrue(any("за конец файла" in w for w in warnings))

    def test_bad_inputs(self):
        self.assertIn("короткий", parse_registry_pol(b""))
        self.assertIn("сигнатура", parse_registry_pol(b"XXXX" + b"\x00" * 4))
        self.assertIn("записей нет", parse_registry_pol(b"PReg\x01\x00\x00\x00"))

    def test_special_value_names_display(self):
        text = parse_registry_pol(pol(pol_entry("K", "**del.Foo", 1, sz(" ")),
                                      pol_entry("K", "**delvals.", 1, sz(" "))))
        self.assertIn("Foo  (удалить значение)", text)
        self.assertIn("удалить все значения", text)

    def test_format_values(self):
        self.assertEqual(format_reg_value(4, dword(5)), "5")
        self.assertEqual(format_reg_value(4, dword(900)), "900 (0x384)")
        self.assertEqual(format_reg_value(4, b"\x01"), "01")
        self.assertEqual(format_reg_value(3, b""), "(empty)")
        self.assertIn("bytes", format_reg_value(3, bytes(range(100))))


class CertificateTest(unittest.TestCase):
    def test_plain_der(self):
        der = make_cert_der("Plain Cert", upn="Administrator@TEST")
        text = decode_certificate(der)
        self.assertIn("CN=Plain Cert", text)
        self.assertIn("Administrator@TEST", text)
        self.assertIn("1234abcd", text)

    def test_der_inside_blob(self):
        der = make_cert_der("Inside Blob")
        blob = b"\x01\x00\x30\x82\xff\xff junk" + b"\x00" * 50 + der + b"\x00\x00"
        self.assertEqual(len(find_certificates(blob)), 1)
        self.assertIn("[DER cert found inside blob]", decode_certificate(blob))
        self.assertIn("[Certificate]", format_reg_value(3, blob))

    def test_no_cert(self):
        self.assertIn("00000000", decode_certificate(b"\x30\x82\x00\x10" + b"\x00" * 200))


class MiscTest(unittest.TestCase):
    def test_is_binary(self):
        self.assertFalse(is_binary(b"Hello, World!\n" * 20))
        self.assertTrue(is_binary(bytes(range(256)) * 4))
        self.assertFalse(is_binary("Hello World\n".encode("utf-16-le") * 20))
        self.assertFalse(is_binary("Привет".encode("utf-8") * 50))
        self.assertFalse(is_binary("Привет, мир\r\n".encode("cp1251") * 50))
        self.assertTrue(is_binary(bytes(range(1, 256)) * 2))        # без NUL, не UTF-8
        self.assertFalse(is_binary(b""))

    def test_hexdump(self):
        hd = hexdump(b"ABCDEFGH\x00\x01\x02\x03")
        self.assertIn("00000000", hd)
        self.assertIn("41 42 43", hd)
        self.assertIn("ABCDEFGH....", hd)

    def test_render_dispatch(self):
        self.assertIn("MinimumPasswordLength", render_gpo_file(r"MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf", utf16(INI)))
        self.assertIn("Registry.pol", render_gpo_file(r"Machine\Registry.pol", pol(pol_entry("K", "V", 4, dword(1)))))
        self.assertIn("hex-preview", render_gpo_file("Machine\\blob.bin", bytes(range(256))))
        self.assertIn("<root/>", render_gpo_file("x.xml", utf16("<root/>")))
        self.assertIn("пустой", render_gpo_file("x.inf", b""))


if __name__ == "__main__":
    unittest.main()
