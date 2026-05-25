"""
test_decoders.py — offline tests for gpo_decoders.py
Run: python test_decoders.py
"""
import struct, sys, os
sys.path.insert(0, os.path.dirname(__file__))
from gpo_decoders import (
    decode_gpttmpl, parse_registry_pol, decode_certificate,
    is_binary, hexdump
)

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"

def check(name, condition, detail=""):
    if condition:
        print(f"  {PASS}  {name}")
    else:
        print(f"  {FAIL}  {name}  {detail}")
        return False
    return True


# ── GptTmpl.inf ──────────────────────────────────────────────────────────────
print("\n── GptTmpl.inf decoder ──")

# UTF-16 LE with BOM (real Windows format)
sample_ini = "[System Access]\r\nMinimumPasswordLength = 8\r\n"
utf16le_bom = b'\xff\xfe' + sample_ini.encode("utf-16-le")
decoded = decode_gpttmpl(utf16le_bom)
check("UTF-16 LE BOM", "MinimumPasswordLength = 8" in decoded, repr(decoded[:80]))

# Plain ASCII
ascii_bytes = sample_ini.encode("ascii")
decoded = decode_gpttmpl(ascii_bytes)
check("Plain ASCII", "MinimumPasswordLength = 8" in decoded)

# UTF-8 BOM
utf8_bom = b'\xef\xbb\xbf' + sample_ini.encode("utf-8")
decoded = decode_gpttmpl(utf8_bom)
check("UTF-8 BOM", "MinimumPasswordLength = 8" in decoded)


# ── Registry.pol ──────────────────────────────────────────────────────────────
print("\n── Registry.pol parser ──")

def make_regpol_entry(key: str, value: str, reg_type: int, data: bytes) -> bytes:
    """Build one PReg entry: [ key\0 ; value\0 ; type(4) ; size(4) ; data ]"""
    def ws(s):
        return s.encode("utf-16-le") + b'\x00\x00'
    sep = b';\x00'
    entry  = b'[\x00'
    entry += ws(key) + sep
    entry += ws(value) + sep
    entry += struct.pack("<I", reg_type) + sep
    entry += struct.pack("<I", len(data)) + sep
    entry += data
    entry += b']\x00'
    return entry

def make_regpol(entries: list) -> bytes:
    header = b'PReg' + struct.pack("<I", 1)
    return header + b''.join(entries)

# REG_SZ entry
entry_sz = make_regpol_entry(
    r"SOFTWARE\Policies\Test", "MyString", 1,
    "HelloWorld".encode("utf-16-le") + b'\x00\x00'
)
pol = make_regpol([entry_sz])
result = parse_registry_pol(pol)
check("REG_SZ parsed", "MyString" in result and "HelloWorld" in result, result[:200])

# REG_DWORD entry
entry_dw = make_regpol_entry(
    r"SOFTWARE\Policies\Test", "MyDword", 4,
    struct.pack("<I", 42)
)
pol = make_regpol([entry_dw])
result = parse_registry_pol(pol)
check("REG_DWORD parsed", "42" in result, result[:200])

# REG_MULTI_SZ entry
multi_data = "foo\x00bar\x00baz\x00\x00".encode("utf-16-le")
entry_ms = make_regpol_entry(r"SOFTWARE\Policies\Test", "Multi", 7, multi_data)
pol = make_regpol([entry_ms])
result = parse_registry_pol(pol)
check("REG_MULTI_SZ parsed", "foo" in result and "bar" in result, result[:200])

# Empty / garbage
check("Empty file", "короткий" in parse_registry_pol(b''))
check("Bad signature", "сигнатура" in parse_registry_pol(b'XXXX' + b'\x00'*4))


# ── is_binary heuristic ───────────────────────────────────────────────────────
print("\n── Binary heuristic ──")
check("Plain text → not binary", not is_binary(b"Hello, World!\n" * 20))
check("Random bytes → binary",   is_binary(bytes(range(256)) * 4))
check("UTF-16 LE text → not binary", not is_binary(
    "Hello World\n".encode("utf-16-le") * 20))


# ── hexdump ───────────────────────────────────────────────────────────────────
print("\n── Hex dump ──")
hd = hexdump(b"ABCDEFGH\x00\x01\x02\x03")
check("hexdump has offset",  "00000000" in hd)
check("hexdump has hex",     "41 42 43" in hd)
check("hexdump has ASCII",   "ABCDEFGH" in hd)
check("hexdump dots non-printable", "." in hd)


print("\nDone.\n")
