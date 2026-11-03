"""Общие построители тестовых данных (без сети)."""

import os
import struct
import sys
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


# ── Registry.pol ──────────────────────────────────────────────────────────────
def pol_entry(key: str, value: str, reg_type: int, data: bytes) -> bytes:
    """[ key\\0 ; value\\0 ; type ; size ; data ] — все разделители UTF-16 LE."""
    def ws(s):
        return s.encode("utf-16-le") + b"\x00\x00"
    sep = b";\x00"
    return (b"[\x00" + ws(key) + sep + ws(value) + sep + struct.pack("<I", reg_type) + sep
            + struct.pack("<I", len(data)) + sep + data + b"]\x00")


def pol(*entries: bytes, version: int = 1) -> bytes:
    return b"PReg" + struct.pack("<I", version) + b"".join(entries)


def dword(v: int) -> bytes:
    return struct.pack("<I", v)


def sz(s: str) -> bytes:
    return s.encode("utf-16-le") + b"\x00\x00"


# ── Сертификат ────────────────────────────────────────────────────────────────
def make_cert_der(cn: str = "Test EFS", upn: str | None = None) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID, ObjectIdentifier

    # RSA-2048: DER > 255 байт, начинается с 30 82 — как реальные сертификаты EFS
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
               .serial_number(0x1234ABCD).not_valid_before(now - timedelta(days=1))
               .not_valid_after(now + timedelta(days=365)))
    if upn:
        value = b"\x0c" + bytes([len(upn)]) + upn.encode()
        builder = builder.add_extension(x509.SubjectAlternativeName(
            [x509.OtherName(ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"), value)]), critical=False)
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


# ── Дескриптор безопасности ───────────────────────────────────────────────────
def make_sd(owner: str, aces: list) -> bytes:
    """aces: [(sid, mask, ace_flags, object_type_guid | None)] — только ACCESS_ALLOWED(_OBJECT)."""
    from impacket.ldap import ldaptypes
    from impacket.uuid import string_to_bin

    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 0x8004
    o = ldaptypes.LDAP_SID()
    o.fromCanonical(owner)
    sd["OwnerSid"] = o
    sd["GroupSid"] = b""
    sd["Sacl"] = b""
    acl = ldaptypes.ACL()
    acl["AclRevision"] = 4
    acl["Sbz1"] = 0
    acl["Sbz2"] = 0
    acl.aces = []
    for sid, mask, flags, obj in aces:
        ace = ldaptypes.ACE()
        if obj:
            ace["AceType"] = 0x05
            body = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE()
            body["Flags"] = 0
            body["ObjectType"] = string_to_bin(obj)
            body["InheritedObjectType"] = b""
        else:
            ace["AceType"] = 0x00
            body = ldaptypes.ACCESS_ALLOWED_ACE()
        ace["AceFlags"] = flags
        m = ldaptypes.ACCESS_MASK()
        m["Mask"] = mask
        body["Mask"] = m
        s = ldaptypes.LDAP_SID()
        s.fromCanonical(sid)
        body["Sid"] = s
        ace["Ace"] = body
        acl.aces.append(ace)
    sd["Dacl"] = acl
    return sd.getData()


def sid_bytes(sid: str) -> bytes:
    from impacket.ldap import ldaptypes
    s = ldaptypes.LDAP_SID()
    s.fromCanonical(sid)
    return s.getData()


def utf16(text: str) -> bytes:
    return b"\xff\xfe" + text.encode("utf-16-le")


def write_tree(root: str, files: dict) -> None:
    """{относительный путь: bytes} -> файлы на диске."""
    for rel, data in files.items():
        full = os.path.join(root, *rel.replace("\\", "/").split("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(data)
