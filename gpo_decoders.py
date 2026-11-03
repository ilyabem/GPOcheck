"""
gpo_decoders.py — декодеры форматов файлов GPO.

  - decode_text         : автоопределение кодировки (UTF-16 LE/BE, UTF-8, cp1251)
  - parse_inf           : разбор GptTmpl.inf / GPT.INI / scripts.ini по секциям
  - read_registry_pol   : строгий парсер Registry.pol (PReg) с ресинхронизацией
  - parse_registry_pol  : текстовое представление Registry.pol для вывода
  - decode_certificate  : DER-сертификат, в т.ч. внутри бинарных blob (EFS и т.п.)
  - render_gpo_file     : выбор декодера по имени файла, никогда не выводит сырые байты
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


# ─────────────────────────────────────────────────────────────────────────────
# Утилиты
# ─────────────────────────────────────────────────────────────────────────────

def hexdump(data: bytes, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {i:08x}  {hex_part:<{width * 3}}  {asc_part}")
    return "\n".join(lines)


def _hexdump_preview(data: bytes, limit: int = 256) -> str:
    result = hexdump(data[:limit])
    if len(data) > limit:
        result += f"\n  ... {len(data)} bytes total"
    return result


def _looks_utf16le(sample: bytes) -> bool:
    """UTF-16 LE без BOM: в ASCII-тексте каждый нечётный байт равен 0x00."""
    odd = sample[1:64:2]
    return len(odd) >= 8 and odd.count(0) > len(odd) * 0.6


def is_binary(data: bytes, sample_size: int = 512, threshold: float = 0.05) -> bool:
    """Эвристика: текст (ASCII/UTF-8/UTF-16/cp1251) или бинарные данные."""
    sample = data[:sample_size]
    if not sample:
        return False
    if sample[:2] in (b'\xff\xfe', b'\xfe\xff') or sample[:3] == b'\xef\xbb\xbf':
        return False
    if _looks_utf16le(sample):
        return False
    if b'\x00' in sample:
        return True
    for cut in range(4):   # выборка могла разрезать многобайтовый символ UTF-8
        try:
            sample[:len(sample) - cut].decode("utf-8")
            break
        except UnicodeDecodeError:
            continue
    else:
        # не UTF-8: однобайтовая кодировка (cp1251) допустима, если почти нет управляющих символов
        controls = sum(1 for b in sample if b < 9 or (13 < b < 32) or b == 127)
        return controls / len(sample) > threshold
    controls = sum(1 for b in sample if b < 9 or (13 < b < 32) or b == 127)
    return controls / len(sample) > 0.30


# ─────────────────────────────────────────────────────────────────────────────
# Текстовые файлы (GptTmpl.inf, GPT.INI, scripts.ini, XML, скрипты)
# ─────────────────────────────────────────────────────────────────────────────

def decode_text(raw: bytes) -> str:
    """Декодировать текстовый файл GPO с автоопределением кодировки."""
    if raw[:2] == b'\xff\xfe':
        return raw[2:].decode("utf-16-le", errors="replace")
    if raw[:2] == b'\xfe\xff':
        return raw[2:].decode("utf-16-be", errors="replace")
    if raw[:3] == b'\xef\xbb\xbf':
        return raw[3:].decode("utf-8", errors="replace")
    if _looks_utf16le(raw[:512]):
        return raw.decode("utf-16-le", errors="replace")
    # Windows сохраняет ANSI-файлы на русских системах в cp1251
    for enc in ("utf-8", "cp1251"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1")


# Обратная совместимость с v1.0
decode_gpttmpl = decode_text


def parse_inf(text: str) -> dict:
    """
    Разобрать INF/INI в {секция_lower: [(ключ, значение), ...]}.
    Строки без '=' (например [Service General Setting]) сохраняются как (строка, None).
    Порядок и повторяющиеся ключи сохраняются.
    """
    sections: dict = {}
    current = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip().lower()
            sections.setdefault(current, [])
            continue
        if current is None:
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            sections[current].append((key.strip(), value.strip()))
        else:
            sections[current].append((line, None))
    return sections


def inf_get(sections: dict, section: str, key: str):
    """Значение ключа из секции (без учёта регистра) или None."""
    for k, v in sections.get(section.lower(), []):
        if k.lower() == key.lower():
            return v
    return None


def inf_int(sections: dict, section: str, key: str):
    """Целое (в т.ч. отрицательное, например -1) или None."""
    v = inf_get(sections, section, key)
    if v is None:
        return None
    try:
        return int(v.strip().strip('"'))
    except ValueError:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# DER-сертификат (и поиск DER внутри бинарных blob)
# ─────────────────────────────────────────────────────────────────────────────

def _cert_dates(cert):
    # cryptography >= 42 — *_utc, более старые версии — naive datetime
    try:
        return cert.not_valid_before_utc, cert.not_valid_after_utc
    except AttributeError:
        return cert.not_valid_before, cert.not_valid_after


def _decode_other_name(value: bytes) -> str:
    """OtherName (например UPN) — обычно DER UTF8String: 0x0c len data."""
    if len(value) >= 2 and value[0] == 0x0C and value[1] < 0x80:
        return value[2:2 + value[1]].decode("utf-8", errors="replace").rstrip("\x00")
    return value.hex()


def _fmt_cert(cert) -> str:
    """Форматировать объект x509.Certificate в текст."""
    not_before, not_after = _cert_dates(cert)
    lines = [
        f"    Subject  : {cert.subject.rfc4514_string()}",
        f"    Issuer   : {cert.issuer.rfc4514_string()}",
        f"    Serial   : {cert.serial_number:x}",
        f"    NotBefore: {not_before}",
        f"    NotAfter : {not_after}",
        f"    SHA-1    : {cert.fingerprint(hashes.SHA1()).hex()}",
        f"    SHA-256  : {cert.fingerprint(hashes.SHA256()).hex()}",
    ]
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_list = san.get_values_for_type(x509.DNSName)
        rfc_list = san.get_values_for_type(x509.RFC822Name)
        other = [_decode_other_name(o.value) for o in san.get_values_for_type(x509.OtherName)]
        if dns_list:
            lines.append(f"    SAN DNS  : {', '.join(dns_list)}")
        if rfc_list:
            lines.append(f"    SAN Email: {', '.join(rfc_list)}")
        if other:
            lines.append(f"    SAN Other: {', '.join(other)}")
    except (x509.ExtensionNotFound, ValueError):
        pass
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        usages = []
        for attr in ("digital_signature", "content_commitment", "key_encipherment",
                     "data_encipherment", "key_agreement", "key_cert_sign", "crl_sign"):
            if getattr(ku, attr, False):
                usages.append(attr.replace("_", " "))
        if usages:
            lines.append(f"    Key Usage: {', '.join(usages)}")
    except (x509.ExtensionNotFound, ValueError):
        pass
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        names = [o._name if o._name != "Unknown OID" else o.dotted_string for o in eku]
        lines.append(f"    EKU      : {', '.join(names)}")
    except (x509.ExtensionNotFound, ValueError):
        pass
    return "\n".join(lines)


def _der_length(raw: bytes, pos: int):
    """Длина DER SEQUENCE в pos -> (полная_длина, ok)."""
    if pos + 2 > len(raw) or raw[pos] != 0x30:
        return 0, False
    first = raw[pos + 1]
    if first < 0x80:
        return 2 + first, True
    n = first & 0x7F
    if n == 0 or n > 3 or pos + 2 + n > len(raw):
        return 0, False
    return 2 + n + int.from_bytes(raw[pos + 2:pos + 2 + n], "big"), True


def find_certificates(raw: bytes) -> list:
    """Найти все DER-сертификаты внутри blob (без повторов)."""
    if not HAS_CRYPTOGRAPHY:
        return []
    certs, seen = [], set()
    idx = 0
    while True:
        pos = raw.find(b'\x30\x82', idx)
        if pos == -1:
            pos = raw.find(b'\x30\x83', idx)
        if pos == -1:
            break
        total, ok = _der_length(raw, pos)
        if ok and pos + total <= len(raw):
            try:
                cert = x509.load_der_x509_certificate(raw[pos:pos + total])
                fp = cert.fingerprint(hashes.SHA256())
                if fp not in seen:
                    seen.add(fp)
                    certs.append(cert)
                idx = pos + total
                continue
            except Exception:
                pass
        idx = pos + 1
    return certs


def decode_certificate(raw: bytes) -> str:
    """Декодировать DER-сертификат (целиком или найденный внутри blob), иначе hex."""
    if not HAS_CRYPTOGRAPHY:
        return _hexdump_preview(raw)
    try:
        return _fmt_cert(x509.load_der_x509_certificate(raw))
    except Exception:
        pass
    try:
        return _fmt_cert(x509.load_pem_x509_certificate(raw))
    except Exception:
        pass
    certs = find_certificates(raw)
    if certs:
        return "\n".join("    [DER cert found inside blob]\n" + _fmt_cert(c) for c in certs)
    return _hexdump_preview(raw)


# ─────────────────────────────────────────────────────────────────────────────
# Registry.pol (PReg)
# ─────────────────────────────────────────────────────────────────────────────
#
# Формат (MS-GPREG): заголовок 'PReg' + DWORD version, далее записи
#   [ key\0 ; value\0 ; type(DWORD) ; size(DWORD) ; data ]
# Все символы-разделители и строки — UTF-16 LE. Выравнивания нет:
# REG_BINARY нечётной длины сдвигает все последующие записи на нечётное смещение.

_REGPOL_SIG = b'PReg'
REG_TYPES = {
    0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY",
    4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN", 6: "REG_LINK", 7: "REG_MULTI_SZ",
    8: "REG_RESOURCE_LIST", 11: "REG_QWORD",
}
_REG_TYPE_BY_NAME = {v: k for k, v in REG_TYPES.items()}


@dataclass
class RegEntry:
    key: str
    value: str
    type: int
    data: bytes

    @property
    def type_name(self) -> str:
        return REG_TYPES.get(self.type, f"REG_UNKNOWN({self.type:#x})")

    @property
    def parsed(self):
        return reg_data_value(self.type, self.data)


def reg_data_value(reg_type: int, data: bytes):
    """Преобразовать данные значения реестра в python-объект."""
    if reg_type in (1, 2):
        return data.decode("utf-16-le", errors="replace").split("\x00", 1)[0]
    if reg_type == 4 and len(data) >= 4:
        return struct.unpack_from("<I", data)[0]
    if reg_type == 5 and len(data) >= 4:
        return struct.unpack_from(">I", data)[0]
    if reg_type == 11 and len(data) >= 8:
        return struct.unpack_from("<Q", data)[0]
    if reg_type == 7:
        return [p for p in data.decode("utf-16-le", errors="replace").split("\x00") if p]
    if reg_type == 0:
        return None
    return data


def _read_utf16z(raw: bytes, pos: int):
    """UTF-16 LE строка с нулевым терминатором, шаг 2 байта от pos -> (str, pos) или (None, pos)."""
    end = pos
    while end + 1 < len(raw):
        if raw[end] == 0 and raw[end + 1] == 0:
            return raw[pos:end].decode("utf-16-le", errors="replace"), end + 2
        end += 2
    return None, pos


def _expect(raw: bytes, pos: int, char: bytes) -> int:
    """Ожидать UTF-16 LE символ в pos; вернуть новую позицию или -1."""
    if raw[pos:pos + 2] == char + b'\x00':
        return pos + 2
    return -1


def read_registry_pol(raw: bytes):
    """
    Разобрать Registry.pol.
    Возвращает (version | None, [RegEntry], [предупреждения]).
    При повреждённой записи парсер ищет следующую '[' и продолжает (с предупреждением).
    """
    if len(raw) < 8:
        return None, [], ["файл слишком короткий для Registry.pol"]
    if raw[:4] != _REGPOL_SIG:
        return None, [], [f"неизвестная сигнатура: {raw[:4].hex()}"]

    version = struct.unpack_from("<I", raw, 4)[0]
    entries, warnings = [], []
    pos = 8
    n = len(raw)

    while pos < n:
        if raw[pos:pos + 2] != b'[\x00':
            nxt = raw.find(b'[\x00', pos + 1)
            if nxt == -1:
                if raw[pos:].strip(b'\x00'):
                    warnings.append(f"мусор в конце файла: {n - pos} байт с {pos:#x}")
                break
            warnings.append(f"пропущено {nxt - pos} байт с {pos:#x} (рассинхронизация)")
            pos = nxt
        entry_start = pos
        pos += 2

        def bad(reason):
            warnings.append(f"повреждённая запись @ {entry_start:#x}: {reason}")
            return entry_start + 2

        key, pos = _read_utf16z(raw, pos)
        if key is None or (pos := _expect(raw, pos, b';')) < 0:
            pos = bad("ключ")
            continue
        value, pos = _read_utf16z(raw, pos)
        if value is None or (pos := _expect(raw, pos, b';')) < 0:
            pos = bad("имя значения")
            continue
        if pos + 4 > n:
            bad("тип")
            break
        reg_type = struct.unpack_from("<I", raw, pos)[0]
        if (pos := _expect(raw, pos + 4, b';')) < 0:
            pos = bad("разделитель после типа")
            continue
        if pos + 4 > n:
            bad("размер")
            break
        size = struct.unpack_from("<I", raw, pos)[0]
        if (pos := _expect(raw, pos + 4, b';')) < 0:
            pos = bad("разделитель после размера")
            continue
        if pos + size > n:
            pos = bad(f"размер данных {size} выходит за конец файла")
            continue
        data = raw[pos:pos + size]
        if (end := _expect(raw, pos + size, b']')) < 0:
            pos = bad("нет закрывающей ']'")
            continue
        pos = end
        entries.append(RegEntry(key, value, reg_type, data))

    return version, entries, warnings


def format_reg_value(reg_type: int, data: bytes) -> str:
    """Текстовое представление данных значения реестра."""
    try:
        if reg_type in (1, 2):
            return reg_data_value(reg_type, data)
        if reg_type in (4, 5, 11):
            if len(data) < (8 if reg_type == 11 else 4):
                return data.hex(" ") or "(empty)"
            v = reg_data_value(reg_type, data)
            return f"{v} ({v:#x})" if v > 9 else str(v)
        if reg_type == 7:
            parts = reg_data_value(reg_type, data)
            return " | ".join(parts) if parts else "(empty)"
        if not data:
            return "(empty)"
        if HAS_CRYPTOGRAPHY and len(data) > 100 and (b'\x30\x82' in data or b'\x30\x83' in data):
            certs = find_certificates(data)
            if certs:
                return "[Certificate]\n" + "\n".join(_fmt_cert(c) for c in certs)
        if len(data) > 64:
            return f"({len(data)} bytes)\n" + _hexdump_preview(data)
        return data.hex(" ")
    except Exception as exc:  # отображение никогда не должно падать
        return f"(parse error: {exc}  raw={data[:16].hex()})"


def _describe_value_name(value: str) -> str:
    low = value.lower()
    if low.startswith("**del."):
        return f"{value[6:]}  (удалить значение)"
    if low.startswith("**delvals"):
        return "(удалить все значения ключа)"
    if low.startswith("**soft."):
        return f"{value[7:]}  (задать, только если не существует)"
    return value


def parse_registry_pol(raw: bytes) -> str:
    """Текстовое представление Registry.pol для вывода в консоль."""
    version, entries, warnings = read_registry_pol(raw)
    if version is None:
        msg = warnings[0] if warnings else "ошибка разбора"
        out = f"  ({msg})"
        if raw[:4] != _REGPOL_SIG and raw:
            out += "\n" + hexdump(raw[:32])
        return out

    lines = [f"  Registry.pol  version={version}  записей={len(entries)}", "  " + "─" * 64]
    for i, e in enumerate(entries, 1):
        lines.append(f"\n  [{i}]")
        lines.append(f"    Key  : {e.key}")
        lines.append(f"    Value: {_describe_value_name(e.value)}")
        lines.append(f"    Type : {e.type_name}")
        lines.append(f"    Data : {format_reg_value(e.type, e.data)}")
    if not entries:
        lines.append("  (записей нет)")
    for w in warnings:
        lines.append(f"  [!] {w}")
    return "\n".join(lines)


def reg_type_from_name(name: str) -> int:
    return _REG_TYPE_BY_NAME.get((name or "").upper(), 1)


# ─────────────────────────────────────────────────────────────────────────────
# Smart dispatcher
# ─────────────────────────────────────────────────────────────────────────────

_TEXT_EXT = (".inf", ".ini", ".xml", ".cmtx", ".adm", ".admx", ".adml", ".csv",
             ".ps1", ".psm1", ".vbs", ".js", ".bat", ".cmd", ".txt", ".aas")
_CERT_EXT = (".cer", ".der", ".crt", ".p7b", ".pem")


def render_gpo_file(filename: str, raw: bytes) -> str:
    """Текстовое представление файла GPO. Никогда не возвращает сырые байты."""
    fl = filename.lower().replace("\\", "/")
    if not raw:
        return "  (пустой файл)"
    if fl.endswith("registry.pol"):
        return parse_registry_pol(raw)
    if fl.endswith(_CERT_EXT):
        return decode_certificate(raw)
    if fl.endswith(_TEXT_EXT) or not is_binary(raw):
        return decode_text(raw)
    return f"  (бинарный файл — {len(raw)} байт, hex-preview)\n" + _hexdump_preview(raw)


def display_gpo_file(filename: str, raw: bytes) -> None:
    print(render_gpo_file(filename, raw))
