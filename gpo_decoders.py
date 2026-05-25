"""
gpo_decoders.py — Binary/text decoders for GPO file formats.

Fixes v2:
  - Registry.pol : исправлен парсер (баг со съехавшим pos при длинных ключах)
  - EFS/Cert blob : декодируется DER-сертификат внутри бинарного blob
  - REG_UNKNOWN   : корректная обработка нестандартных типов
  - is_binary     : поддержка UTF-16 LE без BOM
"""

import struct

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
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


def is_binary(data: bytes, sample_size: int = 512, threshold: float = 0.30) -> bool:
    sample = data[:sample_size]
    if not sample:
        return False
    if sample[:2] in (b'\xff\xfe', b'\xfe\xff'):
        return False
    # UTF-16 LE без BOM: каждый второй байт = 0x00 для ASCII-диапазона
    if len(sample) >= 16:
        odd_nulls = sum(1 for i in range(1, min(len(sample), 64), 2) if sample[i] == 0)
        if odd_nulls > 20:
            return False
    non_print = sum(1 for b in sample if b < 9 or (13 < b < 32) or b > 126)
    return (non_print / len(sample)) > threshold


# ─────────────────────────────────────────────────────────────────────────────
# GptTmpl.inf
# ─────────────────────────────────────────────────────────────────────────────

def decode_gpttmpl(raw: bytes) -> str:
    if raw[:2] == b'\xff\xfe':
        return raw.decode("utf-16-le")
    if raw[:2] == b'\xfe\xff':
        return raw.decode("utf-16-be")
    if raw[:3] == b'\xef\xbb\xbf':
        return raw[3:].decode("utf-8")
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", errors="replace")


# ─────────────────────────────────────────────────────────────────────────────
# DER-сертификат (и поиск DER внутри бинарных blob)
# ─────────────────────────────────────────────────────────────────────────────

def _fmt_cert(cert) -> str:
    """Форматировать объект x509.Certificate в текст."""
    fp = cert.fingerprint(hashes.SHA256()).hex(":")
    lines = [
        f"    Subject  : {cert.subject.rfc4514_string()}",
        f"    Issuer   : {cert.issuer.rfc4514_string()}",
        f"    Serial   : {cert.serial_number}",
        f"    NotBefore: {cert.not_valid_before_utc}",
        f"    NotAfter : {cert.not_valid_after_utc}",
        f"    SHA-256  : {fp}",
    ]
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        upn_list = san.value.get_values_for_type(x509.OtherName)
        dns_list = san.value.get_values_for_type(x509.DNSName)
        rfc_list = san.value.get_values_for_type(x509.RFC822Name)
        if dns_list:
            lines.append(f"    SAN DNS  : {', '.join(dns_list)}")
        if rfc_list:
            lines.append(f"    SAN Email: {', '.join(rfc_list)}")
    except x509.ExtensionNotFound:
        pass
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        usages = []
        for attr in ("digital_signature","content_commitment","key_encipherment",
                     "data_encipherment","key_agreement","key_cert_sign","crl_sign"):
            try:
                if getattr(ku, attr):
                    usages.append(attr.replace("_"," "))
            except Exception:
                pass
        if usages:
            lines.append(f"    Key Usage: {', '.join(usages)}")
    except x509.ExtensionNotFound:
        pass
    return "\n".join(lines)


def decode_certificate(raw: bytes) -> str:
    """
    Попытаться декодировать DER-сертификат.
    Если raw — не чистый DER, ищем подпоследовательность 30 82 ... (SEQUENCE).
    """
    if not HAS_CRYPTOGRAPHY:
        return hexdump(raw[:256]) + (f"\n  ... {len(raw)} bytes total" if len(raw) > 256 else "")

    # 1. Прямой разбор
    try:
        cert = x509.load_der_x509_certificate(raw, default_backend())
        return _fmt_cert(cert)
    except Exception:
        pass

    # 2. Поиск DER SEQUENCE (0x30 0x82 ...) внутри blob
    idx = 0
    while idx < len(raw) - 4:
        pos = raw.find(b'\x30\x82', idx)
        if pos == -1:
            break
        length = struct.unpack_from(">H", raw, pos + 2)[0]
        end = pos + 4 + length
        if end <= len(raw):
            try:
                cert = x509.load_der_x509_certificate(raw[pos:end], default_backend())
                return "    [DER cert found inside blob]\n" + _fmt_cert(cert)
            except Exception:
                pass
        idx = pos + 1

    # 3. Hex dump fallback
    result = hexdump(raw[:256])
    if len(raw) > 256:
        result += f"\n  ... {len(raw)} bytes total"
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Registry.pol — ИСПРАВЛЕННЫЙ парсер
# ─────────────────────────────────────────────────────────────────────────────

_REGPOL_SIG  = b'PReg'
_REG_TYPES = {
    0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY",
    4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN", 7: "REG_MULTI_SZ",
    11: "REG_QWORD",
}


def _read_utf16z(data: bytes, pos: int) -> tuple:
    """
    Читает UTF-16 LE строку с нулевым терминатором из data начиная с pos.
    Возвращает (строка, новый_pos).
    ИСПРАВЛЕНИЕ: поиск двойного нуля с выравниванием по 2 байта,
    чтобы не съезжать при нечётных смещениях.
    """
    start = pos
    # Выровнять на границу 2 байт
    if pos % 2 != 0:
        pos += 1
    while pos + 1 < len(data):
        if data[pos] == 0 and data[pos + 1] == 0:
            try:
                s = data[start:pos].decode("utf-16-le", errors="replace")
            except Exception:
                s = ""
            return s, pos + 2
        pos += 2
    return "", len(data)


def _skip_u16_semicolon(data: bytes, pos: int) -> int:
    """Пропустить UTF-16 LE символ ';' (0x3B 0x00) если он есть."""
    if pos + 1 < len(data) and data[pos] == 0x3B and data[pos + 1] == 0x00:
        return pos + 2
    return pos


def _skip_u16_bracket(data: bytes, pos: int, char: str) -> int:
    """Пропустить UTF-16 LE символ char если он есть."""
    b = ord(char)
    if pos + 1 < len(data) and data[pos] == b and data[pos + 1] == 0x00:
        return pos + 2
    return pos


def _format_reg_value(reg_type: int, data: bytes) -> str:
    try:
        if reg_type in (1, 2):
            return data.decode("utf-16-le", errors="replace").rstrip("\x00")
        if reg_type == 4:
            return str(struct.unpack_from("<I", data)[0]) if len(data) >= 4 else data.hex()
        if reg_type == 5:
            return str(struct.unpack_from(">I", data)[0]) if len(data) >= 4 else data.hex()
        if reg_type == 11:
            return str(struct.unpack_from("<Q", data)[0]) if len(data) >= 8 else data.hex()
        if reg_type == 7:
            decoded = data.decode("utf-16-le", errors="replace")
            parts = [p for p in decoded.split("\x00") if p]
            return " | ".join(parts) if parts else "(empty)"
        # REG_BINARY и прочие — hex
        if not data:
            return "(empty)"
        # Попробовать найти DER-сертификат внутри бинарных данных
        if HAS_CRYPTOGRAPHY and len(data) > 100 and b'\x30\x82' in data:
            cert_text = decode_certificate(data)
            if "Subject" in cert_text:
                return f"[Certificate]\n{cert_text}"
        return data.hex(" ")
    except Exception as exc:
        return f"(parse error: {exc}  raw={data[:16].hex()})"


def parse_registry_pol(raw: bytes) -> str:
    """
    Парсер Windows Registry.pol (PReg).
    
    Формат записи (все строки — UTF-16 LE, нуль-терминированные):
      [ ключ \0 ; значение \0 ; тип(DWORD) ; размер(DWORD) ; данные ]
    """
    if len(raw) < 8:
        return "  (файл слишком короткий для Registry.pol)"

    if raw[:4] != _REGPOL_SIG:
        return f"  (неизвестная сигнатура: {raw[:4].hex()})\n" + hexdump(raw[:32])

    version = struct.unpack_from("<I", raw, 4)[0]
    lines = [f"  Registry.pol  version={version}", "  " + "─" * 64]
    pos = 8
    entry_num = 0

    while pos < len(raw) - 3:
        # Ищем открывающую '[' в UTF-16 LE
        pos = _skip_u16_bracket(raw, pos, '[')
        if pos >= len(raw):
            break

        # Если не нашли '[' — ищем следующую позицию
        # (защита от десинхронизации)
        if not (pos >= 2 and raw[pos - 2] == 0x5B and raw[pos - 1] == 0x00):
            # Сканируем побайтово в поисках '[\x00'
            found = False
            while pos < len(raw) - 1:
                if raw[pos] == 0x5B and raw[pos + 1] == 0x00:
                    pos += 2
                    found = True
                    break
                pos += 1
            if not found:
                break

        entry_start = pos
        entry_num += 1

        # Ключ
        key, pos = _read_utf16z(raw, pos)
        pos = _skip_u16_semicolon(raw, pos)

        # Значение
        value, pos = _read_utf16z(raw, pos)
        pos = _skip_u16_semicolon(raw, pos)

        # Тип (DWORD)
        if pos + 4 > len(raw):
            break
        reg_type = struct.unpack_from("<I", raw, pos)[0]
        pos += 4
        pos = _skip_u16_semicolon(raw, pos)

        # Размер данных (DWORD)
        if pos + 4 > len(raw):
            break
        data_size = struct.unpack_from("<I", raw, pos)[0]
        pos += 4
        pos = _skip_u16_semicolon(raw, pos)

        # Данные
        if pos + data_size > len(raw):
            data_size = len(raw) - pos  # обрезаем по границе файла
        data = raw[pos:pos + data_size]
        pos += data_size

        # Закрывающая ']'
        pos = _skip_u16_bracket(raw, pos, ']')

        type_name = _REG_TYPES.get(reg_type, f"REG_UNKNOWN({reg_type:#010x})")

        # Очищаем ключ от мусора после нулевого терминатора
        key   = key.rstrip("\x00").strip()
        value = value.rstrip("\x00").strip()

        lines.append(f"\n  [{entry_num}]")
        lines.append(f"    Key  : {key}")
        lines.append(f"    Value: {value}")
        lines.append(f"    Type : {type_name}")
        lines.append(f"    Data : {_format_reg_value(reg_type, data)}")

    if entry_num == 0:
        lines.append("  (записей не найдено)")

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Smart dispatcher
# ─────────────────────────────────────────────────────────────────────────────

def display_gpo_file(filename: str, raw: bytes) -> None:
    """Маршрутизировать файл к нужному декодеру. Никогда не выводить raw bytes."""
    fl = filename.lower().replace("\\", "/")

    if not raw:
        print("  (пустой файл)")
        return

    if fl.endswith("gpttmpl.inf"):
        print(decode_gpttmpl(raw))

    elif fl.endswith("registry.pol"):
        print(parse_registry_pol(raw))

    elif fl.endswith(".ini") or fl.endswith("gpt.ini"):
        print(decode_gpttmpl(raw))

    elif fl.endswith(".xml") or fl.endswith(".cmtx"):
        for enc in ("utf-8", "utf-16-le", "utf-16-be", "latin-1"):
            try:
                print(raw.decode(enc))
                break
            except UnicodeDecodeError:
                continue

    elif fl.endswith((".cer", ".der", ".crt", ".p7b")):
        print(decode_certificate(raw))

    elif fl.endswith((".ps1", ".vbs", ".bat", ".cmd")):
        print(decode_gpttmpl(raw))

    else:
        if is_binary(raw):
            print(f"  (бинарный файл — {len(raw)} байт, hex-preview)")
            print(hexdump(raw[:256]))
            if len(raw) > 256:
                print(f"  ... {len(raw)} bytes total")
        else:
            for enc in ("utf-8", "utf-16-le", "latin-1"):
                try:
                    print(raw.decode(enc))
                    break
                except UnicodeDecodeError:
                    continue
