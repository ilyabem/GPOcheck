"""
gpo_report.py — консольный вывод, интерактивный ввод порогов и JSON-отчёт.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime

from gpo_checks import SEVERITIES, SEV_ORDER


class C:
    OK = "\033[92m"
    WARN = "\033[93m"
    ERR = "\033[91m"
    INFO = "\033[94m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RST = "\033[0m"


def setup_streams() -> None:
    # Консоль Windows (cp866/cp1251) не умеет ✓/█/─: без этого print падает с UnicodeEncodeError
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def setup_colors(no_color: bool) -> None:
    if no_color or os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        for attr in [a for a in vars(C) if not a.startswith("_")]:
            setattr(C, attr, "")
    elif os.name == "nt":
        os.system("")  # включает обработку ANSI-последовательностей в консоли Windows


def ok(msg):   print(f"{C.OK}[+]{C.RST} {msg}")
def warn(msg): print(f"{C.WARN}[!]{C.RST} {msg}")
def err(msg):  print(f"{C.ERR}[-]{C.RST} {msg}", file=sys.stderr)
def info(msg): print(f"{C.INFO}[*]{C.RST} {msg}")


_SEV_COLOR = {"CRITICAL": "ERR", "HIGH": "WARN", "MEDIUM": "INFO", "LOW": "OK", "INFO": "DIM"}


def sev_color(sev: str) -> str:
    return getattr(C, _SEV_COLOR.get(sev, "RST"))


# ── Интерактивный ввод порогов ────────────────────────────────────────────────
def is_interactive() -> bool:
    """Ввод с клавиатуры и вывод в терминал (не pipe, не файл, не NUL)."""
    try:
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            return False
    except (AttributeError, ValueError):
        return False
    if os.name == "nt":
        # На Windows isatty() истинно и для устройства NUL (stdin < nul) — проверяем, что это консоль
        import ctypes
        import msvcrt
        try:
            handle = msvcrt.get_osfhandle(sys.stdin.fileno())
            mode = ctypes.c_uint32()
            return bool(ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)))
        except (OSError, ValueError, AttributeError):
            return False
    return True


def _ask_int(prompt: str, default: int, lo: int = 0, hi: int = 99999) -> int:
    while True:
        try:
            raw = input(f"  {prompt} [{default}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return default
        if raw == "":
            return default
        try:
            v = int(raw)
        except ValueError:
            print("    Ожидается целое число")
            continue
        if lo <= v <= hi:
            return v
        print(f"    Введите число от {lo} до {hi}")


def ask_thresholds(t: dict) -> dict:
    print(f"\n{C.BOLD}=== Настройка порогов политики безопасности ==={C.RST}")
    print(f"  {C.DIM}Enter — оставить значение по умолчанию{C.RST}\n")
    print(f"  {C.BOLD}— Политика паролей —{C.RST}")
    t["min_password_length"] = _ask_int("Минимальная длина пароля          (замечание, если меньше)", t["min_password_length"], 0, 128)
    t["require_complexity"] = _ask_int("Требовать сложность пароля        (1=да, 0=нет)", t["require_complexity"], 0, 1)
    t["min_password_age"] = _ask_int("Минимальный возраст пароля, дни   (замечание, если меньше)", t["min_password_age"], 0, 998)
    t["max_password_age"] = _ask_int("Максимальный возраст пароля, дни  (замечание, если больше; 0 = не проверять)", t["max_password_age"], 0, 999)
    t["password_history"] = _ask_int("История паролей                   (замечание, если меньше)", t["password_history"], 0, 24)
    print(f"\n  {C.BOLD}— Политика блокировки —{C.RST}")
    t["lockout_threshold"] = _ask_int("Попыток до блокировки             (замечание, если больше или 0)", t["lockout_threshold"], 1, 999)
    t["lockout_duration"] = _ask_int("Длительность блокировки, мин      (замечание, если меньше)", t["lockout_duration"], 0, 99999)
    t["reset_lockout_count"] = _ask_int("Сброс счётчика попыток, мин       (замечание, если меньше)", t["reset_lockout_count"], 0, 99999)
    print()
    return t


# ── Политика паролей ──────────────────────────────────────────────────────────
POLICY_LABELS = [
    ("complexity", "Сложность пароля"),
    ("min_length", "Мин. длина пароля"),
    ("max_age_days", "Макс. возраст пароля (дни)"),
    ("min_age_days", "Мин. возраст пароля (дни)"),
    ("history", "История паролей"),
    ("lockout_threshold", "Порог блокировки (попыток)"),
    ("lockout_duration_min", "Длительность блокировки (мин)"),
    ("lockout_window_min", "Сброс счётчика (мин)"),
    ("reversible", "Обратимое шифрование"),
]


def _policy_value(field, v):
    if field == "complexity":
        return f"{C.OK}включена ✓{C.RST}" if v else f"{C.WARN}ОТКЛЮЧЕНА ✗{C.RST}"
    if field == "reversible":
        return f"{C.ERR}ВКЛЮЧЕНО ✗{C.RST}" if v else f"{C.OK}выключено ✓{C.RST}"
    if field == "max_age_days" and v is None:
        return "никогда не истекает"
    if field == "lockout_threshold" and v == 0:
        return f"{C.WARN}0 (блокировка отключена){C.RST}"
    if field == "lockout_duration_min" and v == 0:
        return "до разблокировки администратором"
    return str(v)


def print_policy(title: str, policy: dict) -> None:
    print(f"\n  {C.BOLD}{title}{C.RST}")
    print(f"  {'─' * 60}")
    for field, label in POLICY_LABELS:
        if field in policy:
            print(f"    {label:<34} {_policy_value(field, policy[field])}")


def gpo_status(gpo: dict) -> str:
    return {0: "включена", 1: "отключена часть «Пользователь»", 2: "отключена часть «Компьютер»",
            3: "ПОЛНОСТЬЮ ОТКЛЮЧЕНА"}.get(gpo["flags"], f"flags={gpo['flags']}")


# ── Замечания ─────────────────────────────────────────────────────────────────
def print_findings(findings: list, min_sev: str) -> None:
    print(f"\n{C.BOLD}=== Результаты проверки ==={C.RST}")
    shown = [f for f in findings if SEV_ORDER[f.severity] <= SEV_ORDER[min_sev]]
    if not shown:
        ok("Замечаний не обнаружено")
    for f in shown:
        print(f"\n  {sev_color(f.severity)}[{f.severity}]{C.RST} {C.BOLD}{f.title}{C.RST}")
        if f.gpo:
            print(f"    GPO    : {f.gpo}")
        if f.path:
            print(f"    Файл   : {f.path}")
        if f.evidence:
            print(f"    Данные : {f.evidence}")
        if f.description:
            print(f"    Суть   : {f.description}")

    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
    parts = [f"{sev_color(s)}{counts[s]} {s}{C.RST}" for s in SEVERITIES if counts[s]]
    print(f"\n{C.BOLD}  Итого:{C.RST}  " + ("  |  ".join(parts) if parts else "0"))
    hidden = len(findings) - len(shown)
    if hidden:
        print(f"  {C.DIM}Не показано замечаний ниже уровня {min_sev}: {hidden} (см. --min-severity){C.RST}")


# ── JSON ──────────────────────────────────────────────────────────────────────
def _json_default(o):
    if isinstance(o, datetime):
        return o.isoformat()
    if isinstance(o, bytes):
        return o.hex()
    return str(o)


def write_json(path: str, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2, default=_json_default)
