# 🔍 GPOHunter

**Active Directory Group Policy Object Security Analyzer**

GPOHunter подключается к контроллеру домена, читает файлы GPO из SYSVOL и выявляет небезопасные настройки политик — политику паролей, блокировки, RDP, SMB, сертификаты и многое другое. Дополнительно выводит статистику пользователей и групп домена.

---

## Возможности

| Категория | Что проверяет |
|-----------|---------------|
| **Политика паролей** | Сложность, минимальная длина, возраст, история |
| **Политика блокировки** | Порог попыток, длительность, сброс счётчика |
| **Хеши и шифрование** | LM-хеши, WDigest, обратимое шифрование (ClearText) |
| **Протоколы** | SMBv1, Netlogon signing, LDAP signing |
| **RDP** | NLA (Network Level Authentication), пароль при входе |
| **Привилегии** | AlwaysInstallElevated, AutoLogon |
| **Сертификаты** | EFS blob — DER/ASN.1 декодирование внутри Registry.pol |
| **Пользователи** | Кол-во по группам, отключённые учётки, пользователи без групп |

### Корректное декодирование GPO файлов

| Файл | Формат | Обработка |
|------|--------|-----------|
| `GptTmpl.inf` | UTF-16 LE (BOM) | Автоопределение кодировки |
| `Registry.pol` | Бинарный PReg | Полный парсер всех типов REG_* |
| EFS / сертификаты | DER/ASN.1 | Поиск и декодирование внутри blob |
| `*.xml`, `*.cmtx` | UTF-8 / UTF-16 | Автоопределение |
| Прочие бинарники | — | Hex dump (не мусор в терминале) |

---

## Установка

```bash
git clone https://github.com/YOUR_USERNAME/GPOHunter.git
cd GPOHunter
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Зависимости:**

```
ldap3>=2.9.1
impacket>=0.11.0
cryptography>=41.0.0
pycryptodome>=3.19.0
```

> **Ubuntu 22.04+**: если получаете ошибку `unsupported hash type MD4` — установите `pycryptodome`:
> ```bash
> pip install pycryptodome
> ```
> OpenSSL 3.x отключил MD4, который нужен для NTLM-аутентификации. `pycryptodome` предоставляет его напрямую.

---

## Использование

### Базовый запуск (интерактивный ввод порогов)

```bash
python gpo_analyzer_cli.py \
  -u administrator \
  -p 'Password123!' \
  -d corp.local \
  -dc 192.168.1.10 \
  --show-xml
```

При запуске скрипт задаст вопросы о порогах политики:

```
=== Настройка порогов политики безопасности ===

  — Политика паролей —
  Минимальная длина пароля            [12]: 14
  Требовать сложность пароля (1=да)   [1]:
  Максимальный возраст пароля (дни)   [90]: 60

  — Политика блокировки —
  Попыток до блокировки               [5]: 3
  Длительность блокировки (мин)       [15]:
```

### Быстрый запуск без вопросов

```bash
python gpo_analyzer_cli.py \
  -u administrator -p 'Password123!' \
  -d corp.local -dc 192.168.1.10 \
  --no-prompt
```

### Пороги через аргументы

```bash
python gpo_analyzer_cli.py \
  -u administrator -p 'Password123!' \
  -d corp.local -dc 192.168.1.10 \
  --no-prompt \
  --min-pwd-len 14 \
  --max-pwd-age 60 \
  --lockout-count 3
```

### Статистика пользователей и групп

```bash
python gpo_analyzer_cli.py \
  -u administrator -p 'Password123!' \
  -d corp.local -dc 192.168.1.10 \
  --no-prompt \
  --users
```

С детальным списком участников каждой группы:

```bash
python gpo_analyzer_cli.py ... --users --show-members
```

### Всё вместе

```bash
python gpo_analyzer_cli.py \
  -u administrator -p 'Password123!' \
  -d corp.local -dc 192.168.1.10 \
  --show-xml --users --show-members \
  --min-pwd-len 14 --lockout-count 3 --no-prompt
```

---

## Пример вывода

```
GPOHunter v1.0.0 — Active Directory GPO Security Analyzer

[+] Подключено к Active Directory
[+] Найдено GPO: 5

=== Сводка политики паролей ===
  ──────────────────────────────────────────────────
  Сложность пароля                    Включена ✓
  Мин. длина пароля                   7
  Макс. возраст (дни)                 42
  Мин. возраст (дни)                  1
  История паролей                     24
  Порог блокировки (попыток)          0
  Хранить пароли открыто              0
  Отключить LM-хеши                   1

=== Security Analysis ===

  [HIGH] Слабая минимальная длина пароля (7 < 12)
    GPO  : Default Domain Policy
    Файл : MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf
    Инфо : MinimumPasswordLength=7, требуется ≥12

  [HIGH] Блокировка учётной записи отключена (LockoutBadCount=0)
    GPO  : Default Domain Policy
    Файл : MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf
    Инфо : Возможен неограниченный перебор пароля (brute-force)

  Итого:  2 HIGH

=== Отчёт по пользователям и группам ===

  Пользователи:
    Всего      : 120
    Активные   : 115
    Отключённые: 5

  Состав групп:
  ─────────────────────────────────────────────────
  Группа           Тип                 Польз
  Accounting       Security / Global     100  ████████████
  IT               Security / Global      10  ██████████
  Domain Admins    Security / Global       5  █████
```

---

## Уровни severity

| Уровень | Цвет | Описание |
|---------|------|----------|
| `CRITICAL` | 🔴 Красный | Немедленное исправление — прямая угроза безопасности |
| `HIGH` | 🟡 Жёлтый | Серьёзная уязвимость, требует исправления |
| `MEDIUM` | 🔵 Синий | Отклонение от best practices |
| `LOW` | 🟢 Зелёный | Незначительный риск, рекомендуется проверить |

---

## Структура проекта

```
GPOHunter/
├── gpo_analyzer_cli.py   # Основной CLI
├── gpo_decoders.py       # Декодеры GPO файлов (GptTmpl, Registry.pol, DER)
├── gpo_users.py          # Модуль статистики пользователей и групп
├── test_decoders.py      # Офлайн-тесты декодеров
├── requirements.txt
├── setup.sh
└── README.md
```

---

## Все аргументы CLI

```
python gpo_analyzer_cli.py --help

  -u, --username      Имя пользователя AD
  -p, --password      Пароль
  -d, --domain        Домен (например corp.local)
  -dc, --dc           IP или hostname контроллера домена

  --show-xml          Показать содержимое файлов GPO
  --gpo NAME          Фильтровать по имени GPO
  --users             Показать статистику пользователей и групп
  --show-members      Показать участников каждой группы
  --no-prompt         Не задавать вопросов, использовать дефолты
  --no-color          Отключить ANSI-цвета (для pipe/grep)
  --version           Показать версию

Пороги:
  --min-pwd-len N     Минимальная длина пароля (по умолч. 12)
  --max-pwd-age N     Максимальный возраст пароля в днях (по умолч. 90)
  --min-pwd-age N     Минимальный возраст пароля в днях (по умолч. 1)
  --lockout-count N   Порог неверных попыток до блокировки (по умолч. 5)
```

---

## Офлайн-тесты

Проверить корректность декодеров без подключения к AD:

```bash
python test_decoders.py
```

Ожидаемый результат: все тесты PASS.

---

## Требования

- Python 3.10+
- Учётная запись домена с правами на чтение GPO и SYSVOL
- Сетевой доступ к контроллеру домена (порты 389/LDAP, 445/SMB)

---

## Правовая информация

Инструмент предназначен **исключительно для авторизованного аудита безопасности** собственной инфраструктуры или при наличии явного письменного разрешения владельца системы. Использование против систем без разрешения незаконно.

---

## Лицензия

MIT License — см. файл [LICENSE](LICENSE).
