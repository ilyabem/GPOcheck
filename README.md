# GPOCheck

**Active Directory Group Policy Object Security Analyzer**

GPOCheck читает групповые политики домена (объекты GPO в LDAP и файлы в SYSVOL) и выявляет небезопасные настройки: слабую политику паролей, отключённую защиту протоколов, пароли в Group Policy Preferences, опасные привилегии, избыточные права на изменение GPO. Дополнительно проверяет учётные записи домена.

За основу взят и глубоко доработан [GPOHunter](https://github.com/PShlyundin/GPOHunter).

---

## Возможности

| Категория | Что проверяет |
|-----------|---------------|
| **Политика паролей** | Действующая политика домена (из объекта домена, а не из «первой попавшейся» GPO), FGPP, сложность, длина, возраст, история, блокировка |
| **Хеши и учётные данные** | LM-хеши, LmCompatibilityLevel, WDigest, обратимое шифрование, пароль автовхода в GPO, RunAsPPL, CredSSP |
| **Протоколы** | SMBv1, подпись SMB, подпись и channel binding LDAP, защита канала Netlogon (ZeroLogon), DES/RC4 в Kerberos, WinRM, LLMNR |
| **RDP** | NLA, уровень безопасности и шифрования, запрос пароля |
| **Повышение привилегий** | AlwaysInstallElevated, UAC, LocalAccountTokenFilterPolicy, Point and Print (PrintNightmare) |
| **Защитные механизмы** | Отключение Defender и брандмауэра, исключения Defender, журналирование PowerShell |
| **Права и группы** | Опасные привилегии (SeDebug, SeBackup, SeImpersonate…) у широких групп, Restricted Groups, добавление в локальные администраторы через GPP |
| **Group Policy Preferences** | `cpassword` (MS14-025), задачи планировщика, параметры реестра из Registry.xml, сценарии входа/запуска |
| **Объекты GPO** | Кто может изменять GPO (ACL), владелец, несвязанные и отключённые GPO, расхождение версий AD и SYSVOL |
| **Учётные записи** (`--users`) | AS-REP roasting, Kerberoasting, неограниченное делегирование, PASSWD_NOTREQD, бессрочные пароли администраторов, неактивные учётки, возраст пароля krbtgt, состав привилегированных групп с учётом вложенности |

Проверки реестра учитывают **значение** параметра (например, `SMB1=0` — это не уязвимость) и одинаково применяются к `Registry.pol`, секции `[Registry Values]` в `GptTmpl.inf` и `Registry.xml` из GPP.

### Декодирование файлов GPO

| Файл | Формат | Обработка |
|------|--------|-----------|
| `GptTmpl.inf`, `GPT.INI`, `scripts.ini` | UTF-16 LE/BE, UTF-8, cp1251 | Автоопределение кодировки, разбор по секциям |
| `Registry.pol` | Бинарный PReg | Строгий парсер всех типов REG_*, восстановление после повреждённых записей |
| EFS / сертификаты | DER/ASN.1 | Поиск и декодирование сертификатов внутри blob |
| `*.xml` (GPP), `*.cmtx` | UTF-8 / UTF-16 | Разбор XML |
| Прочие бинарные файлы | — | Hex dump |

---

## Установка

```bash
git clone https://github.com/ilyabem/GPOCheck.git
cd GPOCheck
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Требуется Python 3.10+. Для Kerberos на Linux дополнительно нужен пакет `gssapi` (`pip install gssapi`, требует системных библиотек Kerberos) и билет `kinit`.

> **Ошибка `unsupported hash type MD4`** — OpenSSL 3.x отключил MD4, который нужен для NTLM. `pycryptodome` из requirements.txt его предоставляет.

> **Антивирус удаляет файлы.** Некоторые антивирусы (замечено у Kaspersky) эвристически считают инструменты аудита AD хакерскими и удаляют их. Добавьте каталог GPOCheck в исключения.

---

## Использование

### Windows: текущий сеанс домена

Если машина в домене, учётные данные не нужны: используется Kerberos текущего пользователя, SYSVOL читается по UNC-пути через указанный DC.

```bash
python gpo_analyzer_cli.py -d corp.local -dc dc01.corp.local
```

Для Kerberos указывайте **имя** DC (FQDN), а не IP-адрес.

### Логин и пароль (NTLM)

```bash
python gpo_analyzer_cli.py -d corp.local -dc dc01.corp.local -u auditor
```

Пароль будет запрошен без отображения (можно передать `-p`, но тогда он попадёт в историю командной строки). Имя пользователя можно указать как `user`, `CORP\user` или `user@corp.local`. SYSVOL читается по SMB.

Если DC требует подпись LDAP, скрипт сам переключится на LDAPS (636). Принудительно: `--ldaps`.

### Linux: Kerberos

```bash
kinit auditor@CORP.LOCAL
python gpo_analyzer_cli.py -d corp.local -dc dc01.corp.local -k
```

### Офлайн-анализ копии SYSVOL

Скопируйте каталог `\\corp.local\SYSVOL\corp.local\Policies` и проверьте его без подключения к AD:

```bash
python gpo_analyzer_cli.py --offline ./Policies
```

В офлайн-режиме пороги паролей проверяются по Default Domain Policy; связи GPO и права на объекты недоступны.

### Пользователи, отчёт, CI

```bash
python gpo_analyzer_cli.py -d corp.local -dc dc01.corp.local \
  --users --show-members --json report.json --fail-on HIGH --no-prompt
```

`--fail-on HIGH` возвращает код 2, если найдено хотя бы одно замечание HIGH или CRITICAL.

### Пороги политики паролей

При запуске в терминале скрипт спросит пороги (Enter — значение по умолчанию). Без вопросов: `--no-prompt`; при перенаправлении ввода/вывода вопросы не задаются. Пороги можно задать аргументами:

```bash
python gpo_analyzer_cli.py ... --no-prompt --min-pwd-len 14 --max-pwd-age 0 --lockout-count 5
```

`--max-pwd-age 0` отключает проверку срока действия пароля (допустимо при длинных паролях и MFA, см. NIST 800-63B).

---

## Пример вывода

```
GPOCheck v2.0.0 — Active Directory GPO Security Analyzer

[+] Подключено к dc01.corp.local (LDAP, Kerberos) как CORP\auditor
[+] Найдено GPO: 10, связей (gPLink): 7

=== Политика паролей ===

  Действующая политика домена (атрибуты объекта домена)
  ────────────────────────────────────────────────────────────
    Сложность пароля                   включена ✓
    Мин. длина пароля                  7
    Порог блокировки (попыток)         0 (блокировка отключена)

  GPO «Password Policy» — связь с корнем домена ОТКЛЮЧЕНА
  ...

=== Результаты проверки ===

  [HIGH] RDP без NLA (Network Level Authentication)
    GPO    : Remote Access Policy
    Файл   : Machine\Registry.pol
    Данные : MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\UserAuthentication = 0
    Суть   : UserAuthentication=0: сеанс создаётся до аутентификации ...

  [HIGH] Слабая минимальная длина пароля (7 < 12)
    GPO    : Политика домена (действующая)
    Данные : MinimumPasswordLength = 7

  Итого:  2 HIGH  |  1 MEDIUM  |  3 LOW
  Не показано замечаний ниже уровня LOW: 5 (см. --min-severity)
```

---

## Уровни severity

| Уровень | Описание |
|---------|----------|
| `CRITICAL` | Прямая компрометация: пароли в GPO, изменение GPO широкой группой, обратимое шифрование |
| `HIGH` | Серьёзная уязвимость, требует исправления |
| `MEDIUM` | Отклонение от best practices с реальным риском |
| `LOW` | Незначительный риск, рекомендуется проверить |
| `INFO` | Сведения для аудитора (задачи, сценарии, несвязанные GPO); по умолчанию скрыты, показать: `--min-severity INFO` |

---

## Все аргументы

```
Подключение:
  -d, --domain        DNS-имя домена
  -dc, --dc           IP или имя контроллера домена (по умолчанию — имя домена)
  -u, --username      Пользователь (NTLM)
  -p, --password      Пароль (если не указан — будет запрошен)
  -k, --kerberos      Kerberos: текущий сеанс Windows или KRB5CCNAME (Linux)
  --ldaps             LDAPS (636)
  --ldap-port N       Нестандартный порт LDAP
  --smb-port N        Порт SMB (445)
  --timeout N         Таймаут подключения, сек (10)
  --sysvol-path DIR   Читать файлы GPO из каталога Policies вместо SMB
  --offline DIR       Офлайн-анализ каталога Policies

Что проверять и выводить:
  --gpo NAME          Фильтр по имени или GUID GPO
  --show-xml          Показать декодированное содержимое файлов GPO (синоним --show-files)
  --users             Пользователи, группы и проверки учётных записей
  --show-members      Участники групп
  --stale-days N      Порог неактивности учётных записей (90)
  --no-acl            Не проверять права на объекты GPO
  --min-severity LVL  Минимальный выводимый уровень (LOW)
  --json FILE         Полный отчёт в JSON
  --fail-on LVL       Код возврата 2 при замечаниях уровня LVL и выше
  --no-prompt         Не задавать вопросов
  --no-color          Без цветов (также переменная NO_COLOR)

Пороги:
  --min-pwd-len N  --max-pwd-age N  --min-pwd-age N  --pwd-history N
  --lockout-count N  --lockout-duration N  --lockout-reset N
```

---

## Структура проекта

```
GPOCheck/
├── gpo_analyzer_cli.py   # CLI: аргументы и сценарий запуска
├── gpo_checks.py         # Проверки безопасности (без сети)
├── gpo_decoders.py       # Декодеры файлов GPO (INF, Registry.pol, сертификаты)
├── gpo_ldap.py           # LDAP: подключение, GPO, связи, политика паролей, ACL
├── gpo_sysvol.py         # Чтение SYSVOL: SMB, UNC, локальный каталог
├── gpo_users.py          # Пользователи, группы, проверки учётных записей
├── gpo_report.py         # Консольный вывод и JSON
└── tests/                # Тесты (не требуют AD)
```

---

## Тесты

```bash
python -m unittest discover -s tests -t tests
```

Тесты не требуют контроллера домена: LDAP эмулируется mock-стратегией ldap3, SMB — локальным сервером impacket на 127.0.0.1.

---

## Требования к правам

- Любая учётная запись домена: чтение GPO, SYSVOL, политики домена, пользователей и групп.
- FGPP по умолчанию читаются только администраторами домена.
- Сетевой доступ к DC: 389/636 (LDAP/LDAPS), 445 (SMB), 88 (Kerberos).

---

## Правовая информация

Инструмент предназначен **исключительно для авторизованного аудита безопасности** собственной инфраструктуры или при наличии явного письменного разрешения владельца системы. Использование против систем без разрешения незаконно.

---

## Лицензия

MIT License — см. файл [LICENSE](LICENSE).
