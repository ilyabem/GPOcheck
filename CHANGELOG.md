# Changelog

## [2.0.0] — 2026-11-02

### Исправлено
- Ложные срабатывания: SMBv1, WDigest, AlwaysInstallElevated, AutoLogon помечались уязвимыми
  по одному упоминанию имени, даже когда параметр выключен. Теперь проверяется значение.
- Парсер `Registry.pol` терял записи после REG_BINARY нечётной длины (на реальных файлах —
  до половины записей, включая параметры RDP). Новый строгий парсер с ресинхронизацией.
- Политика паролей бралась из первой попавшейся GPO. Теперь действующая политика читается
  из объекта домена; GPO, не связанные с корнем домена, помечаются как недействующие.
- `MaximumPasswordAge = -1` / `LockoutDuration = -1` не распознавались.
- Пользователи и группы: без постраничного поиска AD отдавал не больше 1000 объектов;
  основная группа (Domain Users) не учитывалась, из-за чего почти все попадали в «без групп».
- Падение на консоли Windows (cp866/cp1251) при выводе ✓/█/─.
- Ошибки SMB проглатывались молча; новое SMB-соединение открывалось на каждую GPO.
- `cryptography < 42` падал на `not_valid_before_utc`.
- Проверки RDP (NLA, запрос пароля), заявленные в README, фактически не выполнялись.

### Добавлено
- ~60 проверок реестра (LDAP signing/channel binding, Netlogon/ZeroLogon, PrintNightmare,
  Defender, брандмауэр, UAC, WinRM, Kerberos DES/RC4, LLMNR и др.) для Registry.pol,
  `[Registry Values]` GptTmpl.inf и Registry.xml (GPP).
- Group Policy Preferences: `cpassword` (MS14-025), задачи планировщика, Groups.xml, сценарии.
- Опасные привилегии и Restricted Groups в GptTmpl.inf.
- Права на объекты GPO (кто может изменять), связи GPO (gPLink), несвязанные/отключённые GPO,
  расхождение версий AD и SYSVOL, FGPP, ms-DS-MachineAccountQuota.
- Проверки учётных записей (`--users`): AS-REP roasting, Kerberoasting, делегирование,
  PASSWD_NOTREQD, krbtgt, неактивные и привилегированные учётные записи.
- Kerberos (`-k`): текущий сеанс Windows (SSPI) или KRB5CCNAME на Linux; на Windows без
  учётных данных используется текущий сеанс.
- LDAPS (`--ldaps`) и автоматический переход на него, если DC требует подпись LDAP.
- Офлайн-анализ копии каталога Policies (`--offline`), `--sysvol-path`.
- `--json`, `--fail-on`, `--min-severity`, уровень INFO, запрос пароля без отображения.
- Тесты `tests/` (84 теста, без AD: mock LDAP, локальный SMB-сервер).

### Изменено
- Код разделён на модули: `gpo_checks`, `gpo_ldap`, `gpo_sysvol`, `gpo_report`.
- `-u`/`-p` больше не обязательны (запрос пароля / Kerberos).

## [1.0.0] — 2025-05-25

### Добавлено
- Полный парсер `Registry.pol` (PReg-формат): поддержка REG_SZ, REG_DWORD,
  REG_QWORD, REG_MULTI_SZ, REG_BINARY — исправлен баг со съехавшим смещением
  при длинных ключах (EFS/сертификаты)
- Автоопределение кодировки `GptTmpl.inf`: UTF-16 LE BOM, UTF-16 BE, UTF-8 BOM, ASCII, Latin-1
- Декодирование DER/ASN.1 сертификатов внутри бинарных blob (EFS, SystemCertificates)
- Бинарная эвристика: файлы с >30% non-printable байт выводятся как hex dump,
  а не мусор в терминале
- Интерактивный ввод порогов политики безопасности при запуске
- Сводная таблица политики паролей с явным отображением статуса сложности
  (Включена ✓ / ОТКЛЮЧЕНА ✗)
- Настраиваемые проверки: минимальная длина пароля, возраст, история,
  порог и длительность блокировки
- Статические проверки: LM-хеши, WDigest, ClearText, SMBv1, AlwaysInstallElevated,
  AutoLogon, LDAP signing, Netlogon signing, RDP без NLA
- Модуль `gpo_users.py`: статистика пользователей и групп домена
  (всего / активные / отключённые, состав групп с гистограммой,
  пользователи без групп, список отключённых учётных записей)
- Флаг `--show-members` для вывода участников каждой группы
- Флаг `--no-prompt` и аргументы `--min-pwd-len`, `--max-pwd-age`,
  `--min-pwd-age`, `--lockout-count` для неинтерактивного запуска
- Итоговая сводка по severity: CRITICAL | HIGH | MEDIUM | LOW
- Офлайн-тесты декодеров `test_decoders.py` (14 тестов, не требуют AD)
- `.gitignore`, `LICENSE` (MIT), `CHANGELOG.md`
