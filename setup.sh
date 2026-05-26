#!/usr/bin/env bash
# setup.sh — быстрая установка GPOCheck
set -e

VENV_DIR="venv"
PYTHON="${PYTHON:-python3}"

echo ""
echo "  GPOCheck — установка"
echo "  ─────────────────────"

# Проверить python3-venv
if ! $PYTHON -c "import ensurepip" 2>/dev/null; then
    echo ""
    echo "  [!] Модуль ensurepip не найден."
    echo "      Установите: sudo apt install python3-venv python3-full"
    exit 1
fi

echo "  [*] Создаю виртуальное окружение..."
$PYTHON -m venv "$VENV_DIR"

echo "  [*] Обновляю pip..."
"$VENV_DIR/bin/pip" install --upgrade pip -q

echo "  [*] Устанавливаю зависимости..."
"$VENV_DIR/bin/pip" install -r requirements.txt -q

echo ""
echo "  [+] Готово!"
echo ""
echo "      Активировать:  source venv/bin/activate"
echo "      Справка:       python gpo_analyzer_cli.py --help"
echo "      Тесты:         python test_decoders.py"
echo ""
