#!/usr/bin/env bash
# cipherDNS Universal Launcher
# Automatically uses .venv python and handles port 53 privileges

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Locate virtualenv python
if [ -f "$SCRIPT_DIR/.venv/bin/python3" ]; then
    PYTHON_EXEC="$SCRIPT_DIR/.venv/bin/python3"
elif [ -n "$VIRTUAL_ENV" ] && [ -f "$VIRTUAL_ENV/bin/python3" ]; then
    PYTHON_EXEC="$VIRTUAL_ENV/bin/python3"
else
    PYTHON_EXEC="$(which python3)"
fi

echo "============================================================"
echo "  🚀 Starting cipherDNS..."
echo "  Python Interpreter: $PYTHON_EXEC"
echo "============================================================"

# Check if port 53 is requested or running as root
if [ "$EUID" -eq 0 ]; then
    # Running as root / sudo -> port 53 works directly
    exec "$PYTHON_EXEC" run.py --dns-port 53 --dns-host 127.0.0.1 --web-port 8000 "$@"
else
    # Not root
    if [ "$1" == "--port-53" ] || [ "$1" == "-p53" ] || [ "$1" == "53" ]; then
        echo "[!] Port 53 requires root privileges on Linux. Elevating with sudo..."
        exec sudo "$PYTHON_EXEC" run.py --dns-port 53 --dns-host 127.0.0.1 --web-port 8000 "${@:2}"
    else
        # Default unprivileged demo mode (fallback handled automatically)
        exec "$PYTHON_EXEC" run.py "$@"
    fi
fi

