#!/usr/bin/env bash
# browser-vpn.sh — открыть ссылку в Brave с отдельным VPN-профилем.
#
# Скрипт подставляется приложению (Qoder и т.п.) в $BROWSER. Приложение
# запущено внутри per-app VPN, поэтому Brave наследует тот же namespace и
# тот же сервер — IP у приложения и у браузера совпадают.
set -u

exe=$(command -v brave-browser-stable || command -v brave-browser || true)
if [ -z "$exe" ]; then
    command -v notify-send >/dev/null && \
        notify-send -a vpntui -i brave-browser \
        "VPN-браузер" "Не найден Brave (brave-browser-stable)"
    echo "browser-vpn: не найден Brave" >&2
    exit 1
fi

exec "$exe" --user-data-dir="$HOME/.config/brave-vpn-profile" "$@"
