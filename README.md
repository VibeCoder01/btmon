# btmon

A fullscreen TUI that scans for Bluetooth devices and logs presence changes for tracked devices. The goal is to detect when a person is nearby by observing their phone (or other carried device).

## Requirements

- Linux with BlueZ tools installed (`bluetoothctl`)
- A Bluetooth adapter enabled (`rfkill` not blocked)
- Python 3 (standard library only)

## Quick Start

1) Create `config.json` from the example:

```bash
make init-config
```

2) Edit `config.json` and add your device MAC addresses.
3) Run the app:

```bash
make run
```

Alternatives: `cp config.example.json config.json` and `python3 src/btmon.py`.

`config.json`, logs, and cache data are ignored by Git.

Logs are written to `btmon.log` by default. The TUI shows discovered devices, tracked state, and an overall human presence indicator.
Device details (name/alias/class/icon/paired/trusted/connected/manufacturer) refresh via periodic deep scans, with new devices scanned immediately.
An alarm flashes the screen (and can beep) when a tracked device returns after being away longer than the configured threshold.
Cached device info persists across runs for the configured TTL to keep last-seen and deep-scan details visible.

Key bindings:

- `q` quit
- `r` scan now
- `up/down` select a MAC in the devices list
- `PageUp/PageDown` scroll the current list by a page
- `space` toggle multi-select and move down
- `t` toggle tracking for the selected device(s)
- `e` edit the selected MAC/label
- `d` delete all records for the selected device(s)
- `a` toggle alarm for the selected tracked device(s)
- `h` hide/unhide the selected device(s)
- `f` cycle device filter (normal/hidden/all)
- `l` toggle recent log entries for the selected MAC
- `c` toggle the config view (scrollable list of config values)
- `e` edits the highlighted config value while in config view
- `n` toggle the noise graph view
- `k` acknowledge the active alarm
- `1-9` sort the devices by the numbered column

Info warnings from deep scans are summarized in the footer and listed in the log panel (`l`).

## Config

`config.json` fields:

- `scan_interval`: seconds between scans.
- `scan_timeout`: seconds for each scan window.
- `scan_use_tty`: use a pseudo-tty for scans (can help RSSI output on some systems).
- `presence_ttl`: seconds a device remains "present" after last seen.
- `info_refresh_interval`: seconds between deep scans that refresh detailed device info.
- `alarm_enabled`: whether to trigger the alarm on return.
- `alarm_away_threshold`: seconds a tracked device must be away before alarm triggers.
- `alarm_flash_seconds`: seconds to flash the screen on alarm.
- `alarm_beep`: whether to beep on alarm.
- `log_path`: log file path.
- `cache_path`: path to the cache file storing last seen and deep-scan details.
- `cache_ttl`: seconds to keep cache entries before ignoring them.
- `oui_path`: path to a local IEEE OUI file for vendor lookup (optional).
- `hidden_devices`: list of hidden MACs.
- `tracked_devices`: list of `{ "mac": "AA:BB:...", "label": "Phone", "alarm": true }`.

Use `c` in the TUI to open the config view, then `up/down` to select and `e` to edit values.

## Notes

- The scanner uses `bluetoothctl --timeout <seconds> scan on`; if your BlueZ version does not support `--timeout`, it falls back to `timeout <seconds> bluetoothctl scan on`.
- The "human" indicator is `PRESENT` if any tracked device is present within the TTL window.
- For vendor lookup, use the included `oui.txt` or download the latest IEEE OUI list and set `oui_path` to the local file path.
