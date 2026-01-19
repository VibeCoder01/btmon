#!/usr/bin/env python3
import argparse
from collections import deque
import curses
import datetime as dt
import json
import os
import queue
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time

DEFAULT_CONFIG = {
    "scan_interval": 20,
    "scan_timeout": 8,
    "scan_use_tty": False,
    "presence_ttl": 120,
    "info_refresh_interval": 300,
    "alarm_enabled": True,
    "alarm_away_threshold": 300,
    "alarm_flash_seconds": 6,
    "alarm_beep": False,
    "log_path": "btmon.log",
    "tracked_devices": [],
    "hidden_devices": [],
    "cache_path": "btmon.cache.json",
    "cache_ttl": 86400,
    "oui_path": "",
}

NOISE_RATE_WINDOW_SECONDS = 60
NOISE_GRAPH_WINDOW_SECONDS = 300
ALARM_INTENSE_SECONDS = 4
ALARM_SIREN_INTERVAL_SECONDS = 0.4
ALARM_BEEP_INTERVAL_SECONDS = 5

CONFIG_ORDER = [
    "scan_interval",
    "scan_timeout",
    "scan_use_tty",
    "presence_ttl",
    "info_refresh_interval",
    "alarm_enabled",
    "alarm_away_threshold",
    "alarm_flash_seconds",
    "alarm_beep",
    "log_path",
    "tracked_devices",
    "hidden_devices",
    "cache_path",
    "cache_ttl",
    "oui_path",
]

CONFIG_DESCRIPTIONS = {
    "scan_interval": "Seconds between scans",
    "scan_timeout": "Seconds per scan window",
    "scan_use_tty": "Use pseudo-tty for scans",
    "presence_ttl": "Seconds a device stays present",
    "info_refresh_interval": "Seconds between deep scans",
    "alarm_enabled": "Enable alarm on return",
    "alarm_away_threshold": "Seconds away before alarm",
    "alarm_flash_seconds": "Seconds to flash screen",
    "alarm_beep": "Beep on alarm",
    "log_path": "Log file path",
    "tracked_devices": "Tracked MACs (read-only)",
    "hidden_devices": "Hidden MACs (read-only)",
    "cache_path": "Cache file path",
    "cache_ttl": "Seconds to keep cache entries",
    "oui_path": "Path to OUI vendor file",
}

DEVICE_RE = re.compile(r"Device ([0-9A-Fa-f:]{17}) (.+)$")
RSSI_RE_HEX_PAREN = re.compile(r"RSSI:\s+0x[0-9a-fA-F]+\s*\(\s*(-?\d+)\s*\)")
RSSI_RE_PAREN = re.compile(r"RSSI:.*\((-?\d+)\)")
RSSI_RE_SIMPLE = re.compile(r"RSSI:\s*(-?\d+)")
MAC_IN_LINE_RE = re.compile(r"Device ([0-9A-Fa-f:]{17})")
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
MAC_RE = re.compile(r"^[0-9A-Fa-f:]{17}$")
MAC_NAME_STRIP_RE = re.compile(r"[-: ]+")


def normalize_mac(mac):
    return mac.strip().upper()


def normalize_mac_name(value):
    if not value:
        return ""
    return MAC_NAME_STRIP_RE.sub("", value.strip()).upper()


def format_mac_blocks(mac):
    compact = normalize_mac_name(mac)
    if len(compact) != 12:
        return mac or "-"
    return f"{compact[:6]}:{compact[6:]}"


def normalize_oui_prefix(value):
    if not value:
        return ""
    return MAC_NAME_STRIP_RE.sub("", value.strip()).upper()


def is_mac_name_match(mac, name):
    if not mac or not name:
        return False
    return normalize_mac_name(mac) == normalize_mac_name(name)


def is_noise_device(mac, info):
    if not info:
        return False
    name = info.get("name") or ""
    if is_mac_name_match(mac, name):
        return True
    alias = info.get("alias") or ""
    if alias and is_unfriendly_name(name, mac) and is_mac_name_match(mac, alias):
        return True
    return False


def is_noise_assessed(info):
    if not info:
        return False
    return bool(info.get("name") or info.get("alias"))


def is_valid_mac(mac):
    return bool(MAC_RE.match(mac.strip()))


def load_config(path):
    if not os.path.exists(path):
        return DEFAULT_CONFIG.copy(), f"Config not found: {path}"
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        return DEFAULT_CONFIG.copy(), f"Config error: {exc}"

    config = DEFAULT_CONFIG.copy()
    config.update({k: v for k, v in data.items() if k in config})

    tracked = []
    for item in data.get("tracked_devices", []):
        mac = item.get("mac")
        if not mac:
            continue
        tracked.append(
            {
                "mac": normalize_mac(mac),
                "label": item.get("label") or item.get("name") or "",
                "alarm": item.get("alarm", True),
            }
        )
    config["tracked_devices"] = tracked
    hidden = []
    for mac in data.get("hidden_devices", []):
        if not mac:
            continue
        if not is_valid_mac(mac):
            continue
        hidden.append(normalize_mac(mac))
    config["hidden_devices"] = hidden
    return config, None


def load_oui_registry(path):
    if not path:
        return {}, None
    if not os.path.exists(path):
        return {}, f"OUI file not found: {path}"
    registry = {}
    hex_pattern = re.compile(
        r"^([0-9A-F]{2})[-:]([0-9A-F]{2})[-:]([0-9A-F]{2})\s+\(hex\)\s+(.+)$",
        re.IGNORECASE,
    )
    base_pattern = re.compile(
        r"^([0-9A-F]{6})\s+\(base 16\)\s+(.+)$", re.IGNORECASE
    )
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            for raw in handle:
                line = raw.strip()
                if not line:
                    continue
                match = hex_pattern.match(line)
                if match:
                    prefix = f"{match.group(1)}:{match.group(2)}:{match.group(3)}"
                    vendor = match.group(4).strip()
                    registry[prefix] = vendor
                    continue
                match = base_pattern.match(line)
                if match:
                    prefix = normalize_oui_prefix(match.group(1))
                    if len(prefix) == 6:
                        vendor = match.group(2).strip()
                        registry[
                            f"{prefix[0:2]}:{prefix[2:4]}:{prefix[4:6]}"
                        ] = vendor
    except OSError as exc:
        return {}, f"OUI error: {exc}"
    return registry, None


def lookup_oui_vendor(mac, registry):
    if not registry:
        return ""
    if not is_valid_mac(mac):
        return ""
    prefix = normalize_mac(mac)[:8]
    return registry.get(prefix, "")


def save_config(path, config, device_state, hidden_macs):
    data = {
        "scan_interval": config["scan_interval"],
        "scan_timeout": config["scan_timeout"],
        "scan_use_tty": config["scan_use_tty"],
        "presence_ttl": config["presence_ttl"],
        "info_refresh_interval": config["info_refresh_interval"],
        "alarm_enabled": config["alarm_enabled"],
        "alarm_away_threshold": config["alarm_away_threshold"],
        "alarm_flash_seconds": config["alarm_flash_seconds"],
        "alarm_beep": config["alarm_beep"],
        "log_path": config["log_path"],
        "tracked_devices": [
            {
                "mac": mac,
                "label": info.get("label") or "",
                "alarm": bool(info.get("alarm", True)),
            }
            for mac, info in sorted(device_state.items())
        ],
        "hidden_devices": sorted(hidden_macs),
        "cache_path": config["cache_path"],
        "cache_ttl": config["cache_ttl"],
        "oui_path": config.get("oui_path", ""),
    }
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
            handle.write("\n")
    except OSError as exc:
        return str(exc)
    return None


def ensure_log(log_path):
    if os.path.exists(log_path):
        return
    try:
        with open(log_path, "w", encoding="utf-8") as handle:
            handle.write("timestamp,event,mac,label,rssi,detail\n")
    except OSError:
        pass


def delete_log_entries(log_path, macs):
    if not log_path or not macs:
        return "Invalid log delete request"
    if isinstance(macs, str):
        mac_set = {macs}
    else:
        mac_set = set(macs)
    try:
        with open(log_path, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except OSError as exc:
        return str(exc)

    header = "timestamp,event,mac,label,rssi,detail\n"
    kept = [header]
    for line in lines:
        if line.startswith("timestamp,"):
            continue
        parts = line.strip().split(",", 5)
        if len(parts) < 6:
            continue
        if parts[2] in mac_set:
            continue
        kept.append(line if line.endswith("\n") else f"{line}\n")

    tmp_path = f"{log_path}.tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as handle:
            handle.writelines(kept)
        os.replace(tmp_path, log_path)
    except OSError as exc:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass
        return str(exc)
    return None

def write_log(log_path, event, mac, label, rssi, detail):
    timestamp = dt.datetime.now().isoformat(timespec="seconds")
    line = f"{timestamp},{event},{mac},{label},{rssi},{detail}\n"
    try:
        with open(log_path, "a", encoding="utf-8") as handle:
            handle.write(line)
    except OSError:
        pass


def run_scan(timeout, use_tty=False):
    start = time.time()
    output = ""
    error = None
    devices = {}

    def run_command(cmd, use_script=False):
        if use_script:
            if shutil.which("script") is None:
                return "", "script command not available"
            script_cmd = " ".join(shlex.quote(part) for part in cmd)
            cmd = ["script", "-q", "-c", script_cmd, "/dev/null"]
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=False
        )
        return (result.stdout or "") + (result.stderr or ""), None

    cmd = ["bluetoothctl", "--timeout", str(timeout), "scan", "on"]
    try:
        use_script = use_tty and shutil.which("script") is not None
        output, error = run_command(cmd, use_script=use_script)
        if "Unknown option --timeout" in output:
            cmd = ["timeout", str(timeout + 2), "bluetoothctl", "scan", "on"]
            output, error = run_command(cmd, use_script=use_script)
    except FileNotFoundError as exc:
        error = f"Command not found: {exc.filename}"
        return {
            "started_at": start,
            "ended_at": time.time(),
            "devices": devices,
            "error": error,
        }

    for line in output.splitlines():
        line = strip_ansi(line)
        line = line.replace("\r", "").strip()
        if "RSSI:" in line:
            mac_match = MAC_IN_LINE_RE.search(line)
            if mac_match:
                rssi_match = RSSI_RE_HEX_PAREN.search(line)
                if not rssi_match:
                    rssi_match = RSSI_RE_PAREN.search(line)
                if not rssi_match:
                    rssi_match = RSSI_RE_SIMPLE.search(line)
                if rssi_match:
                    mac = normalize_mac(mac_match.group(1))
                    rssi = parse_rssi_value(rssi_match.group(1).strip())
                    if rssi:
                        devices.setdefault(mac, {})["rssi"] = rssi
                    continue
        match = DEVICE_RE.search(line)
        if match:
            mac = normalize_mac(match.group(1))
            name = sanitize_name(match.group(2))
            if name:
                devices.setdefault(mac, {})["name"] = name

    if not output.strip() and not error:
        error = "No scan output received"

    return {
        "started_at": start,
        "ended_at": time.time(),
        "devices": devices,
        "error": error,
    }


def format_age(seconds):
    if seconds is None:
        return "never"
    if seconds < 60:
        return f"{int(seconds)}s"
    if seconds < 3600:
        return f"{int(seconds / 60)}m"
    if seconds < 86400:
        return f"{int(seconds / 3600)}h"
    return f"{int(seconds / 86400)}d"


def format_timestamp(ts):
    if ts is None:
        return "-"
    return dt.datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def read_log_entries(log_path, mac, limit):
    entries = deque(maxlen=limit)
    try:
        with open(log_path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("timestamp,"):
                    continue
                parts = line.split(",", 5)
                if len(parts) < 6:
                    continue
                timestamp, event, entry_mac, _label, rssi, detail = parts
                if entry_mac != mac:
                    continue
                entries.append(
                    {
                        "time": timestamp,
                        "event": event,
                        "rssi": parse_rssi_value(rssi),
                        "detail": detail,
                    }
                )
    except OSError:
        return []
    return list(entries)


def load_cache(cache_path, cache_ttl):
    if not os.path.exists(cache_path):
        return {}, None
    try:
        with open(cache_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        return {}, f"Cache error: {exc}"

    devices = data.get("devices", {})
    now = time.time()
    entries = {}
    for mac, info in devices.items():
        if not is_valid_mac(mac):
            continue
        last_seen = info.get("last_seen")
        last_info = info.get("last_info")
        updated_at = info.get("updated_at")
        if updated_at is None:
            updated_at = max(last_seen or 0, last_info or 0) or None
        if updated_at is None:
            continue
        if cache_ttl and (now - updated_at) > cache_ttl:
            continue
        entry = default_known_info()
        entry["name"] = sanitize_name(info.get("name") or "")
        entry["rssi"] = parse_rssi_value(info.get("rssi") or "")
        entry["last_seen"] = last_seen
        entry["alias"] = info.get("alias") or ""
        entry["class"] = info.get("class") or ""
        entry["icon"] = info.get("icon") or ""
        entry["paired"] = info.get("paired") or ""
        entry["trusted"] = info.get("trusted") or ""
        entry["connected"] = info.get("connected") or ""
        entry["manufacturer"] = info.get("manufacturer") or ""
        entry["last_info"] = last_info
        entries[normalize_mac(mac)] = entry
    return entries, None


def should_cache_entry(entry):
    if entry.get("last_seen") or entry.get("last_info"):
        return True
    for key in (
        "name",
        "alias",
        "class",
        "icon",
        "paired",
        "trusted",
        "connected",
        "manufacturer",
        "rssi",
    ):
        if entry.get(key):
            return True
    return False


def save_cache(cache_path, known_devices):
    devices = {}
    now = time.time()
    for mac, info in known_devices.items():
        if not should_cache_entry(info):
            continue
        last_seen = info.get("last_seen")
        last_info = info.get("last_info")
        updated_at = max(last_seen or 0, last_info or 0) or now
        devices[mac] = {
            "name": info.get("name") or "",
            "rssi": parse_rssi_value(info.get("rssi") or ""),
            "last_seen": last_seen,
            "alias": info.get("alias") or "",
            "class": info.get("class") or "",
            "icon": info.get("icon") or "",
            "paired": info.get("paired") or "",
            "trusted": info.get("trusted") or "",
            "connected": info.get("connected") or "",
            "manufacturer": info.get("manufacturer") or "",
            "last_info": last_info,
            "updated_at": updated_at,
        }
    payload = {"saved_at": now, "devices": devices}
    try:
        with open(cache_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
    except OSError as exc:
        return str(exc)
    return None


def format_yes_no(value):
    value = (value or "").strip().lower()
    if value in ("yes", "true", "1"):
        return "yes"
    if value in ("no", "false", "0"):
        return "no"
    return "-"


def is_unfriendly_name(name, mac):
    if not name:
        return True
    value = name.strip()
    if not value:
        return True
    lower = value.lower()
    if lower.startswith("manufacturerdata"):
        return True
    if lower.startswith("rssi") or ("rssi" in lower and "alias" in lower):
        return True
    if lower.startswith("txpower") or lower.startswith("tx power"):
        return True
    if lower in ("unknown", "unknown device", "n/a", "none"):
        return True
    if MAC_RE.match(value) or value.upper() == mac:
        return True
    if lower.startswith("0x"):
        return True
    if re.fullmatch(r"[0-9a-fx: -]+", lower):
        return True
    return False


def sanitize_name(value):
    if not value:
        return ""
    cleaned = value.strip()
    lower = cleaned.lower()
    if lower.startswith("manufacturerdata"):
        return ""
    if lower.startswith("rssi:"):
        return ""
    if lower.startswith("txpower:") or lower.startswith("tx power:"):
        return ""
    return cleaned


def parse_rssi_value(value):
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    match = re.search(r"\((-?\d+)\)", text)
    if match:
        return match.group(1)
    if re.fullmatch(r"-?\d+", text):
        return text
    if "0x" in text.lower():
        return ""
    match = re.search(r"(-?\d+)", text)
    if match:
        return match.group(1)
    return ""


def strip_ansi(value):
    return ANSI_ESCAPE_RE.sub("", value)


def display_name(label, name, alias, mac):
    if label:
        return label
    if alias and is_unfriendly_name(name, mac):
        return alias
    if name:
        return name
    if alias:
        return alias
    return "-"


def resolve_target_macs(device_items, selected_index, selected_macs):
    if selected_macs:
        return sorted(selected_macs)
    if not device_items or not (0 <= selected_index < len(device_items)):
        return []
    return [device_items[selected_index][0]]


def build_device_state(tracked):
    state = {}
    for item in tracked:
        mac = normalize_mac(item["mac"])
        state[mac] = {
            "label": item.get("label") or "",
            "name": item.get("label") or "",
            "alias": "",
            "class": "",
            "icon": "",
            "paired": "",
            "trusted": "",
            "connected": "",
            "manufacturer": "",
            "last_info": None,
            "alarm": bool(item.get("alarm", True)),
            "last_away": None,
            "last_seen": None,
            "rssi": "",
            "present": False,
        }
    return state


def default_known_info():
    return {
        "name": "",
        "rssi": "",
        "last_seen": None,
        "alias": "",
        "class": "",
        "icon": "",
        "paired": "",
        "trusted": "",
        "connected": "",
        "manufacturer": "",
        "last_info": None,
    }


def build_known_devices(tracked):
    known = {}
    for item in tracked:
        mac = normalize_mac(item["mac"])
        known[mac] = default_known_info()
    return known


def prune_mac_named_devices(known_devices, device_state):
    for mac, info in list(known_devices.items()):
        if mac in device_state:
            continue
        if is_noise_device(mac, info):
            known_devices.pop(mac, None)


def record_noise_event(
    noise_events, noise_history, timestamp, mac, log_path, name, rssi, source
):
    noise_events.append((timestamp, mac))
    noise_history.append(timestamp)


def prune_noise_events(noise_events, now, window_seconds=NOISE_RATE_WINDOW_SECONDS):
    while noise_events and (now - noise_events[0][0]) > window_seconds:
        noise_events.popleft()


def prune_noise_history(
    noise_history, now, window_seconds=NOISE_GRAPH_WINDOW_SECONDS
):
    while noise_history and (now - noise_history[0]) > window_seconds:
        noise_history.popleft()


def noise_rate_per_minute(noise_events):
    if not noise_events:
        return 0
    return len(noise_events)


def build_noise_buckets(noise_history, now, window_seconds, bucket_seconds):
    bucket_seconds = max(1.0, float(bucket_seconds))
    bucket_count = int(window_seconds / bucket_seconds)
    if window_seconds > (bucket_count * bucket_seconds):
        bucket_count += 1
    bucket_count = max(1, bucket_count)
    window_start = now - window_seconds
    buckets = [0] * bucket_count
    for timestamp in noise_history:
        if timestamp < window_start:
            continue
        offset = timestamp - window_start
        index = int(offset / bucket_seconds)
        if index >= bucket_count:
            index = bucket_count - 1
        buckets[index] += 1
    return buckets


def resample_noise_buckets(buckets, width):
    if width <= 0:
        return []
    if not buckets:
        return [0] * width
    source_len = len(buckets)
    if source_len == width:
        return list(buckets)
    if source_len < width:
        return [buckets[int(i * source_len / width)] for i in range(width)]
    result = []
    for i in range(width):
        start = int(i * source_len / width)
        end = int((i + 1) * source_len / width)
        if end <= start:
            end = min(source_len, start + 1)
        result.append(sum(buckets[start:end]))
    return result


def device_sort_value(
    mac, info, now, device_state, sort_key, sort_reverse, registry
):
    tracked = mac in device_state
    if sort_key == "mac":
        return mac
    if sort_key == "name":
        label = device_state[mac]["label"] if tracked else ""
        display = display_name(
            label,
            info.get("name") or "",
            info.get("alias") or "",
            mac,
        )
        return display.lower()
    if sort_key == "last_seen":
        value = info.get("last_seen")
        if value is None:
            return float("-inf") if sort_reverse else float("inf")
        return value
    if sort_key == "age":
        last_seen = info.get("last_seen")
        if last_seen is None:
            return float("-inf") if sort_reverse else float("inf")
        return now - last_seen
    if sort_key == "rssi":
        rssi = parse_rssi_value(info.get("rssi") or "")
        if rssi == "":
            return float("-inf") if sort_reverse else float("inf")
        return int(rssi)
    if sort_key == "icon":
        return (info.get("icon") or "").lower()
    if sort_key == "vendor":
        return lookup_oui_vendor(mac, registry).lower()
    if sort_key == "alarm":
        if not tracked:
            return 2
        return 0 if device_state[mac].get("alarm", True) else 1
    if sort_key == "state":
        if not tracked:
            return 2
        return 0 if device_state[mac].get("present") else 1
    return mac


def parse_info_output(output):
    info = {
        "name": "",
        "alias": "",
        "class": "",
        "icon": "",
        "paired": "",
        "trusted": "",
        "connected": "",
        "manufacturer": "",
        "rssi": "",
    }
    manufacturer_key = ""
    manufacturer_value = ""
    capture_manufacturer_value = False

    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("Device "):
            continue
        if line.startswith("ManufacturerData Value"):
            capture_manufacturer_value = True
            value = line.split(":", 1)[1].strip()
            if value:
                manufacturer_value = value
                capture_manufacturer_value = False
            continue
        if capture_manufacturer_value:
            if ":" in line and not line.startswith("0x"):
                capture_manufacturer_value = False
                continue
            if line.startswith("0x"):
                manufacturer_value = line
                capture_manufacturer_value = False
            continue
        if line.startswith("ManufacturerData Key"):
            manufacturer_key = line.split(":", 1)[1].strip()
            continue
        if line.startswith("Manufacturer:"):
            info["manufacturer"] = line.split(":", 1)[1].strip()
            continue
        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key == "Name":
            info["name"] = sanitize_name(value)
        elif key == "Alias":
            info["alias"] = value
        elif key == "Class":
            info["class"] = value
        elif key == "Icon":
            info["icon"] = value
        elif key == "Paired":
            info["paired"] = value
        elif key == "Trusted":
            info["trusted"] = value
        elif key == "Connected":
            info["connected"] = value
        elif key == "RSSI":
            info["rssi"] = parse_rssi_value(value)

    if not info["manufacturer"]:
        combined = " ".join(
            part for part in [manufacturer_key, manufacturer_value] if part
        ).strip()
        info["manufacturer"] = combined

    return info


def build_config_items(config):
    items = []
    seen = set()
    for key in CONFIG_ORDER:
        if key not in config:
            continue
        items.append(key)
        seen.add(key)
    for key in sorted(config.keys()):
        if key not in seen:
            items.append(key)
    return items


def format_config_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return f"{len(value)} items"
    if isinstance(value, dict):
        return f"{len(value)} entries"
    return str(value)


def parse_config_value(value_type, raw):
    raw = raw.strip()
    if value_type == "int":
        return int(raw), None
    if value_type == "float":
        return float(raw), None
    if value_type == "bool":
        if raw.lower() in ("y", "yes", "true", "1", "on"):
            return True, None
        if raw.lower() in ("n", "no", "false", "0", "off"):
            return False, None
        return None, "Use yes/no or true/false"
    if value_type == "str":
        return raw, None
    return None, "Unsupported value type"


def config_value_type(value):
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    return "readonly"


def run_info(mac):
    cmd = ["bluetoothctl", "info", mac]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=False
        )
    except FileNotFoundError as exc:
        return None, f"Command not found: {exc.filename}"

    output = (result.stdout or "") + (result.stderr or "")
    if "not available" in output.lower():
        return None, "Device not available"
    if not output.strip():
        return None, "No info output received"

    return parse_info_output(output), None


def run_info_batch(macs):
    results = {}
    errors = []
    for mac in macs:
        info, error = run_info(mac)
        if error:
            errors.append(f"{mac}: {error}")
        if info:
            results[mac] = info
    return {"results": results, "errors": errors}


def prompt_input(stdscr, prompt):
    height, width = stdscr.getmaxyx()
    y = max(0, height - 2)
    stdscr.move(y, 0)
    stdscr.clrtoeol()
    prompt_text = prompt[: max(0, width - 1)]
    stdscr.addstr(y, 0, prompt_text)
    stdscr.refresh()

    max_len = max(1, width - len(prompt_text) - 1)
    stdscr.nodelay(False)
    curses.echo()
    try:
        curses.curs_set(1)
    except curses.error:
        pass
    try:
        data = stdscr.getstr(y, min(len(prompt_text), width - 1), max_len)
    except curses.error:
        data = b""
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    curses.noecho()
    stdscr.nodelay(True)

    if data is None:
        return ""
    return data.decode("utf-8", errors="ignore").strip()


def prompt_confirm(stdscr, prompt):
    response = prompt_input(stdscr, f"{prompt} (y/n): ")
    return response.lower().startswith("y")


def main(stdscr, config_path):
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.keypad(True)
    colors_enabled = curses.has_colors()
    if colors_enabled:
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_CYAN, -1)
        curses.init_pair(2, curses.COLOR_YELLOW, -1)
        curses.init_pair(3, curses.COLOR_GREEN, -1)
        curses.init_pair(4, curses.COLOR_RED, -1)
        curses.init_pair(5, curses.COLOR_BLUE, -1)
        curses.init_pair(6, curses.COLOR_BLACK, curses.COLOR_CYAN)
    title_color = curses.color_pair(1) if colors_enabled else 0
    header_color = curses.color_pair(2) if colors_enabled else 0
    ok_color = curses.color_pair(3) if colors_enabled else 0
    warn_color = curses.color_pair(4) if colors_enabled else 0
    info_color = curses.color_pair(5) if colors_enabled else 0
    multi_select_color = curses.color_pair(6) if colors_enabled else curses.A_BOLD
    dim_color = curses.A_DIM if colors_enabled else 0

    config, config_error = load_config(config_path)
    device_state = build_device_state(config["tracked_devices"])
    known_devices = build_known_devices(config["tracked_devices"])
    hidden_macs = set(config.get("hidden_devices", []))
    cache_path = config["cache_path"]
    cache_ttl = config["cache_ttl"]
    oui_path = config.get("oui_path", "")
    oui_registry, oui_error = load_oui_registry(oui_path)
    cache_entries, cache_error = load_cache(cache_path, cache_ttl)
    if cache_entries:
        for mac, entry in cache_entries.items():
            known_devices.setdefault(mac, default_known_info())
            known = known_devices[mac]
            for key, value in entry.items():
                if value is not None and value != "":
                    known[key] = value
            if mac in device_state:
                device_state[mac]["last_seen"] = known.get("last_seen")
                if known.get("rssi"):
                    device_state[mac]["rssi"] = known["rssi"]

    prune_mac_named_devices(known_devices, device_state)

    log_path = config["log_path"]
    ensure_log(log_path)

    scan_queue = queue.Queue()
    scan_thread = None
    last_scan = None
    last_scan_error = None
    last_scan_devices = []
    next_scan = time.time()
    force_scan = False
    info_queue = queue.Queue()
    info_thread = None
    next_info_refresh = 0
    last_info_error_count = 0
    pending_info_macs = set()
    pending_full_scan = False

    human_present = False
    last_human_present = False
    selected_index = 0
    status_message = ""
    status_until = 0.0
    show_logs = False
    log_cache = []
    log_cache_mac = ""
    log_cache_time = 0.0
    view_mode = "devices"
    config_index = 0
    config_scroll = 0
    device_scroll = 0
    alarm_active = False
    alarm_intense_until = 0.0
    alarm_message = ""
    alarm_next_siren = 0.0
    alarm_next_beep = 0.0
    config_page_size = 1
    device_page_size = 1
    config_count = 0
    device_count = 0
    device_filter = "normal"
    selected_mac_key = ""
    selected_macs = set()
    sort_key = "default"
    sort_reverse = False
    cache_dirty = False
    next_cache_save = time.time() + 2
    info_warnings = deque(maxlen=50)
    manual_scan_pending = False
    manual_scan_active = False
    active_scan_reason = "auto"
    noise_events = deque()
    noise_history = deque()
    noise_graph_buckets = []
    noise_graph_max = 0
    next_noise_refresh = time.time()

    removed_tracked = []
    for mac in list(device_state.keys()):
        if is_noise_device(mac, known_devices.get(mac, {})):
            removed_tracked.append(mac)
    if removed_tracked:
        for mac in removed_tracked:
            device_state.pop(mac, None)
            known_devices.pop(mac, None)
            hidden_macs.discard(mac)
        cache_dirty = True
        save_error = save_config(config_path, config, device_state, hidden_macs)
        if save_error:
            config_error = save_error
            status_message = f"Save failed: {save_error}"
        else:
            config_error = None
            suffix = "MAC" if len(removed_tracked) == 1 else "MACs"
            status_message = f"Removed noise tracked {suffix} on startup."
        status_until = time.time() + 4

    while True:
        now = time.time()
        height, width = stdscr.getmaxyx()
        prune_noise_events(noise_events, now)
        prune_noise_history(noise_history, now)
        noise_rate = noise_rate_per_minute(noise_events)
        if now >= next_noise_refresh:
            bucket_seconds = max(1, int(config["scan_interval"]))
            raw_buckets = build_noise_buckets(
                noise_history, now, NOISE_GRAPH_WINDOW_SECONDS, bucket_seconds
            )
            noise_graph_buckets = resample_noise_buckets(
                raw_buckets, max(1, width - 1)
            )
            noise_graph_max = max(noise_graph_buckets) if noise_graph_buckets else 0
            next_noise_refresh = now + config["scan_interval"]

        if scan_thread is None and (now >= next_scan or force_scan):
            active_scan_reason = "manual" if (force_scan or manual_scan_pending) else "auto"
            manual_scan_active = active_scan_reason == "manual"
            manual_scan_pending = False
            force_scan = False
            next_scan = now + config["scan_interval"]

            def scan_worker():
                scan_queue.put(
                    run_scan(
                        config["scan_timeout"],
                        config.get("scan_use_tty", False),
                    )
                )

            scan_thread = threading.Thread(target=scan_worker, daemon=True)
            scan_thread.start()

        if scan_thread and not scan_thread.is_alive():
            scan_thread = None

        if now >= next_info_refresh and known_devices:
            pending_full_scan = True

        if info_thread is None and scan_thread is None and known_devices:
            macs = []
            if pending_full_scan:
                macs = sorted(known_devices.keys())
                pending_full_scan = False
                pending_info_macs.clear()
                next_info_refresh = now + config["info_refresh_interval"]
            elif pending_info_macs:
                macs = sorted(pending_info_macs)
                pending_info_macs.clear()

            if macs:
                def info_worker():
                    info_queue.put(run_info_batch(macs))

                info_thread = threading.Thread(target=info_worker, daemon=True)
                info_thread.start()

        if info_thread and not info_thread.is_alive():
            info_thread = None

        try:
            while True:
                scan_result = scan_queue.get_nowait()
                first_scan = last_scan is None
                last_scan = scan_result
                last_scan_error = scan_result["error"]
                last_scan_devices = []
                scan_time = scan_result["ended_at"]
                new_macs = []
                noise_macs = set()
                removed_tracked = []
                for mac, info in scan_result["devices"].items():
                    name = info.get("name") or ""
                    rssi = info.get("rssi") or ""
                    if is_noise_device(mac, {"name": name}):
                        if mac not in noise_macs:
                            noise_macs.add(mac)
                            record_noise_event(
                                noise_events,
                                noise_history,
                                scan_time,
                                mac,
                                log_path,
                                name,
                                rssi,
                                "scan",
                            )
                        known_devices.pop(mac, None)
                        pending_info_macs.discard(mac)
                        if mac in device_state:
                            removed_tracked.append(mac)
                        continue
                    last_scan_devices.append((mac, name, rssi))
                    if mac not in known_devices:
                        known_devices[mac] = default_known_info()
                        new_macs.append(mac)
                    known_info = known_devices[mac]
                    if name:
                        known_info["name"] = sanitize_name(name)
                    if rssi:
                        known_info["rssi"] = rssi
                    known_info["last_seen"] = scan_time
                    if mac in device_state:
                        device_state[mac]["last_seen"] = scan_time
                        if name:
                            device_state[mac]["name"] = name
                        if rssi:
                            device_state[mac]["rssi"] = rssi
                if new_macs:
                    pending_info_macs.update(new_macs)
                if first_scan and scan_result["devices"]:
                    pending_full_scan = True
                if scan_result["devices"]:
                    cache_dirty = True
                if removed_tracked:
                    for mac in removed_tracked:
                        device_state.pop(mac, None)
                        known_devices.pop(mac, None)
                        hidden_macs.discard(mac)
                    save_error = save_config(
                        config_path, config, device_state, hidden_macs
                    )
                    if save_error:
                        config_error = save_error
                        status_message = f"Save failed: {save_error}"
                    else:
                        config_error = None
                        if len(removed_tracked) == 1:
                            status_message = f"Removed noise tracked {removed_tracked[0]}."
                        else:
                            status_message = f"Removed noise tracked MACs: {len(removed_tracked)}."
                    status_until = time.time() + 4
                if active_scan_reason == "manual":
                    manual_scan_active = False
                    if not status_message:
                        status_message = "Manual scan complete."
                        status_until = time.time() + 2
        except queue.Empty:
            pass

        try:
            while True:
                info_result = info_queue.get_nowait()
                errors = info_result.get("errors") or []
                last_info_error_count = len(errors)
                info_time = time.time()
                noise_macs = set()
                removed_tracked = []
                for mac, info in info_result["results"].items():
                    name = info.get("name") or ""
                    if is_noise_device(mac, info):
                        if mac not in noise_macs:
                            noise_macs.add(mac)
                            record_noise_event(
                                noise_events,
                                noise_history,
                                info_time,
                                mac,
                                log_path,
                                name,
                                info.get("rssi") or "",
                                "info",
                            )
                        known_devices.pop(mac, None)
                        pending_info_macs.discard(mac)
                        if mac in device_state:
                            removed_tracked.append(mac)
                        continue
                    if mac not in known_devices:
                        known_devices[mac] = default_known_info()
                    known_info = known_devices[mac]
                    if name:
                        known_info["name"] = name
                    known_info["alias"] = info.get("alias") or ""
                    known_info["class"] = info.get("class") or ""
                    known_info["icon"] = info.get("icon") or ""
                    known_info["paired"] = info.get("paired") or ""
                    known_info["trusted"] = info.get("trusted") or ""
                    known_info["connected"] = info.get("connected") or ""
                    known_info["manufacturer"] = info.get("manufacturer") or ""
                    if info.get("rssi"):
                        known_info["rssi"] = info["rssi"]
                    known_info["last_info"] = info_time
                    if mac in device_state and info.get("name"):
                        device_state[mac]["name"] = info["name"]
                if info_result["results"]:
                    cache_dirty = True
                if removed_tracked:
                    for mac in removed_tracked:
                        device_state.pop(mac, None)
                        known_devices.pop(mac, None)
                        hidden_macs.discard(mac)
                    save_error = save_config(
                        config_path, config, device_state, hidden_macs
                    )
                    if save_error:
                        config_error = save_error
                        status_message = f"Save failed: {save_error}"
                    else:
                        config_error = None
                        if len(removed_tracked) == 1:
                            status_message = f"Removed noise tracked {removed_tracked[0]}."
                        else:
                            status_message = f"Removed noise tracked MACs: {len(removed_tracked)}."
                    status_until = time.time() + 4
                if errors:
                    timestamp = dt.datetime.now().strftime("%H:%M:%S")
                    for error in errors:
                        info_warnings.append(f"{timestamp} {error}")
        except queue.Empty:
            pass

        if cache_dirty and now >= next_cache_save:
            prune_mac_named_devices(known_devices, device_state)
            cache_error = save_cache(cache_path, known_devices)
            cache_dirty = False if not cache_error else cache_dirty
            next_cache_save = now + 5

        if status_message and now >= status_until:
            status_message = ""

        human_present = False
        for mac, info in device_state.items():
            last_seen = info["last_seen"]
            present = False
            if last_seen is not None:
                present = (now - last_seen) <= config["presence_ttl"]
            if present != info["present"]:
                info["present"] = present
                event = "present" if present else "away"
                label = info.get("label") or info.get("name") or ""
                if not present:
                    info["last_away"] = now
                else:
                    last_away = info.get("last_away")
                    if (
                        config.get("alarm_enabled")
                        and info.get("alarm", True)
                        and mac not in hidden_macs
                        and last_away is not None
                        and (now - last_away) >= config["alarm_away_threshold"]
                    ):
                        alarm_active = True
                        alarm_message = f"ALARM TRIGGERED by {label or mac}"
                        alarm_intense_until = max(
                            alarm_intense_until,
                            now + ALARM_INTENSE_SECONDS,
                        )
                        alarm_next_siren = now
                        alarm_next_beep = max(
                            alarm_next_beep, now + ALARM_BEEP_INTERVAL_SECONDS
                        )
                write_log(
                    log_path,
                    f"device_{event}",
                    mac,
                    label,
                    info.get("rssi") or "",
                    format_timestamp(last_seen),
                )
            human_present = human_present or present

        if human_present != last_human_present:
            event = "human_present" if human_present else "human_away"
            write_log(log_path, event, "-", "-", "", "tracked devices")
            last_human_present = human_present

        alarm_intense = alarm_active and now < alarm_intense_until
        if alarm_active and config.get("alarm_beep"):
            if alarm_intense:
                if now >= alarm_next_siren:
                    try:
                        curses.beep()
                    except curses.error:
                        pass
                    alarm_next_siren = now + ALARM_SIREN_INTERVAL_SECONDS
            else:
                if now >= alarm_next_beep:
                    try:
                        curses.beep()
                    except curses.error:
                        pass
                    alarm_next_beep = now + ALARM_BEEP_INTERVAL_SECONDS

        flash_on = alarm_intense and int(now * 2) % 2 == 0
        stdscr.bkgd(" ", curses.A_REVERSE if flash_on else curses.A_NORMAL)
        stdscr.erase()

        title = "BTMON - Bluetooth Presence Monitor"
        title_style = curses.A_BOLD | title_color
        if flash_on:
            title_style |= curses.A_BLINK
        stdscr.addstr(0, 0, title[: width - 1], title_style)

        alarm_status = "ALARM" if alarm_active else "ok"
        scan_state = "idle"
        if scan_thread:
            if manual_scan_active:
                spinner = "|/-\\"[int(now * 4) % 4]
                scan_state = f"manual {spinner}"
            else:
                scan_state = "scanning"
        status_prefix = (
            f"Time: {dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  "
            f"Scan: {scan_state}  "
            f"Interval: {config['scan_interval']}s  Timeout: {config['scan_timeout']}s  "
            f"Deep: {config['info_refresh_interval']}s  Alarm: "
        )
        alarm_color = warn_color if alarm_active else ok_color
        stdscr.addstr(1, 0, status_prefix[: width - 1], info_color)
        status_cursor = len(status_prefix)
        if status_cursor < width - 1:
            stdscr.addstr(
                1,
                status_cursor,
                alarm_status[: max(0, width - status_cursor - 1)],
                alarm_color,
            )
            status_cursor += len(alarm_status)
        noise_text = f"  Noise: {noise_rate}/min"
        if status_cursor < width - 1:
            stdscr.addstr(
                1,
                status_cursor,
                noise_text[: max(0, width - status_cursor - 1)],
                info_color,
            )

        if alarm_active and not alarm_intense and int(now * 2) % 2 == 0:
            alert = alarm_message or "ALARM TRIGGERED"
            stdscr.addstr(
                2,
                0,
                alert[: width - 1],
                warn_color | curses.A_BOLD | curses.A_BLINK,
            )

        device_items = []
        if view_mode == "config":
            line = 3
            stdscr.addstr(
                line,
                0,
                "Config"[: width - 1],
                curses.A_UNDERLINE | header_color,
            )
            line += 1
            stdscr.addstr(
                line,
                0,
                "Key                    Value                     Notes"[: width - 1],
                header_color,
            )
            line += 1

            config_items = build_config_items(config)
            config_count = len(config_items)
            bottom_reserved = 3
            available_rows = max(0, height - bottom_reserved - line)
            config_page_size = max(1, available_rows)
            if config_items and config_index >= len(config_items):
                config_index = len(config_items) - 1
            if config_index < 0:
                config_index = 0
            if config_index < config_scroll:
                config_scroll = config_index
            if config_index >= config_scroll + available_rows:
                config_scroll = max(0, config_index - available_rows + 1)

            visible = config_items[config_scroll : config_scroll + available_rows]
            for idx, key in enumerate(visible):
                if line >= height - bottom_reserved:
                    break
                value = config.get(key)
                desc = CONFIG_DESCRIPTIONS.get(key, "")
                display = format_config_value(value)
                row = f"{key:<22} {display:<25.25} {desc}"
                style = (
                    curses.A_REVERSE
                    if (config_scroll + idx) == config_index
                    else curses.A_NORMAL
                )
                stdscr.addstr(line, 0, row[: width - 1], style)
                line += 1
        elif view_mode == "noise":
            line = 3
            window_minutes = max(1, NOISE_GRAPH_WINDOW_SECONDS // 60)
            header_title = f"Noise Over Time (last {window_minutes}m)"
            stdscr.addstr(
                line,
                0,
                header_title[: width - 1],
                curses.A_UNDERLINE | header_color,
            )
            line += 1
            summary = f"Events/min: {noise_rate}  Window: {window_minutes}m"
            stdscr.addstr(line, 0, summary[: width - 1], info_color)
            line += 1

            bottom_reserved = 3
            graph_top = line
            graph_bottom = max(graph_top + 1, height - bottom_reserved)
            graph_height = max(1, graph_bottom - graph_top)
            graph_width = max(1, width - 1)
            column_width = 4
            if graph_width < column_width:
                column_width = graph_width
            column_count = max(1, graph_width // column_width)
            buckets = resample_noise_buckets(noise_graph_buckets, column_count)
            max_count = max(buckets) if buckets else 0
            if graph_height < 2:
                bar_top = graph_bottom
                bar_height = 0
            else:
                bar_top = graph_top + 1
                bar_height = max(1, graph_bottom - bar_top)

            for idx, count in enumerate(buckets):
                col_x = idx * column_width
                if col_x >= graph_width:
                    break
                count_text = f"{min(count, 99):>2}"
                count_x = col_x + max(0, (column_width - 2) // 2)
                if graph_top < graph_bottom and count_x < graph_width:
                    max_len = min(2, graph_width - count_x)
                    stdscr.addstr(
                        graph_top,
                        count_x,
                        count_text[:max_len],
                        info_color,
                    )
                if max_count and bar_height:
                    height_units = int((count / max_count) * bar_height)
                else:
                    height_units = 0
                for y in range(height_units):
                    row = graph_bottom - 1 - y
                    if row < bar_top:
                        break
                    fill_len = min(column_width, graph_width - col_x)
                    stdscr.addstr(row, col_x, "#" * fill_len)
        else:
            line = 3
            header_title = f"Devices (filter: {device_filter})"
            stdscr.addstr(
                line,
                0,
                header_title[: width - 1],
                curses.A_UNDERLINE | header_color,
            )
            line += 1
            header = (
                f"{'1 MAC':<13} | {'2 Label/Name':<25} | {'3 Seen':<9} | "
                f"{'4 Age':<5} | {'5 RSS':<5} | {'6 Icon':<10} | {'7 Vendor':<12} | "
                f"{'8 Alm':<5} | {'9 State':<7}"
            )
            stdscr.addstr(
                line,
                0,
                header[: width - 1],
                header_color,
            )
            line += 1

            device_items = [
                item
                for item in known_devices.items()
                if (
                    device_filter == "all"
                    or (device_filter == "normal" and item[0] not in hidden_macs)
                    or (device_filter == "hidden" and item[0] in hidden_macs)
                )
                and (
                    item[0] in device_state
                    or is_noise_assessed(item[1])
                )
                and not is_noise_device(item[0], item[1])
            ]
            if sort_key == "default":
                device_items = sorted(
                    device_items,
                    key=lambda item: (
                        0 if item[0] in device_state else 1,
                        -(item[1].get("last_seen") or 0),
                        item[0],
                    ),
                )
            else:
                device_items = sorted(
                    device_items,
                    key=lambda item: (
                        device_sort_value(
                            item[0],
                            item[1],
                            now,
                            device_state,
                            sort_key,
                            sort_reverse,
                            oui_registry,
                        ),
                        item[0],
                    ),
                    reverse=sort_reverse,
                )
            device_count = len(device_items)
            device_mac_set = {mac for mac, _info in device_items}
            selected_macs.intersection_update(device_mac_set)
            bottom_reserved = 3
            desired_details = 8
            log_entry_limit = 3
            warning_lines_reserved = 0
            if show_logs and info_warnings:
                warning_lines_reserved = 1 + min(3, len(info_warnings))
            desired_logs = 0
            if show_logs:
                desired_logs = 4 + log_entry_limit + warning_lines_reserved
            available_rows = max(
                0, height - bottom_reserved - desired_details - desired_logs - line
            )
            device_page_size = max(1, available_rows)
            if selected_mac_key:
                index_by_mac = {mac: idx for idx, (mac, _info) in enumerate(device_items)}
                if selected_mac_key in index_by_mac:
                    selected_index = index_by_mac[selected_mac_key]
            if device_items and selected_index >= len(device_items):
                selected_index = len(device_items) - 1
            if selected_index < 0:
                selected_index = 0
            if selected_index < device_scroll:
                device_scroll = selected_index
            if selected_index >= device_scroll + available_rows:
                device_scroll = max(0, selected_index - available_rows + 1)

            selected_mac = device_items[selected_index][0] if device_items else ""
            if show_logs:
                if selected_mac != log_cache_mac or now - log_cache_time >= 1.0:
                    log_cache = read_log_entries(
                        log_path, selected_mac, log_entry_limit
                    )
                    log_cache_mac = selected_mac
                    log_cache_time = now

            visible_items = device_items[device_scroll : device_scroll + available_rows]
            for idx, (mac, info) in enumerate(visible_items):
                if line >= height - bottom_reserved:
                    break
                tracked = mac in device_state
                label = device_state[mac]["label"] if tracked else ""
                display_text = display_name(
                    label,
                    info.get("name") or "",
                    info.get("alias") or "",
                    mac,
                )
                last_seen = info.get("last_seen")
                age = None if last_seen is None else now - last_seen
                rssi = info.get("rssi") or ""
                icon = info.get("icon") or "-"
                vendor = lookup_oui_vendor(mac, oui_registry) or "-"
                alarm_flag = "-"
                state = "-"
                if tracked:
                    alarm_flag = "yes" if device_state[mac].get("alarm", True) else "no"
                    state = "present" if device_state[mac]["present"] else "away"
                    if state == "away":
                        last_away = device_state[mac].get("last_away")
                        if (
                            config.get("alarm_enabled")
                            and device_state[mac].get("alarm", True)
                            and mac not in hidden_macs
                            and last_away is not None
                            and (now - last_away) >= config["alarm_away_threshold"]
                        ):
                            state = "away*"
                display_mac = format_mac_blocks(mac)
                row = (
                    f"{display_mac:<13} | {display_text:<25.25} | {format_timestamp(last_seen):<9} | "
                    f"{format_age(age):<5} | {rssi:<5} | {icon:<10.10} | {vendor:<12.12} | "
                    f"{alarm_flag:<5} | {state:<7}"
                )
                is_selected = (device_scroll + idx) == selected_index
                is_marked = mac in selected_macs
                style = multi_select_color if is_marked else curses.A_NORMAL
                if not is_marked:
                    if tracked:
                        style |= ok_color
                    if mac in hidden_macs:
                        style |= dim_color
                if is_selected:
                    style |= curses.A_REVERSE
                stdscr.addstr(line, 0, row[: width - 1], style)
                line += 1

            if line < height - bottom_reserved:
                stdscr.addstr(
                    line,
                    0,
                    "Selected Device Details"[: width - 1],
                    curses.A_UNDERLINE | header_color,
                )
                line += 1
                if device_items and line < height - bottom_reserved:
                    mac, info = device_items[selected_index]
                    tracked = mac in device_state
                    label = device_state[mac]["label"] if tracked else "-"
                    name = info.get("name") or "-"
                    alias = info.get("alias") or "-"
                    last_seen = info.get("last_seen")
                    seen_age = None if last_seen is None else now - last_seen
                    last_info = info.get("last_info")
                    info_age = None if last_info is None else now - last_info
                    tracked_flag = "yes" if tracked else "no"
                    alarm_flag = "yes" if tracked and device_state[mac].get("alarm", True) else "no"
                    state = "-"
                    if tracked:
                        state = "present" if device_state[mac]["present"] else "away"
                    vendor = lookup_oui_vendor(mac, oui_registry) or "-"
                    detail_lines = [
                        f"Selected: {mac}  Tracked: {tracked_flag}  Alarm: {alarm_flag}  State: {state}",
                        f"Seen: {format_timestamp(last_seen)} ({format_age(seen_age)})  RSSI: {info.get('rssi') or '-'}",
                        f"Info: {format_timestamp(last_info)} ({format_age(info_age)})",
                        f"Label: {label}  Name: {name}  Alias: {alias}",
                        f"Class: {info.get('class') or '-'}  Icon: {info.get('icon') or '-'}",
                        f"Vendor: {vendor}",
                    ]
                    for detail in detail_lines:
                        if line >= height - bottom_reserved:
                            break
                        stdscr.addstr(line, 0, detail[: width - 1])
                        line += 1
                else:
                    stdscr.addstr(line, 0, "No devices discovered yet."[: width - 1])
                    line += 1

            if show_logs and line < height - bottom_reserved:
                stdscr.addstr(
                    line,
                    0,
                    "Recent Log Entries (selected)"[: width - 1],
                    curses.A_UNDERLINE | header_color,
                )
                line += 1
                if not selected_mac:
                    stdscr.addstr(line, 0, "No device selected."[: width - 1])
                    line += 1
                elif not log_cache:
                    last_seen_text = format_timestamp(
                        known_devices[selected_mac].get("last_seen")
                    )
                    last_rssi = known_devices[selected_mac].get("rssi") or "-"
                    stdscr.addstr(
                        line,
                        0,
                        f"Last scan: {last_seen_text}  RSSI: {last_rssi}"[: width - 1],
                    )
                    line += 1
                    stdscr.addstr(line, 0, "No log entries yet."[: width - 1])
                    line += 1
                else:
                    last_seen_text = format_timestamp(
                        known_devices[selected_mac].get("last_seen")
                    )
                    last_rssi = known_devices[selected_mac].get("rssi") or "-"
                    stdscr.addstr(
                        line,
                        0,
                        f"Last scan: {last_seen_text}  RSSI: {last_rssi}"[: width - 1],
                    )
                    line += 1
                    for entry in log_cache:
                        if line >= height - bottom_reserved:
                            break
                        time_text = entry["time"].split("T")[-1]
                        row = (
                            f"{time_text:<8} {entry['event']:<14} "
                            f"{entry['rssi']:<4} {entry['detail']}"
                        )
                        stdscr.addstr(line, 0, row[: width - 1])
                        line += 1

                if info_warnings and line < height - bottom_reserved:
                    stdscr.addstr(
                        line,
                        0,
                        "Info Warnings"[: width - 1],
                        curses.A_UNDERLINE | header_color,
                    )
                    line += 1
                    for warning in list(info_warnings)[-3:]:
                        if line >= height - bottom_reserved:
                            break
                        stdscr.addstr(
                            line,
                            0,
                            warning[: width - 1],
                            warn_color,
                        )
                        line += 1

        footer_lines = 2 if height >= 2 else 1
        status_limit = max(0, height - footer_lines)
        line = max(0, status_limit - 2)
        if config_error:
            if line < status_limit:
                stdscr.addstr(line, 0, config_error[: width - 1], curses.A_BOLD)
                line += 1
        if last_scan_error:
            if line < status_limit:
                stdscr.addstr(
                    line, 0, f"Scan warning: {last_scan_error}"[: width - 1]
                )
                line += 1
        if last_info_error_count and line < status_limit:
            noun = "device" if last_info_error_count == 1 else "devices"
            summary = (
                f"Info warning: {last_info_error_count} {noun} unavailable (press l)"
            )
            stdscr.addstr(line, 0, summary[: width - 1])
            line += 1
        if cache_error and line < status_limit:
            stdscr.addstr(line, 0, f"Cache warning: {cache_error}"[: width - 1])
            line += 1
        if oui_error and line < status_limit:
            stdscr.addstr(line, 0, f"OUI warning: {oui_error}"[: width - 1])
            line += 1
        if status_message and line < status_limit:
            stdscr.addstr(line, 0, status_message[: width - 1], curses.A_BOLD)
            line += 1

        keys_line1 = (
            "Keys: q quit, r scan, c config, n noise, k ack, 1-9 sort"
        )
        keys_line2 = (
            "      f filter, up/down select, space select, t track, e edit, "
            "d delete, a alarm, h hide, l logs"
        )
        if footer_lines == 2:
            stdscr.addstr(height - 2, 0, keys_line1[: width - 1])
            stdscr.addstr(height - 1, 0, keys_line2[: width - 1])
        elif height > 0:
            stdscr.addstr(height - 1, 0, keys_line1[: width - 1])

        stdscr.refresh()

        try:
            key = stdscr.getch()
        except curses.error:
            key = -1
        if key in (ord("q"), ord("Q")):
            break
        if key in (ord("n"), ord("N")):
            view_mode = "devices" if view_mode == "noise" else "noise"
            next_noise_refresh = 0
        if key in (ord("c"), ord("C")) and view_mode != "noise":
            view_mode = "devices" if view_mode == "config" else "config"
        if key in (ord("k"), ord("K")):
            if alarm_active:
                alarm_active = False
                alarm_intense_until = 0.0
                alarm_message = ""
                alarm_next_siren = 0.0
                alarm_next_beep = 0.0
                status_message = "Alarm acknowledged."
                status_until = time.time() + 2
            continue
        if key in (ord("r"), ord("R")):
            force_scan = True
            manual_scan_pending = True
            status_message = "Manual scan queued."
            status_until = time.time() + 2
        if view_mode == "noise":
            time.sleep(0.1)
            continue
        if key in (ord("1"), ord("2"), ord("3"), ord("4"), ord("5"), ord("6"), ord("7"), ord("8"), ord("9")):
            if view_mode == "devices":
                column_map = {
                    ord("1"): "mac",
                    ord("2"): "name",
                    ord("3"): "last_seen",
                    ord("4"): "age",
                    ord("5"): "rssi",
                    ord("6"): "icon",
                    ord("7"): "vendor",
                    ord("8"): "alarm",
                    ord("9"): "state",
                }
                new_key = column_map.get(key, "default")
                if sort_key == new_key:
                    sort_reverse = not sort_reverse
                else:
                    sort_key = new_key
                    default_reverse = {
                        "mac": False,
                        "name": False,
                        "last_seen": True,
                        "age": False,
                        "rssi": True,
                        "icon": False,
                        "vendor": False,
                        "alarm": False,
                        "state": False,
                    }
                    sort_reverse = default_reverse.get(new_key, False)
                selected_index = 0
                device_scroll = 0
                selected_mac_key = ""
            continue
        if key in (ord("l"), ord("L")):
            show_logs = not show_logs
        if key in (ord("f"), ord("F")):
            if view_mode == "config":
                status_message = "Filter toggle not available in config view."
                status_until = time.time() + 3
            else:
                if device_filter == "normal":
                    device_filter = "hidden"
                elif device_filter == "hidden":
                    device_filter = "all"
                else:
                    device_filter = "normal"
                selected_index = 0
                device_scroll = 0
                selected_mac_key = ""
                status_message = f"Filter: {device_filter}."
                status_until = time.time() + 2
        if key in (ord("a"), ord("A")):
            if view_mode == "config":
                status_message = "Alarm toggle not available in config view."
                status_until = time.time() + 3
            else:
                targets = resolve_target_macs(
                    device_items, selected_index, selected_macs
                )
                if not targets:
                    status_message = "No device selected."
                    status_until = time.time() + 3
                else:
                    toggled = 0
                    skipped = 0
                    last_mac = ""
                    last_current = True
                    for mac in targets:
                        if mac not in device_state:
                            skipped += 1
                            continue
                        current = device_state[mac].get("alarm", True)
                        device_state[mac]["alarm"] = not current
                        toggled += 1
                        last_mac = mac
                        last_current = current
                    if toggled == 0:
                        status_message = "No tracked devices selected."
                        status_until = time.time() + 3
                    else:
                        error = save_config(config_path, config, device_state, hidden_macs)
                        if error:
                            status_message = f"Save failed: {error}"
                        else:
                            config_error = None
                            if len(targets) == 1 and skipped == 0:
                                status_message = (
                                    f"Alarm {'enabled' if not last_current else 'disabled'} "
                                    f"for {last_mac}."
                                )
                            else:
                                suffix = "device" if toggled == 1 else "devices"
                                status_message = f"Alarm toggled for {toggled} {suffix}."
                                if skipped:
                                    status_message += f" Skipped {skipped} untracked."
                        status_until = time.time() + 3
        if key in (ord("h"), ord("H")):
            if view_mode == "config":
                status_message = "Hide toggle not available in config view."
                status_until = time.time() + 3
            else:
                targets = resolve_target_macs(
                    device_items, selected_index, selected_macs
                )
                if not targets:
                    status_message = "No device selected."
                    status_until = time.time() + 3
                else:
                    hidden_count = 0
                    shown_count = 0
                    last_mac = ""
                    last_action = ""
                    for mac in targets:
                        if mac in hidden_macs:
                            hidden_macs.remove(mac)
                            shown_count += 1
                            last_action = "shown"
                        else:
                            hidden_macs.add(mac)
                            hidden_count += 1
                            last_action = "hidden"
                        last_mac = mac
                    error = save_config(config_path, config, device_state, hidden_macs)
                    if error:
                        status_message = f"Save failed: {error}"
                    else:
                        config_error = None
                        if len(targets) == 1:
                            status_message = f"{last_mac} {last_action}."
                        else:
                            status_message = f"Hidden {hidden_count}, shown {shown_count}."
                    status_until = time.time() + 3
        if key == curses.KEY_UP:
            if view_mode == "config":
                config_index = max(0, config_index - 1)
            else:
                selected_index = max(0, selected_index - 1)
        if key == curses.KEY_DOWN:
            if view_mode == "config":
                config_index = min(
                    max(0, config_count - 1),
                    config_index + 1,
                )
            else:
                selected_index = min(
                    max(0, device_count - 1), selected_index + 1
                )
        if key == curses.KEY_PPAGE:
            if view_mode == "config":
                config_index = max(0, config_index - config_page_size)
            else:
                selected_index = max(0, selected_index - device_page_size)
        if key == curses.KEY_NPAGE:
            if view_mode == "config":
                config_index = min(
                    max(0, config_count - 1), config_index + config_page_size
                )
            else:
                selected_index = min(
                    max(0, device_count - 1), selected_index + device_page_size
                )
        if key == ord(" "):
            if view_mode == "config":
                status_message = "Multi-select not available in config view."
                status_until = time.time() + 3
            else:
                selected_mac = device_items[selected_index][0] if device_items else ""
                if not selected_mac:
                    status_message = "No device selected."
                    status_until = time.time() + 3
                else:
                    if selected_mac in selected_macs:
                        selected_macs.remove(selected_mac)
                    else:
                        selected_macs.add(selected_mac)
                    if device_items:
                        selected_index = min(len(device_items) - 1, selected_index + 1)

        if view_mode != "config":
            if device_items and 0 <= selected_index < len(device_items):
                selected_mac_key = device_items[selected_index][0]
            else:
                selected_mac_key = ""
        if key in (ord("t"), ord("T")):
            if view_mode == "config":
                status_message = "Track toggle not available in config view."
                status_until = time.time() + 3
                continue
            targets = resolve_target_macs(
                device_items, selected_index, selected_macs
            )
            if not targets:
                status_message = "No device selected."
                status_until = time.time() + 3
                continue
            tracked_count = 0
            untracked_count = 0
            last_mac = ""
            last_action = ""
            for mac in targets:
                if mac in device_state:
                    device_state.pop(mac, None)
                    untracked_count += 1
                    last_action = "untracked"
                else:
                    known_info = known_devices.get(mac)
                    if not known_info:
                        known_devices[mac] = default_known_info()
                        known_info = known_devices[mac]
                    device_state[mac] = {
                        "label": "",
                        "name": known_info.get("name") or "",
                        "alias": "",
                        "class": "",
                        "icon": "",
                        "paired": "",
                        "trusted": "",
                        "connected": "",
                        "manufacturer": "",
                        "last_info": None,
                        "alarm": True,
                        "last_away": None,
                        "last_seen": known_info.get("last_seen"),
                        "rssi": known_info.get("rssi") or "",
                        "present": False,
                    }
                    hidden_macs.discard(mac)
                    pending_info_macs.add(mac)
                    tracked_count += 1
                    last_action = "tracked"
                last_mac = mac
            error = save_config(config_path, config, device_state, hidden_macs)
            if error:
                status_message = f"Save failed: {error}"
            else:
                config_error = None
                if len(targets) == 1:
                    status_message = f"{last_mac} {last_action}."
                else:
                    status_message = (
                        f"Tracked {tracked_count}, untracked {untracked_count}."
                    )
            status_until = time.time() + 3
        if key in (ord("e"), ord("E")):
            if view_mode == "config":
                config_items = build_config_items(config)
                if not config_items:
                    status_message = "No config entries."
                    status_until = time.time() + 3
                    continue
                key_name = config_items[config_index]
                value = config.get(key_name)
                if key_name in ("tracked_devices", "hidden_devices"):
                    status_message = f"{key_name} is read-only here."
                    status_until = time.time() + 3
                    continue
                value_type = config_value_type(value)
                if value_type == "readonly":
                    status_message = f"{key_name} is not editable."
                    status_until = time.time() + 3
                    continue
                prompt = f"{key_name} ({value_type}, blank keeps {format_config_value(value)}): "
                raw = prompt_input(stdscr, prompt)
                if raw:
                    parsed, error = parse_config_value(value_type, raw)
                    if error:
                        status_message = f"Invalid value: {error}"
                        status_until = time.time() + 3
                    else:
                        config[key_name] = parsed
                        save_error = save_config(config_path, config, device_state, hidden_macs)
                        if save_error:
                            status_message = f"Save failed: {save_error}"
                        else:
                            config_error = None
                            status_message = f"Updated {key_name}."
                            if key_name == "log_path":
                                log_path = config["log_path"]
                                ensure_log(log_path)
                                log_cache = []
                                log_cache_mac = ""
                            if key_name == "cache_path":
                                cache_path = config["cache_path"]
                                cache_dirty = True
                            if key_name == "cache_ttl":
                                cache_ttl = config["cache_ttl"]
                            if key_name == "oui_path":
                                oui_path = config.get("oui_path", "")
                                oui_registry, oui_error = load_oui_registry(oui_path)
                            if key_name in ("scan_interval", "scan_timeout"):
                                next_scan = time.time() + config["scan_interval"]
                                next_noise_refresh = time.time() + config["scan_interval"]
                            if key_name == "info_refresh_interval":
                                next_info_refresh = time.time() + config["info_refresh_interval"]
                        status_until = time.time() + 3
                continue

            selected_mac = device_items[selected_index][0] if device_items else ""
            if not selected_mac:
                status_message = "No device selected."
                status_until = time.time() + 3
            elif selected_mac not in device_state:
                status_message = "Selected MAC is not tracked."
                status_until = time.time() + 3
            else:
                mac = selected_mac
                info = device_state[mac]
                label_input = prompt_input(
                    stdscr, f"Label (blank keeps '{info.get('label') or info.get('name') or ''}'): "
                )
                mac_input = prompt_input(stdscr, f"MAC (blank keeps {mac}): ")
                new_mac = mac
                if mac_input:
                    mac_input = normalize_mac(mac_input)
                    if not is_valid_mac(mac_input):
                        status_message = "Invalid MAC address format."
                        status_until = time.time() + 3
                        mac_input = ""
                    elif mac_input != mac and mac_input in device_state:
                        status_message = "MAC already tracked."
                        status_until = time.time() + 3
                        mac_input = ""
                    else:
                        new_mac = mac_input
                if mac_input == "":
                    new_mac = mac
                if label_input:
                    info["label"] = label_input
                if is_noise_device(new_mac, known_devices.get(new_mac, {})):
                    status_message = "MAC looks like noise; not tracked."
                    status_until = time.time() + 3
                    continue
                if new_mac != mac:
                    device_state.pop(mac, None)
                    device_state[new_mac] = info
                    if new_mac not in known_devices:
                        known_devices[new_mac] = default_known_info()
                    if mac in hidden_macs:
                        hidden_macs.discard(mac)
                        hidden_macs.add(new_mac)
                error = save_config(config_path, config, device_state, hidden_macs)
                if error:
                    status_message = f"Save failed: {error}"
                else:
                    config_error = None
                    status_message = f"Updated {new_mac}."
                status_until = time.time() + 4
                pending_info_macs.add(new_mac)
        if key in (ord("d"), ord("D")):
            if view_mode == "config":
                status_message = "Delete not available in config view."
                status_until = time.time() + 3
                continue
            targets = resolve_target_macs(
                device_items, selected_index, selected_macs
            )
            if not targets:
                status_message = "No device selected."
                status_until = time.time() + 3
                continue
            if len(targets) == 1:
                prompt = f"Delete all records for {targets[0]}?"
            else:
                prompt = f"Delete all records for {len(targets)} devices?"
            if not prompt_confirm(stdscr, prompt):
                continue
            for mac in targets:
                device_state.pop(mac, None)
                known_devices.pop(mac, None)
                hidden_macs.discard(mac)
                pending_info_macs.discard(mac)
                selected_macs.discard(mac)
            if log_cache_mac in targets:
                log_cache = []
                log_cache_mac = ""
            save_error = save_config(config_path, config, device_state, hidden_macs)
            log_error = delete_log_entries(log_path, targets)
            cache_error = save_cache(cache_path, known_devices)
            if save_error:
                status_message = f"Save failed: {save_error}"
            elif log_error:
                status_message = f"Log delete failed: {log_error}"
            elif cache_error:
                status_message = f"Cache delete failed: {cache_error}"
            else:
                config_error = None
                if len(targets) == 1:
                    status_message = f"Deleted records for {targets[0]}."
                else:
                    status_message = f"Deleted records for {len(targets)} devices."
            status_until = time.time() + 4
        time.sleep(0.1)


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Bluetooth presence TUI monitor")
    parser.add_argument(
        "--config",
        default="config.json",
        help="Path to config file (default: config.json)",
    )
    return parser.parse_args(argv)


def entrypoint():
    args = parse_args(sys.argv[1:])
    curses.wrapper(main, args.config)


if __name__ == "__main__":
    entrypoint()
