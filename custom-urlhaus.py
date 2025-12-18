#!/var/ossec/framework/python/bin/python3
# URLhaus integration for Wazuh
# Works with Suricata alerts where HTTP fields are flattened into data.http
# Falls back to data.suricata.eve.http when present
# Sends a slim JSON event to avoid Wazuh JSON decoder field limits

import json
import os
import sys
import time
from socket import socket, AF_UNIX, SOCK_DGRAM

try:
    import requests
except Exception:
    print("requests module missing. Install with:")
    print("/var/ossec/framework/python/bin/python3 -m pip install requests")
    sys.exit(1)

WAZUH_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
SOCKET_ADDR = f"{WAZUH_ROOT}/queue/sockets/queue"
LOG_FILE = f"{WAZUH_ROOT}/logs/integrations.log"
DEBUG_DUMP_FILE = f"{WAZUH_ROOT}/logs/urlhaus-last.alert.json"

URLHAUS_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"

debug_enabled = False


def now_str():
    return time.strftime("%Y-%m-%d %H:%M:%S %Z")


def debug(msg):
    if not debug_enabled:
        return

    line = f"{now_str()} urlhaus: {msg}\n"
    try:
        print(line, end="")
    except Exception:
        pass

    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass


def dump_alert_for_debug(alert_obj):
    if not debug_enabled:
        return
    try:
        with open(DEBUG_DUMP_FILE, "w", encoding="utf-8") as f:
            json.dump(alert_obj, f)
        debug(f"Wrote debug alert to {DEBUG_DUMP_FILE}")
    except Exception as e:
        debug(f"Could not write debug alert file: {e}")


def build_url(host, path, port):
    if not host or not path:
        return None

    if isinstance(path, str) and (path.startswith("http://") or path.startswith("https://")):
        return path

    if not isinstance(path, str):
        return None

    use_port = None
    try:
        if port is not None:
            use_port = int(str(port))
    except Exception:
        use_port = None

    if use_port and use_port not in (80, 443):
        if path.startswith("/"):
            return f"http://{host}:{use_port}{path}"
        return f"http://{host}:{use_port}/{path}"

    if path.startswith("/"):
        return f"http://{host}{path}"
    return f"http://{host}/{path}"


def extract_url_from_alert(alert):
    data = alert.get("data", {})

    http_flat = data.get("http")
    if isinstance(http_flat, dict):
        host = http_flat.get("hostname") or http_flat.get("host")
        path = http_flat.get("url") or http_flat.get("uri")
        port = http_flat.get("http_port") or data.get("dest_port")
        url = build_url(host, path, port)
        if url:
            return url

    eve_http = (
        data.get("suricata", {})
            .get("eve", {})
            .get("http")
    )
    if isinstance(eve_http, dict):
        host = eve_http.get("hostname") or eve_http.get("host")
        path = eve_http.get("url") or eve_http.get("uri")
        port = eve_http.get("http_port")
        url = build_url(host, path, port)
        if url:
            return url

    return None


def query_urlhaus(url):
    try:
        r = requests.post(URLHAUS_ENDPOINT, data={"url": url}, timeout=10)
        return r.status_code, r.json()
    except Exception as e:
        debug(f"URLhaus request failed: {e}")
        return 0, {"query_status": "error"}


def send_event(payload, agent=None):
    if not agent or agent.get("id") == "000":
        msg = f"1:urlhaus:{json.dumps(payload)}"
    else:
        agent_id = agent.get("id", "000")
        agent_name = agent.get("name", "unknown")
        agent_ip = agent.get("ip", "any")
        msg = f"1:[{agent_id}] ({agent_name}) {agent_ip}->urlhaus:{json.dumps(payload)}"

    debug(f"Sending event to queue")

    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(SOCKET_ADDR)
    sock.send(msg.encode())
    sock.close()


def build_output(alert, url, resp_json):
    if resp_json.get("query_status") != "ok":
        return None

    out = {
        "integration": "urlhaus",
        "found": 1,
        "url": url,
        "url_status": resp_json.get("url_status"),
        "threat": resp_json.get("threat"),
        "date_added": resp_json.get("date_added"),
        "reference": resp_json.get("urlhaus_reference"),
        "rule_id": alert.get("rule", {}).get("id"),
        "rule_description": alert.get("rule", {}).get("description"),
    }
    return out


def main(argv):
    global debug_enabled

    if len(argv) < 2:
        sys.exit(1)

    if len(argv) > 2 and argv[2] == "debug":
        debug_enabled = True

    alert_file = argv[1]
    debug(f"Starting URLhaus integration with alert file {alert_file}")

    with open(alert_file, "r", encoding="utf-8") as f:
        alert = json.load(f)

    dump_alert_for_debug(alert)

    url = extract_url_from_alert(alert)
    if not url:
        debug("No URL found in this alert, skipping")
        return

    debug(f"Extracted URL: {url}")

    status, resp_json = query_urlhaus(url)
    debug(f"URLhaus HTTP status: {status}")
    debug(f"URLhaus query_status: {resp_json.get('query_status')}")

    out = build_output(alert, url, resp_json)
    if not out:
        debug("URL not found in URLhaus, no event sent")
        return

    send_event(out, alert.get("agent"))


if __name__ == "__main__":
    try:
        main(sys.argv)
    except Exception as e:
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"{now_str()} urlhaus: Fatal error: {e}\n")
        except Exception:
            pass
        raise
