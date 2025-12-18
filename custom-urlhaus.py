#!/var/ossec/framework/python/bin/python3
# URLhaus integration for Wazuh + Suricata EVE JSON
# Safe against missing fields and mixed event types.

import json
import sys
import time
import os
from socket import socket, AF_UNIX, SOCK_DGRAM

try:
    import requests
except Exception:
    print("No module 'requests' found. Install: /var/ossec/framework/python/bin/python3 -m pip install requests")
    sys.exit(1)

debug_enabled = True
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")

log_file = f"{pwd}/logs/integrations.log"
socket_addr = f"{pwd}/queue/sockets/queue"
urlhaus_endpoint = "https://urlhaus-api.abuse.ch/v1/url/"

def debug(msg):
    if not debug_enabled:
        return
    line = f"{now}: {msg}\n"
    print(line)
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(line)

def extract_url_from_alert(alert):
    data = alert.get("data", {})

    # Legacy format some blog posts use (proxy/web logs)
    http_old = data.get("http", {})
    if isinstance(http_old, dict):
        redirect = http_old.get("redirect")
        if redirect:
            return redirect

    # Suricata EVE format in Wazuh
    suri = data.get("suricata", {})
    if not isinstance(suri, dict):
        return None

    eve = suri.get("eve", {})
    if not isinstance(eve, dict):
        return None

    http = eve.get("http", {})
    if not isinstance(http, dict):
        return None

    host = http.get("hostname") or http.get("host")
    path = http.get("url") or http.get("uri")

    if host and path:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if path.startswith("/"):
            return f"http://{host}{path}"
        return f"http://{host}/{path}"

    return None

def query_urlhaus(url):
    try:
        response = requests.post(urlhaus_endpoint, data={"url": url}, timeout=8)
        return response.status_code, response.json()
    except Exception as e:
        debug(f"# URLhaus request failed: {e}")
        return 0, {"query_status": "error"}

def in_database(json_response):
    return json_response.get("query_status") == "ok"

def collect(json_response):
    urlhaus_reference = json_response.get("urlhaus_reference")
    url_status = json_response.get("url_status")
    date_added = json_response.get("date_added")
    threat = json_response.get("threat")
    blacklists = json_response.get("blacklists", {}) if isinstance(json_response.get("blacklists", {}), dict) else {}
    spamhaus_dbl = blacklists.get("spamhaus_dbl")
    surbl = blacklists.get("surbl")
    tags = json_response.get("tags")
    host = json_response.get("host")
    return urlhaus_reference, url_status, date_added, threat, spamhaus_dbl, surbl, tags, host

def build_output(alert, url, json_response):
    out = {
        "integration": "urlhaus",
        "urlhaus": {
            "found": 0,
            "source": {
                "alert_id": alert.get("id"),
                "rule": alert.get("rule", {}).get("id"),
                "description": alert.get("rule", {}).get("description"),
                "url": url
            }
        }
    }

    if not in_database(json_response):
        return None

    out["urlhaus"]["found"] = 1
    urlhaus_reference, url_status, date_added, threat, spamhaus_dbl, surbl, tags, host = collect(json_response)

    out["urlhaus"]["urlhaus_reference"] = urlhaus_reference
    out["urlhaus"]["url_status"] = url_status
    out["urlhaus"]["date_added"] = date_added
    out["urlhaus"]["threat"] = threat
    out["urlhaus"]["blacklists"] = {"spamhaus_dbl": spamhaus_dbl, "surbl": surbl}
    out["urlhaus"]["tags"] = tags
    out["urlhaus"]["host"] = host

    return out

def send_event(msg, agent=None):
    if not agent or agent.get("id") == "000":
        string = f"1:urlhaus:{json.dumps(msg)}"
    else:
        agent_id = agent.get("id", "000")
        agent_name = agent.get("name", "unknown")
        agent_ip = agent.get("ip", "any")
        string = f"1:[{agent_id}] ({agent_name}) {agent_ip}->urlhaus:{json.dumps(msg)}"

    debug(f"# Sending event: {string}")

    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()

def main(args):
    debug("# Starting URLhaus integration")

    if len(args) < 2:
        debug("# Exiting: Missing alert file argument")
        sys.exit(1)

    alert_file_location = args[1]
    debug(f"# Alert file: {alert_file_location}")

    with open(alert_file_location, "r", encoding="utf-8") as alert_file:
        alert = json.load(alert_file)

    url = extract_url_from_alert(alert)
    if not url:
        debug("# No URL found in this alert. Skipping.")
        return

    debug(f"# Extracted URL: {url}")

    status, json_response = query_urlhaus(url)
    debug(f"# URLhaus HTTP status: {status}")
    debug(f"# URLhaus response status: {json_response.get('query_status')}")

    out = build_output(alert, url, json_response)
    if not out:
        debug("# URL not found in URLhaus. No event sent.")
        return

    send_event(out, alert.get("agent"))

if __name__ == "__main__":
    try:
        main(sys.argv)
    except Exception as e:
        debug(f"# Fatal error: {e}")
        raise
