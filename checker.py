import concurrent.futures
import json
import os
import socket
import subprocess
import tempfile
import time
import base64
import threading
from urllib.parse import parse_qs, unquote, urlparse
import requests

# ==================== الإعدادات ====================
SOURCE_URLS = [
    "https://github.com/Mohamedhnini-a/Neverstops-2/raw/refs/heads/main/sub.txt",
]

XRAY = "./xray/xray"

# المرحلة 1: سريعة (204 endpoints) — كتفلتر 90% من الخايبين بسرعة
PHASE1_URLS = [
    "http://www.gstatic.com/generate_204",
    "http://cp.cloudflare.com/generate_204",
    "http://edge-http.microsoft.com/captiveportal/generate_204",
]

# المرحلة 2: على اللي بقاو — تأكيد حقيقي للـ IP + اتصال فعلي
PHASE2_URLS = [
    "https://api.ipify.org?format=json",
    "http://detectportal.firefox.com/success.txt",
]

TIMEOUT = 3
MAX_WORKERS = 15
BASE_PORT = 20000
MAX_LATENCY_MS = 5000

# ==================== Session ====================
_tls = threading.local()

def get_session():
    if not hasattr(_tls, "s"):
        s = requests.Session()
        s.trust_env = False
        _tls.s = s
    return _tls.s


# ==================== اختبار الاتصال ====================
def test_once(proxies, urls, verify_ip=False):
    last_error = None
    session = get_session()
    for url in urls:
        try:
            start = time.perf_counter()
            response = session.get(url, proxies=proxies, timeout=TIMEOUT,
                                   allow_redirects=True)
            elapsed = (time.perf_counter() - start) * 1000

            if response.status_code in (200, 204):
                if verify_ip and "ipify" in url:
                    try:
                        ip = response.json().get("ip", "")
                        if not ip or ("." not in ip and ":" not in ip):
                            last_error = "no_ip"
                            continue
                    except Exception:
                        last_error = "bad_json"
                        continue
                return round(elapsed), None

            last_error = f"http_{response.status_code}"
            continue

        except requests.exceptions.Timeout:
            last_error = "timeout"
            continue
        except requests.exceptions.ProxyError:
            return None, "proxy_error"
        except Exception as e:
            last_error = type(e).__name__
            continue

    return None, last_error


# ==================== التحميل ====================
def download_configs():
    configs = []
    for source_url in SOURCE_URLS:
        try:
            print(f"Downloading: {source_url}", flush=True)
            response = requests.get(source_url, timeout=20)
            response.raise_for_status()
            configs.extend([line.strip() for line in response.text.splitlines() if line.strip()])
        except Exception as e:
            print(f"FAILED: {e}", flush=True)
    return list(dict.fromkeys(configs))


# ==================== تحليل الكونفيغ ====================
def parse_config(line):
    try:
        if line.startswith("vmess://"):
            b64_str = line[8:].split("#")[0].strip()
            b64_str += "=" * ((4 - len(b64_str) % 4) % 4)
            config = json.loads(base64.b64decode(b64_str).decode('utf-8'))
            return {
                "protocol": "vmess", "server": config.get("add"), "port": int(config.get("port", 443)),
                "id": config.get("id"), "aid": int(config.get("aid", 0)), "scy": config.get("scy", "auto"),
                "net": config.get("net", "tcp"), "tls": config.get("tls", ""), "host": config.get("host", ""),
                "sni": config.get("sni", ""), "path": config.get("path", "/"), "original": line,
            }

        if line.startswith("vless://") or line.startswith("trojan://"):
            parsed = urlparse(line)
            params = parse_qs(parsed.query, keep_blank_values=True)
            get = lambda name: params.get(name, [""])[0]
            return {
                "protocol": parsed.scheme.lower(), "server": parsed.hostname, "port": parsed.port or 443,
                "uuid": parsed.username, "password": parsed.username, "net": get("type") or "tcp",
                "security": get("security") or "none", "sni": get("sni") or parsed.hostname,
                "host": get("host") or "", "path": unquote(get("path")) or "/", "alpn": get("alpn") or "",
                "fp": get("fp") or "", "pbk": get("pbk") or "", "sid": get("sid") or "",
                "spx": get("spx") or "/", "flow": get("flow") or "", "original": line,
            }
    except Exception:
        return None
    return None


# ==================== بناء كونفيغ Xray ====================
def make_xray_config(config, local_port):
    stream_settings = {
        "network": config.get("net", "tcp"),
        "security": config.get("security", config.get("tls") or "none"),
    }

    if stream_settings["security"] == "tls":
        stream_settings["tlsSettings"] = {
            "serverName": config.get("sni") or config.get("server"),
            "allowInsecure": False,
        }
        if config.get("alpn"):
            stream_settings["tlsSettings"]["alpn"] = config["alpn"].split(",")
        if config.get("fp"):
            stream_settings["tlsSettings"]["fingerprint"] = config["fp"]

    elif stream_settings["security"] == "reality":
        stream_settings["realitySettings"] = {
            "serverName": config.get("sni") or config.get("server"),
            "fingerprint": config.get("fp") or "chrome",
            "publicKey": config.get("pbk"),
            "shortId": config.get("sid"),
            "spiderX": config.get("spx"),
        }

    net = config.get("net", "tcp")
    if net == "ws":
        stream_settings["wsSettings"] = {
            "path": config.get("path", "/"),
            "host": config.get("host") or config.get("sni"),
        }
    elif net == "grpc":
        stream_settings["grpcSettings"] = {"serviceName": config.get("path")}

    if config["protocol"] == "vless":
        user = {"id": config["uuid"], "encryption": "none"}
        if config.get("flow"):
            user["flow"] = config["flow"]
        outbound = {
            "protocol": "vless",
            "settings": {"vnext": [{"address": config["server"], "port": config["port"], "users": [user]}]},
            "streamSettings": stream_settings,
        }
    elif config["protocol"] == "trojan":
        outbound = {
            "protocol": "trojan",
            "settings": {"servers": [{"address": config["server"], "port": config["port"], "password": config["password"]}]},
            "streamSettings": stream_settings,
        }
    elif config["protocol"] == "vmess":
        outbound = {
            "protocol": "vmess",
            "settings": {"vnext": [{"address": config["server"], "port": config["port"],
                                    "users": [{"id": config["id"], "alterId": config["aid"], "security": config["scy"]}]}]},
            "streamSettings": stream_settings,
        }
    else:
        return None

    return {
        "log": {"loglevel": "error"},
        "inbounds": [{"listen": "127.0.0.1", "port": local_port, "protocol": "http", "settings": {}}],
        "outbounds": [outbound],
    }


# ==================== اختبار كونفيغ واحد ====================
def test_config(index, config, urls, verify_ip=False):
    local_port = BASE_PORT + (index % 40000)
    config_file, log_file, process = None, None, None

    try:
        xray_config = make_xray_config(config, local_port)
        if not xray_config:
            return {"ok": False, "reason": "make_failed", "server": config.get("server")}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(xray_config, f)
            config_file = f.name

        log_file = tempfile.NamedTemporaryFile(suffix=".log", delete=False).name
        with open(log_file, "w") as log_handle:
            process = subprocess.Popen(
                [XRAY, "run", "-c", config_file],
                stdout=subprocess.DEVNULL, stderr=log_handle,
                start_new_session=True,
            )

        started = False
        for _ in range(30):
            if process.poll() is not None:
                break
            try:
                with socket.create_connection(("127.0.0.1", local_port), timeout=0.3):
                    pass
                started = True
                break
            except OSError:
                time.sleep(0.1)

        if not started:
            try:
                with open(log_file, "r", errors="ignore") as lf:
                    err_tail = lf.read()[-300:]
            except Exception:
                err_tail = ""
            return {"ok": False, "reason": "xray_died", "server": config.get("server"), "log": err_tail}

        proxies = {
            "http": f"http://127.0.0.1:{local_port}",
            "https": f"http://127.0.0.1:{local_port}",
        }
        latency, err = test_once(proxies, urls, verify_ip=verify_ip)

        if latency is not None and latency <= MAX_LATENCY_MS:
            return {"ok": True, "latency": latency, "line": config["original"], "server": config["server"]}
        return {"ok": False, "reason": err, "server": config.get("server")}

    except Exception as e:
        return {"ok": False, "reason": type(e).__name__, "server": config.get("server")}
    finally:
        if process:
            try:
                process.terminate()
                process.wait(timeout=0.5)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
        for path in (config_file, log_file):
            if path and os.path.exists(path):
                try:
                    os.remove(path)
                except Exception:
                    pass


# ==================== تشغيل مرحلة ====================
def run_phase(configs, urls, verify_ip):
    tasks = list(enumerate(configs, start=1))
    results = []
    completed = 0
    working_count = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        iterator = iter(tasks)
        pending = set()
        for _ in range(MAX_WORKERS):
            try:
                pending.add(executor.submit(test_config, *next(iterator), urls, verify_ip))
            except StopIteration:
                break

        while pending:
            done, pending = concurrent.futures.wait(pending, return_when=concurrent.futures.FIRST_COMPLETED)
            for future in done:
                completed += 1
                try:
                    res = future.result()
                    if res.get("ok"):
                        working_count += 1
                        results.append(res)
                        print(f"[ONLINE✅] {res['latency']}ms | {res['server']}", flush=True)
                    else:
                        print(f"[FAILED❌] {res.get('server')} | {res.get('reason')}", flush=True)
                except Exception as e:
                    print(f"[ERROR] {type(e).__name__}: {e}", flush=True)

                if completed % 10 == 0 or completed == len(configs):
                    print(f"--- [Progress] {completed}/{len(configs)} | Working: {working_count} ---", flush=True)

                try:
                    pending.add(executor.submit(test_config, *next(iterator), urls, verify_ip))
                except StopIteration:
                    pass

    return results


# ==================== main ====================
def main():
    print("Downloading configs...", flush=True)
    lines = download_configs()
    configs = [c for c in (parse_config(l) for l in lines) if c]
    total = len(configs)
    print(f"\n✅ Total configs to test: {total}\n", flush=True)
    if not configs:
        return

    # ---------- المرحلة 1: تصفية سريعة ----------
    print("🚀 Phase 1: fast filter (204 endpoints)\n", flush=True)
    phase1 = run_phase(configs, PHASE1_URLS, verify_ip=False)
    print(f"\n✅ Phase 1 done: {len(phase1)} passed\n", flush=True)
    if not phase1:
        return

    # ---------- المرحلة 2: تأكيد نهائي ----------
    print(f"🚀 Phase 2: verify {len(phase1)} survivors\n", flush=True)
    phase2 = run_phase(phase1, PHASE2_URLS, verify_ip=True)

    phase2.sort(key=lambda x: x["latency"])
    with open("working.txt", "w", encoding="utf-8") as f:
        for r in phase2:
            f.write(r["line"] + "\n")
    print(f"\n✅ Done! Saved {len(phase2)} working configs to working.txt", flush=True)


if __name__ == "__main__":
    main()
