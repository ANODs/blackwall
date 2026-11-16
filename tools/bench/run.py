"""Benchmarks BLACKWALL's data plane against the cores other clients ship. macOS.

    python3 tools/bench/run.py [--quick]                          the stand on this machine
    python3 tools/bench/run.py --remote <server-id> [--bind en0]  a real server

The stand runs on 127.0.0.1: one Xray server (the reference implementation) serves every
client, and an HTTPS site behind it is what they download from, so what is left is the
cost of the client itself. --remote takes a VLESS server (REALITY over TCP, or TLS over
TCP or WebSocket) by its id in BLACKWALL's configuration, reaches it past the system VPN
through --bind (default en0), and downloads from Cloudflare's speed test; the link is
read there and written nowhere but the clients' configurations in a private temporary
folder, removed at the end.

    curl ─SOCKS5─▶ client under test ─VLESS+REALITY+Vision / Shadowsocks 2022─▶ server ─▶ site

Clients (all run at once on their own ports; the transfers take turns, round by round):
    BLACKWALL   this repository, ReleaseSafe (as released)    blackwall-proxy
    Happ        the Xray core inside /Applications/Happ.app    (if installed)
    Xray        Xray-core, the core of v2rayN and v2RayTun     xray (Homebrew)
    sing-box    the core of Hiddify                            sing-box (Homebrew)

The counters come from the kernel (proc_pid_rusage), not from sampling:
    start_ms         from exec to a listening port, median of 3
    idle_mb          memory footprint (what Activity Monitor shows), idle after start
    idle_wakeups     times per second the idle process wakes the CPU
    mbps             one download, median of the rounds
    cpu_ms_per_gb    the client's CPU time per GB carried
    energy_j_per_gb  the energy the kernel bills to the client per GB carried
    par_mbps         several downloads at once, in total
    peak_mb          the highest memory footprint over the whole run
    handshake_ms     a small request over a new connection each time, median

Writes its part of site/data/bench.json ("local" or "remote"; the other part is kept).
Needs go, xray, sing-box, curl and zig.
"""

import base64
import ctypes
import json
import pathlib
import platform
import re
import secrets
import shutil
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from urllib.parse import parse_qs, unquote, urlsplit

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
OUT = ROOT / "site" / "data" / "bench.json"
CONFIG = pathlib.Path.home() / "Library" / "Application Support" / "BLACKWALL" / "config.json"
ARGS = sys.argv[1:]
QUICK = "--quick" in ARGS
REMOTE = int(ARGS[ARGS.index("--remote") + 1]) if "--remote" in ARGS else None
BIND = ARGS[ARGS.index("--bind") + 1] if "--bind" in ARGS else ("en0" if REMOTE else None)

GB = 10**9
if REMOTE:  # a real link, often metered: tens of megabytes, not gigabytes
    ROUNDS, SINGLE, PAR_N, PAR_SIZE, HS_N = (1, 5 * 10**6, 4, 1 * 10**6, 8) if QUICK else (3, 15 * 10**6, 8, 2_500_000, 20)
else:
    ROUNDS, SINGLE, PAR_N, PAR_SIZE, HS_N = (1, 256 << 20, 16, 32 << 20, 30) if QUICK else (3, 1 << 30, 16, 128 << 20, 100)
IDLE_S = 5 if QUICK else 10
PORT_SITE, PORT_REALITY, PORT_SS, PORT_SOCKS = 19480, 19443, 19444, 19100

# sing-box 1.12 and 1.14 fail the REALITY authentication of Xray 26.11 (with every uTLS
# fingerprint), and the server hands them to the target site; checked 2026-11-16
SKIP = {("singbox", "reality"): "fails REALITY authentication against Xray 26.11"}


# ---------------------------------------------------------------- the kernel's counters

_libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib")


class _Timebase(ctypes.Structure):
    _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]


_tb = _Timebase()
_libc.mach_timebase_info(ctypes.byref(_tb))


def usage(pid: int) -> dict:
    """rusage_info_v6 of a process: times are in Mach ticks, energy in nanojoules."""
    buf = ctypes.create_string_buffer(1024)
    if _libc.proc_pid_rusage(ctypes.c_int(pid), ctypes.c_int(6), buf) != 0:
        raise RuntimeError(f"no rusage for {pid}")
    v = struct.unpack_from("<16x42Q", buf.raw)
    return {
        "cpu_s": (v[0] + v[1]) * _tb.numer / _tb.denom / 1e9,
        "wakeups": v[2] + v[3],
        "footprint_mb": v[7] / 2**20,
        "peak_mb": v[28] / 2**20,
        "energy_j": v[40] / 1e9,
    }


# ---------------------------------------------------------------- helpers

def sh(*cmd: str) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout


def listening(port: int) -> bool:
    try:
        socket.create_connection(("127.0.0.1", port), 0.2).close()
        return True
    except OSError:
        return False


def wait_port(port: int, timeout: float = 10) -> float:
    """Seconds until something accepts on the port."""
    t0 = time.perf_counter()
    while time.perf_counter() - t0 < timeout:
        if listening(port):
            return time.perf_counter() - t0
        time.sleep(0.002)
    raise RuntimeError(f"nothing listens on {port}")


def curl(port: int, *urls: str, extra: tuple = (), strict: bool = True) -> list[str]:
    """One line per URL: "<status> <bytes> <seconds>". Strict raises on any failed request."""
    outs = [a for u in urls for a in ("-o", "/dev/null", u)]  # -o applies to one URL only
    cmd = ["curl", "-sk", "--max-time", "60" if REMOTE else "120", "--socks5-hostname", f"127.0.0.1:{port}",
           "-w", "%{http_code} %{size_download} %{time_total}\n", *extra, *outs]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=900).stdout.split("\n")
    lines = [l for l in out if l]
    if strict and (not lines or any(not l.startswith("2") for l in lines)):
        raise RuntimeError(f"a request through {port} failed: {lines[:3]}")
    return lines or ["000 0 0"]


def complete(line: str, size: int = 0) -> bool:
    """A request that answered 2xx with all the bytes asked for."""
    code, got, _ = line.split()
    return code.startswith("2") and int(got) >= size


def mbps(line: str) -> float:
    _, size, secs = line.split()
    return float(size) * 8 / float(secs) / 1e6


# ---------------------------------------------------------------- servers

def stand_keys() -> dict:
    out = sh("xray", "x25519")
    return {
        "uuid": str(uuid.uuid4()),
        "priv": re.search(r"PrivateKey:\s*(\S+)", out).group(1),
        "pub": re.search(r"(?:Password \(PublicKey\)|Public key):\s*(\S+)", out).group(1),
        "sid": secrets.token_hex(4),
        "ss": base64.b64encode(secrets.token_bytes(16)).decode(),
    }


def stand_servers(k: dict) -> dict:
    user = base64.urlsafe_b64encode(f"2022-blake3-aes-128-gcm:{k['ss']}".encode()).decode().rstrip("=")
    return {
        "reality": {"proto": "vless", "host": "127.0.0.1", "port": PORT_REALITY, "uuid": k["uuid"],
                    "flow": "xtls-rprx-vision", "sni": "localhost", "fp": "chrome", "pbk": k["pub"], "sid": k["sid"],
                    "link": f"vless://{k['uuid']}@127.0.0.1:{PORT_REALITY}?type=tcp&security=reality&sni=localhost"
                            f"&fp=chrome&pbk={k['pub']}&sid={k['sid']}&flow=xtls-rprx-vision#bench"},
        "ss2022": {"proto": "ss", "host": "127.0.0.1", "port": PORT_SS, "method": "2022-blake3-aes-128-gcm",
                   "password": k["ss"], "link": f"ss://{user}@127.0.0.1:{PORT_SS}#bench"},
    }


def stand_server_config(k: dict) -> dict:
    return {
        "log": {"loglevel": "none"},
        "inbounds": [
            {"listen": "127.0.0.1", "port": PORT_REALITY, "protocol": "vless",
             "settings": {"clients": [{"id": k["uuid"], "flow": "xtls-rprx-vision"}], "decryption": "none"},
             "streamSettings": {"network": "raw", "security": "reality", "realitySettings": {
                 "target": f"127.0.0.1:{PORT_SITE}", "serverNames": ["localhost"],
                 "privateKey": k["priv"], "shortIds": [k["sid"]]}}},
            {"listen": "127.0.0.1", "port": PORT_SS, "protocol": "shadowsocks",
             "settings": {"method": "2022-blake3-aes-128-gcm", "password": k["ss"], "network": "tcp"}},
        ],
        # the site is on 127.0.0.1, which Xray's freedom refuses by default
        "outbounds": [{"protocol": "freedom", "settings": {
            "domainStrategy": "UseIPv4", "finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}}],
    }


def remote_server(server_id: int) -> tuple[str, str, dict]:
    """(country, protocol label, server) of a VLESS server: REALITY over TCP, or TLS over TCP or WebSocket."""
    cfg = json.loads(CONFIG.read_text())
    s = next((x for x in cfg["servers"] if x["id"] == server_id), None)
    if s is None:
        sys.exit(f"bench: no server {server_id} in {CONFIG}")
    u = urlsplit(s["link"])
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    net = {"raw": "tcp"}.get(q.get("type", "tcp"), q.get("type", "tcp"))
    sec = q.get("security", "none")
    if u.scheme != "vless" or (sec, net) not in (("reality", "tcp"), ("tls", "tcp"), ("tls", "ws")) or "ed=" in q.get("path", ""):
        sys.exit("bench: --remote takes VLESS with REALITY over TCP, or TLS over TCP or WebSocket")
    label = "VLESS + " + {"reality": "REALITY", "tls": "TLS"}[sec] + {"tcp": "", "ws": " + WebSocket"}[net]
    if "vision" in q.get("flow", ""):
        label += " + Vision"
    return s.get("country") or "??", label, {
        "proto": "vless", "security": sec, "net": net, "host": u.hostname, "port": u.port, "uuid": unquote(u.username),
        "flow": q.get("flow", ""), "sni": q.get("sni", ""), "fp": q.get("fp", "chrome"), "alpn": q.get("alpn", ""),
        "pbk": q.get("pbk", ""), "sid": q.get("sid", ""), "path": q.get("path", "/"), "wshost": q.get("host", ""),
        "link": s["link"]}


def rtt_ms(host: str, port: int) -> float:
    """TCP connect time to the server, out of the bound interface."""
    times = []
    for _ in range(5):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if BIND:
            s.setsockopt(socket.IPPROTO_IP, 25, socket.if_nametoindex(BIND))  # IP_BOUND_IF
        s.settimeout(5)
        t0 = time.perf_counter()
        s.connect((host, port))
        times.append((time.perf_counter() - t0) * 1000)
        s.close()
    return round(statistics.median(times), 1)


# ---------------------------------------------------------------- clients

def client_list(tmp: pathlib.Path) -> list[dict]:
    happ = pathlib.Path("/Applications/Happ.app/Contents/MacOS/core/xray")
    out = [{"id": "blackwall", "name": "BLACKWALL", "bin": tmp / "rel" / "bin" / "blackwall-proxy", "kind": "blackwall"}]
    if happ.exists():
        out.append({"id": "happ", "name": "Happ", "bin": happ, "kind": "xray"})
    xray = pathlib.Path(shutil.which("xray")).resolve()
    if (xray.parent.parent / "libexec" / "xray").exists():  # Homebrew's bin/xray is a wrapper script
        xray = xray.parent.parent / "libexec" / "xray"
    out.append({"id": "xray", "name": "Xray", "bin": xray, "kind": "xray"})
    out.append({"id": "singbox", "name": "sing-box", "bin": pathlib.Path(shutil.which("sing-box")).resolve(), "kind": "singbox"})
    return out


def version(c: dict) -> str:
    if c["kind"] == "blackwall":
        return re.search(r'\.version = "([^"]+)"', (ROOT / "build.zig.zon").read_text()).group(1)
    out = subprocess.run([str(c["bin"]), "version"], capture_output=True, text=True).stdout
    m = re.search(r"(\d+\.\d+\.\d+)", out)
    return m.group(1) if m else "?"


def xray_config(s: dict, port: int) -> dict:
    if s["proto"] == "vless":
        if s.get("security", "reality") == "reality":
            stream = {"network": "raw", "security": "reality", "realitySettings": {
                "serverName": s["sni"], "fingerprint": s["fp"], "publicKey": s["pbk"], "shortId": s["sid"]}}
        else:
            tls = {"serverName": s["sni"], "fingerprint": s["fp"]}
            if s["alpn"]:
                tls["alpn"] = s["alpn"].split(",")
            stream = {"network": "ws" if s["net"] == "ws" else "raw", "security": "tls", "tlsSettings": tls}
            if s["net"] == "ws":
                stream["wsSettings"] = {"path": s["path"], "host": s["wshost"]}
        out = {"protocol": "vless",
               "settings": {"vnext": [{"address": s["host"], "port": s["port"],
                                       "users": [{"id": s["uuid"], "encryption": "none", "flow": s["flow"]}]}]},
               "streamSettings": stream}
    else:
        out = {"protocol": "shadowsocks", "settings": {"servers": [
            {"address": s["host"], "port": s["port"], "method": s["method"], "password": s["password"]}]}}
    if BIND:
        out.setdefault("streamSettings", {})["sockopt"] = {"interface": BIND}
    return {"log": {"loglevel": "none"},
            "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": {"udp": False}}],
            "outbounds": [out]}


def singbox_config(s: dict, port: int) -> dict:
    if s["proto"] == "vless":
        tls = {"enabled": True, "server_name": s["sni"], "utls": {"enabled": True, "fingerprint": s["fp"]}}
        if s.get("security", "reality") == "reality":
            tls["reality"] = {"enabled": True, "public_key": s["pbk"], "short_id": s["sid"]}
        elif s["alpn"]:
            tls["alpn"] = s["alpn"].split(",")
        out = {"type": "vless", "server": s["host"], "server_port": s["port"], "uuid": s["uuid"], "tls": tls}
        if s["flow"]:
            out["flow"] = s["flow"]
        if s.get("net") == "ws":
            out["transport"] = {"type": "ws", "path": s["path"], "headers": {"Host": s["wshost"]}}
    else:
        out = {"type": "shadowsocks", "server": s["host"], "server_port": s["port"],
               "method": s["method"], "password": s["password"]}
    if BIND:
        out["bind_interface"] = BIND
    return {"log": {"disabled": True},
            "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": port}],
            "outbounds": [out]}


def command(c: dict, s: dict, port: int, tmp: pathlib.Path) -> list[str]:
    if c["kind"] == "blackwall":
        return [str(c["bin"]), *(["--bind", BIND] if BIND else []), str(port), s["link"]]
    cfg = tmp / f"{c['id']}-{port}.json"
    cfg.write_text(json.dumps(xray_config(s, port) if c["kind"] == "xray" else singbox_config(s, port)))
    cfg.chmod(0o600)
    return [str(c["bin"]), "run", "-c", str(cfg)]


def start(cmd: list[str], port: int) -> tuple[subprocess.Popen, float]:
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return p, wait_port(port)


def stop(p: subprocess.Popen) -> None:
    p.terminate()
    try:
        p.wait(5)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()


# ---------------------------------------------------------------- the run

def run_suite(cs: list[dict], s: dict, big, small, tmp: pathlib.Path, base_port: int, label: str) -> dict:
    """All clients against one server: start, idle, rounds of single downloads, parallel, handshakes."""
    live, res = [], {}
    for j, c in enumerate(cs):
        port = base_port + j
        if (c["id"], label) in SKIP:
            print(f"bench: {label:8} {c['name']}: skipped, {SKIP[c['id'], label]}", flush=True)
            res[c["id"]] = None
            continue
        cmd = command(c, s, port, tmp)
        starts = []
        for _ in range(3):
            p, t = start(cmd, port)
            starts.append(t * 1000)
            stop(p)
            while listening(port):
                time.sleep(0.01)
        p, _ = start(cmd, port)
        live.append((c, p, port))
        res[c["id"]] = {"start_ms": round(statistics.median(starts), 1)}

    time.sleep(3)
    before = {c["id"]: usage(p.pid) for c, p, _ in live}
    time.sleep(IDLE_S)
    for c, p, _ in live:
        u = usage(p.pid)
        res[c["id"]].update({
            "idle_mb": round(u["footprint_mb"], 1),
            "idle_wakeups": round((u["wakeups"] - before[c["id"]]["wakeups"]) / IDLE_S, 1),
        })

    # a client that cannot fetch one small page in three tries does not work here at all
    for c, p, port in list(live):
        if not any(complete(curl(port, small, strict=False)[0]) for _ in range(3)):
            print(f"bench: {label:8} {c['name']}: carries nothing here", flush=True)
            res[c["id"]] = None
            stop(p)
            live.remove((c, p, port))

    # every request from here on counts: a failed one is recorded, not retried
    asked = {c["id"]: 0 for c, _, _ in live}
    failed = {c["id"]: 0 for c, _, _ in live}
    speeds = {c["id"]: [] for c, _, _ in live}
    cpu = {c["id"]: [] for c, _, _ in live}
    energy = {c["id"]: [] for c, _, _ in live}
    for r in range(ROUNDS):
        for c, p, port in live:
            u0 = usage(p.pid)
            line = curl(port, big(SINGLE), strict=False)[0]
            u1 = usage(p.pid)
            asked[c["id"]] += 1
            if not complete(line, SINGLE):
                failed[c["id"]] += 1
                print(f"bench: {label:8} round {r + 1} {c['name']:10} failed ({line})", flush=True)
                continue
            speeds[c["id"]].append(mbps(line))
            cpu[c["id"]].append((u1["cpu_s"] - u0["cpu_s"]) * 1000 / (SINGLE / GB))
            energy[c["id"]].append((u1["energy_j"] - u0["energy_j"]) / (SINGLE / GB))
            print(f"bench: {label:8} round {r + 1} {c['name']:10} {speeds[c['id']][-1]:8.0f} Mbit/s", flush=True)

    for c, p, port in live:
        lock, done = threading.Lock(), {"bytes": 0, "failed": 0}

        def one():
            line = curl(port, big(PAR_SIZE), strict=False)[0]
            with lock:
                if complete(line, PAR_SIZE):
                    done["bytes"] += PAR_SIZE
                else:
                    done["failed"] += 1

        t0 = time.perf_counter()
        threads = [threading.Thread(target=one) for _ in range(PAR_N)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        par = done["bytes"] * 8 / (time.perf_counter() - t0) / 1e6
        lines = curl(port, *[small] * HS_N, extra=("-H", "Connection: close"), strict=False)
        hs = [float(l.split()[2]) * 1000 for l in lines if complete(l)]
        asked[c["id"]] += PAR_N + HS_N
        failed[c["id"]] += done["failed"] + HS_N - len(hs)
        med = lambda xs, nd=0: round(statistics.median(xs), nd) if xs else None
        res[c["id"]].update({
            "mbps": med(speeds[c["id"]]),
            "cpu_ms_per_gb": med(cpu[c["id"]]),
            "energy_j_per_gb": med(energy[c["id"]], 2),
            "par_mbps": round(par),
            "handshake_ms": med(hs, 1),
            "peak_mb": round(usage(p.pid)["peak_mb"], 1),
            "requests": asked[c["id"]],
            "failed": failed[c["id"]],
        })
        print(f"bench: {label:8} {c['name']:10} {res[c['id']]}", flush=True)

    for _, p, _ in live:
        stop(p)
    return res


def app_mb(path: pathlib.Path) -> float | None:
    return round(int(sh("du", "-sk", str(path)).split()[0]) / 1024, 1) if path.exists() else None


def main() -> None:
    for tool in ("go", "xray", "sing-box", "curl", "zig"):
        if not shutil.which(tool):
            sys.exit(f"bench: {tool} is needed")
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="bw-bench-"))
    procs = []
    try:
        print("bench: building BLACKWALL (ReleaseSafe)", flush=True)
        subprocess.run(["zig", "build", "-Doptimize=ReleaseSafe", "--prefix", str(tmp / "rel")], cwd=ROOT, check=True)
        cs = client_list(tmp)
        data = json.loads(OUT.read_text()) if OUT.exists() else {}
        chip = sh("sysctl", "-n", "machdep.cpu.brand_string").strip()
        data["machine"] = f"{chip}, macOS {platform.mac_ver()[0]}"
        data["clients"] = [{"id": c["id"], "name": c["name"], "version": version(c)} for c in cs]

        if REMOTE:
            country, proto, s = remote_server(REMOTE)
            big = lambda n: f"https://speed.cloudflare.com/__down?bytes={n}"
            small = "https://cp.cloudflare.com/generate_204"
            rtt = rtt_ms(s["host"], s["port"])
            print(f"bench: server in {country}, {proto}, connect {rtt} ms", flush=True)
            res = run_suite(cs, s, big, small, tmp, PORT_SOCKS, "remote")
            gw = subprocess.run(["route", "-n", "get", "-ifscope", BIND, "default"], capture_output=True, text=True).stdout
            data["remote"] = {
                "date": time.strftime("%Y-%m-%d"), "quick": QUICK, "country": country, "rtt_ms": rtt,
                "protocol": proto, "site": "speed.cloudflare.com",
                "network": "mobile" if "172.20.10.1" in gw else "fixed",
                "single_mb": SINGLE // 10**6, "results": res,
            }
        else:
            subprocess.run(["go", "build", "-o", str(tmp / "target"), str(ROOT / "tools" / "bench" / "target.go")], check=True)
            procs.append(subprocess.Popen([str(tmp / "target"), str(PORT_SITE), str(tmp)], stderr=subprocess.DEVNULL))
            wait_port(PORT_SITE)
            k = stand_keys()
            (tmp / "server.json").write_text(json.dumps(stand_server_config(k)))
            procs.append(subprocess.Popen(["xray", "run", "-c", str(tmp / "server.json")],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            wait_port(PORT_REALITY)
            wait_port(PORT_SS)
            big = lambda n: f"https://localhost:{PORT_SITE}/bytes/{n}"
            small = f"https://localhost:{PORT_SITE}/"
            protocols = {}
            for i, (proto, s) in enumerate(stand_servers(k).items()):
                protocols[proto] = run_suite(cs, s, big, small, tmp, PORT_SOCKS + i * 10, proto)

            print("bench: sizes", flush=True)
            subprocess.run(["zig", "build", "package", "-Doptimize=ReleaseSafe", "-Dlang=en", "--prefix", str(tmp / "pkg")],
                           cwd=ROOT, check=True, capture_output=True)
            bundle = next((tmp / "pkg").rglob("BLACKWALL.app"), None)
            zips = list((tmp / "pkg").rglob("*-macos-arm64.zip"))
            data["local"] = {"date": time.strftime("%Y-%m-%d"), "quick": QUICK, "single_mb": SINGLE // 2**20,
                             "protocols": protocols}
            data["sizes"] = {
                "core_mb": {c["id"]: round(c["bin"].stat().st_size / 1e6, 1) for c in cs},
                "app_mb": {
                    "blackwall": app_mb(bundle) if bundle else None,
                    "happ": app_mb(pathlib.Path("/Applications/Happ.app")),
                    "v2raytun": app_mb(pathlib.Path("/Applications/v2RayTun.app")),
                    "hiddify": app_mb(pathlib.Path("/Applications/Hiddify.app")),
                },
                "download_mb": {"blackwall": round(zips[0].stat().st_size / 1e6, 1) if zips else None},
            }
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        print(f"bench: wrote {OUT.relative_to(ROOT)}", flush=True)
    finally:
        for p in procs:
            stop(p)
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
