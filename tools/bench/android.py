"""Benchmarks VPN clients on Android: BLACKWALL against NekoBox and Hiddify (both sing-box).

    python3 tools/bench/android.py stand                 start the stand on this Mac, print the links
    python3 tools/bench/android.py measure <package>     measure the client that is connected now
    python3 tools/bench/android.py stop                  stop the stand

The stand is the one tools/bench/run.py uses, reached from the emulator at 10.0.2.2: an Xray
server with Shadowsocks 2022 (sing-box does not pass Xray 26's REALITY check, see run.py),
whose freedom outbound hands every connection to 203.0.113.10 to the bench site's plain HTTP
port. The emulator downloads from 203.0.113.10 with tools/bench/probe.zig: a public address,
so no client lets it bypass the VPN as a local one, and no DNS in the way.

    probe (emulator, root) ─▶ client under test (VpnService) ─SS 2022─▶ Xray (Mac) ─▶ site

Each client is connected by hand in its own window (add http://10.0.2.2:19490/sub, or the
ss:// link it prints; NekoBox: open the link; Hiddify: hiddify://import/<sub url>), then sent
to the background with Home, then measured. Needs an emulator with root (a google_apis image),
adb, go, xray and zig.

Counters come from the emulator's kernel, summed over every process of the package:
    idle_pss_mb    proportional memory, idle
    peak_rss_mb    the highest resident memory (VmHWM) over the run
    idle_cpu_ms_s  CPU time per second while idle (a minute, 10 s after Home)
    mbps           one download, median of the rounds
    par_mbps       8 downloads at once, in total
    cpu_ms_per_gb  CPU time per GB carried
    handshake_ms   a small request on a new connection, median
    apk_mb, installed_mb

    python3 tools/bench/android.py battery   the battery estimate again (see battery())
"""

import base64
import json
import os
import pathlib
import re
import secrets
import signal
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
OUT = ROOT / "site" / "data" / "bench.json"
ADB = str(pathlib.Path.home() / "Library" / "Android" / "sdk" / "platform-tools" / "adb")
STATE = pathlib.Path(tempfile.gettempdir()) / "blackwall-android-bench"
PORT_SITE, PORT_PLAIN, PORT_SS, PORT_SUB = 19480, 19482, 19444, 19490
SITE_IP = "203.0.113.10"
PROBE = "/data/local/tmp/probe"
CLIENTS = {
    "dev.blackwall": "BLACKWALL",
    "moe.nb4a": "NekoBox",
    "app.hiddify.com": "Hiddify",
}
ROUNDS, SINGLE, PAR_N, PAR_SIZE, HS_N = 3, 256 << 20, 8, 64 << 20, 50
# settle after Home, then the idle window (the kernel counts CPU in 10 ms ticks)
IDLE_SETTLE_S, IDLE_S = 10, 60


def adb(*cmd: str) -> str:
    return subprocess.run([ADB, "shell", *cmd], capture_output=True, text=True, check=True).stdout


# ---------------------------------------------------------------- the stand

def stand() -> None:
    STATE.mkdir(mode=0o700, exist_ok=True)
    key = base64.b64encode(secrets.token_bytes(16)).decode()
    (STATE / "xray.json").write_text(json.dumps({
        "log": {"loglevel": "none"},
        "inbounds": [{"listen": "127.0.0.1", "port": PORT_SS, "protocol": "shadowsocks",
                      "settings": {"method": "2022-blake3-aes-128-gcm", "password": key, "network": "tcp,udp"}}],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            # the site is on 127.0.0.1, which Xray's freedom refuses by default
            {"tag": "site", "protocol": "freedom", "settings": {
                "redirect": f"127.0.0.1:{PORT_PLAIN}",
                "finalRules": [{"action": "allow", "network": "tcp,udp", "ip": ["127.0.0.0/8"]}]}},
        ],
        "routing": {"rules": [{"ip": [SITE_IP], "outboundTag": "site"}]},
    }))
    user = base64.urlsafe_b64encode(f"2022-blake3-aes-128-gcm:{key}".encode()).decode().rstrip("=")
    link = f"ss://{user}@10.0.2.2:{PORT_SS}#bench"
    www = STATE / "www"
    www.mkdir(exist_ok=True)
    (www / "sub").write_text(link + "\n")
    subprocess.run(["go", "build", "-o", str(STATE / "target"), str(ROOT / "tools" / "bench" / "target.go")], check=True)
    subprocess.run(["zig", "build-exe", str(ROOT / "tools" / "bench" / "probe.zig"), "-target", "aarch64-linux-musl",
                    "-O", "ReleaseFast", "-fstrip", f"-femit-bin={STATE / 'probe'}"], check=True)
    pids = [
        subprocess.Popen([str(STATE / "target"), str(PORT_SITE), str(STATE), str(PORT_PLAIN)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).pid,
        subprocess.Popen(["xray", "run", "-c", str(STATE / "xray.json")], stdout=subprocess.DEVNULL).pid,
        subprocess.Popen([sys.executable, "-m", "http.server", str(PORT_SUB), "--bind", "127.0.0.1", "--directory", str(www)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).pid,
    ]
    (STATE / "pids").write_text(" ".join(map(str, pids)))
    subprocess.run([ADB, "root"], capture_output=True)
    time.sleep(2)
    subprocess.run([ADB, "wait-for-device"], check=True)
    subprocess.run([ADB, "push", str(STATE / "probe"), PROBE], capture_output=True, check=True)
    adb("chmod", "755", PROBE)
    print(f"subscription: http://10.0.2.2:{PORT_SUB}/sub")
    print(f"hiddify:      hiddify://import/http://10.0.2.2:{PORT_SUB}/sub#bench")
    print(f"link:         {STATE / 'www' / 'sub'}")


def stop() -> None:
    for pid in (STATE / "pids").read_text().split():
        try:
            os.kill(int(pid), signal.SIGTERM)
        except ProcessLookupError:
            pass


# ---------------------------------------------------------------- counters

def pids(package: str) -> list[str]:
    out = adb("ps", "-A", "-o", "PID,NAME")
    return [l.split()[0] for l in out.splitlines()[1:] if l.split()[-1] == package or l.split()[-1].startswith(package + ":")]


def cpu_ms(ps: list[str]) -> float:
    """utime + stime of the processes, in ms (the kernel counts in 1/100 s)."""
    total = 0
    for p in ps:
        f = adb("cat", f"/proc/{p}/stat").rsplit(")", 1)[1].split()
        total += int(f[11]) + int(f[12])
    return total * 10.0


def memory(ps: list[str]) -> tuple[float, float]:
    """(PSS, VmHWM) in MB, summed."""
    pss = hwm = 0
    for p in ps:
        pss += int(re.search(r"^Pss:\s+(\d+)", adb("cat", f"/proc/{p}/smaps_rollup"), re.M).group(1))
        hwm += int(re.search(r"^VmHWM:\s+(\d+)", adb("cat", f"/proc/{p}/status"), re.M).group(1))
    return pss / 1024, hwm / 1024


def probe(*args: str) -> list[float]:
    return [float(x) for x in adb(PROBE, args[0], SITE_IP, "80", *args[1:]).split()]


def sizes(package: str) -> dict:
    path = adb("pm", "path", package).splitlines()[0].removeprefix("package:").rsplit("/", 1)[0]
    installed = int(adb("du", "-sk", path).split()[0])
    apk = int(adb("stat", "-c", "%s", f"{path}/base.apk").strip())
    return {"apk_mb": round(apk / 2**20, 1), "installed_mb": round(installed / 1024, 1)}


def measure(package: str) -> dict:
    ps = pids(package)
    if not ps:
        sys.exit(f"bench: {package} is not running")
    probe("get", "1000")  # the VPN is up and carries
    time.sleep(IDLE_SETTLE_S)
    c0 = cpu_ms(ps)
    time.sleep(IDLE_S)
    idle_cpu = (cpu_ms(ps) - c0) / IDLE_S
    idle_pss, _ = memory(ps)

    c0 = cpu_ms(ps)
    carried = 0
    single = []
    par = []
    for _ in range(ROUNDS):
        got, secs = probe("get", str(SINGLE))
        carried += got
        single.append(got * 8 / secs / 1e6)
        got, secs = probe("par", str(PAR_N), str(PAR_SIZE))
        carried += got
        par.append(got * 8 / secs / 1e6)
    cpu = cpu_ms(ps) - c0
    hs = probe("hs", str(HS_N))[0]
    _, peak = memory(ps)
    return {
        "idle_pss_mb": round(idle_pss, 1),
        "peak_rss_mb": round(peak, 1),
        "idle_cpu_ms_s": round(idle_cpu, 2),
        "mbps": round(statistics.median(single)),
        "par_mbps": round(statistics.median(par)),
        "cpu_ms_per_gb": round(cpu / (carried / 1e9)),
        "handshake_ms": hs,
        **sizes(package),
    }


# ---------------------------------------------------------------- battery, estimated

BATTERY_J = 5000e-3 * 3.85 * 3600  # a 5000 mAh phone battery at 3.85 V
AWAKE_S = 8 * 3600  # hours a day the phone is not asleep, VPN on all day
DAY_GB = (2, 10)  # a usual day's traffic, a heavy one


def joules_per_cpu_s(data: dict) -> float:
    """Energy per second of CPU on this Mac, from the kernel's own counters in the desktop
    bench (run.py, Shadowsocks 2022, every client): the emulator ran on the same cores."""
    rows = [r for r in data.get("local", {}).get("protocols", {}).get("ss2022", {}).values()
            if r and r.get("cpu_ms_per_gb") and r.get("energy_j_per_gb")]
    if not rows:
        return 4.0
    return statistics.median(r["energy_j_per_gb"] / (r["cpu_ms_per_gb"] / 1000) for r in rows)


def battery(data: dict) -> None:
    """Share of a phone battery a client's own CPU takes in a day: idle while the phone is
    awake, plus its CPU per GB carried. Not measured on a phone: the radio, the same for
    every client, is left out, and so is deep sleep with the screen off."""
    part = data["android"]
    j = joules_per_cpu_s(data)
    out = {"assumptions": {"battery_mah": 5000, "volts": 3.85, "awake_hours": AWAKE_S // 3600,
                           "day_gb": list(DAY_GB), "joules_per_cpu_s": round(j, 2),
                           "joules_from": "kernel energy counters of the desktop bench on the same Mac"},
           "clients": {}}
    for pkg, c in part["clients"].items():
        cpu_s = {gb: c["idle_cpu_ms_s"] * AWAKE_S / 1000 + c["cpu_ms_per_gb"] / 1000 * gb for gb in DAY_GB}
        out["clients"][pkg] = {
            f"pct_{gb}gb": round(cpu_s[gb] * j / BATTERY_J * 100, 2) for gb in DAY_GB
        } | {
            # what that share is in minutes, for a phone that lasts a day on a charge
            f"minutes_{gb}gb": round(cpu_s[gb] * j / BATTERY_J * 24 * 60, 1) for gb in DAY_GB
        }
    part["battery"] = out


def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "stand":
        return stand()
    if cmd == "stop":
        return stop()
    if cmd == "battery":  # the estimate again, from the stored measurements
        data = json.loads(OUT.read_text())
        battery(data)
        OUT.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        print(json.dumps(data["android"]["battery"], indent=2))
        return
    if cmd == "baseline":  # the emulator's own network, no VPN: the ceiling
        got, secs = [float(x) for x in adb(PROBE, "get", "10.0.2.2", str(PORT_PLAIN), str(SINGLE)).split()]
        print(json.dumps({"direct_mbps": round(got * 8 / secs / 1e6)}))
        return
    if cmd != "measure" or len(sys.argv) < 3 or sys.argv[2] not in CLIENTS:
        sys.exit(__doc__)
    package = sys.argv[2]
    result = measure(package)
    print(json.dumps(result))
    data = json.loads(OUT.read_text()) if OUT.exists() else {}
    part = data.setdefault("android", {})
    part["date"] = time.strftime("%Y-%m-%d")
    part["device"] = "Android " + adb("getprop", "ro.build.version.release").strip() + " emulator (arm64), on " + data.get("machine", "this Mac")
    part["protocol"] = "Shadowsocks 2022"
    version = re.search(r"versionName=(\S+)", adb("dumpsys", "package", package)).group(1)
    part.setdefault("clients", {})[package] = {"name": CLIENTS[package], "version": version, **result}
    battery(data)
    OUT.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
