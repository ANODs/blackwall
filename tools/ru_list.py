#!/usr/bin/env python3
"""Builds lists/ru-direct.txt: the sites of Russia and the CIS that the
client sends direct, never through a VPN server, and lists/ru-block.xray.json:
the same names (and Russian addresses) refused on a VPN server.

Sources: v2fly/domain-list-community `category-ru` with everything it
includes (MIT; the Russian zones and the Russian services elsewhere), and
lists/extra.txt (picked by hand). Entries tagged @ads are left out, as are
regexp: and keyword: ones (the client matches names and what is under them).

    python3 tools/ru_list.py            # writes both files
    python3 tools/ru_list.py --check    # fails when they would change
"""

import io
import json
import os
import sys
import tarfile
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LISTS = os.path.join(ROOT, "lists")
V2FLY = "https://codeload.github.com/v2fly/domain-list-community/tar.gz/refs/heads/master"


def v2fly_data():
    """Every file of v2fly's data/ directory, by name."""
    req = urllib.request.Request(V2FLY, headers={"User-Agent": "blackwall-lists"})
    with urllib.request.urlopen(req, timeout=60) as r:
        blob = r.read()
    files = {}
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
        for m in tar.getmembers():
            parts = m.name.split("/")
            if len(parts) == 3 and parts[1] == "data" and m.isfile():
                files[parts[2]] = tar.extractfile(m).read().decode()
    return files


def resolve(files, name, seen, out):
    if name in seen:
        return
    seen.add(name)
    for line in files[name].splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        words = line.split()
        if words[0].startswith("include:"):
            resolve(files, words[0][len("include:"):], seen, out)
            continue
        if "@ads" in words[1:]:
            continue
        kind, _, value = words[0].rpartition(":")
        if kind in ("regexp", "keyword"):
            continue
        out.add(value.lower())


def hand_picked():
    names = set()
    with open(os.path.join(LISTS, "extra.txt")) as f:
        for line in f:
            line = line.split("#", 1)[0].strip().lower()
            if line:
                names.add(line)
    return names


def minimal(names):
    """Without the names a shorter one already covers ("ru" covers "a.ru")."""
    keep = set()
    for n in sorted(names, key=lambda x: x.count(".")):
        labels = n.split(".")
        if any(".".join(labels[i:]) in keep for i in range(1, len(labels))):
            continue
        keep.add(n)
    # zones first, then by name
    return sorted(keep, key=lambda x: ("." in x, x))


def main():
    files = v2fly_data()
    names = set()
    resolve(files, "category-ru", set(), names)
    names |= hand_picked()
    names = minimal(n for n in names if n and all(c.isalnum() or c in "-._" for c in n))

    txt = (
        "# BLACKWALL: sites of Russia and the CIS that go direct, never through a VPN server.\n"
        "# Built by tools/ru_list.py from v2fly/domain-list-community category-ru (MIT)\n"
        "# and lists/extra.txt. A name covers everything under it. Do not edit by hand.\n"
        + "".join(n + "\n" for n in names)
    )
    xray = {
        "_comment": "Merge into a server's Xray config: requests to Russian sites and addresses "
        "never leave the server. Built by tools/ru_list.py from lists/ru-direct.txt. "
        "Inbounds need sniffing on (http, tls, quic) for clients that send addresses.",
        "routing": {
            "rules": [
                {"type": "field", "domain": ["domain:" + n for n in names], "outboundTag": "block-ru"},
                {"type": "field", "ip": ["geoip:ru"], "outboundTag": "block-ru"},
            ]
        },
        "outbounds": [{"tag": "block-ru", "protocol": "blackhole"}],
    }
    out = {
        "ru-direct.txt": txt,
        "ru-block.xray.json": json.dumps(xray, indent=2, ensure_ascii=False) + "\n",
    }
    check = "--check" in sys.argv
    changed = False
    for name, body in out.items():
        path = os.path.join(LISTS, name)
        old = open(path).read() if os.path.exists(path) else None
        if old == body:
            continue
        changed = True
        if not check:
            with open(path, "w") as f:
                f.write(body)
    print(f"{len(names)} names, {'changed' if changed else 'unchanged'}")
    if check and changed:
        sys.exit(1)


if __name__ == "__main__":
    main()
