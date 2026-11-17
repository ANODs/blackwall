"""Builds the landing page into _site/ (what GitHub Pages serves).

    python3 tools/site.py                 # build
    python3 tools/site.py --offline       # build without asking GitHub for releases
    python3 tools/site.py --serve 4173    # build, serve, rebuild when a source changes

One template per page (site/src/*.html), one strings file per language
(site/i18n/*.json). Every language must have the same keys, and a template may
only use keys that exist: anything else stops the build, as in src/i18n.zig.

    /            English
    /ru/         Russian
    /zh/         Chinese

Template syntax:  {{key}} a string,  {{@name}} a build value,
{{@inc:file}} a file from site/src placed inline.

Releases: the latest version, the files of every language and system and the
download counts come from the GitHub API at build time (GITHUB_TOKEN is used
when set). When that fails, the version of build.zig.zon and the file names of
the release workflow are used, without counts. Standard library only.
"""

import functools
import html
import http.server
import json
import os
import pathlib
import re
import shutil
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
SRC = SITE / "src"
OUT = ROOT / "_site"

LANGS = ["en", "ru", "zh"]
PAGES = {"index.html": ""}
LOCALES = {"en": "en_US", "ru": "ru_RU", "zh": "zh_CN"}
SYSTEMS = {"mac": "macos-arm64.zip", "win": "windows-x86_64.exe", "linux": "linux-x86_64.tar.gz", "android": "android.apk"}

# The first visit to "/" goes to the visitor's language: a saved or explicit choice,
# then the browser's languages, then the time zone. No request leaves the page.
DETECT = """(function(){try{var L=['en','ru','zh'],S='bw-lang',q=new URLSearchParams(location.search).get('lang'),l=null;
if(L.indexOf(q)>=0){l=q;localStorage.setItem(S,q)}else{var s=localStorage.getItem(S);if(L.indexOf(s)>=0)l=s}
if(!l){var n=navigator.languages||[navigator.language||''];for(var i=0;i<n.length&&!l;i++){var c=String(n[i]).toLowerCase().slice(0,2);if(c==='ru'||c==='be'||c==='kk')l='ru';else if(c==='zh')l='zh'}}
if(!l){var z=Intl.DateTimeFormat().resolvedOptions().timeZone||'';
if(/^(Europe\\/(Moscow|Kaliningrad|Samara|Volgograd|Saratov|Ulyanovsk|Astrakhan|Kirov|Minsk|Simferopol)|Asia\\/(Yekaterinburg|Omsk|Novosibirsk|Barnaul|Tomsk|Novokuznetsk|Krasnoyarsk|Irkutsk|Chita|Yakutsk|Khandyga|Vladivostok|Ust-Nera|Magadan|Sakhalin|Srednekolymsk|Kamchatka|Anadyr|Almaty|Qyzylorda|Qostanay|Aqtobe|Aqtau|Atyrau|Oral|Bishkek))$/.test(z))l='ru';
else if(/^Asia\\/(Shanghai|Urumqi|Chongqing|Harbin|Hong_Kong|Macau|Taipei|Singapore)$/.test(z))l='zh'}
if(l&&l!=='en')location.replace(l+'/'+location.hash)}catch(e){}})();"""


def fail(message: str) -> None:
    sys.exit(f"site: {message}")


def version() -> str:
    m = re.search(r'^\s*\.version = "([^"]+)"', (ROOT / "build.zig.zon").read_text(), re.M)
    if not m:
        fail("no version in build.zig.zon")
    return m.group(1)


def vkey(v: str) -> tuple:
    return tuple(int(x) for x in v.split("."))


def normalize(releases: list) -> dict | None:
    """GitHub's release list -> {version, files[lang][system], downloads}. Same shape as worker/src/index.js."""
    downloads = {"total": 0, **{s: 0 for s in SYSTEMS}}
    best, files = None, {}
    for rel in releases:
        m = re.fullmatch(r"v(\d+\.\d+\.\d+)-(en|ru|zh)", rel.get("tag_name", ""))
        if not m or rel.get("draft") or rel.get("prerelease"):
            continue
        ver, lang = m.groups()
        for asset in rel.get("assets", []):
            system = next((s for s, suffix in SYSTEMS.items() if asset["name"].endswith("-" + suffix)), None)
            if not system:
                continue
            downloads[system] += asset.get("download_count", 0)
            downloads["total"] += asset.get("download_count", 0)
            if best is None or vkey(ver) > vkey(best):
                best, files = ver, {}
            if ver == best:
                files.setdefault(lang, {})[system] = {"url": asset["browser_download_url"], "size": asset["size"]}
    if best is None or any(s not in files.get(l, {}) for l in LANGS for s in SYSTEMS):
        return None
    return {"version": best, "files": files, "downloads": downloads}


def fetch_releases(repo: str) -> dict | None:
    req = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/releases?per_page=100",
        headers={"Accept": "application/vnd.github+json", "User-Agent": "site-build"},
    )
    if os.environ.get("GITHUB_TOKEN"):
        req.add_header("Authorization", "Bearer " + os.environ["GITHUB_TOKEN"])
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return normalize(json.load(r))
    except Exception as e:  # no network, a private repository, no release yet
        print(f"site: releases not read from GitHub ({e}); using build.zig.zon")
        return None


def fallback_releases(cfg: dict) -> dict:
    ver = version()
    sizes = cfg.get("fallback_sizes_mb", {})
    files = {
        lang: {
            s: {
                "url": f"https://github.com/{cfg['repo']}/releases/download/v{ver}-{lang}/BLACKWALL-{ver}-{'' if s == 'android' else lang + '-'}{suffix}",
                "size": int(sizes[s] * 1e6) if s in sizes else None,
            }
            for s, suffix in SYSTEMS.items()
        }
        for lang in LANGS
    }
    return {"version": ver, "files": files, "downloads": None}


def load_strings() -> dict:
    strings = {lang: json.loads((SITE / "i18n" / f"{lang}.json").read_text()) for lang in LANGS}
    keys = set(strings["en"])
    for lang in LANGS:
        diff = keys ^ set(strings[lang])
        if diff:
            fail(f"i18n/{lang}.json differs from en.json in: {', '.join(sorted(diff))}")
    return strings


def render(template: str, strings: dict, ctx: dict) -> str:
    def include(m: re.Match) -> str:
        return (SRC / m.group(1)).read_text()

    def value(m: re.Match) -> str:
        key = m.group(1)
        if key.startswith("@"):
            if key[1:] not in ctx:
                fail(f"unknown build value {{{{{key}}}}}")
            return ctx[key[1:]]
        if key not in strings:
            fail(f"unknown string {{{{{key}}}}}")
        return html.escape(strings[key], quote=True)

    text = re.sub(r"\{\{@inc:([\w.\-]+)\}\}", include, template)
    return re.sub(r"\{\{(@?\w+)\}\}", value, text)


def jsonld(cfg: dict, strings: dict, lang: str, url: str, base: str, releases: dict) -> str:
    """What search engines read about the program: schema.org SoftwareApplication."""
    repo = "https://github.com/" + cfg["repo"]
    data = {
        "@context": "https://schema.org",
        "@type": "SoftwareApplication",
        "name": "BLACKWALL",
        "description": strings["description"],
        "featureList": strings["seo_features"].split(";"),
        "url": url,
        "image": f"{base}assets/icon-512.png",
        "screenshot": f"{base}assets/og-{lang}.png",
        "applicationCategory": "SecurityApplication",
        "applicationSubCategory": "VPN client",
        "operatingSystem": "macOS, Windows, Linux, Android",
        "softwareVersion": releases["version"],
        "downloadUrl": f"{repo}/releases",
        "license": "https://opensource.org/license/mit",
        "isAccessibleForFree": True,
        "inLanguage": ["en", "ru", "zh"],
        "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"},
        "codeRepository": repo,
        "programmingLanguage": "Zig",
    }
    return json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")


def bench_data() -> dict | None:
    """site/data/bench.json, written by tools/bench/run.py."""
    p = SITE / "data" / "bench.json"
    return json.loads(p.read_text()) if p.exists() else None


MONTHS = {
    "en": ["January", "February", "March", "April", "May", "June", "July", "August", "September",
           "October", "November", "December"],
    "ru": ["января", "февраля", "марта", "апреля", "мая", "июня", "июля", "августа", "сентября",
           "октября", "ноября", "декабря"],
}


def fmt_date(iso: str, lang: str) -> str:
    """2026-11-17 as the page's language writes it (the same as Intl.DateTimeFormat, long month)."""
    y, m, d = (int(x) for x in iso.split("-"))
    if lang == "zh":
        return f"{y}年{m}月{d}日"
    if lang == "ru":
        return f"{d} {MONTHS['ru'][m - 1]} {y} г."
    return f"{MONTHS['en'][m - 1]} {d}, {y}"


def fmt_num(v: float, digits: int, lang: str) -> str:
    """A number as the page's language writes it: 1 088,5 in Russian, 1,088.5 otherwise."""
    s = f"{v:,.{digits}f}"
    return s.replace(",", " ").replace(".", ",") if lang == "ru" else s


def hero_tiles(items: list, strings: dict, lang: str) -> str:
    """Headline ratios, written into the page so that they are read without scripts. Each one
    is ours against the best of the others; one under 1.2 is not a headline."""
    out = []
    for key, r in items:
        if not r or r < 1.2:
            continue
        num = (f"{r:.0f}" if r >= 10 else fmt_num(r, 1, lang)) + "×"
        out.append(f'<div><b>{num}</b><span>{html.escape(strings["bench_x_" + key])}</span></div>')
    return "\n".join(out)


def bench_hero(bench: dict | None, strings: dict, lang: str) -> str:
    """macOS: each ratio against the best of the other cores, the smallest over both protocols."""
    if not bench or "local" not in bench:
        return ""
    protos = [p for p in bench["local"]["protocols"].values()]

    def ratio(key: str) -> float | None:
        rs = []
        for res in protos:
            ours = (res.get("blackwall") or {}).get(key)
            theirs = [v[key] for k, v in res.items() if k != "blackwall" and v and v.get(key)]
            if ours and theirs:
                rs.append(min(theirs) / ours)
        return min(rs) if rs else None

    apps = (bench.get("sizes") or {}).get("app_mb") or {}
    others = [v for k, v in apps.items() if k != "blackwall" and v]
    return hero_tiles([
        ("memory", ratio("idle_mb")),
        ("peak", ratio("peak_mb")),
        ("start", ratio("start_ms")),
        ("size", min(others) / apps["blackwall"] if apps.get("blackwall") and others else None),
    ], strings, lang)


OURS_ANDROID = "dev.blackwall"


def android_hero(bench: dict | None, strings: dict, lang: str) -> str:
    """Android: memory and size only, where the lead holds against NekoBox as well. Speed and
    CPU are close to NekoBox's and are left to the table, which shows them as they are."""
    a = (bench or {}).get("android")
    if not a or OURS_ANDROID not in a.get("clients", {}):
        return ""
    ours = a["clients"][OURS_ANDROID]
    others = [c for k, c in a["clients"].items() if k != OURS_ANDROID]

    def ratio(key: str) -> float | None:
        theirs = [c[key] for c in others if c.get(key)]
        return min(theirs) / ours[key] if ours.get(key) and theirs else None

    return hero_tiles([
        ("memory", ratio("idle_pss_mb")),
        ("peak", ratio("peak_rss_mb")),
        ("apk", ratio("apk_mb")),
        ("installed", ratio("installed_mb")),
    ], strings, lang)


def android_table(bench: dict | None, strings: dict, lang: str) -> str:
    """The Android comparison as a table in the page: a row per measure, a column per client.
    In each row the best value is lit, whoever it belongs to; the caveats sit under the rows
    they are about. Bars are scaled to the row's largest value, speeds to the speed without
    a VPN on the same emulator."""
    a = (bench or {}).get("android")
    if not a or OURS_ANDROID not in a.get("clients", {}):
        return ""
    e = lambda s: html.escape(s, quote=True)  # noqa: E731
    t = lambda k: e(strings[k])  # noqa: E731
    pkgs = [OURS_ANDROID] + [k for k in a["clients"] if k != OURS_ANDROID]
    clients = a["clients"]
    battery = (a.get("battery") or {}).get("clients", {})
    assume = (a.get("battery") or {}).get("assumptions", {})
    base = a.get("baseline") or {}
    core = {OURS_ANDROID: "Zig"}

    def field(key, scale=1.0):
        return lambda pkg: (clients[pkg].get(key) / scale) if clients[pkg].get(key) is not None else None

    def batt(key):
        return lambda pkg: (battery.get(pkg) or {}).get(key)

    # group, lower is better, [(label, value, digits, ceiling, sub-label)]
    groups = [
        ("memory", True, [("idle_mem", field("idle_pss_mb"), 1, None, ""),
                          ("peak_mem", field("peak_rss_mb"), 1, None, "")]),
        ("cpu", True, [("idle_cpu", field("idle_cpu_ms_s"), 2, None, ""),
                       ("cpu_gb", field("cpu_ms_per_gb", 1000), 1, None, "")]),
        ("speed", False, [("single", field("mbps"), 0, base.get("direct_mbps"), "direct_mbps"),
                          ("par", field("par_mbps"), 0, base.get("direct_par_mbps"), "direct_par_mbps")]),
        ("latency", True, [("hs", field("handshake_ms"), 1, None, "")]),
        ("size", True, [("apk", field("apk_mb"), 1, None, ""),
                        ("installed", field("installed_mb"), 1, None, "")]),
        ("battery", True, [("day2", batt("pct_2gb"), 2, None, ""),
                           ("day10", batt("pct_10gb"), 2, None, "")]),
    ]
    notes = {
        "speed": strings["bench_a_mtu"] if a.get("note") and "9000" in a["note"] else "",
        "battery": strings["bench_a_battery"].replace("{mah}", str(assume.get("battery_mah", "")))
                                             .replace("{hours}", str(assume.get("awake_hours", ""))),
    }

    out = [f'<table class="at" role="table" aria-label="{t("bench_a_caption")}">',
           '<thead role="rowgroup"><tr role="row">',
           f'<th class="at-c" role="columnheader" scope="col">{e(a.get("protocol", ""))}</th>']
    for pkg in pkgs:
        c = clients[pkg]
        sub = f'{c.get("version", "")} · {core.get(pkg, "sing-box")}'
        me = ' class="me"' if pkg == OURS_ANDROID else ""
        out.append(f'<th{me} role="columnheader" scope="col"><b>{e(c["name"])}</b><span>{e(sub)}</span></th>')
    out.append("</tr></thead>")

    row_i = 0
    for g, lower, rows in groups:
        if not any(get(p) is not None for _, get, *_ in rows for p in pkgs):
            continue
        hint = strings["bench_lower" if lower else "bench_higher"]
        if g == "battery":
            hint = strings["bench_a_estimate"] + " · " + hint
        out.append(f'<tbody role="rowgroup"><tr class="at-g" role="row">'
                   f'<th role="rowheader" scope="rowgroup" colspan="4">{t("bench_ag_" + g)}<span>{e(hint)}</span></th></tr>')
        for label, get, digits, ceiling, base_key in rows:
            vals = {p: get(p) for p in pkgs}
            shown = {p: (round(v, digits) if v is not None else None) for p, v in vals.items()}
            known = [v for v in shown.values() if v is not None]
            best = (min if lower else max)(known) if known else None
            scale = ceiling or max((v for v in vals.values() if v is not None), default=1) or 1
            sub = ""
            if base_key and base.get(base_key):
                sub = f'<span>{e(strings["bench_a_novpn"].replace("{n}", fmt_num(base[base_key], 0, lang)))}</span>'
            out.append(f'<tr role="row"><th role="rowheader" scope="row">{t("bench_ar_" + label)}{sub}</th>')
            for col, p in enumerate(pkgs):
                cls = [c for c in ("me" if p == OURS_ANDROID else "", "best" if shown[p] == best else "") if c]
                attr = f' class="{" ".join(cls)}"' if cls else ""
                if vals[p] is None:
                    out.append(f'<td{attr} role="cell"><b>·</b></td>')
                    continue
                w = min(vals[p] / scale * 100, 100)
                mark = f'<span class="vh"> ({t("bench_best")})</span>' if "best" in cls else ""
                out.append(f'<td{attr} role="cell"><b>{fmt_num(vals[p], digits, lang)}</b>{mark}'
                           f'<span class="at-t"><i style="--w:{w:.2f}%;--d:{row_i * 40 + col * 70}ms"></i></span></td>')
            out.append("</tr>")
            row_i += 1
        if notes.get(g):
            out.append(f'<tr class="at-n" role="row"><td role="cell" colspan="4">{e(notes[g])}</td></tr>')
        out.append("</tbody>")
    out.append("</table>")
    return "\n".join(out)


def android_foot(bench: dict | None, strings: dict, lang: str) -> str:
    """Where and how: the emulator, the Mac under it, the date, why Shadowsocks 2022, the counters."""
    a = (bench or {}).get("android")
    if not a:
        return ""
    device = a.get("device", "")
    android = re.search(r"Android (\S+)", device)
    machine = re.search(r"\bon (.+)$", device)
    return html.escape(strings["bench_a_foot"]
                       .replace("{android}", android.group(1) if android else "")
                       .replace("{machine}", machine.group(1) if machine else (bench or {}).get("machine", ""))
                       .replace("{date}", fmt_date(a["date"], lang) if a.get("date") else ""))


def write_sitemap(base: str) -> None:
    def loc(l: str) -> str:
        return base + ("" if l == "en" else l + "/")

    links = "".join(f'<xhtml:link rel="alternate" hreflang="{l}" href="{loc(l)}"/>' for l in LANGS)
    links += f'<xhtml:link rel="alternate" hreflang="x-default" href="{base}"/>'
    urls = "".join(f"<url><loc>{loc(l)}</loc>{links}</url>" for l in LANGS)
    (OUT / "sitemap.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">'
        f"{urls}</urlset>\n"
    )


def write_manifest(strings: dict) -> None:
    manifest = {
        "name": "BLACKWALL",
        "short_name": "BLACKWALL",
        "description": strings["description"],
        "start_url": "../",
        "display": "browser",
        "background_color": "#0B0B0D",
        "theme_color": "#0B0B0D",
        "icons": [
            {"src": "icon-192.png", "sizes": "192x192", "type": "image/png"},
            {"src": "icon-512.png", "sizes": "512x512", "type": "image/png"},
            {"src": "icon.svg", "sizes": "any", "type": "image/svg+xml"},
        ],
    }
    (OUT / "assets" / "site.webmanifest").write_text(json.dumps(manifest, ensure_ascii=False, indent=2))


def build(offline: bool = False, releases: dict | None = None) -> dict:
    cfg = json.loads((SITE / "site.json").read_text())
    strings = load_strings()
    if releases is None:
        releases = (None if offline else fetch_releases(cfg["repo"])) or fallback_releases(cfg)

    if OUT.exists():
        shutil.rmtree(OUT)
    shutil.copytree(SITE / "static", OUT / "assets")
    shutil.copy(SRC / "mark.svg", OUT / "assets" / "icon.svg")
    if not (SITE / "static" / "og-en.png").exists():
        fail("no icons and previews: run tools/site_images.py")

    fonts = sorted((SITE / "static" / "fonts").glob("Geist-Regular.woff*"))
    if not fonts:
        fail("no web fonts: run tools/site_fonts.py")
    font_ext = fonts[-1].suffix[1:]  # woff2 when both are there

    base = cfg["base_url"].rstrip("/") + "/"
    bench = bench_data()
    for name, page in PAGES.items():
        template = (SRC / name).read_text()
        for lang in LANGS:
            prefix = "" if lang == "en" else lang + "/"
            path = prefix + page
            root = "../" * path.count("/")
            data = {
                "lang": lang,
                "page": "/" + page,
                "repo": cfg["repo"],
                "worker": cfg.get("worker_url", "").rstrip("/"),
                "releases": releases,
                "bench": bench,
            }
            ctx = {
                "bench_hero": bench_hero(bench, strings[lang], lang),
                "bench_android_hero": android_hero(bench, strings[lang], lang),
                "bench_android_table": android_table(bench, strings[lang], lang),
                "bench_android_foot": android_foot(bench, strings[lang], lang),
                "bench_android_on": "" if (bench or {}).get("android") else " hidden",
                "lang": lang,
                "root": root,
                "url": base + path,
                "og": f"{base}assets/og-{lang}.png",
                "og_locale": LOCALES[lang],
                "og_locales": "\n".join(
                    f'<meta property="og:locale:alternate" content="{LOCALES[l]}">' for l in LANGS if l != lang
                ),
                "jsonld": jsonld(cfg, strings[lang], lang, base + path, base, releases),
                "repo_url": "https://github.com/" + cfg["repo"],
                "version": releases["version"],
                "font_ext": font_ext,
                "detect": DETECT if path == "" else "",
                "data": json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/"),
                "alternates": "\n".join(
                    f'<link rel="alternate" hreflang="{l}" href="{base}{"" if l == "en" else l + "/"}{page}">'
                    for l in LANGS
                )
                + f'\n<link rel="alternate" hreflang="x-default" href="{base}{page}">',
            }
            for l in LANGS:
                ctx["href_" + l] = (root + ("" if l == "en" else l + "/") + page) or "./"
                ctx["cur_" + l] = ' aria-current="true"' if l == lang else ""
            ctx["home"] = ctx["href_" + lang]
            ctx["site_home"] = (root + prefix) or "./"
            for s in SYSTEMS:
                ctx["file_" + s] = html.escape(releases["files"][lang][s]["url"], quote=True)
            out = OUT / path / "index.html"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(render(template, strings[lang], ctx))

    write_sitemap(base)
    write_manifest(strings["en"])
    size = (OUT / "index.html").stat().st_size
    print(f"site: built {len(PAGES) * len(LANGS)} pages, v{releases['version']}, index.html {size / 1024:.1f} KB")
    return releases


def sources_mtime() -> float:
    paths = [p for p in SITE.rglob("*") if p.is_file()] + [ROOT / "build.zig.zon"]
    return max(p.stat().st_mtime for p in paths)


def serve(port: int, offline: bool) -> None:
    state = {"releases": build(offline), "mtime": sources_mtime()}

    class Handler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            mtime = sources_mtime()
            if mtime != state["mtime"]:
                state["mtime"] = mtime
                try:
                    build(releases=state["releases"])
                except SystemExit as e:
                    print(e)
            super().do_GET()

        def end_headers(self):
            self.send_header("Cache-Control", "no-store")
            super().end_headers()

        def log_message(self, *args):
            pass

    handler = functools.partial(Handler, directory=str(OUT))
    print(f"site: http://localhost:{port}/")
    http.server.ThreadingHTTPServer(("127.0.0.1", port), handler).serve_forever()


if __name__ == "__main__":
    args = sys.argv[1:]
    offline = "--offline" in args
    if "--serve" in args:
        i = args.index("--serve")
        serve(int(args[i + 1]) if len(args) > i + 1 else 4173, offline)
    else:
        build(offline)
