"""Builds the landing page into _site/ (what GitHub Pages serves).

    python3 tools/site.py                 # build
    python3 tools/site.py --offline       # build without asking GitHub for releases
    python3 tools/site.py --serve 4173    # build, serve, rebuild when a source changes

One template per page (site/src/*.html), one strings file per language
(site/i18n/*.json). Every language must have the same keys, and a template may
only use keys that exist: anything else stops the build, as in src/i18n.zig.

    /            English          /stats/        statistics
    /ru/         Russian          /ru/stats/
    /zh/         Chinese          /zh/stats/

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
PAGES = {"index.html": "", "stats.html": "stats/"}
SYSTEMS = {"mac": "macos-arm64.zip", "win": "windows-x86_64.exe", "linux": "linux-x86_64.tar.gz"}

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
                "url": f"https://github.com/{cfg['repo']}/releases/download/v{ver}-{lang}/BLACKWALL-{ver}-{lang}-{suffix}",
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


def build(offline: bool = False, releases: dict | None = None) -> dict:
    cfg = json.loads((SITE / "site.json").read_text())
    strings = load_strings()
    if releases is None:
        releases = (None if offline else fetch_releases(cfg["repo"])) or fallback_releases(cfg)

    if OUT.exists():
        shutil.rmtree(OUT)
    shutil.copytree(SITE / "static", OUT / "assets")
    shutil.copy(ROOT / "docs" / "screens" / "2-connect-on.png", OUT / "assets" / "og.png")

    fonts = sorted((SITE / "static" / "fonts").glob("Geist-Regular.woff*"))
    if not fonts:
        fail("no web fonts: run tools/site_fonts.py")
    font_ext = fonts[-1].suffix[1:]  # woff2 when both are there

    base = cfg["base_url"].rstrip("/") + "/"
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
            }
            ctx = {
                "lang": lang,
                "root": root,
                "url": base + path,
                "og": base + "assets/og.png",
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
