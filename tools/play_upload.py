#!/usr/bin/env python3
"""Upload an App Bundle to Google Play (the release workflow's "Google Play" job).

    play_upload.py <app.aab> <version> <track>

One edit of the Android Publisher API: upload the bundle, give the track a release of it
with the notes of docs/releases/<version>/{en,ru}.md, commit. The service account's JSON key
comes in PLAY_SERVICE_ACCOUNT_JSON; it is never written anywhere but a 0600 temp file that
openssl signs the token request with. Standard library and openssl only. See docs/android.md.
"""
import base64
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

PACKAGE = "dev.blackwall"
API = f"https://androidpublisher.googleapis.com/androidpublisher/v3/applications/{PACKAGE}"
UPLOAD = f"https://androidpublisher.googleapis.com/upload/androidpublisher/v3/applications/{PACKAGE}"
# docs/releases/<version>/<file> → the Play language it is shown in
NOTES = {"en": "en-US", "ru": "ru-RU"}
NOTES_MAX = 500  # Play's limit per language


class ApiError(Exception):
    pass


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def access_token(key: dict) -> str:
    now = int(time.time())
    header = b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    claims = b64url(json.dumps({
        "iss": key["client_email"],
        "scope": "https://www.googleapis.com/auth/androidpublisher",
        "aud": key["token_uri"],
        "iat": now,
        "exp": now + 3600,
    }).encode())
    signing_input = f"{header}.{claims}".encode()
    fd, pem = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(key["private_key"])
        sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", pem],
                             input=signing_input, capture_output=True, check=True).stdout
    finally:
        os.remove(pem)
    body = urllib.parse.urlencode({
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": f"{header}.{claims}.{b64url(sig)}",
    }).encode()
    return call("POST", key["token_uri"], body, "application/x-www-form-urlencoded")["access_token"]


def call(method, url, body=None, content_type="application/json", token=None):
    req = urllib.request.Request(url, data=body, method=method)
    if body is not None:
        req.add_header("Content-Type", content_type)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=600) as r:
            data = r.read()
    except urllib.error.HTTPError as e:
        raise ApiError(f"{method} {url.split('?')[0]}: {e.code} {e.read().decode(errors='replace')}") from None
    return json.loads(data) if data else {}


def notes_text(path: pathlib.Path) -> str:
    """The first section's bullet points of a release's notes, as plain text that fits Play."""
    lines, in_section = [], False
    for line in path.read_text().splitlines():
        if line.startswith("### "):
            if in_section:
                break
            in_section = True
        elif in_section and line.startswith("- "):
            lines.append("• " + line[2:].replace("`", "").replace("**", ""))
    text = ""
    for line in lines:
        candidate = f"{text}\n{line}" if text else line
        if len(candidate) > NOTES_MAX:
            break
        text = candidate
    if not text and lines:
        text = lines[0][:NOTES_MAX - 1] + "…"
    return text


def release_notes(version: str) -> list:
    out = []
    for name, lang in NOTES.items():
        # docs/releases/<version>/play/<lang>.txt, when present, is taken as it is
        own = pathlib.Path(f"docs/releases/{version}/play/{name}.txt")
        text = own.read_text().strip()[:NOTES_MAX] if own.exists() else notes_text(pathlib.Path(f"docs/releases/{version}/{name}.md"))
        if text:
            out.append({"language": lang, "text": text})
    return out


def main():
    aab, version, track = sys.argv[1:4]
    key = json.loads(os.environ["PLAY_SERVICE_ACCOUNT_JSON"])
    token = access_token(key)

    edit = call("POST", f"{API}/edits", b"{}", token=token)["id"]
    print(f"edit {edit}")
    with open(aab, "rb") as f:
        bundle = call("POST", f"{UPLOAD}/edits/{edit}/bundles?uploadType=media", f.read(),
                      "application/octet-stream", token)
    code = str(bundle["versionCode"])
    print(f"uploaded versionCode {code}")

    # notes only for the languages the store listing has, which Play would refuse otherwise
    listed = {l["language"] for l in call("GET", f"{API}/edits/{edit}/listings", token=token).get("listings", [])}
    notes = [n for n in release_notes(version) if n["language"] in listed]

    def assign(status):
        release = {"name": version, "versionCodes": [code], "status": status}
        if notes:
            release["releaseNotes"] = notes
        call("PUT", f"{API}/edits/{edit}/tracks/{track}",
             json.dumps({"track": track, "releases": [release]}).encode(), token=token)

    status = os.environ.get("PLAY_RELEASE_STATUS", "completed")
    try:
        assign(status)
    except ApiError as e:
        if "draft app" not in str(e) or status == "draft":
            raise
        # an app that was never published takes only draft releases
        print("::warning::the app is still a draft on Google Play: the release is saved as a draft, roll it out in Play Console")
        assign("draft")
    try:
        call("POST", f"{API}/edits/{edit}:commit", token=token)
    except ApiError as e:
        if "changesNotSentForReview" in str(e):
            print("::warning::Google Play would not send the changes for review itself: press 'Send for review' in Play Console")
            call("POST", f"{API}/edits/{edit}:commit?changesNotSentForReview=true", token=token)
        else:
            raise
    print(f"versionCode {code} ({version}) is on the {track} track, notes: {', '.join(n['language'] for n in notes) or 'none'}")


if __name__ == "__main__":
    try:
        main()
    except (ApiError, KeyError, subprocess.CalledProcessError) as e:
        print(f"::error::Google Play: {e}")
        sys.exit(1)
