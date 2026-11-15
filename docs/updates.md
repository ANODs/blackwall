# Automatic updates

BLACKWALL updates itself from this repository's GitHub Releases. New versions download,
check out and install on their own; the user's settings, subscriptions and rules are kept.
**Settings → About → Auto-update** turns it off (on by default).

Code: `src/core/update.zig` (selection, signatures, install steps), `src/app.zig` (when it
runs), `src/tools/sign.zig` (the signing tool), `.github/workflows/release.yml` (signing in CI).

## One-time setup: the signing key

Every release file is signed with an Ed25519 key. The app trusts only the public key that
was built into it, so whoever holds the secret key decides what the apps install.

1. Generate a key pair on a trusted machine:

   ```sh
   zig build sign
   zig-out/bin/blackwall-sign keygen
   ```

   It prints a **secret seed** and a **public key**, both base64.

2. In the GitHub repository, **Settings → Secrets and variables → Actions**:
   - secret **`BLACKWALL_UPDATE_KEY`** = the secret seed;
   - variable (tab "Variables") **`BLACKWALL_UPDATE_PUBKEY`** = the public key (a secret of
     the same name works too).

3. Keep a copy of the seed offline (password manager). Do not commit it anywhere.

If either is missing, releases still build and publish, but the apps are built without the
updater (the workflow prints a warning), and no `.sig` files are made.

**Losing the seed** means existing installs can no longer be updated automatically: a new
key needs a new build, which users install by hand once. **Leaking the seed** lets anyone
who can also publish to this repository's releases ship code to every install: rotate the
key (new pair, new manual release) and revoke whoever had access.

## How a release gets signed

`release.yml`, on a `vX.Y.Z` tag:

1. **Build**: each language × platform is packaged with
   `-Dupdate-repo=<owner/name> -Dupdate-pubkey=<public key>`. These build options
   (`build.zig`) compile the updater in; a build without `-Dupdate-repo` (every local
   build) has no updater and no Settings row.
2. **Publish**: per language, `blackwall-sign sign` writes `<file>.sig` next to every file
   (base64 of the Ed25519 signature over the file's bytes, seed from the secret), then
   `blackwall-sign verify` checks all of them against the public key variable, so a
   mismatched secret/variable pair fails the release instead of shipping files no client
   accepts. The `.sig` files are uploaded with the release.

Files per release `v<version>-<lang>`:

| Platform | Release file | Signature |
|---|---|---|
| macOS arm64 | `BLACKWALL-<version>-<lang>-macos-arm64.zip` (BLACKWALL.app) | `….zip.sig` |
| Windows x86_64 | `BLACKWALL-<version>-<lang>-windows-x86_64.exe` | `….exe.sig` |
| Linux x86_64 | `BLACKWALL-<version>-<lang>-linux-x86_64.tar.gz` | `….tar.gz.sig` |

Signing by hand (for example to re-sign a release):

```sh
BLACKWALL_UPDATE_KEY='<seed>' zig-out/bin/blackwall-sign sign BLACKWALL-0.2.0-ru-macos-arm64.zip
BLACKWALL_UPDATE_PUBKEY='<public key>' zig-out/bin/blackwall-sign verify BLACKWALL-0.2.0-ru-macos-arm64.zip
```

## What the app does

When auto-update is on: the first check runs 15 s after start, then every 6 hours, on a
background thread. Nothing of it blocks the window.

1. **Check**: `GET https://api.github.com/repos/<repo>/releases?per_page=20` with the
   User-Agent `BLACKWALL-updater` and nothing else about the user or the device. From the
   answer it takes the newest release that is not a draft or a pre-release, whose tag is
   `v<X.Y.Z>-<our language>` and that has both our platform's file and its `.sig`. It is
   used only when its version is newer than ours (semantic order: 0.10.0 > 0.9.9).
2. **Download** the `.sig` and the file from `github.com/<repo>/releases/download/<tag>/`
   (at most 256 MiB).
3. **Verify** the signature with the built-in public key. A bad or missing signature
   stops here: nothing has been written to disk yet.
4. **Unpack** next to the installed app into a hidden staging folder
   (`.BLACKWALL.app.staging`): macOS with `/usr/bin/ditto -x -k`, Linux with `tar -xzf`,
   Windows needs nothing. Then it checks that the unpacked app really is the expected
   version: the macOS `Info.plist` version, and on every platform a version stamp
   (`BLACKWALL-VERSION=<version>;`) inside the executable. An older release that is
   validly signed therefore cannot be installed as a newer one.
5. **Install**, on the window thread, as soon as no dialog or menu is open:
   - the config is saved and the local proxy stopped (its port is free for the new copy);
   - a marker `.BLACKWALL.app.update` records `pending <version>` (written to
     `.BLACKWALL.app.update.new` and renamed, so it is never half-written);
   - `BLACKWALL.app` → `BLACKWALL.app.previous`, staged app → `BLACKWALL.app`
     (two renames in one folder; if the second fails, the first is undone and the marker
     removed);
   - the new version is started (`open -n` on macOS, the executable itself elsewhere)
     and the old process exits.

   On Windows and Linux the same happens with the executable file instead of the bundle
   (`blackwall.exe` → `blackwall.exe.previous`, …). Windows allows renaming a running
   executable, so no helper process is needed.

Network or GitHub errors are only logged and retried at the next check. A failed install
(unpacking, version check, renames, for example no write access to the folder) shows one
short message and leaves the current version as it was.

The updater only ever writes inside the folder that contains the app, and only these
names: `<app>.previous`, `<app>.failed`, `.<app>.staging`, `.<app>.update`, `.<app>.update.new`. User data
(`~/Library/Application Support/BLACKWALL`, `%APPDATA%\BLACKWALL`, `~/.config/blackwall`)
is never touched.

When the app is not installed from a release, nothing is installed and the log says
"not installed from a release": on macOS this is any executable outside an `.app` bundle,
and a bundle that macOS runs from a randomized read-only location (App Translocation,
when a downloaded app is opened before being moved to Applications).

## Rollback

At every start, as the very first step (before the config is loaded, so a new version that
crashes while loading it is still caught), the app reads the marker next to itself:

| Marker | Meaning | Action |
|---|---|---|
| none | normal start | remove leftovers (`.previous`, `.failed`, staging) |
| `pending V` | first start of the freshly installed V | becomes `launched V`; once the app has run for 3 s (or quits cleanly), `.previous` and the marker are removed |
| `launched V` | V was started but never got that far (crashed, hung, was killed) | `BLACKWALL.app` → `.failed`, `.previous` → `BLACKWALL.app`, marker becomes `rejected V`, the old version is started and this process exits |
| `rejected V` | V was rolled back | V and older are never installed again; a newer release is |

## Developing and testing

- Local builds have no updater. To try one: `zig build -Dupdate-repo=<owner/name> -Dupdate-pubkey=<public key>`.
- `zig build test` covers version order, tag parsing, asset names, signature checks
  (valid, tampered, wrong key), parsing a sample releases response, and the install steps
  on fake installs in a temporary folder: a fake `BLACKWALL.app` zipped with `ditto` is
  unpacked, swapped in, rolled back and confirmed (macOS), and the same for a single
  executable (all platforms).
