# Android

The Android app is the same core as the desktop one, behind a thin shell.

```
android/                         the shell (Java, no libraries, no Gradle)
  java/dev/blackwall/Core.java   the link to the core: one socket pair, a line of JSON each way
  java/dev/blackwall/Tunnel.java the VpnService: establishes what the core asks for
  java/dev/blackwall/Main.java   the window: switch, applications, servers, settings
  java/dev/blackwall/Boot.java   brings the VPN back after a restart or an update
  res/                           strings (en, ru, zh), theme, icons
  build.sh                       packs the APK with the SDK's tools
src/android/
  lib.zig                        libblackwall.so: one native function, `Core.start(fd)`
  session.zig                    the core's side of the socket; runs and is tested on any POSIX system
```

## Who does what

The shell owns what only Android can give: the VPN consent, the TUN descriptor, the list
of installed applications, the owner of a connection, downloads through the system's
trust store. The core owns everything else: the configuration, subscriptions and keys,
the routes, the data plane. The shell is never given a link or a subscription address
back; it shows names and numbers.

The native interface is one function that takes a descriptor. Everything else is JSON
over that socket (the messages are listed at the top of `src/android/session.zig`), so
the core's side is tested on the build machine by `zig build test`.

## How routes map onto Android

Android's own per-application VPN does most of the work, at no cost to the tunnel:

| Route | What happens |
|---|---|
| Direct | The application is left out of the VPN (`addDisallowedApplication`). |
| Through VPN only, default | The application's traffic enters the TUN and goes to the server. |
| No network | The traffic enters the TUN, the core finds the owner of each flow (`getConnectionOwnerUid`) and refuses it. |
| After Disconnect, with "Hold apps" on | The VPN stays up for the applications that may only use the VPN (`addAllowedApplication`), and the core refuses everything there. The rest of the device is outside the VPN. |

The app itself is always outside its own VPN, which is how the core's connections reach
the servers; no socket needs to be "protected" one by one. The owner of a flow is asked
for only while some rule differs inside the tunnel.

A change that the VPN itself must reflect (an application becomes Direct, IPv6 mode)
establishes a new interface, which Android swaps in without a gap; any other change is
only a new routing table for the core.

IPv6: "Block" adds no IPv6 address, so Android refuses that family for the applications
in the VPN; "Tunnel" routes `::/0` into the TUN; "System" lets it pass outside.

## The notification

While the VPN is up the service shows one notification: the server in use, the time
connected (a system chronometer, nothing is redrawn for it), the download and upload
speed, and a Disconnect button; while applications are only held it says so and offers
Connect. It is updated once a second and only while the screen is on.

On Android 16 the same notification asks to be a Live Update
(`android.requestPromotedOngoing`, permission `POST_PROMOTED_NOTIFICATIONS`): the system
then shows it as a chip in the status bar, on the lock screen and on the always-on
display. The chip carries the download speed while something is moving and the time
connected otherwise. Whether an app's Live Updates are shown is the user's choice in the
system's notification settings.

## Staying on

- The switch and the hold are restored after the device restarts and after the app is
  updated (`Boot`), and when Android restarts the service.
- The kill switch is Android's own: Settings, Network, VPN, BLACKWALL, "Always-on VPN"
  and "Block connections without VPN". The app's settings screen opens that page. With
  the block on, Android also cuts off the applications set to Direct.
- If another VPN takes over, or the VPN is switched off in the system, nothing can be
  held any more and the app shows itself as off.

## Building

```sh
export ANDROID_HOME=~/Library/Android/sdk
export JAVA_HOME=/path/to/jdk-17
zig build android -Doptimize=ReleaseSafe
adb install -r zig-out/package/BLACKWALL-<version>-android.apk
adb logcat -s blackwall        # the core's log
```

`ANDROID_NDK_HOME` picks an NDK other than the one named in `build.zig`. The minimum is
Android 10 (API 29), the first release that tells a VPN who owns a connection.

Google Play takes an App Bundle instead of an APK:

```sh
zig build android-bundle -Doptimize=ReleaseSafe    # zig-out/package/BLACKWALL-<version>-android.aab
```

That needs Google's [bundletool](https://github.com/google/bundletool/releases) jar at
`$ANDROID_HOME/bundletool/bundletool.jar` (or wherever `BLACKWALL_BUNDLETOOL` points). The
store page's texts and pictures are in [docs/play](play/); the feature graphic is drawn by
`tools/play_graphics.swift` from the icon's own art.

## Signing

An update installs only over an app signed with the same key, so releases use one
keystore for good:

- Locally: `BLACKWALL_ANDROID_KEYSTORE` (path), `BLACKWALL_ANDROID_KEYSTORE_PASS` and
  `BLACKWALL_ANDROID_KEYSTORE_ALIAS`. Without them the SDK's debug key
  (`~/.android/debug.keystore`) signs the build, which is fine for trying it out.
- In the release workflow: the same three names as repository secrets, the keystore as
  base64 (`base64 -i release.jks | pbcopy`). Without them a release is published without
  the Android package.

Keep the keystore and its password somewhere safe: losing them means every user has to
uninstall before the next version installs.

On Google Play the app is signed by a key Google keeps (Play App Signing); the keystore
above only signs what is uploaded. So the app from Play and the APK from the releases
page carry different signatures, and one does not update the other.

## Google Play

Every release goes to Google Play by itself: the `android` job of `release.yml` builds the
App Bundle beside the APK (bundletool is downloaded at a pinned version and checksum), and
the `play` job hands it to the Android Publisher API (`tools/play_upload.py`, standard
library and openssl): one edit uploads the bundle, gives the track a release of it and
commits. The GitHub releases do not wait for it; a Play failure fails only its own job.

- **Track**: `PLAY_TRACK` at the top of `release.yml`, now `alpha` ("Closed testing -
  Alpha"). `production` once Play has opened production for the account.
- **Release notes**: the first section's bullet points of `docs/releases/<version>/en.md`
  and `ru.md` → en-US and ru-RU, plain text, as many whole points as fit Play's 500
  characters. A `docs/releases/<version>/play/<en|ru>.txt` replaces them when present. A
  language the store listing does not have is left out.
- **versionCode** = major·10000 + minor·100 + patch, from `build.zig.zon`. Play refuses a
  code it has seen, so re-running a release's Play job fails: upload the bundle by hand, or
  make a new version.
- While Play still counts the app as a draft, the release is saved as a draft (a warning
  says so) and is rolled out in Play Console. If Play will not send changes for review on
  its own, they are committed without it and wait for **Send for review**.

One-time setup (done for `dev.blackwall`: project `blackwall-play`, account
`play-release@blackwall-play.iam.gserviceaccount.com`): a Google Cloud project with the **Google Play
Android Developer API** on; a service account in it, no Cloud roles; in Play Console →
**Users and permissions**, that account's email invited with release rights for BLACKWALL
only. Its JSON key (Cloud Console → IAM → Service accounts → the account → Keys → Add key →
JSON) goes into the repository secret:

```sh
gh secret set PLAY_SERVICE_ACCOUNT_JSON --repo ANODs/blackwall < key.json
rm key.json
```

Without that secret the `play` job only warns. A leaked key can push releases of this app
only: delete it under Keys and make a new one.

## Not there yet

- Automatic updates (Android does not let an app replace itself silently).
- A pinned server per application in the interface (the core supports it).
- A Quick Settings tile.
- 32-bit devices.
