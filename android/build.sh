#!/bin/sh
# Packs the Android app without Gradle, with the SDK's own tools:
#   build.sh <sdk> <version> <out.apk | out.aab> <abi>=<libblackwall.so>...
# Called by `zig build android` (an APK, to install directly) and by
# `zig build android-bundle` (an App Bundle, the form Google Play takes);
# build.zig builds the libraries.
#
# Signing: the key in BLACKWALL_ANDROID_KEYSTORE (with _PASS and _ALIAS)
# when set, as a release must be; otherwise the SDK's usual debug key
# (~/.android/debug.keystore, made on first use). An update installs only
# over an app signed with the same key. A bundle is signed with the same
# key, which Google Play knows as the upload key.
#
# A bundle also needs Google's bundletool: BLACKWALL_BUNDLETOOL names the
# jar (default: <sdk>/bundletool/bundletool.jar).
set -eu

# the build passes paths relative to where it runs; the packing happens elsewhere
abs() { case $1 in /*) echo "$1" ;; *) echo "$PWD/$1" ;; esac; }

SDK=$1
VERSION=$2
OUT=$(abs "$3")
shift 3
START=$PWD
HERE=$(cd "$(dirname "$0")" && pwd)

newest() { ls "$1" | sort -t. -k1,1n -k2,2n -k3,3n | tail -1; }
BT=$SDK/build-tools/$(newest "$SDK/build-tools")
PLATFORM=$SDK/platforms/$(ls "$SDK/platforms" | sort -t- -k2,2n | tail -1)/android.jar
[ -x "$BT/aapt2" ] || { echo "no build-tools in $SDK" >&2; exit 1; }
[ -f "$PLATFORM" ] || { echo "no platform in $SDK" >&2; exit 1; }
if [ -n "${JAVA_HOME:-}" ]; then PATH=$JAVA_HOME/bin:$PATH; fi
command -v javac >/dev/null || { echo "no JDK: set JAVA_HOME" >&2; exit 1; }

case $OUT in
    *.aab)
        BUNDLE=1
        TOOL=${BLACKWALL_BUNDLETOOL:-$SDK/bundletool/bundletool.jar}
        [ -f "$TOOL" ] || { echo "no bundletool at $TOOL (github.com/google/bundletool/releases)" >&2; exit 1; }
        ;;
    *) BUNDLE=0 ;;
esac

# 0.1.1 -> 101: grows with every release, as Android requires
CODE=$(echo "$VERSION" | awk -F. '{ print $1 * 10000 + $2 * 100 + $3 }')

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

# a bundle carries the manifest and the resource table in protobuf form
FORMAT=
[ "$BUNDLE" = 1 ] && FORMAT=--proto-format
"$BT/aapt2" compile --dir "$HERE/res" -o "$W/res.zip"
"$BT/aapt2" link $FORMAT -o "$W/app.apk" -I "$PLATFORM" \
    --manifest "$HERE/AndroidManifest.xml" --java "$W/gen" \
    --min-sdk-version 29 --target-sdk-version 36 \
    --version-name "$VERSION" --version-code "$CODE" \
    "$W/res.zip"

mkdir "$W/classes"
find "$HERE/java" "$W/gen" -name '*.java' > "$W/sources"
javac -Xlint:-options --release 11 -classpath "$PLATFORM" -d "$W/classes" @"$W/sources"
find "$W/classes" -name '*.class' > "$W/class-files"
"$BT/d8" --release --min-api 29 --lib "$PLATFORM" --output "$W" @"$W/class-files"

KS=${BLACKWALL_ANDROID_KEYSTORE:-}
if [ -n "$KS" ]; then
    KS=$(abs "$KS")
    PASS=${BLACKWALL_ANDROID_KEYSTORE_PASS:?}
    ALIAS=${BLACKWALL_ANDROID_KEYSTORE_ALIAS:?}
else
    KS=$HOME/.android/debug.keystore
    PASS=android
    ALIAS=androiddebugkey
    if [ ! -f "$KS" ]; then
        mkdir -p "$HOME/.android"
        keytool -genkeypair -keystore "$KS" -storepass "$PASS" -keypass "$PASS" -alias "$ALIAS" \
            -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Android Debug,O=Android,C=US" >/dev/null 2>&1
    fi
fi

cd "$W"
if [ "$BUNDLE" = 0 ]; then
    zip -q app.apk classes.dex
    for pair in "$@"; do
        abi=${pair%%=*}
        mkdir -p "lib/$abi"
        cp "$(cd "$START" && abs "${pair#*=}")" "lib/$abi/libblackwall.so"
        # stored, not compressed: the system maps it straight from the APK
        zip -q -0 app.apk "lib/$abi/libblackwall.so"
    done
    "$BT/zipalign" -P 16 -f 4 app.apk aligned.apk
    # the password through the environment, not the command line, which every
    # process on the machine can read
    BW_KS_PASS="$PASS" "$BT/apksigner" sign --ks "$KS" --ks-pass env:BW_KS_PASS --ks-key-alias "$ALIAS" --out "$OUT" aligned.apk
else
    # the one module of the bundle, laid out as bundletool expects it
    mkdir -p base/manifest base/dex
    (cd base && unzip -q ../app.apk)
    mv base/AndroidManifest.xml base/manifest/
    cp classes.dex base/dex/
    for pair in "$@"; do
        abi=${pair%%=*}
        mkdir -p "base/lib/$abi"
        cp "$(cd "$START" && abs "${pair#*=}")" "base/lib/$abi/libblackwall.so"
    done
    (cd base && zip -q -r ../base.zip .)
    # libraries stay uncompressed in the APKs Play makes, aligned for 16 KB pages
    cat > config.json <<'EOF'
{ "optimizations": { "uncompressNativeLibraries": { "enabled": true, "alignment": "PAGE_ALIGNMENT_16K" } } }
EOF
    java -jar "$TOOL" build-bundle --modules=base.zip --config=config.json --output=app.aab
    BW_KS_PASS="$PASS" jarsigner -keystore "$KS" -storepass:env BW_KS_PASS -keypass:env BW_KS_PASS \
        -sigalg SHA256withRSA -digestalg SHA-256 app.aab "$ALIAS" >/dev/null
    cp app.aab "$OUT"
fi
