#!/usr/bin/env bash
#
# Build an installable, ad-hoc signed KeePassXC.app and package it as a DMG,
# the same way the macOS job in .github/workflows/kps-release.yml does.
#
# Usage: utils/make-dmg.sh
#
# Environment:
#   BUILD_DIR  Configured build directory (default: build-kps)
#
# The DMG is written to $BUILD_DIR/KeePassXC-<commit>-<arch>.dmg

set -euo pipefail

BUILD_DIR="${BUILD_DIR:-build-kps}"

cd "$(git rev-parse --show-toplevel)"

if [[ ! -f "$BUILD_DIR/CMakeCache.txt" ]]; then
    echo "$BUILD_DIR is not configured; run utils/sync-upstream.sh first." >&2
    exit 1
fi

# A global CPATH (e.g. /opt/homebrew/include) is searched before the Qt 6
# include paths and pulls in Homebrew's Qt 5 headers instead
unset CPATH CPLUS_INCLUDE_PATH

VERSION="$(git rev-parse --short HEAD)"
ARCH="$(uname -m)"
STAGING="$BUILD_DIR/staging"
APP="$STAGING/KeePassXC.app"
DMG="$BUILD_DIR/KeePassXC-$VERSION-$ARCH.dmg"

echo "==> Building in $BUILD_DIR"
cmake --build "$BUILD_DIR" --parallel "$(sysctl -n hw.ncpu)"

echo "==> Installing into $STAGING"
rm -rf "$STAGING"
cmake --install "$BUILD_DIR" --prefix "$PWD/$STAGING"

echo "==> Signing $APP (ad-hoc)"
# Belongs to the official signing identity
rm -f "$APP/Contents/embedded.provisionprofile"
codesign --force --deep --sign - "$APP"
codesign --verify --deep --strict "$APP"

echo "==> Creating $DMG"
ln -s /Applications "$STAGING/Applications"
hdiutil create -volname KeePassXC -srcfolder "$STAGING" -fs HFS+ -format UDBZ -ov "$DMG"
shasum -a 256 "$DMG" > "$DMG.sha256"

echo "==> Done: $DMG"
