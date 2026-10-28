#!/usr/bin/env bash
#
# Pull the latest changes from the upstream KeePassXC repository into the
# current branch and rebuild.
#
# Usage: utils/sync-upstream.sh [--rebase] [--no-build] [--test]
#
#   --rebase    Rebase the current branch onto upstream instead of merging
#               (rewrites history; the fork branch then needs a force push)
#   --no-build  Only update the sources, do not build
#   --test      Run the test suite after building
#
# Environment:
#   UPSTREAM_REMOTE  Remote of the original repository (default: origin)
#   UPSTREAM_BRANCH  Branch to pull from (default: develop)
#   BUILD_DIR        Build directory (default: build-kps)
#   QT_DIR           Qt installation used when configuring a fresh build
#                    directory (default: ~/Qt/6.8.3/macos)

set -euo pipefail

UPSTREAM_REMOTE="${UPSTREAM_REMOTE:-origin}"
UPSTREAM_BRANCH="${UPSTREAM_BRANCH:-develop}"
BUILD_DIR="${BUILD_DIR:-build-kps}"
QT_DIR="${QT_DIR:-$HOME/Qt/6.8.3/macos}"

MODE=merge
BUILD=1
TEST=0

for arg in "$@"; do
    case "$arg" in
        --rebase) MODE=rebase ;;
        --no-build) BUILD=0 ;;
        --test) TEST=1 ;;
        -h|--help) sed -n '3,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $arg" >&2; exit 1 ;;
    esac
done

cd "$(git rev-parse --show-toplevel)"

if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
    echo "Working tree has uncommitted changes; commit or stash them first." >&2
    exit 1
fi

CURRENT_BRANCH="$(git symbolic-ref --short HEAD)"
UPSTREAM_REF="$UPSTREAM_REMOTE/$UPSTREAM_BRANCH"

echo "==> Fetching $UPSTREAM_REMOTE"
git fetch --prune "$UPSTREAM_REMOTE"

if [[ "$CURRENT_BRANCH" == "$UPSTREAM_BRANCH" ]]; then
    echo "==> Fast-forwarding $CURRENT_BRANCH"
    git merge --ff-only "$UPSTREAM_REF"
else
    # Keep the local copy of the upstream branch current as well
    if git show-ref --verify --quiet "refs/heads/$UPSTREAM_BRANCH"; then
        git fetch . "$UPSTREAM_REF:$UPSTREAM_BRANCH" 2>/dev/null \
            || echo "    (local $UPSTREAM_BRANCH has diverged from $UPSTREAM_REF; left untouched)"
    fi

    if git merge-base --is-ancestor "$UPSTREAM_REF" HEAD; then
        echo "==> $CURRENT_BRANCH already contains $UPSTREAM_REF"
    elif [[ "$MODE" == rebase ]]; then
        echo "==> Rebasing $CURRENT_BRANCH onto $UPSTREAM_REF"
        git rebase "$UPSTREAM_REF"
    else
        echo "==> Merging $UPSTREAM_REF into $CURRENT_BRANCH"
        git merge --no-edit "$UPSTREAM_REF"
    fi
fi

[[ "$BUILD" == 1 ]] || exit 0

# A global CPATH (e.g. /opt/homebrew/include) is searched before the Qt 6
# include paths and pulls in Homebrew's Qt 5 headers instead
unset CPATH CPLUS_INCLUDE_PATH

if [[ ! -f "$BUILD_DIR/CMakeCache.txt" ]]; then
    echo "==> Configuring $BUILD_DIR"
    PREFIX_PATH="$QT_DIR"
    for pkg in botan minizip qrencode zlib readline; do
        PREFIX_PATH+=";$(brew --prefix "$pkg")"
    done
    cmake -S . -B "$BUILD_DIR" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_PREFIX_PATH="$PREFIX_PATH" \
        -DWITH_XC_ALL=ON \
        -DWITH_XC_DOCS=OFF
fi

echo "==> Building in $BUILD_DIR"
cmake --build "$BUILD_DIR" --parallel "$(sysctl -n hw.ncpu)"

if [[ "$TEST" == 1 ]]; then
    echo "==> Running tests"
    ctest --test-dir "$BUILD_DIR" --output-on-failure --parallel "$(sysctl -n hw.ncpu)"
fi

echo "==> Done: $(git log -1 --format='%h %s')"
