#!/usr/bin/env bash

set -euo pipefail

script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
extractor="$script_directory/extract-release-header.sh"
test_directory=$(mktemp -d)
trap 'rm -rf "$test_directory"' EXIT

changelog="$test_directory/CHANGELOG.md"
actual="$test_directory/actual.md"
expected="$test_directory/expected.md"

cat > "$changelog" <<'EOF'
## Unreleased

* Work in progress that must not leak into a release.

## 2.3.0 (August 7, 2026)

FEATURES:

* Added a new resource.

BUG FIXES:

* Corrected refresh behavior.

## 2.2.0 (July 1, 2026)

* Previous release content that must not be included.
EOF

"$extractor" v2.3.0 "$changelog" "$actual"

cat > "$expected" <<'EOF'
## Release highlights

FEATURES:

* Added a new resource.

BUG FIXES:

* Corrected refresh behavior.
EOF

diff -u "$expected" "$actual"

cat >> "$changelog" <<'EOF'

## 2.4.0-rc.1

* Release candidate notes.
EOF

"$extractor" v2.4.0-rc.1 "$changelog" "$actual"
grep -q 'Release candidate notes' "$actual"

if "$extractor" v9.9.9 "$changelog" "$actual" 2>/dev/null; then
  echo "expected a missing release section to fail" >&2
  exit 1
fi

if "$extractor" release-2.3.0 "$changelog" "$actual" 2>/dev/null; then
  echo "expected a malformed release tag to fail" >&2
  exit 1
fi

cat > "$changelog" <<'EOF'
## 2.3.1


## 2.3.0

* Previous release.
EOF

if "$extractor" v2.3.1 "$changelog" "$actual" 2>/dev/null; then
  echo "expected an empty release section to fail" >&2
  exit 1
fi

echo "extract-release-header tests passed"
