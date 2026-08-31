#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "usage: $0 <vMAJOR.MINOR.PATCH[-PRERELEASE]> <changelog> <output>" >&2
}

if [[ $# -ne 3 ]]; then
  usage
  exit 2
fi

release_tag=$1
changelog_file=$2
output_file=$3

if [[ ! $release_tag =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]]; then
  echo "release notes: tag '$release_tag' is not a supported semantic version tag" >&2
  exit 1
fi

if [[ ! -f $changelog_file ]]; then
  echo "release notes: changelog '$changelog_file' does not exist" >&2
  exit 1
fi

output_directory=$(dirname -- "$output_file")
if [[ ! -d $output_directory ]]; then
  echo "release notes: output directory '$output_directory' does not exist" >&2
  exit 1
fi

version=${release_tag#v}
curated_notes=$(mktemp)
trap 'rm -f "$curated_notes"' EXIT

if ! awk -v version="$version" '
  function is_target_heading(line, expected) {
    expected = "## " version
    return line == expected || index(line, expected " (") == 1
  }

  {
    sub(/\r$/, "")

    if (!found && is_target_heading($0)) {
      found = 1
      next
    }

    if (found && /^##[[:space:]]/) {
      done = 1
    }

    if (found && !done) {
      lines[++count] = $0
    }
  }

  END {
    if (!found) {
      exit 3
    }

    first = 1
    while (first <= count && lines[first] ~ /^[[:space:]]*$/) {
      first++
    }

    last = count
    while (last >= first && lines[last] ~ /^[[:space:]]*$/) {
      last--
    }

    for (i = first; i <= last; i++) {
      print lines[i]
    }
  }
' "$changelog_file" > "$curated_notes"; then
  echo "release notes: CHANGELOG.md has no '## $version' release section" >&2
  exit 1
fi

if ! grep -q '[^[:space:]]' "$curated_notes"; then
  echo "release notes: CHANGELOG.md section '## $version' is empty" >&2
  exit 1
fi

{
  printf '%s\n\n' '## Release highlights'
  cat "$curated_notes"
} > "$output_file"

echo "release notes: prepared curated header for $release_tag at $output_file"
