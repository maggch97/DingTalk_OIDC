#!/usr/bin/env bash
set -euo pipefail

# Determine next semantic version based on conventional commits since last tag.
# Tags expected format: vMAJOR.MINOR.PATCH
# Bump rules:
#   - commit with BREAKING CHANGE: or ! after type -> major
#   - feat: -> minor (unless major already)
#   - fix: / perf: / refactor: / chore: / docs: / test: -> patch (if no higher bump)
# If no conventional commits found -> exit with code 2 (no bump).
# Initial version if no prior tag: v0.1.0 (treat first feat as 0.1.0)

LATEST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || true)
if [[ -z "$LATEST_TAG" ]]; then
  BASE_VERSION="v0.0.0"
  RANGE="HEAD"
else
  BASE_VERSION="$LATEST_TAG"
  RANGE="$LATEST_TAG..HEAD"
fi

COMMITS=$(git log --format=%s %s -- $RANGE || true)
if [[ -z "$COMMITS" ]]; then
  echo "No new commits since $BASE_VERSION" >&2
  exit 2
fi

BUMP=""
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  if grep -qiE 'BREAKING CHANGE:' <<<"$line"; then BUMP="major"; break; fi
  if [[ $line =~ ^([a-zA-Z]+)(\([^)]+\))?!: ]]; then BUMP="major"; break; fi
  if [[ $line =~ ^feat(\(|!|: ) ]]; then [[ "$BUMP" != "major" ]] && BUMP="minor"; fi
  if [[ $line =~ ^(fix|perf|refactor|chore|docs|test)(\(|: ) ]]; then [[ -z "$BUMP" ]] && BUMP="patch"; fi
done <<<"$COMMITS"

if [[ -z "$BUMP" ]]; then
  echo "No conventional commit keywords detected; skipping bump" >&2
  exit 2
fi

parse_version() { # v1.2.3 -> 1 2 3
  local v=${1#v}; IFS='.' read -r MAJOR MINOR PATCH <<<"$v"; echo "$MAJOR $MINOR $PATCH"
}
read MAJOR MINOR PATCH < <(parse_version "$BASE_VERSION")

case "$BUMP" in
  major)
    ((MAJOR++)); MINOR=0; PATCH=0 ;;
  minor)
    ((MINOR++)); PATCH=0 ;;
  patch)
    ((PATCH++)) ;;
  *) echo "Unknown bump $BUMP" >&2; exit 1 ;;
 esac

NEXT="v${MAJOR}.${MINOR}.${PATCH}"

echo "$NEXT" # stdout prints next version
