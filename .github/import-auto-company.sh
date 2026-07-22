#!/usr/bin/env bash
set -Eeuo pipefail
trap 'status=$?; echo "Import failed at line ${LINENO} with status ${status}" >&2; exit "$status"' ERR

: "${SOURCE_REPOSITORY:?SOURCE_REPOSITORY is required}"
: "${SOURCE_URL:?SOURCE_URL is required}"
: "${SOURCE_BRANCH:?SOURCE_BRANCH is required}"
: "${SOURCE_SHA:?SOURCE_SHA is required}"
: "${IMPORT_BRANCH:?IMPORT_BRANCH is required}"

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"

echo "1/8 Prepare independent upstream access"
checkout_auth_header="$(git config --local --get-all http.https://github.com/.extraheader | head -n 1 || true)"
git config --local --unset-all http.https://github.com/.extraheader || true

git remote remove upstream 2>/dev/null || true
git remote add upstream "$SOURCE_URL"

echo "2/8 Fetch public upstream branch"
git fetch --quiet --no-tags --depth=1 upstream "$SOURCE_BRANCH"
fetched_sha="$(git rev-parse FETCH_HEAD)"

if [[ -n "$checkout_auth_header" ]]; then
  git config --local http.https://github.com/.extraheader "$checkout_auth_header"
fi

echo "3/8 Verify pinned upstream commit"
if [[ "$fetched_sha" != "$SOURCE_SHA" ]]; then
  echo "Pinned source commit mismatch: expected=$SOURCE_SHA fetched=$fetched_sha" >&2
  exit 1
fi

source_tree_sha="$(git rev-parse "$SOURCE_SHA^{tree}")"
source_file_count="$(git ls-tree -r --name-only "$SOURCE_SHA" | wc -l | tr -d ' ')"

echo "4/8 Load exact upstream tree"
git checkout --quiet -B "$IMPORT_BRANCH" origin/main
git read-tree --reset -u "$SOURCE_SHA"

if git cat-file -e "$SOURCE_SHA:IMPORT_SOURCE.md" 2>/dev/null; then
  echo "Upstream unexpectedly contains IMPORT_SOURCE.md; choose a non-conflicting provenance path." >&2
  exit 1
fi

echo "5/8 Add import provenance"
cat > IMPORT_SOURCE.md <<EOF
# Import provenance

This repository contains a complete tree import from the upstream project.

- Source repository: https://github.com/${SOURCE_REPOSITORY}
- Source branch: \`${SOURCE_BRANCH}\`
- Source commit: \`${SOURCE_SHA}\`
- Source tree: \`${source_tree_sha}\`
- Imported by: GitHub Actions
- Import date: 2026-07-22

The upstream files, executable modes, documentation, package metadata, attribution, and license declarations are retained unchanged. This provenance file is the only destination-specific addition.
EOF
git add IMPORT_SOURCE.md

echo "6/8 Verify file count and exact source tree SHA"
imported_source_file_count="$(git ls-files | grep -v '^IMPORT_SOURCE.md$' | wc -l | tr -d ' ')"
if [[ "$source_file_count" != "$imported_source_file_count" ]]; then
  echo "Source/imported file-count mismatch: source=$source_file_count imported=$imported_source_file_count" >&2
  exit 1
fi

git rm --cached --quiet IMPORT_SOURCE.md
imported_source_tree_sha="$(git write-tree)"
git add IMPORT_SOURCE.md

if [[ "$source_tree_sha" != "$imported_source_tree_sha" ]]; then
  echo "Source/imported tree mismatch: source=$source_tree_sha imported=$imported_source_tree_sha" >&2
  exit 1
fi

echo "7/8 Commit imported application"
git commit --quiet -m "import: transfer Auto-Company at ${SOURCE_SHA}"

echo "8/8 Push imported branch"
git push --quiet --force origin "$IMPORT_BRANCH"

echo "Imported source commit $SOURCE_SHA"
echo "Verified source tree $source_tree_sha"
echo "Verified tracked source files $source_file_count"
echo "Pushed destination branch $IMPORT_BRANCH"

{
  echo "## Auto-Company import"
  echo "- Upstream commit: \`${SOURCE_SHA}\`"
  echo "- Upstream tree: \`${source_tree_sha}\`"
  echo "- Imported tracked files: ${source_file_count}"
  echo "- Destination branch: \`${IMPORT_BRANCH}\`"
} >> "$GITHUB_STEP_SUMMARY"
