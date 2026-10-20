#!/bin/bash
# Print the review-gate fingerprint for a checkout's pending changes.
#
# Both sides of the code-review gate MUST derive their hash from here —
# githooks/pre-commit (which compares) and .claude/hooks/mark-reviewed.sh
# (which records). They used to inline the same pipeline separately, which is
# how they drifted into the bug below; keeping one implementation means they
# cannot disagree again.
#
# WHAT WENT WRONG (fixed 2026-09-26)
# The old fingerprint was:
#
#     (git diff HEAD; git ls-files --others --exclude-standard) | shasum
#
# which mixes two different REPRESENTATIONS of a file. `git diff HEAD` emits a
# file's full content as +/- lines, while `ls-files --others` emits only its
# path. An untracked file therefore contributed its NAME before `git add` and
# its entire CONTENT afterwards — so merely staging a reviewed change moved the
# hash and the hook refused the commit with "no /code-review approval recorded",
# even though not one byte had changed. That is the normal order of work
# (review, then stage, then commit), so the gate mis-fired on any packet
# introducing new files and trained people to reach for --no-verify, which
# defeats the gate entirely.
#
# THE FIX
# Hash the WORKING TREE, which is what actually gets reviewed, and describe
# every path the same way no matter what the index happens to hold:
#
#   * `git diff HEAD --name-only` lists tracked paths that differ from HEAD.
#     It compares the working tree to HEAD and ignores the index, so a given
#     edit reads identically whether or not it has been staged.
#   * `ls-files --others --exclude-standard` adds untracked, non-ignored paths.
#   * Each surviving path contributes `<blob-hash> <path>`, computed from the
#     file on disk by `git hash-object`. Content, not a diff rendering — so
#     staging cannot change it.
#   * A path that is gone from disk (a deletion, staged or not) contributes
#     `deleted <path>`, so removing a file still invalidates a stale approval.
#
# Scope is deliberately unchanged from the old pipeline: both staged and
# unstaged edits count, and ignored files never do. This fixes WHEN the hash
# moves, not WHAT it covers.
#
# NUL-delimited throughout, so a path containing a space, a newline or a
# non-ASCII byte is handled exactly like any other (plain `--name-only` would
# also quote such a path, making the hash depend on core.quotePath). Output is
# sorted so the order git happens to list paths in cannot move the hash.
#
# Usage: review-hash.sh [repo_root]   (defaults to the enclosing checkout)
set -u

root=${1:-$(git rev-parse --show-toplevel)} || exit 1

{
    git -C "$root" diff HEAD --name-only -z
    git -C "$root" ls-files --others --exclude-standard -z
} | sort -zu | {
    while IFS= read -r -d '' path; do
        if [ -e "$root/$path" ] || [ -L "$root/$path" ]; then
            blob=$(git -C "$root" hash-object -- "$root/$path" 2>/dev/null) || blob="unreadable"
            printf '%s %s\n' "$blob" "$path"
        else
            printf 'deleted %s\n' "$path"
        fi
    done
} | shasum | cut -d' ' -f1
