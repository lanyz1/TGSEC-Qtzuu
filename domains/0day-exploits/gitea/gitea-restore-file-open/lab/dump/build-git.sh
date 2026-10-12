#!/bin/sh
# Build a mirror-style git dir so restore can clone dump/git.
set -eu
DUMP="${1:-/data/restore-dump}"
SRC="/tmp/lab-dump-src"
rm -rf "${SRC}" "${DUMP}/git"
mkdir -p "${SRC}"
git init -b main "${SRC}"
git -C "${SRC}" config user.email lab@localhost.invalid
git -C "${SRC}" config user.name lab
printf 'lab dump\n' > "${SRC}/README.md"
git -C "${SRC}" add README.md
git -C "${SRC}" -c user.email=lab@localhost.invalid -c user.name=lab commit -m "init"
git -C "${SRC}" branch -M main
git -C "${SRC}" tag v1.0
git clone --mirror "${SRC}" "${DUMP}/git"

