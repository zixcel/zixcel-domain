#!/usr/bin/env bash
# Standard local entry. Uses existing credentials; never starts a legacy session.
set -euo pipefail
umask 077
if ! command -v zix >/dev/null; then
  echo 'Install and verify Zixcel CLI and the Domain native extension first.' >&2
  exit 2
fi
exec zix domain "$@"
