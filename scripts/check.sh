#!/usr/bin/env bash
# Run all repository checks required before a phase is declared complete.
set -euo pipefail
cd "$(dirname "$0")/.."
exec make check