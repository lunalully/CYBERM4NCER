#!/usr/bin/env bash
# Build a static CYBERM4NCER binary with injected build metadata.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${VERSION:-0.1.0-dev}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
MODULE="github.com/lunalully/cyberm4ncer"
DIST="${DIST:-dist}"
BINARY="cyberm4ncer"

mkdir -p "$DIST"
CGO_ENABLED="${CGO_ENABLED:-0}" go build -trimpath \
  -ldflags "-s -w \
    -X ${MODULE}/internal/version.Version=${VERSION} \
    -X ${MODULE}/internal/version.Commit=${COMMIT} \
    -X ${MODULE}/internal/version.BuildDate=${BUILD_DATE}" \
  -o "${DIST}/${BINARY}" ./cmd/cyberm4ncer

echo "built ${DIST}/${BINARY} (${VERSION}, ${COMMIT})"