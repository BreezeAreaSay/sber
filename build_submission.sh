#!/bin/bash
# Build submission.zip: run.sh must sit at the archive root.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE/agent"
find . -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
rm -f "$HERE/submission.zip"
zip -qr "$HERE/submission.zip" run.sh agent.py acpagent -x '*.pyc' -x '*__pycache__*'
ls -la "$HERE/submission.zip"
unzip -l "$HERE/submission.zip"
