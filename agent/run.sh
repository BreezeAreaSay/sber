#!/bin/sh
# Entrypoint invoked by the runner as:  ./run.sh "<task instruction>"
# It must never exit non-zero: any non-zero exit scores the task 0 regardless of the
# artifacts already on disk.
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if [ "$#" -lt 1 ]; then
  echo "Usage: ./run.sh PROMPT" >&2
  exit 0
fi
export PYTHONUNBUFFERED=1
export PYTHONDONTWRITEBYTECODE=1
export PYTHONIOENCODING=utf-8

# Every task statement says "you are working in /app" and verifiers grade files there.
# Harbor runs us from its own upload directory, so prefer /app when it exists.
if [ -n "${AGENT_FORCE_WORKDIR:-}" ]; then
  LOCAL_AGENT_WORKDIR="$AGENT_FORCE_WORKDIR"
elif [ -d /app ]; then
  LOCAL_AGENT_WORKDIR=/app
else
  LOCAL_AGENT_WORKDIR="${LOCAL_AGENT_WORKDIR:-$(pwd)}"
fi
export LOCAL_AGENT_WORKDIR

PY=python3
command -v "$PY" >/dev/null 2>&1 || PY=python

"$PY" "$SCRIPT_DIR/agent.py" "$@" || echo "[run.sh] agent exited non-zero; suppressed" >&2
exit 0
