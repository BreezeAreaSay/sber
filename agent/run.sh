#!/bin/sh
# Entrypoint invoked by the runner as:  ./run.sh "<task instruction>"
#
# It must never exit non-zero: any non-zero exit scores the task 0 regardless of the
# artifacts already on disk. It must also never do nothing: if the instruction arrives
# by some route other than argv (standard input, an environment variable, a task file),
# every task would score 0 at once, so the agent is started regardless and works out
# where the statement is for itself.
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

export PYTHONUNBUFFERED=1
export PYTHONDONTWRITEBYTECODE=1
export PYTHONIOENCODING=utf-8

# Every task statement says "you are working in /app" and verifiers grade files there.
# Harbor runs us from its own upload directory, so prefer /app when it holds the task.
if [ -n "${AGENT_FORCE_WORKDIR:-}" ]; then
  LOCAL_AGENT_WORKDIR="$AGENT_FORCE_WORKDIR"
elif [ -d /app ] && [ -n "$(ls -A /app 2>/dev/null | grep -v -e '^\.venv$' -e '^\..*')" ]; then
  # only when /app actually holds the task. The base image ships /app/.venv, so an
  # otherwise-empty /app must not hide a task the runner placed somewhere else.
  LOCAL_AGENT_WORKDIR=/app
else
  LOCAL_AGENT_WORKDIR="${LOCAL_AGENT_WORKDIR:-$(pwd)}"
fi
export LOCAL_AGENT_WORKDIR

PY=python3
command -v "$PY" >/dev/null 2>&1 || PY=python

# Pass standard input through: the agent falls back to it when argv carries no
# statement, and closes it immediately when there is nothing to read.
"$PY" "$SCRIPT_DIR/agent.py" "$@" || echo "[run.sh] agent exited non-zero; suppressed" >&2
exit 0
