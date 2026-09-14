#!/bin/bash
# Run tasks sequentially (single LLM slot); append one RESULT line per task to harness/results.log
HERE=$(cd "$(dirname "$0")" && pwd)
LOG="$HERE/results.log"
echo "=== run_all $(date -Iseconds) agent=${2:-/home/user/sber/agent} ===" >> "$LOG"
for t in $1; do
  "$HERE/run_task.sh" "$t" "${2:-/home/user/sber/agent}" 2>&1 | grep -E '^RESULT' | tee -a "$LOG"
done
echo "=== end $(date -Iseconds) ===" >> "$LOG"
