#!/bin/bash
# Run one local task end-to-end in its docker image against a local LLM endpoint.
# Usage: run_task.sh <task-name> [agent-dir] ; env: MODEL_URL (default http://127.0.0.1:8080/v1), MODEL_NAME, AGENT_TIMEOUT
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
TASK="$1"
AGENT_DIR="${2:-/home/user/sber/agent}"
TASKS_DIR="$HERE/../pubrepo/local_task"
TDIR="$TASKS_DIR/$TASK"
[ -d "$TDIR" ] || TDIR="$HERE/extra_tasks/$TASK"
MODEL_URL="${MODEL_URL:-http://127.0.0.1:8080/v1}"
MODEL_NAME="${MODEL_NAME:-qwen3-4b}"
OUT="$HERE/out/$TASK"; rm -rf "$OUT"; mkdir -p "$OUT"
IMG="task-$TASK"
C="t-$TASK"
# Local CPU inference is ~10x slower than the competition endpoint: allow longer local runs
# (override with AGENT_TIMEOUT / LOCAL_DEADLINE to test the real limits).
AGENT_TIMEOUT="${AGENT_TIMEOUT:-1500}"
LOCAL_DEADLINE="${LOCAL_DEADLINE:-1300}"
INSTR=$(cat "$TDIR/instruction.md")

docker rm -f "$C" >/dev/null 2>&1
if [ -f "$HERE/entrypoints/$TASK.sh" ]; then
  docker run -d --network host --name "$C" "$IMG" bash -c "$(cat "$HERE/entrypoints/$TASK.sh")" >/dev/null
  sleep 3
elif docker image inspect "$IMG" >/dev/null 2>&1 && docker run --rm "$IMG" test -f /app/main.py 2>/dev/null; then
  # API app task: reset host DB, start uvicorn inside the container (postgres lives on the host)
  su postgres -c "psql -q -c \"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='appdb';\"" >/dev/null 2>&1
  su postgres -c "dropdb --if-exists appdb" >/dev/null 2>&1; su postgres -c "createdb appdb -O appuser" >/dev/null 2>&1
  docker run -d --network host --name "$C" "$IMG" bash -c 'cd /app && (uvicorn main:app --host 0.0.0.0 --port 8000 > /tmp/uvicorn.log 2>&1 &) ; tail -f /dev/null' >/dev/null
  for i in $(seq 1 30); do curl -sf http://127.0.0.1:8000/healthz >/dev/null && break; sleep 1; done
else
  docker run -d --network host --name "$C" "$IMG" tail -f /dev/null >/dev/null
fi
docker exec "$C" mkdir -p /opt/harbor/local-agent /logs/agent /logs/verifier
docker cp "$AGENT_DIR/." "$C:/opt/harbor/local-agent/"
docker exec "$C" chmod +x /opt/harbor/local-agent/run.sh
START=$(date +%s)
timeout --signal=KILL "$AGENT_TIMEOUT" docker exec -w /opt/harbor/local-agent \
  -e LOCAL_AGENT_MODEL="$MODEL_NAME" -e OPENAI_BASE_URL="$MODEL_URL" -e OPENAI_API_KEY=local \
  -e LOCAL_AGENT_WORKDIR=/opt/harbor/local-agent -e LOCAL_AGENT_DEADLINE_SEC="$LOCAL_DEADLINE" -e LOCAL_AGENT_IDLE_TIMEOUT="${LOCAL_IDLE:-900}" \
  -e LOCAL_AGENT_FORCE_TEXT_TOOLS="${FORCE_TEXT:-}" -e AGENT_DISABLE_SQLFIX="${NO_SQLFIX:-}" \
  "$C" sh -c './run.sh "$0" 2>&1' "$INSTR" > "$OUT/agent.log" 2>&1
RC=$?
END=$(date +%s)
docker cp "$TDIR/tests" "$C:/tests" >/dev/null
docker exec "$C" bash /tests/test.sh > "$OUT/verifier.log" 2>&1
REWARD=$(docker exec "$C" cat /logs/verifier/reward.txt 2>/dev/null | tr -d '[:space:]')
docker exec "$C" sh -c 'cat /logs/verifier/pytest_output.txt 2>/dev/null' > "$OUT/pytest_output.txt" 2>/dev/null
docker exec "$C" sh -c 'for f in /app/security_report.json /app/incident_report.txt /app/hello.txt /app/bye.txt /app/flag.txt; do [ -f $f ] && { echo "=== $f ==="; cat $f; echo; }; done; cd /app && git status --short 2>/dev/null' > "$OUT/deliverables.txt" 2>/dev/null
docker exec "$C" sh -c 'cd /app && for f in $(find . -name "*.py" -newer /opt/harbor/local-agent/run.sh -not -path "./.venv/*" 2>/dev/null); do echo "=== changed: $f ==="; cat $f; done' > "$OUT/changed_files.txt" 2>/dev/null
TEL=$(grep -E '^\[agent\] done:' "$OUT/agent.log" | tail -1)
echo "RESULT task=$TASK reward=${REWARD:-none} rc=$RC time=$((END-START))s | $TEL"
docker rm -f "$C" >/dev/null 2>&1
