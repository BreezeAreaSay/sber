#!/bin/bash
# Build local task images. Usage: build.sh [task...]
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
TASKS_DIR="$HERE/../pubrepo/local_task"
tasks=("$@"); [ ${#tasks[@]} -eq 0 ] && tasks=(hello-file bye-file incident-log-forensics find-sqli-login fix-sqli-login fix-sqli-search)
for t in "${tasks[@]}"; do
  env="$TASKS_DIR/$t/environment"; [ -d "$env" ] || env="$HERE/extra_tasks/$t/environment"
  if [ -d "$env/app" ]; then
    ctx="$HERE/ctx/$t"; rm -rf "$ctx"; mkdir -p "$ctx"; cp -r "$env/app" "$ctx/app"; cp /root/.ccr/ca-bundle.crt "$ctx/ca.crt"
    docker build --network host -q -t "task-$t" -f "$HERE/Dockerfile.app" "$ctx" > /dev/null && echo "built task-$t (app)" || echo "FAILED task-$t"
  else
    docker build --network host -q -t "task-$t" "$env" > /dev/null && echo "built task-$t" || echo "FAILED task-$t"
  fi
done
