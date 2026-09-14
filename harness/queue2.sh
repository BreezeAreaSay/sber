#!/bin/bash
S=/tmp/claude-0/-home-user-sber/d51f7823-826d-5329-93a8-9c35c3fc22f6/scratchpad
while pgrep -f "run_task.sh incident-log-forensics" >/dev/null; do sleep 5; done
pkill -f llama-server; sleep 3
cd $S/llm && (nohup ./llama-b10952/llama-server -m qwen3-4b-instruct-q4km.gguf --host 127.0.0.1 --port 8080 -c 20480 -t 4 --jinja -np 1 --no-warmup -fa on --cache-reuse 256 > llama_server.log 2>&1 &)
for i in $(seq 1 120); do curl -sf http://127.0.0.1:8080/health >/dev/null 2>&1 && break; sleep 2; done
echo "llama-server restarted: $(curl -s http://127.0.0.1:8080/health)"
$S/harness/run_all.sh "find-sqli-login fix-sqli-login fix-sqli-search ctf-vault forensics-ssh-bruteforce find-flask-cmdi fix-flask-cmdi"
