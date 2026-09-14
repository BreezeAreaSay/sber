#!/bin/bash
mkdir -p /logs/verifier
pkill -f "app.py" >/dev/null 2>&1; pkill -f "flask" >/dev/null 2>&1; sleep 1
cd /app && (nohup /app/.venv/bin/python app.py > /logs/verifier/app.log 2>&1 &)
for i in $(seq 1 30); do curl -sf http://127.0.0.1:5000/healthz >/dev/null && break; sleep 1; done
cd /app && /app/.venv/bin/python -m pytest /tests -q --tb=short > /logs/verifier/pytest_output.txt 2>&1 && echo 1 > /logs/verifier/reward.txt || echo 0 > /logs/verifier/reward.txt
pkill -f "app.py" >/dev/null 2>&1
