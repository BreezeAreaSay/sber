#!/bin/bash
mkdir -p /logs/verifier
cd /app && /app/.venv/bin/python -m pytest /tests -q --tb=short > /logs/verifier/pytest_output.txt 2>&1 && echo 1 > /logs/verifier/reward.txt || echo 0 > /logs/verifier/reward.txt
