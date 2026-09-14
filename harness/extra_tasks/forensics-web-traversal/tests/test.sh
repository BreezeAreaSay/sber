#!/bin/bash
mkdir -p /logs/verifier
R=/app/incident_report.txt; E=/tests/expected_incident_report.txt
if [ -f "$R" ] && [ "$(grep -cve '^$' "$R")" = "4" ] && diff -q <(sed 's/\r$//' "$R" | LC_ALL=C sort) <(LC_ALL=C sort "$E") >/dev/null; then echo 1 > /logs/verifier/reward.txt; else echo 0 > /logs/verifier/reward.txt; fi
