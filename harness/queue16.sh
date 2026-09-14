#!/bin/bash
S=/tmp/claude-0/-home-user-sber/d51f7823-826d-5329-93a8-9c35c3fc22f6/scratchpad
while ps -eo args | grep -E 'harness/queue15\.sh' | grep -vq grep && sleep 15; do :; done
echo "=== profile seed: deterministic regression ===" >> $S/harness/results.log
$S/harness/run_all.sh "hello-file incident-log-forensics ctf-vault fix-sqli-login fix-sqli-search fix-sqli-tags"
echo "=== profile seed: model path (web traversal, ssh brute force, exfil forced) ===" >> $S/harness/results.log
LOCAL_DEADLINE=3000 AGENT_TIMEOUT=3300 $S/harness/run_all.sh "forensics-web-traversal forensics-ssh-bruteforce"
echo "=== profile seed: exfil on the model path ===" >> $S/harness/results.log
ALWAYS_MODEL=1 LOCAL_DEADLINE=3000 AGENT_TIMEOUT=3300 $S/harness/run_all.sh "incident-log-forensics"
