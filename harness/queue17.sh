#!/bin/bash
S=/tmp/claude-0/-home-user-sber/d51f7823-826d-5329-93a8-9c35c3fc22f6/scratchpad
echo "=== v3: deterministic regression (gate solver + high-conf forensics early return) ===" >> $S/harness/results.log
$S/harness/run_all.sh "hello-file bye-file incident-log-forensics ctf-vault ctf-password-gate forensics-ssh-bruteforce forensics-web-traversal fix-sqli-login fix-sqli-search fix-sqli-tags fix-sqli-comments fix-sqli-filter fix-sqli-users fix-flask-cmdi find-flask-cmdi"
echo "@@ deterministic batch complete @@" >> $S/harness/results.log
echo "=== v3: model path (exfil forced, ssh forced) — seed-as-hint + voting ===" >> $S/harness/results.log
ALWAYS_MODEL=1 LOCAL_DEADLINE=2600 AGENT_TIMEOUT=2900 $S/harness/run_all.sh "incident-log-forensics forensics-ssh-bruteforce"
echo "@@ model-path batch complete @@" >> $S/harness/results.log
