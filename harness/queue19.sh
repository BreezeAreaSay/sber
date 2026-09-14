#!/bin/bash
S=/tmp/claude-0/-home-user-sber/d51f7823-826d-5329-93a8-9c35c3fc22f6/scratchpad
echo "=== v5: full regression after report builder + verifier + triage changes ===" >> $S/harness/results.log
$S/harness/run_all.sh "hello-file bye-file incident-log-forensics ctf-vault ctf-password-gate forensics-ssh-bruteforce forensics-web-traversal fix-sqli-login fix-sqli-search fix-sqli-tags fix-sqli-comments fix-sqli-filter fix-sqli-users"
echo "@@ v5 deterministic complete @@" >> $S/harness/results.log
echo "=== v5: model-path families (report + code fix) ===" >> $S/harness/results.log
$S/harness/run_all.sh "find-sqli-login fix-flask-cmdi find-flask-cmdi"
echo "@@ v5 model-path complete @@" >> $S/harness/results.log
