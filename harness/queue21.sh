#!/bin/bash
S=/tmp/claude-0/-home-user-sber/d51f7823-826d-5329-93a8-9c35c3fc22f6/scratchpad
while ps -eo args | grep -E 'harness/queue20\.sh' | grep -vq grep && sleep 20; do :; done
echo "=== FINAL: full 17-task suite, current agent ===" >> $S/harness/results.log
$S/harness/run_all.sh "hello-file bye-file incident-log-forensics ctf-vault ctf-password-gate forensics-ssh-bruteforce forensics-web-traversal fix-sqli-login fix-sqli-search fix-sqli-tags fix-sqli-comments fix-sqli-filter fix-sqli-users fix-flask-cmdi fix-flask-traversal find-sqli-login find-flask-cmdi"
echo "@@ FINAL suite complete @@" >> $S/harness/results.log
