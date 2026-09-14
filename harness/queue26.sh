#!/bin/bash
S=/tmp/claude-0/-home-user-sber/d51f7823-826d-5329-93a8-9c35c3fc22f6/scratchpad
for i in $(seq 1 60); do curl -sf http://127.0.0.1:8080/health >/dev/null 2>&1 && break; sleep 3; done
echo "=== FINAL6: 19 tasks after contract + test-baseline hardening ===" >> $S/harness/results.log
$S/harness/run_all.sh "hello-file bye-file incident-log-forensics ctf-vault ctf-password-gate forensics-ssh-bruteforce forensics-web-traversal fix-sqli-login fix-sqli-search fix-sqli-tags fix-sqli-comments fix-sqli-filter fix-sqli-users fix-flask-cmdi fix-flask-traversal fix-flask-ssrfxss fix-flask-idor find-sqli-login find-flask-cmdi"
echo "@@ FINAL6 complete @@" >> $S/harness/results.log
