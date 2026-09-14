#!/bin/bash
S=/tmp/claude-0/-home-user-sber/d51f7823-826d-5329-93a8-9c35c3fc22f6/scratchpad
echo "=== v4: vuln report family (draft report before the model) ===" >> $S/harness/results.log
$S/harness/run_all.sh "find-sqli-login"
echo "@@ vuln report batch complete @@" >> $S/harness/results.log
