#!/bin/bash
S=/tmp/claude-0/-home-user-sber/d51f7823-826d-5329-93a8-9c35c3fc22f6/scratchpad
echo "=== v6: code-fix family (sql + new traversal fixer), postgres restored ===" >> $S/harness/results.log
$S/harness/run_all.sh "fix-sqli-login fix-sqli-search fix-sqli-tags fix-sqli-comments fix-sqli-filter fix-sqli-users fix-flask-traversal fix-flask-cmdi"
echo "@@ v6 code-fix complete @@" >> $S/harness/results.log
echo "=== v6: report family ===" >> $S/harness/results.log
$S/harness/run_all.sh "find-sqli-login find-flask-cmdi"
echo "@@ v6 report complete @@" >> $S/harness/results.log
