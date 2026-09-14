# IR-2026-0612 — SSH brute force on bastion-02

A brute-force campaign against the bastion host ended with one successful login. Review the evidence under `/app/evidence/` (`auth.log` from sshd on bastion-02, plus `netflow.csv` for context) and record your conclusion in `/app/incident_report.txt`.

The deliverable must contain exactly four lines, one `key=value` per line, no spaces around `=`, no blank lines, no extra keys:

- `attacker_ip` — the source IP of the successful login (the attacker), taken from the `Accepted password` line.
- `compromised_account` — the username that was successfully logged into from that IP.
- `first_success_utc` — the timestamp of that first successful login converted to UTC in the form `YYYY-MM-DDTHH:MM:SSZ` (the host clock in `auth.log` is `Europe/Berlin`, UTC+02:00 in June).
- `failed_attempts` — the number of `Failed password` lines from that attacker IP before the first successful login (integer).
