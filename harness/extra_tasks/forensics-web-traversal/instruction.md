# IR-2026-0733 — Suspected file disclosure on web-01

The web team reports that internal configuration files may have been read through the public site. Review the evidence under `/app/logs/` (`access.log` from nginx on web-01; timestamps are in the server's local time zone, see the header comment) and record your conclusion in `/app/incident_report.txt`.

The deliverable must contain exactly four lines, one `key=value` per line, no spaces around `=`, no blank lines, no extra keys:

- `attacker_ip` — the client IP that performed the directory-traversal (`../`) requests.
- `first_attack_utc` — the timestamp of that client's first traversal request, converted to UTC in the form `YYYY-MM-DDTHH:MM:SSZ`.
- `traversal_requests` — how many requests from that client contained `../` (integer).
- `leaked_file` — the path requested in the first traversal request that returned HTTP 200, exactly as it appears in the log (the request path without the host).
