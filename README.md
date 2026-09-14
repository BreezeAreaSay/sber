# Autonomous offline security agent (AIRI / Sber "Universal Agentic Competition")

`agent/` is the submission: `run.sh` + `agent.py` + `acpagent/` — standard library only, no
third-party dependencies, so nothing can be missing in the `secureintelligent/acp` runtime.
`./build_submission.sh` produces `submission.zip` with `run.sh` at the archive root.

## How a task is handled

1. **Triage** (`spec.py`) reads the statement: task kind (exact-content file / key=value report /
   JSON findings report / CTF / code fix / generic), the graded file path, required keys or
   JSON fields (parsed from the example in the statement), the test command, no-modify rules.
2. **Deterministic shortcuts** run first and finish the task at 0 tokens when they verify:
   - exact-content files (one or several);
   - the structured exfiltration-forensics family (`forensic_seed.py`, mirrors the normative
     field mapping of the statement; used as a hint to the model otherwise);
   - **mechanical SQL parameterization** (`sqlfix.py`): SQL built with f-strings, `%`,
     `.format()` or `+` concatenation → bound parameters (asyncpg / psycopg / sqlite styles),
     including the `conditions.append(f"...")` idiom; kept only if the code compiles, the app
     server restarts and the project's tests pass, otherwise reverted;
   - **mechanical command-injection / configuration hardening** (`safefix.py`): `subprocess`/
     `os.system` with `shell=True` templates → argument lists, `yaml.load` → `safe_load`,
     `debug=True`, `verify=False`; same test-verified keep-or-revert rule;
   - **CTF flag recovery**: literal / base64 / base32 / hex / rot13 / reversed / single-byte XOR /
     repeating-key XOR with keys taken from source string constants (and `.join()`ed lists),
     archive members (zip/tar/gz, encrypted zips with source passwords), git history — a single
     clean candidate with the expected prefix is written directly.
3. **Briefing** (`brief.py`, `digest.py`, `profile.py`) gathers context before the first model
   call: directory tree, HTTP routes, a risky-pattern scan (SQLi, command/code injection,
   traversal, SSRF, secrets, weak crypto, XSS, XXE …), heads of data files; for forensics,
   deterministic per-entity profiles (per-IP/per-account failed vs accepted logins, first
   success and "failed before first success", HTTP access and JSONL audit profiles, rare events
   in full) with every timestamp converted to UTC from the file's declared time zone, plus a
   per-file digest; for CTF, the output of the challenge's own programs and the flag scan.
4. **Model loop** (`agent.py`, `llm.py`, `tools.py`): a bounded ReAct loop over four tools
   (bash / read_file / write_file / str_replace), native function calling with automatic
   fallback to a text protocol, streaming with an idle timeout, transcript trimming, per-round
   output budgets, repeat/stall detection, a fresh-transcript retry for stalled CTF/forensics
   attempts, and a token/time budget. Tool results carry immediate feedback: syntax errors after
   an edit, indentation auto-repair of pasted blocks, whitespace-insensitive `str_replace`,
   heredoc hints on shell quoting errors, large data files summarised instead of dumped.
5. **Oracles and fallbacks** (`oracle.py`): "DONE" is accepted only when the deliverable
   verifies — JSON (or Markdown) report shape (repaired and normalised, severities
   canonicalised), key=value format without placeholders and with entity values that actually
   occur in the evidence, flag-shaped content, or for code fixes: changed files compile, the app
   server restarts from the edited code, the project tests pass. Failures are fed back to the
   model. Key=value answers additionally pass derivation checks (UTC values must be a real
   conversion of an evidence timestamp, counts must be integers, entities must occur in the
   evidence) and, when time allows, are re-derived by independent attempts (one with reasoning
   enabled, one with a checklist) and combined per key by majority. At exit the agent always
   leaves a well-formed artifact: scan-derived and heuristic access-control findings merged into
   the report, answers salvaged from the reply or tool outputs, broken files restored. `run.sh`
   always exits 0.

Task statements in English and Russian are recognised. The LLM client copes with servers that
reject tool schemas or `tool_choice`, ignore tools, stream `<think>` blocks, want
`max_completion_tokens`, or serve a differently named model.

## Local testing

`harness/` builds the public tasks and the synthetic ones under `harness/extra_tasks`
(CTF, Flask command-injection find/fix, SSH brute-force forensics) on the acp image and runs
the agent end to end against any OpenAI-compatible endpoint (`MODEL_URL`, `MODEL_NAME`):

```
harness/build.sh                # build task images (postgres runs on the host)
harness/run_task.sh fix-sqli-login
harness/run_all.sh "hello-file bye-file incident-log-forensics find-sqli-login fix-sqli-login fix-sqli-search"
```

Local validation used llama.cpp + Qwen3-4B-Instruct on CPU (~3 tok/s, hence the long local
deadlines in the harness; the agent's own defaults target the 600 s task limit).
