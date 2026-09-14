# Autonomous offline security agent (AIRI / Sber "Universal Agentic Competition")

`agent/` is the submission: `run.sh` + `agent.py` + `acpagent/` (stdlib only, no third-party
dependencies). `./build_submission.sh` produces `submission.zip` with `run.sh` at the root.

## How it works
1. `spec.py` reads the task statement: deliverable path, task kind (exact file / key=value report /
   JSON findings report / CTF / code fix / generic), required keys or JSON fields, test command.
2. Deterministic shortcuts run first (exact-content files, a structured-forensics correlator seed).
3. `brief.py` gathers context for the model up front: directory tree, HTTP routes, a risky-pattern
   scan of the code, heads of data files, flag-shaped strings.
4. `agent.py` runs a bounded ReAct loop over four tools (bash / read_file / write_file / str_replace)
   with native function calling and automatic fallback to a text protocol, transcript trimming,
   repeat detection and budget control (`llm.py`, `tools.py`).
5. `oracle.py` verifies the deliverable before accepting "DONE" (JSON/kv format repair, syntax
   check, app-server restart, project tests) and feeds failures back to the model; at exit it
   guarantees a well-formed artifact (scan-derived findings, salvaged answers, best-effort flag).

## Local testing
`harness/` builds the public tasks (plus a few synthetic ones under `harness/extra_tasks`) on
the `secureintelligent/acp` image and runs the agent against any OpenAI-compatible endpoint
(`MODEL_URL`, `MODEL_NAME`). See `harness/run_task.sh`.
