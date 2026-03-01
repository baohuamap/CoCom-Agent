# AGENTS.md — CoCom-Agent Repository Rules

This file governs how any AI agent (Copilot, Claude, GPT, etc.) must reason about and contribute to this codebase. These rules are non-negotiable and must be followed in every session.

---

## Repository Purpose

CoCom-Agent is a research pipeline for **Analysis-Aware Context Compression (AACC)** of large codebases. It uses Code Property Graphs (CPG) to compute minimal reachability corridors $G' = R_s \cap R_t$, then applies deterministic KB entailment before invoking an LLM oracle — minimizing token cost while maximizing reasoning precision.

---

## Directory Structure (Authoritative)

```
CoCom-Agent/
├── config/          # Static knowledge bases only. JSON format. No logic.
├── src/
│   ├── core/        # Pipeline entry points: orchestrator, alignment
│   ├── graph/       # Graph operators: AACC engine, CPG queries
│   ├── reasoning/   # Assumption ledger, KB entailment, LLM oracle
│   └── evaluation/  # Benchmarking, metrics, parallel runners
└── tests/           # Pytest unit tests mirroring src/ structure
```

**Never** place application logic in `config/`. **Never** place test fixtures in `src/`.

---

## Absolute Rules

### 1. Monotonicity Must Be Preserved
The `LedgerDAG` in `src/reasoning/ledger_dag.py` enforces **Theorem 1**: once an assumption is invalidated, it can never be re-asserted. Any change to `LedgerDAG` or `Assumption` must maintain this invariant. Tests in `tests/test_monotonicity.py` must always pass.

### 2. LLM Oracle Is the Last Resort
The call order is fixed and must not be inverted:
1. `KBEntailmentEngine.evaluate()` first — returns an `EvidenceState` dict
2. If `state == EvidenceState.NEUTRAL` → `LedgerLLMOracle.evaluate_assumption()`

Never call `LedgerLLMOracle` when the KB can give a deterministic answer.

### 3. All Neo4j Credentials Come from Environment Variables
Never hardcode credentials. The only allowed defaults are the local development fallbacks already present:
- `NEO4J_URI` → `bolt://localhost:7687`
- `NEO4J_USER` → `neo4j`
- `NEO4J_PASSWORD` → `cocom_secure_password`

### 4. Graph Compression Stays in `src/graph/`
The AACC operator $C: G \rightarrow G'$ and all Cypher/APOC queries live exclusively in `src/graph/aacc_engine.py`. Do not scatter graph queries into other modules.

### 5. KB Files Are Declarative Only
`config/java_kb.json` and `config/python_kb.json` must remain pure data (patterns, safe sinks, taint sources). No scripting, no executable content.

### 6. Pinned Dependencies
Do not change version pins in `requirements.txt` without an explicit user instruction. The pinned versions are:
```
neo4j==5.16.0
networkx==3.2.1
openai==1.12.0
pandas==2.2.0
tqdm==4.66.2
```

### 7. Tests Must Mirror Source Structure
Every module in `src/` must have a corresponding test file under `tests/`. New modules require new test files before the work is considered complete.

### 8. No Silent Failures
All subprocess calls (`CoComOrchestrator._run_joern`, `CoComOrchestrator._run_codeql`) must raise on non-zero exit codes. Do not swallow errors or return `None` on failure.

---

## Code Style

- Python 3.11+. No walrus operator abuse, no implicit `Any`.
- Type hints required on all public method signatures.
- Docstrings required on all public classes and methods.
- Use `os.getenv` for all environment variable access.
- `pathlib.Path` over raw string paths everywhere.
- No `print()` in library code — use structured log messages with `[ClassName]` prefixes (matching the existing style).

---

## Adding a New Module

1. Create the file under the correct `src/` subdirectory.
2. Add `__init__.py` if creating a new package.
3. Write a corresponding `tests/test_<module>.py`.
4. Update `README.md` architecture table if the module is user-facing.
5. Do **not** update `AGENTS.md` unless the repo's fundamental structure changes.
