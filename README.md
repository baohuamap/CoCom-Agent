# CoCom-Agent

**Analysis-Aware Context Compression for LLM-Assisted Code Reasoning**

CoCom-Agent is a production-grade pipeline that compresses repository context using graph reachability over Code Property Graphs (CPGs), enabling precise, bounded LLM reasoning over large codebases.

---

## Architecture Overview

```
cocom-agent/
├── config/          # Deterministic Knowledge Bases (Java, Python)
├── src/
│   ├── core/        # Pipeline orchestration (CodeQL + Joern triggers, alignment)
│   ├── graph/       # AACC Engine: G → G' reachability compression via Neo4j/APOC
│   ├── reasoning/   # Assumption Ledger, KB Entailment, LLM Oracle, Ledger DAG
│   └── evaluation/  # Distributed benchmarking & metrics
└── tests/           # CI/CD unit tests (Theorem 1 monotonicity proofs)
```

## Core Concepts

- **AACC (Analysis-Aware Context Compression):** Operator $C: G \rightarrow G'$ that intersects forward reachability $R_s$ from source nodes and backward reachability $R_t$ from sink nodes, yielding the minimal corridor subgraph $G' = R_s \cap R_t$.
- **Monotonic Invalidation DAG:** Assumption ledger enforcing Theorem 1 — no assumption is re-asserted once invalidated.
- **KB Entailment:** Deterministic regex/AST short-circuiting to bypass LLM calls for known patterns.
- **LLM Oracle:** Bounded OpenAI API calls for semantic verification of assumptions outside the KB.

---

## Quick Start

### Prerequisites
- Docker & Docker Compose
- OpenAI API Key

### Run

```bash
export OPENAI_API_KEY=sk-...
docker-compose up --build
```

Neo4j browser available at `http://localhost:7474` (credentials: `neo4j` / `cocom_secure_password`).

---

## Development

```bash
pip install -r requirements.txt
```

Run tests:
```bash
pytest tests/
```

---

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `OPENAI_API_KEY` | OpenAI API key | required |
| `NEO4J_URI` | Neo4j Bolt URI | `bolt://localhost:7687` |
| `NEO4J_USER` | Neo4j username | `neo4j` |
| `NEO4J_PASSWORD` | Neo4j password | `cocom_secure_password` |
