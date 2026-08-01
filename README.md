# BoundaryForge

> **Automated contrastive prompt generator for cybersecurity LLM red-teaming.**

[![License: Research/Non-Commercial](https://img.shields.io/badge/License-Research%2FNon--Commercial-lightgrey.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

---

## Overview

BoundaryForge generates contrastive **Benign / Warn / Dangerous** prompt packages for cybersecurity LLM red-teaming. It keeps generation, validation, and auditing logic UI-agnostic while exposing a thin Streamlit dashboard and a CLI for one-off generation.

Each package shares a single technical topic and exchange type across all three danger levels, then escalates in capability, actionability, autonomy, and operational scope.

## Quick Start

```bash
pip install -e ".[all]"

# CLI
boundaryforge generate --domain kubernetes_rbac_container_escape --exchange-type agentic

# Dashboard
streamlit run src/prompt_generator/dashboard.py

# Docker
docker compose up -d
```

Then open http://localhost:8501.

## Architecture

```
Dashboard / CLI
      │
      ▼
VariantGenerationService
      │
      ▼
┌─────────────────────────────────────┐
│  PromptGenerator                    │
│  ConstraintValidator                │
│  ContrastiveAuditor                 │
│  BoundaryForgeValidator             │
│  Humanizer                          │
└─────────────────────────────────────┘
```

## Features

- Typed `TaskSpec`, `PromptVariant`, and `PromptPackage` schemas
- Deterministic constraint validation with stable rule IDs
- Context-aware contrastive-gradient auditing via `RiskVector`
- Clause-aware negation handling for hard-danger signals
- Humanization pass that preserves locked technical tokens
- Streamlit dashboard with Warn safeguards and Dangerous uplift controls
- CLI with distinct exit codes: `0/1/2/3/4`
- promptfoo integration for dataset export
- Docker support

## Project Structure

```
.
├── src/prompt_generator/
│   ├── cli.py                         # CLI entrypoint
│   ├── dashboard.py                   # Thin Streamlit UI
│   ├── models.py                      # Core schemas
│   ├── task_spec.py                   # Task-spec builder
│   ├── export/                        # JSON/Markdown export
│   ├── generation/                    # Generator, humanizer, evaluator
│   ├── normalization/                 # URL/IP/email normalization
│   ├── services/
│   │   └── variant_generation_service.py  # Dashboard orchestration
│   └── validators/                    # Constraint, contrastive, aggregate
├── tests/
├── Dockerfile
├── docker-compose.yml
├── LICENSE
├── README.md
└── pyproject.toml
```

## License

This project is licensed under the **BoundaryForge Research and Evaluation
License**.

- **Non-commercial research, educational, academic, and personal evaluation use**
  is permitted.
- **Commercial, for-profit, or enterprise use requires prior written permission**.

See [LICENSE](LICENSE) for the full text. If you need a commercial license,
please contact the copyright holder.

> **Note:** I am not a lawyer. The license text above is provided as a
> starting point and should be reviewed by qualified legal counsel before
> publication or enforcement.
