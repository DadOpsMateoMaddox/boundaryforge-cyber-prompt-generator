# BoundaryForge

> **Automated contrastive prompt generator for cybersecurity LLM red-teaming.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

---

## Overview

BoundaryForge generates contrastive **Benign / Warn / Dangerous** prompt packages for cybersecurity red-teaming. It keeps generation, validation, and auditing logic UI-agnostic while exposing a thin Streamlit dashboard and a CLI for one-off generation.

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

## Architecture

```
Dashboard / CLI
      │
      ▼
VariantGenerationService
      │
      ▼
┌─────────────────┐
│ PromptGenerator │
│ ConstraintValidator │
│ ContrastiveAuditor  │
│ BoundaryForgeValidator │
└─────────────────┘
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

## License

MIT — see [LICENSE](LICENSE).

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Orchestrator                         │
│                                                             │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐   │
│   │  Agent  A   │  │  Agent  B   │  │    Agent  C     │   │
│   │ (Recon)     │  │ (Analysis)  │  │ (Exploitation)  │   │
│   └──────┬──────┘  └──────┬──────┘  └────────┬────────┘   │
│          │                │                   │            │
│          └────────────────┼───────────────────┘            │
│                           │                                 │
│               ┌───────────▼────────────┐                   │
│               │   Policy Chokepoint    │                    │
│               │  (Scope · Auth · Log)  │                    │
│               └───────────┬────────────┘                   │
│                           │                                 │
│               ┌───────────▼────────────┐                   │
│               │      Evidence Store    │                    │
│               │   (Findings · Audit)   │                    │
│               └────────────────────────┘                   │
└─────────────────────────────────────────────────────────────┘
```

| Component | Role |
|---|---|
| **Agent A — Recon** | Enumerates the target surface area (endpoints, deps, configs) |
| **Agent B — Analysis** | Static and dynamic analysis of discovered artifacts |
| **Agent C — Exploitation** | Controlled, scoped exploitation attempts for PoC evidence |
| **Policy Chokepoint** | Validates scope, enforces authorization, and gates all outputs |
| **Evidence Store** | Immutable, timestamped log of all agent findings |

---

## Features

- 🔒 **Policy-first design** — no agent output reaches downstream consumers without chokepoint approval
- 🗂️ **Evidence-backed findings** — every result includes provenance, timestamps, and raw artifact links
- 🎯 **Scope enforcement** — configurable allow/deny lists prevent out-of-scope actions
- 🤖 **Three specialized agents** — recon, analysis, and exploitation run independently and in parallel
- 📊 **Real-time dashboard** — live view of agent status, finding counts, and policy decisions
- 🔁 **Replay & audit** — full audit trail supports post-hoc review and compliance reporting
- 🐍 **Python-native** — easy to extend with custom agents or policy plugins

---

## Dashboard Screenshots

The dashboard provides a real-time view of all three agents, the chokepoint status, and the evidence store.

> **To add screenshots:** place PNG or JPG files in [`docs/screenshots/`](docs/screenshots/) and update the image paths below.

### Overview Panel

![Dashboard Overview](docs/screenshots/dashboard-overview.png)
*Full dashboard showing all three agents, chokepoint queue, and finding summary.*

### Agent Status View

![Agent Status](docs/screenshots/agent-status.png)
*Per-agent status cards with live progress, task counts, and last-heartbeat timestamps.*

### Policy Chokepoint Queue

![Chokepoint Queue](docs/screenshots/chokepoint-queue.png)
*Pending and decided items in the policy enforcement queue, with approve/deny audit log.*

### Evidence Store

![Evidence Store](docs/screenshots/evidence-store.png)
*Searchable, timestamped evidence store with artifact previews and export options.*

### Finding Detail

![Finding Detail](docs/screenshots/finding-detail.png)
*Drilldown view for a single finding: raw output, agent that produced it, policy decision, and remediation notes.*

---

## Getting Started

### Prerequisites

- Python 3.10 or higher
- `pip` or `uv` for dependency management
- (Optional) Docker for containerized deployment

### Installation

```bash
# Clone the repository
git clone https://github.com/DadOpsMateoMaddox/three-agents-one-chokepoint.git
cd three-agents-one-chokepoint

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

### Running the Agents

```bash
# Start all three agents with the default policy configuration
python -m three_agents run --config config/default.yaml

# Run a single agent in isolation (useful for debugging)
python -m three_agents run --agent recon --config config/default.yaml
```

### Viewing the Dashboard

```bash
# Launch the real-time dashboard (defaults to http://localhost:8501)
python -m three_agents dashboard
```

Navigate to `http://localhost:8501` in your browser to view the live dashboard.

---

## Configuration

Configuration lives in `config/`. Copy the example and adjust for your environment:

```bash
cp config/example.yaml config/default.yaml
```

Key configuration options:

| Key | Default | Description |
|---|---|---|
| `scope.targets` | `[]` | Allowed target hosts / URLs |
| `scope.deny_patterns` | `[]` | Regex patterns that are always out-of-scope |
| `policy.require_approval` | `true` | Gate exploitation attempts behind human approval |
| `policy.max_severity` | `critical` | Maximum finding severity agents may act on autonomously |
| `evidence.store_path` | `./evidence` | Directory for the immutable evidence store |
| `dashboard.port` | `8501` | Port the dashboard listens on |
| `agents.parallel` | `true` | Run all three agents in parallel |

---

## Project Structure

```
three-agents-one-chokepoint/
├── config/                  # Configuration files
│   └── example.yaml
├── docs/
│   └── screenshots/         # Dashboard screenshots (add your own here)
├── three_agents/            # Main Python package
│   ├── agents/
│   │   ├── recon.py         # Agent A — Recon
│   │   ├── analysis.py      # Agent B — Analysis
│   │   └── exploitation.py  # Agent C — Exploitation
│   ├── chokepoint/
│   │   └── policy.py        # Policy enforcement chokepoint
│   ├── evidence/
│   │   └── store.py         # Immutable evidence store
│   ├── dashboard/
│   │   └── app.py           # Real-time dashboard (Streamlit)
│   └── __main__.py          # CLI entrypoint
├── tests/                   # Test suite
├── LICENSE
└── README.md
```

---

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes and add tests where appropriate
4. Ensure all tests pass: `pytest`
5. Open a pull request with a clear description of the change

Please read [CONTRIBUTING.md](CONTRIBUTING.md) (coming soon) for the full code of conduct and contribution guidelines.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
