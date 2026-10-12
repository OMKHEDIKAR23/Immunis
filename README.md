# Immunis

**A security layer for personal AI agents.**

Immunis is a personal AI agent designed to resist prompt injection, protect user-authorized actions, and make long-term memory auditable and revocable.

Its central principle is simple: **untrusted content may provide information, but it must not gain authority over the agent.**

> **Project status:** Early development. The security architecture is a design goal, not a claim of proven protection. Features and benchmark results will be documented as they are implemented and tested.

## The problem

Personal AI agents may read webpages, emails, PDFs, and files while also accessing tools and maintaining persistent memory. Malicious content can attempt to manipulate an agent's behavior or introduce false information into its memory.

Immunis aims to reduce these risks through isolation, deterministic policy enforcement, source-tracked memory, and repeatable adversarial evaluation.

## How it works

The planned architecture contains six major components:

1. **Quarantine:** A tool-less NVIDIA Nemotron model extracts structured information from untrusted content.
2. **Validation:** Strict schema checks reject malformed or unexpected model output.
3. **Provenance memory:** SQLite records facts, their sources, and relationships between derived facts.
4. **Planner:** A larger Nemotron model proposes actions using validated information and trusted user instructions.
5. **Policy gate:** Deterministic Python code evaluates proposed actions, permissions, taint, and external destinations before execution.
6. **Red team:** Repeatable attacks compare a naive baseline with quarantine-only and full Immunis configurations.

Untrusted tool results must pass through quarantine before the planner can use them. Sensitive actions require appropriate authorization.

## Security principles

* Fail closed when quarantine output is invalid.
* Never give the planner raw untrusted document text.
* Treat quarantined output as potentially attacker-influenced data.
* Enforce permissions in deterministic code rather than relying on a model's assurances.
* Require a traceable source for every stored fact.
* Support revocation of facts derived from a compromised source.
* Keep API credentials on the backend.
* Test with synthetic fixtures and harmless canary tokens.
* Publish measured results, including failures and limitations.

## Technology stack

Planned technologies:

* Python
* NVIDIA Nemotron models
* Nebius Token Factory
* SQLite
* FastAPI
* Tavily web search
* HTML, CSS, and JavaScript

Dependencies will be added as implementation requires them.

## Repository structure

The repository will grow toward the following structure:

```text
immunis/
├── LICENSE
├── README.md
├── requirements.txt
├── .env.example
├── AGENT_BRIEF.md
├── immunis/
├── scripts/
├── attacks/
├── fixtures/
├── results/
├── tests/
└── web/
```

## Setup

The complete installation and run instructions will be added as the application becomes runnable.

The intended setup process is:

1. Install a supported Python version.
2. Create and activate a virtual environment.
3. Install dependencies from `requirements.txt`.
4. Copy `.env.example` to `.env`.
5. Configure a Nebius Token Factory API key and verified model IDs.
6. Run the offline tests.
7. Start the application using the documented command.

Never commit `.env` or publish API keys.

## Nebius and NVIDIA integration

Immunis is being developed for the Nebius × NVIDIA Global AI Hackathon.

* **Nebius Token Factory:** Planned inference endpoint for model requests.
* **NVIDIA Nemotron Nano:** Planned quarantine and red-team model.
* **NVIDIA Nemotron Super or Ultra:** Planned planner model, subject to model availability and testing.
* **Tavily:** Planned web search integration for retrieving external content and evaluating prompt-injection defenses.

Exact model IDs, API behavior, costs, and performance must be verified during implementation. This section will be updated with the actual configuration and measured usage.

## Evaluation

The planned benchmark compares three configurations:

1. Naive baseline agent.
2. Quarantine-only agent.
3. Full Immunis pipeline.

Target evaluation includes at least 200 attack cases and 20 benign tasks.

Metrics will include attack success rate, schema validity, detection rate, false positives, benign task success, latency, and token cost.

No benchmark results are claimed until experiments have been run. Evaluation methodology, attack cases, seeds, and reproducible outputs will be published where practical.

## Limitations and threat model

Immunis is intended to reduce prompt-injection risk, not guarantee perfect security.

The threat model assumes an attacker can control external document content. The initial scope does not attempt to defend against compromised user devices, malicious model weights, side-channel attacks, or attackers who control the user's own trusted messages.

Quarantine models may misclassify content or produce attacker-influenced structured fields. Schema validation cannot establish that extracted claims are true. Policy rules can be incomplete, and model behavior may vary.

Security claims will therefore be tied to reproducible tests and reported with their limitations.

## Development status

The project is in its initial setup phase. Components, integration tests, deployment, and benchmark results will be marked complete only after verification.

## License

Immunis is released under the MIT License. See [LICENSE](LICENSE).
