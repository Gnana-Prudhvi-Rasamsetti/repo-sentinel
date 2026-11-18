# AI Usage Log

## Runtime AI

Repo Sentinel does not use an LLM or other generative AI service at runtime. Its repository review is performed by deterministic static-analysis rules and heuristics. Optional dependency auditing queries the OSV public API; that is not an AI service.

## AI assistance during development

OpenAI Codex assisted with project implementation and review, explaining design choices, and drafting the README and demo walkthrough. The project owner directed the work, reviewed the changes, and remains responsible for the submitted code. No model API key or AI provider integration is required to install or run Repo Sentinel.

## Data handling

The local scanner reads files in the repository path supplied by the user. It does not transmit source code to an LLM. If the optional dependency audit is enabled, supported pinned package coordinates and versions are sent to the OSV public API to check for advisories.
