# SOC Evidence Benchmark Design

## Goal

Turn Benchmark from a multiple-choice showcase into a reproducible SOC evaluation that produces inspectable evidence for product demos and paper results.

## Scope

- Keep the existing multiple-choice suites as the knowledge subscore.
- Add `soc_evidence`, a structured open-response suite built from deterministic telemetry cases.
- Compare `base` (plain LLM), `rag` (LLM plus retrieval context), and `agent` (CyberOrion multi-Agent workflow plus tools and retrieval).
- Persist every input, prediction, citation, Agent trace, metric, latency, token estimate, and failure reason.
- Expose confidence intervals, failure taxonomy, arm comparison, drill-down, and downloadable JSON/Markdown artifacts.

## Evaluation Contract

Each case contains telemetry with stable evidence IDs, gold incident labels, ATT&CK techniques, required response actions, prohibited actions, and an evidence map. A prediction is structured JSON with verdict, labels, techniques, cited evidence IDs, actions, claims, confidence, and optional tool trace.

Scoring is deterministic: detection and ATT&CK precision/recall/F1; evidence grounding and unsupported-claim rate; response completeness and unsafe-action rate; tool-call validity and useful-action ratio; task success; latency and failure rate. Aggregate means include deterministic bootstrap 95% confidence intervals.

## UI

The Benchmark page is a dark SOC evaluation console. It leads with a three-arm comparison matrix and evidence coverage, then a compact task list and drill-down showing telemetry, expected evidence, prediction, Agent/tool trace, score breakdown, and failure tags. Existing MCQ runs remain readable through compatibility types.

## Reliability

Malformed model output becomes a scored parse failure rather than crashing a run. Report generation is atomic at run completion. Old run files remain listable and viewable.

