# SOC Evidence Benchmark Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a paper-grade, evidence-producing SOC benchmark with three-arm comparisons and an inspectable web report.

**Architecture:** A focused `soc_evidence.py` module owns fixtures, parsing, deterministic scoring, statistics, execution, and reports. Existing benchmark routing delegates to it. The React Benchmark view consumes a backward-compatible union of MCQ and evidence result types.

**Tech Stack:** Python 3.10, FastAPI, pytest, React 18, TypeScript, Vite.

**Spec:** `docs/superpowers/specs/2026-08-18-soc-evidence-benchmark-design.md`

## Global Constraints

- Do not expose credentials, environment secrets, or private server details.
- Preserve existing benchmark run compatibility.
- New scoring must be deterministic for a fixed input and seed.
- Every production behavior starts with a failing test.

---

### Task 1: Evidence task and scoring contract

- [ ] Add failing tests for schema, parsing, metrics, confidence intervals, and reports.
- [ ] Implement `cyberorion/bench/soc_evidence.py` and make focused tests green.

### Task 2: Runner and API integration

- [ ] Add failing API tests for suite acceptance, three modes, preview, comparison, and downloads.
- [ ] Add routing and safe artifact responses while preserving old runs.

### Task 3: Benchmark evaluation console

- [ ] Add strict evidence types and API methods.
- [ ] Build three-arm results, evidence drill-down, and terminal trace UI.
- [ ] Run TypeScript and production build.

### Task 4: Experiment, deploy, and verify

- [ ] Run the benchmark, inspect failure taxonomy, and iterate on weak output.
- [ ] Deploy through `ssh treehole` without printing secrets.
- [ ] Verify public page, API, downloads, responsive layout, and browser console.

