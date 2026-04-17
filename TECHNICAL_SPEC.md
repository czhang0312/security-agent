# Security Agent Technical Spec

## Purpose

This document defines a lean technical design for the MVP of `security-agent`.

The product goal is already captured in `PRD.md`. This spec focuses on how the MVP should work at a system level, with emphasis on the agent-first reachability model.

## MVP Technical Objective

Build a local CLI for Ruby on Rails repositories that:

1. detects vulnerable gems from Bundler metadata
2. launches an autonomous agent to investigate whether vulnerable functionality appears reachable in the repo
3. ranks findings using vulnerability facts plus investigation evidence
4. outputs an actionable report in terminal and JSON formats

## Design Principles

- Deterministic systems establish facts
- The agent is the primary reachability engine
- Every conclusion must be tied to inspectable evidence
- The system should make narrow, defensible claims
- The scan pipeline should be usable end-to-end early

## System Overview

The MVP consists of five main subsystems:

1. CLI layer
2. Dependency and advisory engine
3. Agent investigation runtime
4. Prioritization engine
5. Reporting layer

### High-Level Flow

1. User runs `security-agent scan` inside a Rails repository.
2. CLI validates config and repo type.
3. Dependency engine parses `Gemfile.lock` and builds a normalized gem inventory.
4. Advisory engine matches gem versions to known vulnerabilities.
5. For each candidate finding, the investigation runtime launches an agent task.
6. The agent inspects the repo, runs shell search commands, reads relevant files, and reasons about whether the affected functionality appears reachable.
7. The prioritization engine combines vulnerability metadata with investigation output.
8. The reporting layer renders terminal output and optional JSON.

## Proposed CLI Surface

Initial commands:

- `security-agent scan`
- `security-agent scan --json`
- `security-agent scan --output <path>`
- `security-agent scan --config <path>`
- `security-agent scan --max-findings <n>`

Possible later commands:

- `security-agent advisories update`
- `security-agent explain <finding-id>`
- `security-agent config init`

## Core Components

### 1. CLI Layer

Responsibilities:

- Parse arguments and flags
- Load config
- Detect current repo context
- Orchestrate scan execution
- Set exit codes

Key behavior:

- Fail early if the repo is not a Rails repo
- Support readable human output by default
- Support JSON output for downstream use

### 2. Dependency and Advisory Engine

Responsibilities:

- Parse `Gemfile.lock`
- Build direct and transitive dependency inventory
- Normalize gem metadata
- Match gems to advisory sources
- Recommend fixed versions

Expected output model:

- dependency graph
- vulnerable gem findings
- advisory metadata
- fixed version metadata

This layer should remain deterministic and testable without the agent.

### 3. Agent Investigation Runtime

Responsibilities:

- Receive a vulnerable gem finding plus repo context
- Launch an investigation task
- Allow controlled shell/file exploration of the repo
- Collect evidence
- Return a structured reachability assessment

This is the core differentiator of the system.

### 4. Prioritization Engine

Responsibilities:

- Combine severity, reachability, confidence, and dependency position
- Assign priority tiers
- Explain why a finding is ranked where it is

### 5. Reporting Layer

Responsibilities:

- Format terminal output
- Emit JSON output
- Include evidence and investigation summaries
- Mark suppressed findings appropriately

## Agent-First Investigation Model

The agent is responsible for determining whether a vulnerable gem appears meaningfully reachable in the application.

The agent should be able to:

- search the repo using shell commands
- inspect relevant source files
- follow Rails wiring across routes, controllers, models, jobs, services, and initializers
- trace function calls where possible
- trace variable flow at a lightweight level where relevant
- inspect gem integration points
- identify whether affected APIs, namespaces, or features appear used

The agent should not be treated as a generic freeform chatbot. It should run within a structured investigation loop.

## Investigation Inputs

Each agent investigation should start with a bounded input package.

Minimum inputs:

- repo root path
- gem name
- installed version
- advisory id or CVE
- advisory severity
- advisory summary
- known fixed version
- any known affected classes, methods, namespaces, or usage hints if available

Optional grounding inputs:

- whether gem is direct or transitive
- known `require` names
- lightweight precomputed references from fast repo search

The system should avoid dumping the entire repo into the prompt up front. The agent should retrieve context incrementally through tools.

## Investigation Loop

Each vulnerable finding should move through the same investigation lifecycle.

### Step 1: Plan

The agent forms a short investigation plan:

- what files or directories are likely relevant
- what search terms to try
- what Rails integration points matter

### Step 2: Explore

The agent runs repo navigation and search commands such as:

- fast text search for gem names, namespaces, classes, or methods
- targeted file inspection
- Rails structure inspection

The implementation should strongly prefer fast search tools like `rg`.

### Step 3: Trace

The agent attempts to trace how application code may reach affected functionality by:

- following references
- reading nearby files
- checking where classes or methods are called
- examining control flow and data propagation at a practical level

### Step 4: Decide

The agent returns one of:

- `reachable`
- `possibly_reachable`
- `not_observed`

### Step 5: Explain

The agent must provide:

- reasoning summary
- evidence list
- assumptions list
- confidence score

## Tooling Model

The agent runtime should expose a small set of tools rather than arbitrary execution freedom.

Recommended tool categories:

- shell search tool
- file read tool
- directory listing tool
- structured repo metadata tool

For MVP, a shell tool may be enough if it is constrained and observable.

### Allowed Command Profile

The investigation agent should be optimized for read-only repo exploration.

Initial command set should favor:

- `rg`
- `ls`
- `find`
- `sed`
- `cat`

The runtime should avoid write commands during analysis.

### Command Logging

Every command executed by the agent should be recorded for:

- auditability
- debugging
- user trust

This log does not have to be fully exposed in terminal output, but it should be available in structured results.

## Evidence Schema

Every finding should store structured evidence.

Suggested evidence fields:

- `kind`
- `summary`
- `path`
- `line`
- `symbol`
- `command`
- `snippet`
- `relevance`

Examples of evidence kinds:

- `gem_reference`
- `require_call`
- `class_reference`
- `method_call`
- `route_path`
- `initializer_config`
- `middleware_registration`
- `command_result`
- `reasoning_note`

## Reachability Output Schema

Each investigation should return a structured object similar to:

```json
{
  "status": "reachable",
  "confidence": 0.82,
  "reasoning_summary": "The application loads the gem in an initializer and calls affected functionality from a controller path used in production flows.",
  "assumptions": [
    "The vulnerable method mapping from advisory metadata is accurate."
  ],
  "evidence": [
    {
      "kind": "initializer_config",
      "summary": "Gem configured in an initializer",
      "path": "config/initializers/example.rb",
      "line": 12
    }
  ],
  "commands_run": [
    "rg \"ExampleGem|ExampleNamespace\" .",
    "sed -n '1,120p' config/initializers/example.rb"
  ]
}
```

The exact schema can change, but the MVP should preserve structured evidence instead of returning only prose.

## Guardrails

The system should reduce unsupported conclusions through explicit guardrails.

Required guardrails:

- The agent must distinguish observed evidence from inference
- The agent must not claim exploitability when only usage is observed
- The agent must include assumptions when reasoning depends on incomplete traces
- The agent must return `possibly_reachable` instead of overstating certainty
- The final system should preserve the raw evidence alongside the conclusion

## Rails-Specific Investigation Heuristics

The MVP should include Rails-aware patterns that help the agent search effectively.

High-value investigation targets:

- `config/routes.rb`
- `config/initializers/`
- `app/controllers/`
- `app/models/`
- `app/services/`
- `app/jobs/`
- `lib/`
- middleware setup
- framework config files

High-value questions for the agent:

- Is the gem explicitly required or configured?
- Are gem namespaces or classes referenced in application code?
- Do routes lead into controllers that invoke affected code?
- Is the affected functionality only present in dead or test-only paths?
- Is the gem transitive-only with no observed application touchpoints?

## Orchestration Strategy

The system should not blindly run full investigations for every vulnerability without limits.

Recommended MVP approach:

- identify all vulnerable gems first
- deduplicate similar findings when possible
- investigate highest-severity or highest-signal findings first
- cap investigation count or depth with configurable limits

This matters for latency and cost control.

## Prioritization Model

Priority should be computed after investigation.

Inputs:

- severity
- reachability status
- confidence
- direct vs transitive dependency

Suggested initial logic:

- `High`: severe advisory plus `reachable` plus moderate-to-high confidence
- `Medium`: advisory present plus `possibly_reachable`, or reachable with weak confidence
- `Low`: `not_observed`, or transitive-only with weak evidence

The exact scoring can stay simple in MVP. Explainability matters more than model complexity.

## Output Design

### Terminal Output

The default CLI output should optimize for fast action.

Per finding:

- priority tier
- gem name and version
- advisory id
- reachability status
- confidence
- short reasoning summary
- fixed version

Optional expanded view:

- top evidence items
- assumptions
- files inspected count

### JSON Output

The JSON output should include:

- scan metadata
- dependency summary
- full finding list
- structured investigation output
- suppressions applied

## Configuration

The MVP should support a local config file for scan behavior.

Likely settings:

- advisory cache path
- output mode defaults
- suppression file path
- max findings to investigate
- max commands per investigation
- model/provider settings for agent analysis

## Suppressions

Suppressions should be applied after advisory matching and before final display.

Supported suppression targets:

- advisory id
- gem name

Recommended fields:

- `reason`
- `expires_at`
- `created_by`

## Error Handling

The system should degrade gracefully.

Expected failure modes:

- invalid or missing `Gemfile.lock`
- unsupported repo layout
- advisory source unavailable
- model or agent invocation failure
- incomplete investigation due to command or token limits

Fallback behavior:

- if investigation fails, retain the raw vulnerable finding
- mark reachability as unknown or investigation_failed internally
- surface the failure clearly in JSON and concisely in terminal output

## Testing Strategy

The MVP should be tested at three layers.

### Unit Tests

- lockfile parsing
- version matching
- ranking logic
- config parsing

### Integration Tests

- end-to-end scans on sample Rails repos
- JSON schema stability
- suppression behavior

### Evaluation Cases

- repos where vulnerable gems are clearly used
- repos where vulnerable gems are present but unused
- ambiguous repos where the correct answer is `possibly_reachable`

Because the system is agent-first, curated evaluation repos will be important. They are the main way to judge reasoning quality over time.

## Open Technical Decisions

These decisions still need to be made before implementation starts:

- What language will the CLI and orchestration layer use?
- Which advisory sources will be used first?
- What LLM/provider will run the agent investigations?
- How will shell command execution be sandboxed or constrained?
- What is the JSON schema versioning strategy?
- How many findings should be investigated by default in one scan?
- Should investigations run serially or in parallel?

## Recommended First Implementation Slice

The first end-to-end technical slice should be:

1. CLI scaffold with `scan`
2. Rails repo detection
3. `Gemfile.lock` parsing
4. Advisory matching for vulnerable gems
5. Single-finding agent investigation using read-only repo commands
6. Basic terminal output with one reasoning summary and evidence list

This slice proves the core architecture early. If this works well, the rest of the system becomes mostly scaling, tuning, and productization work.
