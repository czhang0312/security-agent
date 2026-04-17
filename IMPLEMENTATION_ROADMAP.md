# Security Agent Implementation Roadmap

## Purpose

This roadmap translates the product requirements in `PRD.md` into a practical build sequence for the MVP.

The goal is not to design the entire system up front. The goal is to identify the smallest set of implementation milestones needed to produce a useful Ruby on Rails CLI that:

- detects vulnerable gems
- launches an agent to investigate whether they appear used in the repository
- prioritizes what to patch first

## Build Strategy

The MVP should be built in layers:

1. Establish deterministic dependency and advisory detection
2. Build an agent investigation loop with repo navigation and shell access
3. Add Rails-aware investigation patterns and evidence capture
4. Wrap the engine in a usable CLI with clear outputs and suppression support

This sequencing matters. The product should first become correct about vulnerable dependency facts, then useful through agent-led investigation and prioritization.

## Guiding Principles

- Start narrow and credible
- Prefer explainable results over ambitious claims
- Build the scan pipeline end-to-end early
- Make the agent the primary reachability engine
- Treat deterministic analysis as the grounding layer, not the reasoning layer

## MVP Workstreams

### 1. CLI Foundation

Objective:
Create the installable command-line interface and the minimal command structure.

Deliverables:

- Initial project scaffolding
- CLI entrypoint
- `security-agent scan` command
- Basic configuration loading
- Exit code behavior

Notes:

This should produce a runnable tool as early as possible, even if the first output is only dependency inventory.

### 2. Repository Detection and Dependency Inventory

Objective:
Detect Rails repositories and extract a trustworthy dependency graph from Bundler files.

Deliverables:

- Rails repo detection rules
- `Gemfile` parsing support where needed
- `Gemfile.lock` parsing
- Inventory of direct and transitive gems
- Internal normalized dependency model

Notes:

This is the factual foundation of the product. If this layer is wrong, everything downstream becomes unreliable.

### 3. Vulnerability and Advisory Matching

Objective:
Map installed gem versions to known vulnerabilities.

Deliverables:

- Advisory source selection and ingestion
- Normalized vulnerability model
- Gem version matching logic
- Fixed-version recommendation logic
- Local caching strategy for advisory data

Notes:

This milestone should produce a raw vulnerability scan for Rails repos, even before reachability exists.

### 4. Agent Investigation Runtime

Objective:
Create the autonomous investigation loop that can inspect the repository the way a strong engineer would.

Deliverables:

- Agent runtime with access to local repository files
- Ability to run shell commands for code search and navigation
- Investigation session model per vulnerable gem or finding
- Guardrails around what the agent can claim
- Initial evidence model for commands run, files inspected, and conclusions reached

Notes:

This milestone is the core differentiator. The agent should be able to search, navigate, and reason through the repo instead of relying on a rigid static rules engine.

### 5. Rails-Aware Reachability Investigation

Objective:
Teach the agent how to investigate vulnerable gem usage in Ruby on Rails repositories.

Deliverables:

- Investigation prompts and evidence schema for reachability analysis
- Rails-aware investigation patterns covering:
  - initializers
  - routes
  - controllers
  - models
  - jobs
  - services
  - middleware
  - framework configuration
  - `require` usage
  - gem namespaces, methods, and call sites
- Reasoning patterns for tracing:
  - function calls
  - variable propagation
  - feature wiring
  - likely execution paths
- Output classifications:
  - `reachable`
  - `possibly_reachable`
  - `not_observed`
- Confidence scoring rules
- Guardrails to prevent unsupported claims

Notes:

The agent should reason over evidence, not invent evidence. The system should always preserve which facts came from dependency parsing versus which judgments came from investigation.

### 6. Prioritization and Ranking

Objective:
Turn raw findings into a patch-first report.

Deliverables:

- Priority model based on severity, reachability, confidence, and direct vs transitive status
- Ranking algorithm
- Explainability fields for each priority decision
- Stable output ordering

Notes:

This is where the product turns investigations into patch decisions. The ranking must feel useful and defensible, not arbitrary.

### 7. Output Surfaces

Objective:
Present results in a way developers can act on immediately.

Deliverables:

- Human-readable terminal output
- JSON output format
- Summary counts by priority and reachability
- Per-finding evidence display
- Investigation trace summary

Notes:

The terminal report should help a developer decide what to patch now. The JSON output should make the scanner scriptable later.

### 8. Suppressions and Local Configuration

Objective:
Allow teams to manage known exceptions without reintroducing noise.

Deliverables:

- Local config file format
- Advisory-level suppression
- Gem-level suppression
- Reason and expiration fields
- Suppressed finding handling in both terminal and JSON outputs

Notes:

Without suppressions, teams will quickly lose trust in repeated findings that they have consciously accepted or deferred.

## Recommended Milestones

### Milestone A: First Useful Scan

Goal:
Produce a working CLI that detects a Rails repo, parses `Gemfile.lock`, and reports vulnerable gems with fixed versions.

Success criteria:

- User can run `security-agent scan`
- Tool identifies vulnerable gems in a sample Rails repo
- Output is readable and technically correct at the dependency level

### Milestone B: Autonomous Repo Investigation

Goal:
Augment raw vulnerability output with agent-driven investigation of whether vulnerable gems appear used in the repo.

Success criteria:

- Agent can inspect files and run code-search commands during a scan
- Findings include investigation evidence where available
- Tool can separate apparently used gems from gems with no observed usage

### Milestone C: Prioritized Findings

Goal:
Rank findings using agent-derived reachability and confidence instead of severity alone.

Success criteria:

- Output clearly distinguishes top-priority findings
- Priority logic is explainable per finding

### Milestone D: MVP Productization

Goal:
Ship the full MVP experience with JSON output, suppressions, and agent-led investigation.

Success criteria:

- CLI is usable across multiple Rails repos
- Output supports both developer reading and automation
- Users can suppress accepted risk locally

## Suggested Epic Breakdown

### Epic 1: Project and CLI Setup

- Choose language/runtime for the CLI
- Create project scaffolding
- Add command parsing
- Define config loading and file layout

### Epic 2: Dependency Engine

- Parse Bundler lockfiles
- Build dependency graph model
- Normalize dependency metadata

### Epic 3: Advisory Engine

- Ingest advisory data
- Build version matching
- Return raw vulnerability findings

### Epic 4: Reachability Engine

- Build agent investigation runtime
- Define evidence format
- Add reachability classifications

### Epic 5: Agent Integration

- Define repo exploration workflow
- Define prompts and response schema
- Add confidence and guardrails
- Add shell command and file navigation tooling

### Epic 6: Reporting Layer

- Terminal formatter
- JSON serializer
- Summary and ranking output

### Epic 7: Policy Layer

- Config file support
- Suppressions
- Ignore and expiration handling

## Sequencing Recommendation

Recommended build order:

1. CLI scaffold
2. Bundler parsing
3. Advisory matching
4. Agent investigation runtime
5. Rails-aware investigation patterns
6. Priority ranking
7. Terminal and JSON output
8. Suppressions
9. Lightweight static signals only where they improve grounding or speed

This order gets a usable scanner into existence early, then layers in the core differentiator quickly. The agent should arrive early in the architecture, but only after the dependency and advisory facts are stable enough to ground its work.

## Key Technical Decisions To Make Early

These decisions should be made before implementation starts:

- What language will the CLI be written in?
- Which vulnerability/advisory sources will be used first?
- How will advisory data be cached locally?
- How will the agent execute shell commands and access files safely and repeatably?
- What output schema should JSON use?
- How much repo context is allowed to be sent for agentic analysis?
- What confidence thresholds map to `reachable`, `possibly_reachable`, and `not_observed`?

## Delivery Philosophy

The MVP should reach an end-to-end usable state quickly, even if early versions are narrow. A thin but correct scanner is more valuable than a broad but unreliable one.

The first major objective is a trustworthy scan pipeline plus a credible agent investigation loop. Perfect reachability analysis is not required, but inspectable and useful reasoning is.
