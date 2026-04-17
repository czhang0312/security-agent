# Security Agent PRD

## Overview

`security-agent` is a local CLI for Ruby on Rails repositories that identifies vulnerable gems, launches an autonomous agent to investigate the local codebase, and ranks what to patch first based on evidence-backed reachability reasoning.

The product is designed to reduce the noise created by traditional dependency scanners. Instead of only reporting that a vulnerable dependency exists, it uses an agent with repository access to investigate whether the vulnerable functionality appears relevant in the actual codebase.

## Problem

Rails developers regularly receive dependency vulnerability reports that are difficult to prioritize. Existing scanners often stop at version matching and do not answer whether a vulnerable gem is actually used in a meaningful way by the application.

This creates three core problems:

- Too many alerts with too little context
- Developer time wasted patching low-relevance findings first
- Low trust in scanner output because all findings look equally urgent

## Vision

Developers should be able to run a single command locally in a Rails repository and get an evidence-backed list of the vulnerabilities that matter most in their application.

`security-agent` should become the tool that answers:

> Which vulnerable gems in this Rails repo should I patch first, based on an autonomous investigation of how my app actually uses them?

## Target Users

### Primary Users

- Individual Ruby on Rails developers
- Startup engineering teams
- Small teams without dedicated application security staff

### Secondary Users

- Security-conscious engineering teams looking for a local triage tool
- Teams that want a more actionable first pass before broader security review

## Core Value Proposition

Traditional dependency scanners answer:

> A vulnerable gem exists in your dependency tree.

`security-agent` answers:

> This vulnerable gem exists, the agent investigated your repo and found evidence it appears reachable in your Rails app, and it should be prioritized ahead of these other findings.

The differentiation is autonomous repo investigation and prioritization based on repo-specific usage, not just advisory presence.

## Goals

### Primary Goal

Help Rails developers identify which vulnerable gems in their repository should be patched first.

### Secondary Goals

- Reduce alert fatigue from dependency vulnerability scans
- Improve developer trust through evidence-backed prioritization
- Provide actionable output without requiring a hosted platform or security team
- Use agentic investigation to reason through repository structure, call paths, and feature wiring

## Non-Goals

The MVP will not attempt to do the following:

- Support ecosystems beyond Ruby on Rails
- Provide CI integration
- Provide a hosted dashboard or SaaS backend
- Perform runtime instrumentation
- Generate automatic pull requests or code changes
- Act as a full static application security testing tool
- Scan containers, infrastructure, or secrets

## Product Scope

### In Scope for MVP

- Local CLI experience
- Ruby on Rails repository detection
- Bundler dependency parsing via `Gemfile` and `Gemfile.lock`
- Detection of direct and transitive vulnerable gems
- Agent-first reachability analysis for vulnerable gems
- Prioritized findings with evidence
- Human-readable terminal output
- Machine-readable JSON output
- Local suppression and ignore rules

### Out of Scope for MVP

- Non-Rails projects
- Cloud execution or remote dashboards
- Runtime exploit validation
- Auto-remediation
- Broad application security coverage beyond dependency triage

## User Story

As a Rails developer, I want to run a CLI locally in my repository and get a prioritized list of vulnerable gems that appear relevant to my codebase, so I know what to patch first.

## User Workflow

1. The user installs `security-agent`.
2. The user runs `security-agent scan` inside a Rails repository.
3. The tool detects repository structure and parses Bundler dependencies.
4. The tool matches dependency versions against known vulnerability and advisory sources.
5. The tool launches an agent to investigate the repository using shell commands, file traversal, and code inspection.
6. The agent determines whether vulnerable gems and affected functionality appear used.
7. The tool ranks the findings by remediation priority.
8. The tool outputs a readable CLI report and optional JSON data.

## Product Principles

- Local-first workflow
- Evidence over noise
- Narrow, defensible claims
- Explainable prioritization
- One-command usefulness
- Agent-led investigation with transparent evidence

## Functional Requirements

### Repository and Dependency Analysis

- Detect whether the current repository is a Ruby on Rails project
- Parse `Gemfile` and `Gemfile.lock`
- Build an inventory of direct and transitive gems
- Identify installed gem versions accurately

### Vulnerability Detection

- Match gem versions against known vulnerability and advisory data
- Use public Ruby advisory data and CVE enrichment where practical
- Recommend fixed versions when available

### Reachability Analysis

- Launch an autonomous agent with local repo access
- Allow the agent to inspect files and run shell commands needed for investigation
- Allow the agent to navigate Rails-specific integration points such as:
  - initializers
  - middleware configuration
  - framework wiring
  - controllers, models, jobs, services, and routes
  - `require` usage
  - gem namespaces, classes, methods, and call sites referenced in application code
- Support agent reasoning over:
  - call-path tracing
  - variable propagation
  - feature wiring
  - likely execution paths into vulnerable functionality
- Classify findings using:
  - `reachable`
  - `possibly_reachable`
  - `not_observed`

### Prioritization

- Rank findings using:
  - advisory severity
  - reachability status
  - confidence level
  - direct versus transitive dependency status
- Present a clear priority tier for each finding

### Output

- Provide human-readable terminal output for local use
- Provide JSON output for automation and downstream tooling
- Include concise supporting evidence for each prioritized finding
- Include investigation evidence such as files inspected, commands run, and reasoning summary

### Suppressions

- Support a local suppression file
- Allow suppressions by advisory or gem
- Allow a reason and optional expiration date

## Reachability Definition

For the MVP, a vulnerability is considered meaningfully reachable when:

- The vulnerable gem exists in the resolved dependency graph
- The agent finds evidence that the application appears to load or use the gem
- The agent finds evidence that the affected API, namespace, feature, or code path is referenced or likely invoked by the application

The product should not claim confirmed exploitability unless there is unusually strong evidence. In MVP language, `reachable` means usage is observed or strongly inferred, not that exploitation has been proven.

## Analysis Model

The product should combine deterministic vulnerability detection with agent-first repository reasoning.

### Deterministic Layer

- Parse Bundler dependency data
- Match dependencies to advisories
- Provide lightweight grounding signals where useful

### Agentic Investigation Layer

- Investigate the repository using local shell access and file traversal
- Run commands such as fast text search and targeted file inspection
- Follow Rails wiring and code structure to trace how vulnerable functionality may be reached
- Interpret ambiguous usage patterns that simple rules cannot model well
- Produce evidence-backed reasoning and confidence levels

This split keeps the product credible. Deterministic analysis establishes the hard facts about vulnerable gems. The agent performs the primary reachability investigation and supplies the judgment layer.

## Prioritization Model

The MVP prioritization model should be intentionally simple and explainable.

### High Priority

- Severe vulnerability
- Strong evidence from agent investigation that the gem and affected functionality are reachable

### Medium Priority

- Vulnerability present
- Gem appears used
- Affected functionality is uncertain or only partially evidenced

### Low Priority

- Vulnerability present
- No meaningful usage observed, weak evidence only, or transitive-only with no strong usage signal

Future versions may incorporate exploit maturity, exposure level, and environment context, but these are intentionally excluded from MVP unless they prove easy and reliable to add.

## Output Requirements

### Terminal Output

Each finding should include:

- Gem name
- Installed version
- Advisory or CVE identifier
- Severity
- Reachability status
- Short evidence summary
- Investigation summary
- Recommended fixed version
- Priority tier

### JSON Output

The JSON output should include:

- Repository metadata
- Scan timestamp
- Dependency inventory summary
- Full finding objects
- Suppression metadata
- Evidence and confidence fields suitable for downstream automation
- Investigation metadata such as commands run and files inspected where appropriate

## Success Metrics

The MVP should be evaluated against practical usefulness, not raw scan volume.

Key success measures:

- Time to first useful result on a Rails repository
- Percentage of findings with usable supporting evidence
- Reduction in low-value alerts compared to a raw dependency scan
- User-reported trust in prioritization
- Frequency of scans that produce clear top-priority patch actions
- Percentage of findings whose reasoning users judge as credible and inspectable

## Risks

- Ruby and Rails applications can use dynamic patterns that make reachability difficult to prove
- Agentic analysis may overstate confidence or miss paths if not tightly constrained
- Advisory normalization across sources may be inconsistent
- Large repositories may increase scan time and analysis cost
- Users may misinterpret `reachable` as proven exploitability unless wording is precise
- Agent investigations may be nondeterministic across runs if exploration is not well structured
- Evidence may be insufficient if the agent explores too broadly or stops too early

## Assumptions

- The MVP is strictly a local CLI product
- Ruby on Rails is the only supported ecosystem at launch
- Code is allowed to leave the local machine for agent-assisted analysis
- Reachability is primarily determined by agent investigation of observed or strongly inferred usage of vulnerable functionality, not exploit proof
- The initial buyer and user are developers and small teams rather than large enterprise security organizations

## MVP Milestones

### Milestone 1: Dependency and Advisory Foundation

- Rails repo detection
- Bundler dependency inventory
- Advisory and CVE matching

### Milestone 2: Agentic Investigation Foundation

- Agent repo traversal and shell command execution
- Rails-aware investigation patterns for affected functionality

### Milestone 3: Agentic Prioritization

- Agent-led reasoning over repository context
- Evidence-backed reachability classification
- Confidence scoring

### Milestone 4: Usable Product Surface

- Terminal report
- JSON export
- Suppression file support

## Future Opportunities

Potential post-MVP expansions:

- CI integration
- Additional Ruby ecosystem support beyond Rails conventions
- More precise call-path analysis
- Mitigation guidance when patches are unavailable
- Broader ecosystem support beyond Ruby

## Summary

`security-agent` is a Rails-first local CLI that helps developers patch the right vulnerabilities first. Its core product bet is that dependency scanning becomes much more useful when paired with an autonomous repository investigation agent and clear, evidence-backed prioritization.
