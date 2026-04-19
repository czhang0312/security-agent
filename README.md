# security-agent

`security-agent` is a local CLI for Ruby on Rails repositories that finds vulnerable gems, investigates whether the vulnerable functionality appears reachable in your app, and ranks what to patch first.

This is an early MVP. It is designed for technical users and small teams, not as a fully hardened enterprise scanner.

## Current Scope

- Ruby on Rails repositories only
- Bundler / `Gemfile.lock` dependency matching
- Local advisory cache built from GitHub Advisory Database data
- Agent-assisted reachability analysis for the top matched advisories
- Terminal and JSON output

## Requirements

- Python 3.11+
- A Rails repository with `Gemfile`, `Gemfile.lock`, `app/`, and `config/routes.rb`
- Network access for `security-agent advisories update`
- `OPENAI_API_KEY` if you want real agentic analysis with OpenAI

## Install

```bash
pip install security-agent
```

## Quickstart

1. Build the local advisory cache:

```bash
security-agent advisories update
```

2. Set your OpenAI API key:

```bash
export OPENAI_API_KEY="your_api_key_here"
```

3. Scan a Rails repository:

```bash
security-agent scan /path/to/rails-repo --investigator openai
```

## Recommended Usage

The recommended real investigator for this MVP is `openai`.

```bash
security-agent scan /path/to/rails-repo --investigator openai
```

You can also request JSON output:

```bash
security-agent scan /path/to/rails-repo --investigator openai --json
```

`--json` writes the structured result to `stdout`. Progress and retry messages are written to `stderr`, so the JSON stays machine-readable.

## Example

Terminal:

```bash
security-agent scan ../progress_tracker --investigator openai
```

JSON:

```bash
security-agent scan ../progress_tracker --investigator openai --json > result.json
```

## How It Works

1. Parse `Gemfile.lock`
2. Match installed gems against the local advisory cache
3. Rank the findings
4. Investigate the top 3 advisories by default
5. Return reachability evidence and a patch-priority report

Current default investigation budget:

```bash
security-agent scan /path/to/rails-repo --max-investigations 3
```

## Commands

Update the advisory cache:

```bash
security-agent advisories update
```

Scan with the default mock investigator:

```bash
security-agent scan /path/to/rails-repo
```

Scan with OpenAI:

```bash
security-agent scan /path/to/rails-repo --investigator openai
```

## Limitations

- Rails only
- Reachability judgments are not exploit proofs
- Only the top matched advisories are investigated per scan
- Advisory data is local and must be refreshed with `security-agent advisories update`
- Provider failures may fall back to the mock investigator

## Troubleshooting

Missing advisory cache:

```text
error: Advisory cache not found ... Run `security-agent advisories update` first.
```

Fix:

```bash
security-agent advisories update
```

Missing OpenAI API key:

If you run `--investigator openai` without `OPENAI_API_KEY`, the scan will fall back to the mock investigator.

Provider timeout or temporary API failure:

- `security-agent` retries transient OpenAI failures with exponential backoff
- if retries are exhausted, the scan falls back to the mock investigator
- fallback details appear in the result output

Advisory update fails:

- verify you have network access
- retry `security-agent advisories update`
- if needed, override the source URL with `--source-url`

## Exit Codes

- `0`: scan completed and found no matched advisories
- `1`: scan completed and found one or more matched advisories
- `2`: usage error or setup error, such as unsupported repo shape or missing advisory cache

## MVP Positioning

This release is an early technical MVP. The scanner is designed to be evidence-driven and narrow in its claims:

- it can tell you what looks reachable in your repository
- it does not prove exploitability
- it is intended to help developers prioritize, not replace full security review
