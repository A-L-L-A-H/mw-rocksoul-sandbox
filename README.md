# mw-rocksoul-sandbox — Isolated execution sandbox daemon with ephemeral git worktree leases.

**Repository:** [`A-L-L-A-H/mw-rocksoul-sandbox`](https://github.com/A-L-L-A-H/mw-rocksoul-sandbox) · **Stack:** TypeScript · Bun

## What it does

Applies monotonic fencing tokens, allowlisted commands, sanitized environments, bounded output, and secret/PII redaction with OTLP traces.

## Quick start

```bash
bun install
bun run start
```

## Verify

```bash
bun run typecheck
bun test
```

## Configuration

- **Port:** 4540
- **Key configuration:** ROCKSOUL_SANDBOX_PORT · ROCKSOUL_SANDBOX_WORKTREES_DIR

## Notes

Traces are exported to mw-echo at :4310/v1/traces when configured.
