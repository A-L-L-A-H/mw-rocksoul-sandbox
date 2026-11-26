# mw-rocksoul-sandbox

RockSoul isolated execution sandbox daemon (TypeScript/Bun, default port `4540`) providing ephemeral git worktree leases with monotonic fencing tokens, strict allowlisted command execution, stdout/stderr secret & PII redaction, and OTLP JSON tracing to `mw-echo` (`:4310/v1/traces`).

## Components

- `src/lease-manager.ts` — Ephemeral git worktree lease lifecycle (`acquireLease`, `renewLease`, `validateLeaseAccess`, `releaseLease`, `reapExpiredLeases`) with strictly monotonic fencing tokens that reject stale or superseded tokens (`STALE_FENCING_TOKEN`, HTTP `409`).
- `src/redactor.ts` — High-precision redaction of JWTs, PEM private keys, Bearer/Basic tokens, provider API keys (`sk-*`, `ghp_*`, `AKIA*`, `AIza*`, `xox*`), DB credentials, key-value secrets, emails, SSNs, NIKs, E.164 phone numbers, and Luhn-validated credit card numbers.
- `src/command-runner.ts` — Direct `Bun.spawn` execution (no shell invocation) enforcing a strict binary/subcommand allowlist, denied flag rules, sanitized host environment, bounded timeout, bounded output bytes with truncation termination, and mandatory stdout/stderr redaction.
- `src/otel-exporter.ts` — OTLP/HTTP JSON trace exporter (`resourceSpans` / `scopeSpans` / `spans`) compatible with `mw-echo` (`POST http://127.0.0.1:4310/v1/traces`), with automatic attribute redaction and fail-open delivery stats.
- `src/server.ts` — Bun HTTP daemon on port `4540`.

## HTTP Endpoints

- `GET /health` — Service health, active lease counts, and OTLP exporter statistics.
- `POST /leases` — Acquire an ephemeral git worktree lease (`repoPath`, `ownerId`, optional `baseRef`, `ttlMs`, `exclusive`, `label`).
- `GET /leases` / `GET /leases/:id` — Inspect active/historical leases.
- `POST /leases/:id/renew` — Renew lease TTL and monotonically advance its fencing token (invalidating the prior token).
- `DELETE /leases/:id` — Release the lease and remove its ephemeral git worktree.
- `POST /exec` — Execute an allowlisted command inside a leased worktree (`leaseId`, `fencingToken`, `command`, optional `cwd`, `timeoutMs`, `maxOutputBytes`).

## Commands

```bash
bun run start   # Start HTTP daemon on :4540
bun test        # Run full unit & integration test suite
```
