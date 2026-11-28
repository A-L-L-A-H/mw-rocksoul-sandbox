import { describe, expect, it } from 'bun:test';
import {
  CONTRACT_SCHEMA_VERSION,
  ContractError,
  REDACTED_PLACEHOLDER,
  assertSafeRelativePath,
  isExecutionPacket,
  isGatewayUsageEvent,
  isPcwEnvelope,
  isRiskDecision,
  isSafeSegment,
  isWorktreeLease,
  redactObject,
  redactString,
  toContractErrorEnvelope,
  type ExecutionPacket,
  type GatewayUsageEvent,
  type PcwEnvelope,
  type RiskDecision,
  type WorktreeLease,
} from '../src/contracts/index.js';

describe('@moonwitness/contracts v1 wire contracts', () => {
  it('validates all 5 canonical v1 contract payloads', () => {
    const packet: ExecutionPacket = {
      schemaVersion: CONTRACT_SCHEMA_VERSION,
      packetId: 'pkt-001',
      traceId: 'trace-001',
      actorId: 'rocksoul-agent',
      tenantId: 'tenant-1',
      targetRepo: 'mw-rocksoul-core',
      command: 'bun',
      args: ['test'],
      issuedAt: '2026-11-27T09:00:00Z',
      expiresAt: '2026-11-27T09:15:00Z',
    };
    expect(isExecutionPacket(packet)).toBe(true);
    expect(isExecutionPacket({ ...packet, schemaVersion: '0.0.0' })).toBe(false);

    const decision: RiskDecision = {
      schemaVersion: CONTRACT_SCHEMA_VERSION,
      decisionId: 'dec-001',
      packetId: 'pkt-001',
      tier: 'R1',
      verdict: 'allow',
      reason: 'disjoint worktree verified',
      policyRef: 'policy/r1-default',
      decidedAt: '2026-11-27T09:00:05Z',
    };
    expect(isRiskDecision(decision)).toBe(true);
    expect(isRiskDecision({ ...decision, verdict: 'unknown' })).toBe(false);

    const lease: WorktreeLease = {
      schemaVersion: CONTRACT_SCHEMA_VERSION,
      leaseId: 'lease-001',
      repo: 'mw-rocksoul-core',
      branch: 'repo-hygiene-ci-2026-11-27',
      relativePath: 'worktrees/lease-001',
      holderId: 'rocksoul-cli',
      state: 'active',
      acquiredAt: '2026-11-27T09:00:00Z',
      expiresAt: '2026-11-27T09:30:00Z',
    };
    expect(isWorktreeLease(lease)).toBe(true);
    expect(isWorktreeLease({ ...lease, state: 'invalid' })).toBe(false);

    const envelope: PcwEnvelope = {
      schemaVersion: CONTRACT_SCHEMA_VERSION,
      envelopeId: 'pcw-001',
      kind: 'verification',
      source: 'rocksoul-core',
      correlationId: 'corr-001',
      timestamp: '2026-11-27T09:10:00Z',
      payload: { ok: true },
    };
    expect(isPcwEnvelope(envelope)).toBe(true);
    expect(isPcwEnvelope({ ...envelope, payload: null })).toBe(false);

    const usage: GatewayUsageEvent = {
      schemaVersion: CONTRACT_SCHEMA_VERSION,
      eventId: 'evt-001',
      tenantId: 'tenant-1',
      service: 'rocksoul-gateway',
      model: 'qwen2.5-coder:14b',
      inputTokens: 1200,
      outputTokens: 320,
      latencyMs: 145,
      statusCode: 200,
      recordedAt: '2026-11-27T09:05:00Z',
    };
    expect(isGatewayUsageEvent(usage)).toBe(true);
    expect(isGatewayUsageEvent({ ...usage, inputTokens: -1 })).toBe(false);
  });

  it('exposes canonical ContractError, redaction, and path-safety helpers', () => {
    const err = new ContractError({
      code: 'CONTRACT_VALIDATION_FAILED',
      message: 'bad payload',
      traceId: 'trace-err',
    });
    const env = toContractErrorEnvelope(err);
    expect(env.schemaVersion).toBe(CONTRACT_SCHEMA_VERSION);
    expect(env.code).toBe('CONTRACT_VALIDATION_FAILED');
    expect(env.retryable).toBe(false);
    expect(env.traceId).toBe('trace-err');

    expect(redactString('Authorization: Bearer secret_token_123456')).toContain(REDACTED_PLACEHOLDER);
    const redacted = redactObject({ apiKey: 'sk_live_1234567890abcdef', safe: 'ok' }) as Record<string, unknown>;
    expect(redacted.apiKey).toBe(REDACTED_PLACEHOLDER);
    expect(redacted.safe).toBe('ok');

    expect(isSafeSegment('contracts')).toBe(true);
    expect(isSafeSegment('..')).toBe(false);
    expect(assertSafeRelativePath('src/contracts/index.ts')).toBe('src/contracts/index.ts');
    expect(() => assertSafeRelativePath('../etc/passwd')).toThrow(ContractError);
  });
});
