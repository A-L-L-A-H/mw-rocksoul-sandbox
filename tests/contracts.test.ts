import { describe, expect, it } from 'bun:test';
import {
  ContractValidationError,
  SCHEMA_VERSION_EXECUTION_PACKET,
  SCHEMA_VERSION_GATEWAY_USAGE_EVENT,
  SCHEMA_VERSION_PCW_ENVELOPE,
  SCHEMA_VERSION_RISK_DECISION,
  SCHEMA_VERSION_WORKTREE_LEASE,
  parseExecutionPacket,
  parseGatewayUsageEvent,
  parsePcwEnvelope,
  parseRiskDecision,
  parseWorktreeLease,
  serializeExecutionPacket,
  serializeGatewayUsageEvent,
  serializePcwEnvelope,
  serializeRiskDecision,
  serializeWorktreeLease,
  validateExecutionPacket,
  validateGatewayUsageEvent,
  validatePcwEnvelope,
  validateRiskDecision,
  validateWorktreeLease,
  type ExecutionPacket,
  type GatewayUsageEvent,
  type PcwEnvelope,
  type RiskDecision,
  type WorktreeLease,
} from '../src/contracts/index.js';

const TEST_SHA256_A = 'a'.repeat(64);
const TEST_SHA256_B = 'b'.repeat(64);
const TEST_COMMIT = '0123456789abcdef0123456789abcdef01234567';

function validExecutionPacket(): ExecutionPacket {
  return {
    schemaVersion: SCHEMA_VERSION_EXECUTION_PACKET,
    packetId: 'pkt-001',
    taskId: 'task-auth-race',
    sessionId: 'sess-101',
    principalId: 'dev@mw.local',
    agentProfile: 'rocksoul',
    dataClassification: 'local_only',
    riskTier: 'R1',
    action: 'fs.patch',
    capability: 'workspace.write',
    ownedPaths: ['src/contracts/common.ts'],
    command: 'bun',
    args: ['test', 'tests/contracts.test.ts'],
    leaseId: 'lease-001',
    fencingToken: 42,
    parentProofHashes: [TEST_SHA256_A],
    issuedAt: '2026-11-27T09:00:00Z',
    expiresAt: '2026-11-27T09:15:00Z',
    metadata: { wave: 'W4B' },
  };
}

function validRiskDecision(): RiskDecision {
  return {
    schemaVersion: SCHEMA_VERSION_RISK_DECISION,
    decisionId: 'dec-001',
    allowed: true,
    decision: 'allow',
    effectiveRiskTier: 'R1',
    dataClassification: 'local_only',
    targetZone: 'local',
    reasonCodes: [],
    messages: ['allowed in isolated worktree'],
    requiresIndependentVerification: true,
    requiresHumanApproval: false,
    verifiedGrantId: 'grant-1',
    scopeHash: TEST_SHA256_A,
    evaluatedAt: '2026-11-27T09:00:05Z',
    decisionSha256: TEST_SHA256_B,
  };
}

function validWorktreeLease(): WorktreeLease {
  return {
    schemaVersion: SCHEMA_VERSION_WORKTREE_LEASE,
    leaseId: 'lease-001',
    ownerId: 'rocksoul-cli',
    repoPath: 'z:/repo/mw-rocksoul-cli',
    worktreePath: 'z:/repo/.worktrees/lease-001',
    baseRef: 'main',
    baseCommit: TEST_COMMIT,
    fencingToken: 7,
    exclusive: true,
    label: 'wave-rs0',
    status: 'active',
    createdAt: '2026-11-27T09:00:00Z',
    updatedAt: '2026-11-27T09:00:00Z',
    expiresAt: '2026-11-27T09:30:00Z',
  };
}

function validPcwEnvelope(): PcwEnvelope {
  return {
    schemaVersion: SCHEMA_VERSION_PCW_ENVELOPE,
    envelopeId: 'pcw-001',
    taskId: 'task-auth-race',
    producerAgentId: 'w4-rocksoul-ts-contracts',
    reviewerAgentId: 'verifier-1',
    riskTier: 'R1',
    parentProofHashes: [TEST_SHA256_A],
    artifacts: [
      {
        id: 'art-diff',
        kind: 'diff',
        sha256: TEST_SHA256_A,
        sizeBytes: 512,
        path: 'src/contracts/common.ts',
      },
    ],
    checks: [
      {
        code: 'bun_test',
        command: 'bun test',
        status: 'pass',
        mandatory: true,
        exitCode: 0,
      },
    ],
    changedFiles: ['src/contracts/common.ts'],
    producedAt: '2026-11-27T09:10:00Z',
    expiresAt: '2026-11-28T09:10:00Z',
    merkleRoot: TEST_SHA256_A,
    envelopeSha256: TEST_SHA256_B,
  };
}

function validGatewayUsageEvent(): GatewayUsageEvent {
  return {
    schemaVersion: SCHEMA_VERSION_GATEWAY_USAGE_EVENT,
    eventId: 'evt-001',
    agentId: 'rocksoul',
    requestedModel: 'auto',
    resolvedProvider: 'ollama',
    resolvedModel: 'qwen2.5-coder:14b',
    classification: 'local_only',
    statusCode: 200,
    latencyMs: 145,
    promptTokens: 1200,
    completionTokens: 320,
    rtkTokensSaved: 280,
    redactionsCount: 2,
    egressBlocked: false,
    cacheHit: false,
    costUsdMicros: 0,
    createdAt: '2026-11-27T09:05:00Z',
  };
}

describe('TypeScript v1 wire contracts', () => {
  it('round-trips all 5 versioned contracts through JSON serialization and validation', () => {
    const packet = validExecutionPacket();
    const packetJson = serializeExecutionPacket(packet);
    expect((JSON.parse(packetJson) as { schemaVersion: string }).schemaVersion).toBe(
      SCHEMA_VERSION_EXECUTION_PACKET,
    );
    expect(parseExecutionPacket(packetJson)).toEqual(packet);

    const decision = validRiskDecision();
    expect(parseRiskDecision(serializeRiskDecision(decision))).toEqual(decision);

    const lease = validWorktreeLease();
    expect(parseWorktreeLease(serializeWorktreeLease(lease))).toEqual(lease);

    const envelope = validPcwEnvelope();
    expect(parsePcwEnvelope(serializePcwEnvelope(envelope))).toEqual(envelope);

    const usage = validGatewayUsageEvent();
    expect(parseGatewayUsageEvent(serializeGatewayUsageEvent(usage))).toEqual(usage);
  });

  it('enforces ExecutionPacket v1 invariants', () => {
    const cases: Array<{ name: string; mutate: (p: Record<string, unknown>) => void; wantField: string }> = [
      { name: 'wrong schemaVersion', mutate: (p) => { p.schemaVersion = 'v0'; }, wantField: 'schemaVersion' },
      { name: 'invalid riskTier', mutate: (p) => { p.riskTier = 'R9'; }, wantField: 'riskTier' },
      { name: 'invalid classification', mutate: (p) => { p.dataClassification = 'public'; }, wantField: 'dataClassification' },
      { name: 'lease without fencingToken', mutate: (p) => { p.leaseId = 'l1'; p.fencingToken = 0; }, wantField: 'fencingToken' },
      { name: 'negative fencingToken', mutate: (p) => { p.leaseId = undefined; p.fencingToken = -1; }, wantField: 'fencingToken' },
      { name: 'bad parent proof hash', mutate: (p) => { p.parentProofHashes = ['not-sha']; }, wantField: 'parentProofHashes[0]' },
      { name: 'expired window', mutate: (p) => { p.expiresAt = p.issuedAt; }, wantField: 'expiresAt' },
      { name: 'empty owned path', mutate: (p) => { p.ownedPaths = ['  ']; }, wantField: 'ownedPaths[0]' },
      { name: 'invalid calendar date', mutate: (p) => { p.issuedAt = '2026-02-30T09:00:00Z'; }, wantField: 'issuedAt' },
    ];

    for (const tc of cases) {
      const candidate: Record<string, unknown> = { ...validExecutionPacket() };
      tc.mutate(candidate);
      const res = validateExecutionPacket(candidate);
      expect(res.ok, tc.name).toBe(false);
      if (!res.ok) {
        expect(res.issues.some((i) => i.field.includes(tc.wantField)), tc.name).toBe(true);
      }
    }
  });

  it('enforces RiskDecision v1 invariants', () => {
    const cases: Array<{ name: string; mutate: (d: Record<string, unknown>) => void; wantField: string }> = [
      { name: 'wrong schemaVersion', mutate: (d) => { d.schemaVersion = 'bad'; }, wantField: 'schemaVersion' },
      { name: 'r4 cannot be allowed', mutate: (d) => { d.effectiveRiskTier = 'R4'; }, wantField: 'effectiveRiskTier' },
      { name: 'local_only cannot allow cloud', mutate: (d) => { d.targetZone = 'cloud'; }, wantField: 'targetZone' },
      { name: 'allowed mismatch', mutate: (d) => { d.decision = 'deny'; d.reasonCodes = ['DENIED']; }, wantField: 'allowed' },
      { name: 'deny without reasonCodes', mutate: (d) => { d.allowed = false; d.decision = 'deny'; d.reasonCodes = []; }, wantField: 'reasonCodes' },
      { name: 'bad decisionSha256', mutate: (d) => { d.decisionSha256 = 'xyz'; }, wantField: 'decisionSha256' },
      { name: 'bad scopeHash', mutate: (d) => { d.scopeHash = '123'; }, wantField: 'scopeHash' },
    ];

    for (const tc of cases) {
      const candidate: Record<string, unknown> = { ...validRiskDecision() };
      tc.mutate(candidate);
      const res = validateRiskDecision(candidate);
      expect(res.ok, tc.name).toBe(false);
      if (!res.ok) {
        expect(res.issues.some((i) => i.field.includes(tc.wantField)), tc.name).toBe(true);
      }
    }
  });

  it('enforces WorktreeLease v1 invariants', () => {
    const cases: Array<{ name: string; mutate: (l: Record<string, unknown>) => void; wantField: string }> = [
      { name: 'wrong schemaVersion', mutate: (l) => { l.schemaVersion = 'v2'; }, wantField: 'schemaVersion' },
      { name: 'invalid baseCommit', mutate: (l) => { l.baseCommit = 'abc'; }, wantField: 'baseCommit' },
      { name: 'non-positive fencingToken', mutate: (l) => { l.fencingToken = 0; }, wantField: 'fencingToken' },
      { name: 'released without releasedAt', mutate: (l) => { l.status = 'released'; }, wantField: 'releasedAt' },
      { name: 'active with releasedAt', mutate: (l) => { l.releasedAt = '2026-11-27T09:01:00Z'; }, wantField: 'releasedAt' },
      { name: 'updatedAt before createdAt', mutate: (l) => { l.updatedAt = '2026-11-27T08:59:00Z'; }, wantField: 'updatedAt' },
      { name: 'expiresAt not after createdAt', mutate: (l) => { l.expiresAt = l.createdAt; }, wantField: 'expiresAt' },
    ];

    for (const tc of cases) {
      const candidate: Record<string, unknown> = { ...validWorktreeLease() };
      tc.mutate(candidate);
      const res = validateWorktreeLease(candidate);
      expect(res.ok, tc.name).toBe(false);
      if (!res.ok) {
        expect(res.issues.some((i) => i.field.includes(tc.wantField)), tc.name).toBe(true);
      }
    }

    const releasedRes = validateWorktreeLease({
      ...validWorktreeLease(),
      status: 'released',
      releasedAt: '2026-11-27T09:05:00Z',
    });
    expect(releasedRes.ok).toBe(true);
  });

  it('enforces PcwEnvelope (pcw/v1) invariants', () => {
    const cases: Array<{ name: string; mutate: (e: Record<string, unknown>) => void; wantMessage: string }> = [
      { name: 'wrong schemaVersion', mutate: (e) => { e.schemaVersion = 'pcw/v2'; }, wantMessage: 'pcw/v1' },
      { name: 'self approval', mutate: (e) => { e.reviewerAgentId = e.producerAgentId; }, wantMessage: 'self-approval' },
      { name: 'empty artifacts', mutate: (e) => { e.artifacts = []; }, wantMessage: 'at least one artifact' },
      {
        name: 'duplicate artifact id',
        mutate: (e) => {
          const arts = e.artifacts as Array<Record<string, unknown>>;
          e.artifacts = [arts[0], arts[0]];
        },
        wantMessage: 'duplicate artifact id',
      },
      {
        name: 'invalid artifact kind',
        mutate: (e) => {
          const arts = e.artifacts as Array<Record<string, unknown>>;
          e.artifacts = [{ ...arts[0], kind: 'unknown' }];
        },
        wantMessage: 'artifact kind',
      },
      {
        name: 'skipped check without reason',
        mutate: (e) => {
          e.checks = [{ code: 'lint', status: 'skipped' }];
        },
        wantMessage: 'skipped',
      },
      { name: 'bad merkleRoot', mutate: (e) => { e.merkleRoot = '1234'; }, wantMessage: '64 lowercase hex' },
      { name: 'bad envelopeSha256', mutate: (e) => { e.envelopeSha256 = '1234'; }, wantMessage: '64 lowercase hex' },
    ];

    for (const tc of cases) {
      const candidate: Record<string, unknown> = { ...validPcwEnvelope() };
      tc.mutate(candidate);
      const res = validatePcwEnvelope(candidate);
      expect(res.ok, tc.name).toBe(false);
      if (!res.ok) {
        const joined = res.issues.map((i) => `${i.field}: ${i.message}`).join('; ');
        expect(joined, tc.name).toContain(tc.wantMessage);
      }
    }
  });

  it('enforces GatewayUsageEvent v1 invariants', () => {
    const cases: Array<{ name: string; mutate: (e: Record<string, unknown>) => void; wantField: string }> = [
      { name: 'wrong schemaVersion', mutate: (e) => { e.schemaVersion = 'v0'; }, wantField: 'schemaVersion' },
      { name: 'bad statusCode', mutate: (e) => { e.statusCode = 99; }, wantField: 'statusCode' },
      { name: 'negative tokens', mutate: (e) => { e.promptTokens = -1; }, wantField: 'promptTokens' },
      { name: 'negative rtk saved', mutate: (e) => { e.rtkTokensSaved = -5; }, wantField: 'rtkTokensSaved' },
      { name: 'negative cost', mutate: (e) => { e.costUsdMicros = -10; }, wantField: 'costUsdMicros' },
      { name: 'bad timestamp', mutate: (e) => { e.createdAt = 'not-a-time'; }, wantField: 'createdAt' },
    ];

    for (const tc of cases) {
      const candidate: Record<string, unknown> = { ...validGatewayUsageEvent() };
      tc.mutate(candidate);
      const res = validateGatewayUsageEvent(candidate);
      expect(res.ok, tc.name).toBe(false);
      if (!res.ok) {
        expect(res.issues.some((i) => i.field.includes(tc.wantField)), tc.name).toBe(true);
      }
    }
  });

  it('rejects corrupt JSON and non-object inputs via ContractValidationError', () => {
    expect(() => parseExecutionPacket('{broken')).toThrow(ContractValidationError);
    expect(() => parseRiskDecision('[]')).toThrow(ContractValidationError);
    expect(validateWorktreeLease(null).ok).toBe(false);
    expect(validatePcwEnvelope('string').ok).toBe(false);
    expect(validateGatewayUsageEvent(123).ok).toBe(false);
  });
});
