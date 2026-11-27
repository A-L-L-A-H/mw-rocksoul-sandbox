import {
  ARTIFACT_KINDS,
  CHECK_STATUSES,
  IssueCollector,
  RISK_TIERS,
  SCHEMA_VERSION_PCW_ENVELOPE,
  assertContract,
  decodeJsonObject,
  isPlainObject,
  isValidSha256Hex,
  serializeContract,
  type ArtifactKind,
  type CheckStatus,
  type ContractValidationResult,
  type RiskTier,
} from './common.js';

export interface PcwArtifactRecord {
  readonly id: string;
  readonly kind: ArtifactKind;
  readonly sha256: string;
  readonly content?: string;
  readonly sizeBytes?: number;
  readonly path?: string;
}

export interface PcwCheckEvidence {
  readonly code: string;
  readonly command?: string;
  readonly status: CheckStatus;
  readonly mandatory?: boolean;
  readonly exitCode?: number;
  readonly reason?: string;
}

export interface PcwEnvelope {
  readonly schemaVersion: typeof SCHEMA_VERSION_PCW_ENVELOPE;
  readonly envelopeId: string;
  readonly taskId: string;
  readonly producerAgentId: string;
  readonly reviewerAgentId?: string;
  readonly riskTier: RiskTier;
  readonly parentProofHashes: readonly string[];
  readonly artifacts: readonly PcwArtifactRecord[];
  readonly checks: readonly PcwCheckEvidence[];
  readonly changedFiles?: readonly string[];
  readonly producedAt: string;
  readonly expiresAt?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
  readonly merkleRoot: string;
  readonly envelopeSha256: string;
}

export function validatePcwEnvelope(input: unknown): ContractValidationResult<PcwEnvelope> {
  const issues = new IssueCollector();
  if (!isPlainObject(input)) {
    issues.add('$', 'PcwEnvelope must be a JSON object');
    return issues.finish(input as PcwEnvelope);
  }

  issues.requireSchemaVersion(input.schemaVersion, SCHEMA_VERSION_PCW_ENVELOPE);
  issues.requireNonEmptyString('envelopeId', input.envelopeId);
  issues.requireNonEmptyString('taskId', input.taskId);
  const producerAgentId = issues.requireNonEmptyString('producerAgentId', input.producerAgentId);

  if (input.reviewerAgentId !== undefined && typeof input.reviewerAgentId !== 'string') {
    issues.add('reviewerAgentId', 'must be a string');
  } else if (
    typeof input.reviewerAgentId === 'string' &&
    input.reviewerAgentId.trim() !== '' &&
    input.reviewerAgentId === producerAgentId
  ) {
    issues.add('reviewerAgentId', 'must differ from producerAgentId (self-approval prohibited)');
  }

  issues.requireEnum('riskTier', input.riskTier, RISK_TIERS, 'risk tier');
  issues.validateSha256List('parentProofHashes', input.parentProofHashes, true);

  if (!Array.isArray(input.artifacts) || input.artifacts.length === 0) {
    issues.add('artifacts', 'must contain at least one artifact');
  } else {
    const seenIds = new Set<string>();
    for (let i = 0; i < input.artifacts.length; i += 1) {
      const prefix = `artifacts[${i}]`;
      const art = input.artifacts[i];
      if (!isPlainObject(art)) {
        issues.add(prefix, 'must be a JSON object');
        continue;
      }
      const id = issues.requireNonEmptyString(`${prefix}.id`, art.id);
      if (id !== '') {
        if (seenIds.has(id)) {
          issues.add(`${prefix}.id`, `duplicate artifact id "${id}"`);
        }
        seenIds.add(id);
      }
      issues.requireEnum(`${prefix}.kind`, art.kind, ARTIFACT_KINDS, 'artifact kind');
      if (!isValidSha256Hex(art.sha256)) {
        issues.add(`${prefix}.sha256`, 'must be 64 lowercase hex characters');
      }
      if (art.content !== undefined && typeof art.content !== 'string') {
        issues.add(`${prefix}.content`, 'must be a string');
      }
      if (art.sizeBytes !== undefined) {
        issues.requireSafeInteger(`${prefix}.sizeBytes`, art.sizeBytes, 0);
      }
      if (art.path !== undefined && typeof art.path !== 'string') {
        issues.add(`${prefix}.path`, 'must be a string');
      }
    }
  }

  if (!Array.isArray(input.checks)) {
    issues.add('checks', 'must be an array');
  } else {
    for (let i = 0; i < input.checks.length; i += 1) {
      const prefix = `checks[${i}]`;
      const chk = input.checks[i];
      if (!isPlainObject(chk)) {
        issues.add(prefix, 'must be a JSON object');
        continue;
      }
      issues.requireNonEmptyString(`${prefix}.code`, chk.code);
      if (chk.command !== undefined && typeof chk.command !== 'string') {
        issues.add(`${prefix}.command`, 'must be a string');
      }
      issues.requireEnum(`${prefix}.status`, chk.status, CHECK_STATUSES, 'check status');
      if (chk.mandatory !== undefined && typeof chk.mandatory !== 'boolean') {
        issues.add(`${prefix}.mandatory`, 'must be a boolean');
      }
      if (chk.exitCode !== undefined) {
        issues.requireSafeInteger(`${prefix}.exitCode`, chk.exitCode);
      }
      if (chk.reason !== undefined && typeof chk.reason !== 'string') {
        issues.add(`${prefix}.reason`, 'must be a string');
      }
      if (chk.status === 'skipped' && (typeof chk.reason !== 'string' || chk.reason.trim() === '')) {
        issues.add(`${prefix}.reason`, 'is required when check status is skipped');
      }
    }
  }

  issues.validateStringArray('changedFiles', input.changedFiles);

  const producedNs = issues.requireRfc3339('producedAt', input.producedAt);
  if (input.expiresAt !== undefined && typeof input.expiresAt !== 'string') {
    issues.add('expiresAt', 'must be a string');
  } else if (typeof input.expiresAt === 'string' && input.expiresAt.trim() !== '') {
    const expiresNs = issues.requireRfc3339('expiresAt', input.expiresAt);
    if (producedNs !== null && expiresNs !== null && expiresNs <= producedNs) {
      issues.add('expiresAt', 'must be strictly after producedAt');
    }
  }

  if (input.metadata !== undefined && !isPlainObject(input.metadata)) {
    issues.add('metadata', 'must be a JSON object when present');
  }

  if (!isValidSha256Hex(input.merkleRoot)) {
    issues.add('merkleRoot', 'must be 64 lowercase hex characters');
  }
  if (!isValidSha256Hex(input.envelopeSha256)) {
    issues.add('envelopeSha256', 'must be 64 lowercase hex characters');
  }

  return issues.finish(input as unknown as PcwEnvelope);
}

export function assertValidPcwEnvelope(input: unknown): PcwEnvelope {
  return assertContract(input, validatePcwEnvelope);
}

export function parsePcwEnvelope(rawJson: string): PcwEnvelope {
  return assertValidPcwEnvelope(decodeJsonObject(rawJson));
}

export function serializePcwEnvelope(envelope: PcwEnvelope): string {
  return serializeContract(envelope, validatePcwEnvelope);
}
