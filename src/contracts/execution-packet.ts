import {
  DATA_CLASSIFICATIONS,
  IssueCollector,
  RISK_TIERS,
  SCHEMA_VERSION_EXECUTION_PACKET,
  assertContract,
  decodeJsonObject,
  isPlainObject,
  serializeContract,
  type ContractValidationResult,
  type DataClassification,
  type RiskTier,
} from './common.js';

export interface ExecutionPacket {
  readonly schemaVersion: typeof SCHEMA_VERSION_EXECUTION_PACKET;
  readonly packetId: string;
  readonly taskId: string;
  readonly sessionId: string;
  readonly principalId: string;
  readonly agentProfile: string;
  readonly dataClassification: DataClassification;
  readonly riskTier: RiskTier;
  readonly action: string;
  readonly capability: string;
  readonly ownedPaths?: readonly string[];
  readonly command?: string;
  readonly args?: readonly string[];
  readonly leaseId?: string;
  readonly fencingToken?: number;
  readonly parentProofHashes?: readonly string[];
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export function validateExecutionPacket(input: unknown): ContractValidationResult<ExecutionPacket> {
  const issues = new IssueCollector();
  if (!isPlainObject(input)) {
    issues.add('$', 'ExecutionPacket must be a JSON object');
    return issues.finish(input as ExecutionPacket);
  }

  issues.requireSchemaVersion(input.schemaVersion, SCHEMA_VERSION_EXECUTION_PACKET);
  issues.requireNonEmptyString('packetId', input.packetId);
  issues.requireNonEmptyString('taskId', input.taskId);
  issues.requireNonEmptyString('sessionId', input.sessionId);
  issues.requireNonEmptyString('principalId', input.principalId);
  issues.requireNonEmptyString('agentProfile', input.agentProfile);
  issues.requireEnum('dataClassification', input.dataClassification, DATA_CLASSIFICATIONS, 'data classification');
  issues.requireEnum('riskTier', input.riskTier, RISK_TIERS, 'risk tier');
  issues.requireNonEmptyString('action', input.action);
  issues.requireNonEmptyString('capability', input.capability);

  issues.validateStringArray('ownedPaths', input.ownedPaths, { nonEmptyItems: true });
  if (input.command !== undefined && typeof input.command !== 'string') {
    issues.add('command', 'must be a string');
  }
  issues.validateStringArray('args', input.args);
  if (input.leaseId !== undefined && typeof input.leaseId !== 'string') {
    issues.add('leaseId', 'must be a string');
  }

  const hasLeaseId = typeof input.leaseId === 'string' && input.leaseId.trim() !== '';
  if (input.fencingToken !== undefined) {
    issues.requireSafeInteger('fencingToken', input.fencingToken, 0);
  }
  if (hasLeaseId) {
    if (typeof input.fencingToken !== 'number' || !Number.isSafeInteger(input.fencingToken) || input.fencingToken <= 0) {
      issues.add('fencingToken', 'must be a positive integer when leaseId is set');
    }
  }

  issues.validateSha256List('parentProofHashes', input.parentProofHashes, false);

  const issuedNs = issues.requireRfc3339('issuedAt', input.issuedAt);
  const expiresNs = issues.requireRfc3339('expiresAt', input.expiresAt);
  if (issuedNs !== null && expiresNs !== null && expiresNs <= issuedNs) {
    issues.add('expiresAt', 'must be strictly after issuedAt');
  }

  if (input.metadata !== undefined && !isPlainObject(input.metadata)) {
    issues.add('metadata', 'must be a JSON object when present');
  }

  return issues.finish(input as unknown as ExecutionPacket);
}

export function assertValidExecutionPacket(input: unknown): ExecutionPacket {
  return assertContract(input, validateExecutionPacket);
}

export function parseExecutionPacket(rawJson: string): ExecutionPacket {
  return assertValidExecutionPacket(decodeJsonObject(rawJson));
}

export function serializeExecutionPacket(packet: ExecutionPacket): string {
  return serializeContract(packet, validateExecutionPacket);
}
