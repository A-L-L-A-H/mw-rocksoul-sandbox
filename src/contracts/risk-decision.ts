import {
  DATA_CLASSIFICATIONS,
  DECISION_KINDS,
  IssueCollector,
  RISK_TIERS,
  SCHEMA_VERSION_RISK_DECISION,
  TARGET_ZONES,
  assertContract,
  decodeJsonObject,
  isPlainObject,
  isValidSha256Hex,
  serializeContract,
  type ContractValidationResult,
  type DataClassification,
  type DecisionKind,
  type RiskTier,
  type TargetZone,
} from './common.js';

export interface RiskDecision {
  readonly schemaVersion: typeof SCHEMA_VERSION_RISK_DECISION;
  readonly decisionId: string;
  readonly allowed: boolean;
  readonly decision: DecisionKind;
  readonly effectiveRiskTier: RiskTier;
  readonly dataClassification: DataClassification;
  readonly targetZone: TargetZone;
  readonly reasonCodes: readonly string[];
  readonly messages: readonly string[];
  readonly requiresIndependentVerification: boolean;
  readonly requiresHumanApproval: boolean;
  readonly verifiedGrantId?: string;
  readonly verifiedApprovalTokenId?: string;
  readonly scopeHash?: string;
  readonly evaluatedAt: string;
  readonly decisionSha256: string;
}

export function validateRiskDecision(input: unknown): ContractValidationResult<RiskDecision> {
  const issues = new IssueCollector();
  if (!isPlainObject(input)) {
    issues.add('$', 'RiskDecision must be a JSON object');
    return issues.finish(input as RiskDecision);
  }

  issues.requireSchemaVersion(input.schemaVersion, SCHEMA_VERSION_RISK_DECISION);
  issues.requireNonEmptyString('decisionId', input.decisionId);
  const allowed = issues.requireBoolean('allowed', input.allowed);
  const validDecision = issues.requireEnum('decision', input.decision, DECISION_KINDS, 'decision');

  if (validDecision) {
    if (allowed && input.decision !== 'allow') {
      issues.add('allowed', 'cannot be true unless decision is allow');
    }
    if (!allowed && input.decision === 'allow') {
      issues.add('allowed', 'must be true when decision is allow');
    }
  }

  issues.requireEnum('effectiveRiskTier', input.effectiveRiskTier, RISK_TIERS, 'risk tier');
  issues.requireEnum('dataClassification', input.dataClassification, DATA_CLASSIFICATIONS, 'data classification');
  issues.requireEnum('targetZone', input.targetZone, TARGET_ZONES, 'target zone');

  if (input.effectiveRiskTier === 'R4' && allowed) {
    issues.add('effectiveRiskTier', 'R4 operations cannot be allowed');
  }
  if (input.dataClassification === 'local_only' && input.targetZone === 'cloud' && allowed) {
    issues.add('targetZone', 'local_only classification cannot allow cloud targetZone');
  }

  issues.validateStringArray('reasonCodes', input.reasonCodes, { required: true });
  issues.validateStringArray('messages', input.messages, { required: true });

  if (input.decision === 'deny' && (!Array.isArray(input.reasonCodes) || input.reasonCodes.length === 0)) {
    issues.add('reasonCodes', 'must contain at least one reason code when decision is deny');
  }

  issues.requireBoolean('requiresIndependentVerification', input.requiresIndependentVerification);
  issues.requireBoolean('requiresHumanApproval', input.requiresHumanApproval);

  if (input.verifiedGrantId !== undefined && typeof input.verifiedGrantId !== 'string') {
    issues.add('verifiedGrantId', 'must be a string');
  }
  if (input.verifiedApprovalTokenId !== undefined && typeof input.verifiedApprovalTokenId !== 'string') {
    issues.add('verifiedApprovalTokenId', 'must be a string');
  }

  if (input.scopeHash !== undefined) {
    if (typeof input.scopeHash !== 'string') {
      issues.add('scopeHash', 'must be a string');
    } else if (input.scopeHash.trim() !== '' && !isValidSha256Hex(input.scopeHash)) {
      issues.add('scopeHash', 'must be 64 lowercase hex characters when present');
    }
  }

  issues.requireRfc3339('evaluatedAt', input.evaluatedAt);
  if (!isValidSha256Hex(input.decisionSha256)) {
    issues.add('decisionSha256', 'must be 64 lowercase hex characters');
  }

  return issues.finish(input as unknown as RiskDecision);
}

export function assertValidRiskDecision(input: unknown): RiskDecision {
  return assertContract(input, validateRiskDecision);
}

export function parseRiskDecision(rawJson: string): RiskDecision {
  return assertValidRiskDecision(decodeJsonObject(rawJson));
}

export function serializeRiskDecision(decision: RiskDecision): string {
  return serializeContract(decision, validateRiskDecision);
}
