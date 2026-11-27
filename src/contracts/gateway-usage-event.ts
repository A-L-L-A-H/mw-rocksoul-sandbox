import {
  DATA_CLASSIFICATIONS,
  IssueCollector,
  SCHEMA_VERSION_GATEWAY_USAGE_EVENT,
  assertContract,
  decodeJsonObject,
  isPlainObject,
  serializeContract,
  type ContractValidationResult,
  type DataClassification,
} from './common.js';

export interface GatewayUsageEvent {
  readonly schemaVersion: typeof SCHEMA_VERSION_GATEWAY_USAGE_EVENT;
  readonly eventId: string;
  readonly agentId: string;
  readonly requestedModel: string;
  readonly resolvedProvider: string;
  readonly resolvedModel: string;
  readonly classification: DataClassification;
  readonly statusCode: number;
  readonly latencyMs: number;
  readonly promptTokens: number;
  readonly completionTokens: number;
  readonly rtkTokensSaved: number;
  readonly redactionsCount: number;
  readonly egressBlocked: boolean;
  readonly cacheHit: boolean;
  readonly costUsdMicros: number;
  readonly createdAt: string;
}

export function validateGatewayUsageEvent(
  input: unknown,
): ContractValidationResult<GatewayUsageEvent> {
  const issues = new IssueCollector();
  if (!isPlainObject(input)) {
    issues.add('$', 'GatewayUsageEvent must be a JSON object');
    return issues.finish(input as GatewayUsageEvent);
  }

  issues.requireSchemaVersion(input.schemaVersion, SCHEMA_VERSION_GATEWAY_USAGE_EVENT);
  issues.requireNonEmptyString('eventId', input.eventId);
  issues.requireNonEmptyString('agentId', input.agentId);
  issues.requireNonEmptyString('requestedModel', input.requestedModel);
  issues.requireNonEmptyString('resolvedProvider', input.resolvedProvider);
  issues.requireNonEmptyString('resolvedModel', input.resolvedModel);
  issues.requireEnum('classification', input.classification, DATA_CLASSIFICATIONS, 'data classification');

  issues.requireSafeInteger('statusCode', input.statusCode, 100, 599);
  issues.requireSafeInteger('latencyMs', input.latencyMs, 0);
  issues.requireSafeInteger('promptTokens', input.promptTokens, 0);
  issues.requireSafeInteger('completionTokens', input.completionTokens, 0);
  issues.requireSafeInteger('rtkTokensSaved', input.rtkTokensSaved, 0);
  issues.requireSafeInteger('redactionsCount', input.redactionsCount, 0);
  issues.requireBoolean('egressBlocked', input.egressBlocked);
  issues.requireBoolean('cacheHit', input.cacheHit);
  issues.requireSafeInteger('costUsdMicros', input.costUsdMicros, 0);
  issues.requireRfc3339('createdAt', input.createdAt);

  return issues.finish(input as unknown as GatewayUsageEvent);
}

export function assertValidGatewayUsageEvent(input: unknown): GatewayUsageEvent {
  return assertContract(input, validateGatewayUsageEvent);
}

export function parseGatewayUsageEvent(rawJson: string): GatewayUsageEvent {
  return assertValidGatewayUsageEvent(decodeJsonObject(rawJson));
}

export function serializeGatewayUsageEvent(event: GatewayUsageEvent): string {
  return serializeContract(event, validateGatewayUsageEvent);
}
