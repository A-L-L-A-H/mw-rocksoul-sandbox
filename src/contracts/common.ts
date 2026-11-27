export const SCHEMA_VERSION_EXECUTION_PACKET = 'rocksoul.execution_packet/v1' as const;
export const SCHEMA_VERSION_RISK_DECISION = 'rocksoul.risk_decision/v1' as const;
export const SCHEMA_VERSION_WORKTREE_LEASE = 'rocksoul.worktree_lease/v1' as const;
export const SCHEMA_VERSION_PCW_ENVELOPE = 'pcw/v1' as const;
export const SCHEMA_VERSION_GATEWAY_USAGE_EVENT = 'rocksoul.gateway_usage_event/v1' as const;

export const RISK_TIERS = ['R0', 'R1', 'R2', 'R3', 'R4'] as const;
export type RiskTier = (typeof RISK_TIERS)[number];

export const DATA_CLASSIFICATIONS = ['local_only', 'cloud_eligible'] as const;
export type DataClassification = (typeof DATA_CLASSIFICATIONS)[number];

export const TARGET_ZONES = ['local', 'cloud'] as const;
export type TargetZone = (typeof TARGET_ZONES)[number];

export const DECISION_KINDS = ['allow', 'require_human_approval', 'deny'] as const;
export type DecisionKind = (typeof DECISION_KINDS)[number];

export const LEASE_STATUSES = ['active', 'released', 'expired'] as const;
export type LeaseStatus = (typeof LEASE_STATUSES)[number];

export const ARTIFACT_KINDS = [
  'diff',
  'test_log',
  'report',
  'transcript',
  'tool_output',
  'evidence_bundle',
  'eval_result',
] as const;
export type ArtifactKind = (typeof ARTIFACT_KINDS)[number];

export const CHECK_STATUSES = [
  'pass',
  'fail',
  'skipped',
  'not_applicable',
  'not_run',
] as const;
export type CheckStatus = (typeof CHECK_STATUSES)[number];

export const SHA256_HEX_PATTERN = /^[a-f0-9]{64}$/u;
export const COMMIT_SHA_HEX_PATTERN = /^[a-f0-9]{40,64}$/u;

const RFC3339_PATTERN =
  /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(?:[Zz]|([+-])(\d{2}):(\d{2}))$/u;

export interface ContractValidationIssue {
  readonly field: string;
  readonly message: string;
}

export type ContractValidationResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly issues: readonly ContractValidationIssue[] };

export class ContractValidationError extends Error {
  readonly issues: readonly ContractValidationIssue[];

  constructor(issues: readonly ContractValidationIssue[]) {
    super(issues.map((issue) => `${issue.field}: ${issue.message}`).join('; '));
    this.name = 'ContractValidationError';
    this.issues = issues;
  }
}

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function isValidSha256Hex(value: unknown): value is string {
  return typeof value === 'string' && SHA256_HEX_PATTERN.test(value);
}

export function isValidCommitShaHex(value: unknown): value is string {
  return typeof value === 'string' && COMMIT_SHA_HEX_PATTERN.test(value);
}

/**
 * Parses an RFC3339 / RFC3339Nano timestamp into UTC nanoseconds since epoch.
 * Rejects malformed formats and impossible calendar dates (e.g., Feb 30).
 */
export function parseRfc3339Ns(raw: unknown): bigint | null {
  if (typeof raw !== 'string' || raw.trim() === '') {
    return null;
  }
  const match = RFC3339_PATTERN.exec(raw);
  if (!match) {
    return null;
  }

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const fracRaw = match[7] ?? '';
  const tzSign = match[8];
  const tzHour = match[9] !== undefined ? Number(match[9]) : 0;
  const tzMin = match[10] !== undefined ? Number(match[10]) : 0;

  if (month < 1 || month > 12 || day < 1 || day > 31) return null;
  if (hour > 23 || minute > 59 || second > 59) return null;
  if (tzHour > 23 || tzMin > 59) return null;

  const utcCheck = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
  if (
    Number.isNaN(utcCheck.getTime()) ||
    utcCheck.getUTCFullYear() !== year ||
    utcCheck.getUTCMonth() !== month - 1 ||
    utcCheck.getUTCDate() !== day
  ) {
    return null;
  }

  const offsetMinutes =
    tzSign === undefined ? 0 : (tzSign === '-' ? -1 : 1) * (tzHour * 60 + tzMin);
  const utcMs = BigInt(utcCheck.getTime()) - BigInt(offsetMinutes) * 60_000n;
  const subMsNs = BigInt(fracRaw.padEnd(9, '0').slice(3));
  const msFraction = BigInt(fracRaw.padEnd(3, '0').slice(0, 3));
  return (utcMs + msFraction) * 1_000_000n + subMsNs;
}

export class IssueCollector {
  private readonly items: ContractValidationIssue[] = [];

  add(field: string, message: string): void {
    this.items.push({ field, message });
  }

  requireSchemaVersion(actual: unknown, expected: string): void {
    if (actual !== expected) {
      this.add('schemaVersion', `must equal "${expected}" (got "${String(actual)}")`);
    }
  }

  requireNonEmptyString(field: string, value: unknown): string {
    if (typeof value !== 'string' || value.trim() === '') {
      this.add(field, 'must not be empty');
      return '';
    }
    return value;
  }

  requireBoolean(field: string, value: unknown): boolean {
    if (typeof value !== 'boolean') {
      this.add(field, 'must be a boolean');
      return false;
    }
    return value;
  }

  requireSafeInteger(field: string, value: unknown, min?: number, max?: number): number {
    if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
      this.add(field, 'must be a safe integer');
      return NaN;
    }
    if (min !== undefined && value < min) {
      this.add(field, min === 0 ? 'must not be negative' : `must be >= ${min}`);
    }
    if (max !== undefined && value > max) {
      this.add(field, `must be <= ${max}`);
    }
    return value;
  }

  requireEnum<const T extends readonly string[]>(
    field: string,
    value: unknown,
    allowed: T,
    label?: string,
  ): value is T[number] {
    if (typeof value !== 'string' || !allowed.includes(value)) {
      this.add(field, `invalid ${label ?? field} "${String(value)}" (expected ${allowed.join(', ')})`);
      return false;
    }
    return true;
  }

  requireRfc3339(field: string, value: unknown): bigint | null {
    if (typeof value !== 'string' || value.trim() === '') {
      this.add(field, 'must be a non-empty RFC3339 timestamp');
      return null;
    }
    const parsed = parseRfc3339Ns(value);
    if (parsed === null) {
      this.add(field, 'must be a valid RFC3339 timestamp');
      return null;
    }
    return parsed;
  }

  validateSha256List(field: string, value: unknown, required: boolean): void {
    if (value === undefined) {
      if (required) {
        this.add(field, 'must be an array of 64 lowercase hex characters');
      }
      return;
    }
    if (!Array.isArray(value)) {
      this.add(field, 'must be an array');
      return;
    }
    for (let i = 0; i < value.length; i += 1) {
      if (!isValidSha256Hex(value[i])) {
        this.add(`${field}[${i}]`, 'must be 64 lowercase hex characters');
      }
    }
  }

  validateStringArray(
    field: string,
    value: unknown,
    options: { readonly required?: boolean; readonly nonEmptyItems?: boolean } = {},
  ): void {
    if (value === undefined) {
      if (options.required) {
        this.add(field, 'must be an array of strings');
      }
      return;
    }
    if (!Array.isArray(value)) {
      this.add(field, 'must be an array');
      return;
    }
    for (let i = 0; i < value.length; i += 1) {
      const entry = value[i];
      if (typeof entry !== 'string') {
        this.add(`${field}[${i}]`, 'must be a string');
      } else if (options.nonEmptyItems && entry.trim() === '') {
        this.add(`${field}[${i}]`, 'must not be empty');
      }
    }
  }

  finish<T>(value: T): ContractValidationResult<T> {
    if (this.items.length > 0) {
      return { ok: false, issues: [...this.items] };
    }
    return { ok: true, value };
  }
}

export function decodeJsonObject(rawJson: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawJson);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new ContractValidationError([{ field: '$', message: `decode contract JSON: ${detail}` }]);
  }
  if (!isPlainObject(parsed)) {
    throw new ContractValidationError([{ field: '$', message: 'contract JSON root must be an object' }]);
  }
  return parsed;
}

export function assertContract<T>(
  input: unknown,
  validator: (candidate: unknown) => ContractValidationResult<T>,
): T {
  const result = validator(input);
  if (!result.ok) {
    throw new ContractValidationError(result.issues);
  }
  return result.value;
}

export function serializeContract<T>(
  contract: T,
  validator: (candidate: unknown) => ContractValidationResult<T>,
): string {
  const valid = assertContract(contract, validator);
  return JSON.stringify(valid);
}
