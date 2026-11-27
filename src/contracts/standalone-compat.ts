/**
 * Standalone single-repo CI fallback for `@moonwitness/contracts`.
 * In multi-repo workspaces, TypeScript and Bun resolve `@moonwitness/contracts`
 * directly to `../mw-core/packages/contracts/src/index.ts` via `tsconfig.json` paths.
 * When checked out in isolation (e.g. GitHub Actions single-repo CI), resolution falls
 * back to this minimal compatibility surface so `typecheck` and `bun test` stay green.
 */
import path from 'node:path';

export const CONTRACT_SCHEMA_VERSION = '1.0.0' as const;
export type ContractSchemaVersion = typeof CONTRACT_SCHEMA_VERSION;
export type RiskTier = 'R0' | 'R1' | 'R2' | 'R3';
export type RiskVerdict = 'allow' | 'deny' | 'escalate';
export type LeaseState = 'active' | 'released' | 'expired' | 'revoked';

export interface ExecutionPacket {
  readonly schemaVersion: ContractSchemaVersion;
  readonly packetId: string;
  readonly traceId: string;
  readonly actorId: string;
  readonly tenantId: string;
  readonly targetRepo: string;
  readonly command: string;
  readonly args: readonly string[];
  readonly issuedAt: string;
  readonly expiresAt: string;
}

export interface RiskDecision {
  readonly schemaVersion: ContractSchemaVersion;
  readonly decisionId: string;
  readonly packetId: string;
  readonly tier: RiskTier;
  readonly verdict: RiskVerdict;
  readonly reason: string;
  readonly policyRef: string;
  readonly decidedAt: string;
}

export interface WorktreeLease {
  readonly schemaVersion: ContractSchemaVersion;
  readonly leaseId: string;
  readonly repo: string;
  readonly branch: string;
  readonly relativePath: string;
  readonly holderId: string;
  readonly state: LeaseState;
  readonly acquiredAt: string;
  readonly expiresAt: string;
}

export interface PcwEnvelope<TPayload = Record<string, unknown>> {
  readonly schemaVersion: ContractSchemaVersion;
  readonly envelopeId: string;
  readonly kind: string;
  readonly source: string;
  readonly correlationId: string;
  readonly timestamp: string;
  readonly payload: TPayload;
}

export interface GatewayUsageEvent {
  readonly schemaVersion: ContractSchemaVersion;
  readonly eventId: string;
  readonly tenantId: string;
  readonly service: string;
  readonly model: string;
  readonly inputTokens: number;
  readonly outputTokens: number;
  readonly latencyMs: number;
  readonly statusCode: number;
  readonly recordedAt: string;
}

const VALID_TIERS = new Set<string>(['R0', 'R1', 'R2', 'R3']);
const VALID_VERDICTS = new Set<string>(['allow', 'deny', 'escalate']);
const VALID_STATES = new Set<string>(['active', 'released', 'expired', 'revoked']);

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);
const isNonEmpty = (v: unknown): v is string => typeof v === 'string' && v.trim().length > 0;
const isNonNegNum = (v: unknown): v is number =>
  typeof v === 'number' && Number.isFinite(v) && v >= 0;
const hasStrings = (rec: Record<string, unknown>, keys: readonly string[]): boolean =>
  keys.every((k) => isNonEmpty(rec[k]));

export function isExecutionPacket(value: unknown): value is ExecutionPacket {
  const required = ['packetId', 'traceId', 'actorId', 'tenantId', 'targetRepo', 'command', 'issuedAt', 'expiresAt'];
  return (
    isRecord(value) &&
    value.schemaVersion === CONTRACT_SCHEMA_VERSION &&
    hasStrings(value, required) &&
    Array.isArray(value.args) &&
    value.args.every((a) => typeof a === 'string')
  );
}

export function isRiskDecision(value: unknown): value is RiskDecision {
  return (
    isRecord(value) &&
    value.schemaVersion === CONTRACT_SCHEMA_VERSION &&
    hasStrings(value, ['decisionId', 'packetId', 'tier', 'verdict', 'reason', 'policyRef', 'decidedAt']) &&
    VALID_TIERS.has(String(value.tier)) &&
    VALID_VERDICTS.has(String(value.verdict))
  );
}

export function isWorktreeLease(value: unknown): value is WorktreeLease {
  return (
    isRecord(value) &&
    value.schemaVersion === CONTRACT_SCHEMA_VERSION &&
    hasStrings(value, ['leaseId', 'repo', 'branch', 'relativePath', 'holderId', 'state', 'acquiredAt', 'expiresAt']) &&
    VALID_STATES.has(String(value.state))
  );
}

export function isPcwEnvelope(value: unknown): value is PcwEnvelope {
  return (
    isRecord(value) &&
    value.schemaVersion === CONTRACT_SCHEMA_VERSION &&
    hasStrings(value, ['envelopeId', 'kind', 'source', 'correlationId', 'timestamp']) &&
    isRecord(value.payload)
  );
}

export function isGatewayUsageEvent(value: unknown): value is GatewayUsageEvent {
  return (
    isRecord(value) &&
    value.schemaVersion === CONTRACT_SCHEMA_VERSION &&
    hasStrings(value, ['eventId', 'tenantId', 'service', 'model', 'recordedAt']) &&
    ['inputTokens', 'outputTokens', 'latencyMs', 'statusCode'].every((k) => isNonNegNum(value[k]))
  );
}

export type ContractErrorCode =
  | 'CONTRACT_VALIDATION_FAILED'
  | 'CONTRACT_VERSION_MISMATCH'
  | 'PATH_TRAVERSAL_DENIED'
  | 'RISK_POLICY_DENIED'
  | 'LEASE_CONFLICT'
  | 'AUTH_TOKEN_INVALID'
  | 'AUTH_TOKEN_REVOKED'
  | 'INTERNAL_CONTRACT_ERROR';

export interface ContractErrorEnvelope {
  readonly schemaVersion: ContractSchemaVersion;
  readonly code: ContractErrorCode;
  readonly message: string;
  readonly retryable: boolean;
  readonly traceId?: string;
  readonly details?: Readonly<Record<string, unknown>>;
}

export interface ContractErrorOptions {
  readonly code: ContractErrorCode;
  readonly message: string;
  readonly retryable?: boolean;
  readonly traceId?: string;
  readonly details?: Readonly<Record<string, unknown>>;
}

export class ContractError extends Error {
  readonly code: ContractErrorCode;
  readonly retryable: boolean;
  readonly traceId?: string;
  readonly details?: Readonly<Record<string, unknown>>;

  constructor(options: ContractErrorOptions) {
    super(options.message);
    this.name = 'ContractError';
    this.code = options.code;
    this.retryable = options.retryable ?? false;
    this.traceId = options.traceId;
    this.details = options.details;
  }

  toEnvelope(): ContractErrorEnvelope {
    return {
      schemaVersion: CONTRACT_SCHEMA_VERSION,
      code: this.code,
      message: this.message,
      retryable: this.retryable,
      ...(this.traceId ? { traceId: this.traceId } : {}),
      ...(this.details ? { details: this.details } : {}),
    };
  }
}

export function toContractErrorEnvelope(error: unknown, traceId?: string): ContractErrorEnvelope {
  if (error instanceof ContractError) {
    const env = error.toEnvelope();
    return traceId && !env.traceId ? { ...env, traceId } : env;
  }
  return {
    schemaVersion: CONTRACT_SCHEMA_VERSION,
    code: 'INTERNAL_CONTRACT_ERROR',
    message: error instanceof Error ? error.message : 'Unexpected contract error',
    retryable: false,
    ...(traceId ? { traceId } : {}),
  };
}

export const REDACTED_PLACEHOLDER = '[REDACTED]' as const;
export const DEFAULT_SENSITIVE_KEY_PATTERN =
  /(secret|token|password|passwd|apikey|api_key|authorization|cookie|private[_-]?key|credential)/i;
export const DEFAULT_REDACT_PATTERNS: readonly RegExp[] = [
  /Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi,
  /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
  /(?:sk|pk|mw)_(?:live|test|prod)_[A-Za-z0-9]{12,}/g,
  /-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----/g,
];

export function redactString(input: string, patterns: readonly RegExp[] = DEFAULT_REDACT_PATTERNS): string {
  let out = input;
  for (const p of patterns) {
    out = out.replace(p, REDACTED_PLACEHOLDER);
  }
  return out;
}

export function redactObject(
  input: unknown,
  sensitiveKeyPattern: RegExp = DEFAULT_SENSITIVE_KEY_PATTERN,
  patterns: readonly RegExp[] = DEFAULT_REDACT_PATTERNS,
): unknown {
  if (typeof input === 'string') return redactString(input, patterns);
  if (Array.isArray(input)) return input.map((v) => redactObject(v, sensitiveKeyPattern, patterns));
  if (isRecord(input)) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(input)) {
      out[k] = sensitiveKeyPattern.test(k) ? REDACTED_PLACEHOLDER : redactObject(v, sensitiveKeyPattern, patterns);
    }
    return out;
  }
  return input;
}

const WINDOWS_DRIVE_PATTERN = /^[a-zA-Z]:/;

export function isSafeSegment(segment: string): boolean {
  return (
    Boolean(segment) &&
    segment !== '.' &&
    segment !== '..' &&
    !segment.includes('\0') &&
    !/[\\/]/.test(segment) &&
    !WINDOWS_DRIVE_PATTERN.test(segment)
  );
}

export function assertSafeRelativePath(relativePath: string): string {
  if (!relativePath || relativePath.includes('\0')) {
    throw new ContractError({ code: 'PATH_TRAVERSAL_DENIED', message: `Unsafe relative path: ${relativePath}` });
  }
  const normalized = relativePath.replaceAll('\\', '/');
  if (normalized.startsWith('/') || WINDOWS_DRIVE_PATTERN.test(normalized)) {
    throw new ContractError({
      code: 'PATH_TRAVERSAL_DENIED',
      message: `Absolute path is not allowed: ${relativePath}`,
    });
  }
  const segments = normalized.split('/').filter((s) => s.length > 0);
  if (segments.length === 0 || segments.some((s) => !isSafeSegment(s))) {
    throw new ContractError({ code: 'PATH_TRAVERSAL_DENIED', message: `Unsafe relative path: ${relativePath}` });
  }
  return segments.join('/');
}

export function resolveWithinRoot(rootDir: string, relativePath: string): string {
  const safeRel = assertSafeRelativePath(relativePath);
  const absRoot = path.resolve(rootDir);
  const resolved = path.resolve(absRoot, safeRel);
  const rel = path.relative(absRoot, resolved);
  if (rel.startsWith('..') || path.isAbsolute(rel) || rel.includes('\0')) {
    throw new ContractError({ code: 'PATH_TRAVERSAL_DENIED', message: `Path escapes root: ${relativePath}` });
  }
  return resolved;
}
