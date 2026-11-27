import {
  IssueCollector,
  LEASE_STATUSES,
  SCHEMA_VERSION_WORKTREE_LEASE,
  assertContract,
  decodeJsonObject,
  isPlainObject,
  isValidCommitShaHex,
  serializeContract,
  type ContractValidationResult,
  type LeaseStatus,
} from './common.js';

export interface WorktreeLease {
  readonly schemaVersion: typeof SCHEMA_VERSION_WORKTREE_LEASE;
  readonly leaseId: string;
  readonly ownerId: string;
  readonly repoPath: string;
  readonly worktreePath: string;
  readonly baseRef: string;
  readonly baseCommit: string;
  readonly fencingToken: number;
  readonly exclusive: boolean;
  readonly label?: string;
  readonly status: LeaseStatus;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly expiresAt: string;
  readonly releasedAt?: string;
}

export function validateWorktreeLease(input: unknown): ContractValidationResult<WorktreeLease> {
  const issues = new IssueCollector();
  if (!isPlainObject(input)) {
    issues.add('$', 'WorktreeLease must be a JSON object');
    return issues.finish(input as WorktreeLease);
  }

  issues.requireSchemaVersion(input.schemaVersion, SCHEMA_VERSION_WORKTREE_LEASE);
  issues.requireNonEmptyString('leaseId', input.leaseId);
  issues.requireNonEmptyString('ownerId', input.ownerId);
  issues.requireNonEmptyString('repoPath', input.repoPath);
  issues.requireNonEmptyString('worktreePath', input.worktreePath);
  issues.requireNonEmptyString('baseRef', input.baseRef);

  if (!isValidCommitShaHex(input.baseCommit)) {
    issues.add('baseCommit', 'must be 40-64 lowercase hex characters');
  }

  issues.requireSafeInteger('fencingToken', input.fencingToken, 1);
  issues.requireBoolean('exclusive', input.exclusive);
  if (input.label !== undefined && typeof input.label !== 'string') {
    issues.add('label', 'must be a string');
  }
  issues.requireEnum('status', input.status, LEASE_STATUSES, 'status');

  const createdNs = issues.requireRfc3339('createdAt', input.createdAt);
  const updatedNs = issues.requireRfc3339('updatedAt', input.updatedAt);
  const expiresNs = issues.requireRfc3339('expiresAt', input.expiresAt);

  if (createdNs !== null && updatedNs !== null && updatedNs < createdNs) {
    issues.add('updatedAt', 'must not precede createdAt');
  }
  if (createdNs !== null && expiresNs !== null && expiresNs <= createdNs) {
    issues.add('expiresAt', 'must be strictly after createdAt');
  }

  if (input.releasedAt !== undefined && typeof input.releasedAt !== 'string') {
    issues.add('releasedAt', 'must be a string');
  } else {
    const hasReleasedAt = typeof input.releasedAt === 'string' && input.releasedAt.trim() !== '';
    if (input.status === 'released') {
      if (!hasReleasedAt) {
        issues.add('releasedAt', 'is required when status is released');
      } else {
        const releasedNs = issues.requireRfc3339('releasedAt', input.releasedAt);
        if (createdNs !== null && releasedNs !== null && releasedNs < createdNs) {
          issues.add('releasedAt', 'must not precede createdAt');
        }
      }
    } else if (hasReleasedAt) {
      issues.add('releasedAt', 'must only be set when status is released');
    }
  }

  return issues.finish(input as unknown as WorktreeLease);
}

export function assertValidWorktreeLease(input: unknown): WorktreeLease {
  return assertContract(input, validateWorktreeLease);
}

export function parseWorktreeLease(rawJson: string): WorktreeLease {
  return assertValidWorktreeLease(decodeJsonObject(rawJson));
}

export function serializeWorktreeLease(lease: WorktreeLease): string {
  return serializeContract(lease, validateWorktreeLease);
}
