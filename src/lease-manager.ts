import { randomUUID } from 'node:crypto';
import { mkdir, rm, stat } from 'node:fs/promises';
import path from 'node:path';
import { SandboxError } from './errors.js';

export type LeaseStatus = 'active' | 'released' | 'expired';

export interface LeaseRecord {
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

export interface AcquireLeaseParams {
  readonly repoPath: string;
  readonly ownerId: string;
  readonly baseRef?: string;
  readonly ttlMs?: number;
  readonly exclusive?: boolean;
  readonly label?: string;
}

export interface RenewLeaseParams {
  readonly leaseId: string;
  readonly fencingToken: number;
  readonly ttlMs?: number;
}

export interface ReleaseLeaseResult {
  readonly leaseId: string;
  readonly status: 'released';
  readonly releasedAt: string;
  readonly alreadyReleased: boolean;
}

export interface LeaseManagerOptions {
  readonly worktreesRoot: string;
  readonly defaultTtlMs?: number;
  readonly maxTtlMs?: number;
  readonly maxActiveLeases?: number;
  readonly now?: () => number;
}

interface StoredLease {
  readonly leaseId: string;
  readonly ownerId: string;
  readonly repoPath: string;
  readonly canonicalRepoKey: string;
  readonly worktreePath: string;
  readonly baseRef: string;
  readonly baseCommit: string;
  fencingToken: number;
  readonly exclusive: boolean;
  readonly label?: string;
  status: LeaseStatus;
  readonly createdAt: string;
  updatedAt: string;
  expiresAtMs: number;
  releasedAt?: string;
}

const DEFAULT_TTL_MS = 15 * 60 * 1_000;
const MIN_TTL_MS = 100;
const MAX_TTL_MS = 4 * 60 * 60 * 1_000;
const DEFAULT_MAX_ACTIVE_LEASES = 64;
const OWNER_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/u;
const GIT_REF_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._/^~-]{0,127}$/u;
const LABEL_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u;
const COMMIT_SHA_PATTERN = /^[a-f0-9]{40,64}$/u;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

function canonicalPathKey(rawPath: string): string {
  const resolved = path.resolve(rawPath);
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

export function isWithinRoot(rootDir: string, candidatePath: string): boolean {
  const resolvedRoot = path.resolve(rootDir);
  const resolvedCandidate = path.resolve(candidatePath);
  const rel = path.relative(resolvedRoot, resolvedCandidate);
  return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel);
}

async function runGit(repoPath: string, args: readonly string[]): Promise<{
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
}> {
  const proc = Bun.spawn(['git', '-C', repoPath, ...args], {
    stdin: 'ignore',
    stdout: 'pipe',
    stderr: 'pipe',
    env: {
      ...process.env,
      GIT_TERMINAL_PROMPT: '0',
    },
  });

  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  return { exitCode, stdout, stderr };
}

function validateOwnerId(value: string): string {
  if (typeof value !== 'string' || !OWNER_ID_PATTERN.test(value)) {
    throw new SandboxError('INVALID_REQUEST', 'ownerId must be a valid bounded identifier');
  }
  return value;
}

function validateBaseRef(value: string | undefined): string {
  const ref = value === undefined ? 'HEAD' : value;
  if (typeof ref !== 'string' || !GIT_REF_PATTERN.test(ref) || ref.includes('..')) {
    throw new SandboxError('INVALID_REQUEST', 'baseRef must be a valid git ref or commit SHA');
  }
  return ref;
}

function validateLabel(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || !LABEL_PATTERN.test(value)) {
    throw new SandboxError('INVALID_REQUEST', 'label contains unsupported characters');
  }
  return value;
}

function validateFencingToken(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new SandboxError('INVALID_REQUEST', 'fencingToken must be a positive integer');
  }
  return value;
}

function validateLeaseId(value: string): string {
  if (typeof value !== 'string' || !UUID_PATTERN.test(value)) {
    throw new SandboxError('INVALID_REQUEST', 'leaseId must be a valid UUID');
  }
  return value;
}

export class WorktreeLeaseManager {
  private readonly worktreesRoot: string;
  private readonly defaultTtlMs: number;
  private readonly maxTtlMs: number;
  private readonly maxActiveLeases: number;
  private readonly now: () => number;
  private readonly leases = new Map<string, StoredLease>();
  private readonly repoExclusiveFencingFloor = new Map<string, number>();
  private nextFencingToken = 0;

  constructor(options: LeaseManagerOptions) {
    if (typeof options.worktreesRoot !== 'string' || !path.isAbsolute(options.worktreesRoot)) {
      throw new SandboxError('INVALID_REQUEST', 'worktreesRoot must be an absolute directory path');
    }
    this.worktreesRoot = path.resolve(options.worktreesRoot);
    this.maxTtlMs = Math.max(MIN_TTL_MS, Math.min(MAX_TTL_MS, options.maxTtlMs ?? MAX_TTL_MS));
    this.defaultTtlMs = Math.max(
      MIN_TTL_MS,
      Math.min(this.maxTtlMs, options.defaultTtlMs ?? DEFAULT_TTL_MS),
    );
    this.maxActiveLeases = Math.max(1, options.maxActiveLeases ?? DEFAULT_MAX_ACTIVE_LEASES);
    this.now = options.now ?? (() => Date.now());
  }

  get currentFencingToken(): number {
    return this.nextFencingToken;
  }

  get activeLeaseCount(): number {
    let count = 0;
    const nowMs = this.now();
    for (const lease of this.leases.values()) {
      if (lease.status === 'active' && lease.expiresAtMs > nowMs) {
        count += 1;
      }
    }
    return count;
  }

  get totalLeaseCount(): number {
    return this.leases.size;
  }

  private toPublicRecord(lease: StoredLease): LeaseRecord {
    return {
      leaseId: lease.leaseId,
      ownerId: lease.ownerId,
      repoPath: lease.repoPath,
      worktreePath: lease.worktreePath,
      baseRef: lease.baseRef,
      baseCommit: lease.baseCommit,
      fencingToken: lease.fencingToken,
      exclusive: lease.exclusive,
      ...(lease.label !== undefined ? { label: lease.label } : {}),
      status: lease.status,
      createdAt: lease.createdAt,
      updatedAt: lease.updatedAt,
      expiresAt: new Date(lease.expiresAtMs).toISOString(),
      ...(lease.releasedAt !== undefined ? { releasedAt: lease.releasedAt } : {}),
    };
  }

  private allocateFencingToken(): number {
    this.nextFencingToken += 1;
    return this.nextFencingToken;
  }

  private clampTtl(ttlMs: number | undefined): number {
    if (ttlMs === undefined) return this.defaultTtlMs;
    if (typeof ttlMs !== 'number' || !Number.isFinite(ttlMs) || ttlMs < MIN_TTL_MS) {
      throw new SandboxError(
        'INVALID_REQUEST',
        `ttlMs must be a number between ${MIN_TTL_MS} and ${this.maxTtlMs}`,
      );
    }
    return Math.min(this.maxTtlMs, Math.trunc(ttlMs));
  }

  async acquireLease(params: AcquireLeaseParams): Promise<LeaseRecord> {
    await this.reapExpiredLeases();

    if (typeof params.repoPath !== 'string' || !path.isAbsolute(params.repoPath)) {
      throw new SandboxError('INVALID_REQUEST', 'repoPath must be an absolute path to a git repository');
    }
    const repoPath = path.resolve(params.repoPath);
    const repoStat = await stat(repoPath).catch(() => null);
    if (!repoStat || !repoStat.isDirectory()) {
      throw new SandboxError('NOT_FOUND', `Repository directory does not exist: ${repoPath}`);
    }

    const ownerId = validateOwnerId(params.ownerId);
    const baseRef = validateBaseRef(params.baseRef);
    const label = validateLabel(params.label);
    const ttlMs = this.clampTtl(params.ttlMs);
    const exclusive = params.exclusive === true;

    if (this.activeLeaseCount >= this.maxActiveLeases) {
      throw new SandboxError('CONFLICT', `Active lease ceiling (${this.maxActiveLeases}) reached`);
    }

    const revParse = await runGit(repoPath, ['rev-parse', '--verify', `${baseRef}^{commit}`]);
    const baseCommit = revParse.stdout.trim();
    if (revParse.exitCode !== 0 || !COMMIT_SHA_PATTERN.test(baseCommit)) {
      throw new SandboxError(
        'INVALID_REQUEST',
        `Failed to resolve commit for "${baseRef}" in repository: ${revParse.stderr.trim() || 'not a git repository'}`,
      );
    }

    await mkdir(this.worktreesRoot, { recursive: true });
    const leaseId = randomUUID();
    const worktreePath = path.join(this.worktreesRoot, `lease-${leaseId}`);
    if (!isWithinRoot(this.worktreesRoot, worktreePath)) {
      throw new SandboxError('FORBIDDEN', 'Worktree path escapes configured worktrees root');
    }

    const addResult = await runGit(repoPath, ['worktree', 'add', '--detach', worktreePath, baseCommit]);
    if (addResult.exitCode !== 0) {
      throw new SandboxError(
        'INTERNAL',
        `git worktree add failed: ${addResult.stderr.trim() || addResult.stdout.trim()}`,
      );
    }

    const fencingToken = this.allocateFencingToken();
    const canonicalKey = canonicalPathKey(repoPath);
    if (exclusive) {
      this.repoExclusiveFencingFloor.set(canonicalKey, fencingToken);
    }

    const nowMs = this.now();
    const timestamp = new Date(nowMs).toISOString();
    const stored: StoredLease = {
      leaseId,
      ownerId,
      repoPath,
      canonicalRepoKey: canonicalKey,
      worktreePath,
      baseRef,
      baseCommit,
      fencingToken,
      exclusive,
      ...(label !== undefined ? { label } : {}),
      status: 'active',
      createdAt: timestamp,
      updatedAt: timestamp,
      expiresAtMs: nowMs + ttlMs,
    };
    this.leases.set(leaseId, stored);
    return this.toPublicRecord(stored);
  }

  async renewLease(params: RenewLeaseParams): Promise<LeaseRecord> {
    const validLease = await this.validateLeaseAccess(params.leaseId, params.fencingToken);
    const stored = this.leases.get(validLease.leaseId);
    if (!stored) {
      throw new SandboxError('NOT_FOUND', `Unknown lease "${params.leaseId}"`);
    }

    const ttlMs = this.clampTtl(params.ttlMs);
    const nextToken = this.allocateFencingToken();
    stored.fencingToken = nextToken;
    if (stored.exclusive) {
      this.repoExclusiveFencingFloor.set(stored.canonicalRepoKey, nextToken);
    }
    const nowMs = this.now();
    stored.updatedAt = new Date(nowMs).toISOString();
    stored.expiresAtMs = nowMs + ttlMs;

    return this.toPublicRecord(stored);
  }

  async validateLeaseAccess(leaseId: string, rawFencingToken: unknown): Promise<LeaseRecord> {
    const id = validateLeaseId(leaseId);
    const fencingToken = validateFencingToken(rawFencingToken);

    const stored = this.leases.get(id);
    if (!stored) {
      throw new SandboxError('NOT_FOUND', `Lease "${id}" does not exist`);
    }

    const nowMs = this.now();
    if (stored.status === 'active' && nowMs >= stored.expiresAtMs) {
      await this.expireLeaseInternal(stored, nowMs);
    }

    if (stored.status === 'expired') {
      throw new SandboxError('LEASE_EXPIRED', `Lease "${id}" has expired`);
    }
    if (stored.status !== 'active') {
      throw new SandboxError('LEASE_INACTIVE', `Lease "${id}" is ${stored.status}`);
    }

    if (fencingToken < stored.fencingToken) {
      throw new SandboxError(
        'STALE_FENCING_TOKEN',
        `Stale fencing token ${fencingToken} rejected; lease requires monotonic token ${stored.fencingToken}`,
        { details: { providedToken: fencingToken, requiredToken: stored.fencingToken } },
      );
    }

    if (fencingToken !== stored.fencingToken) {
      throw new SandboxError(
        'STALE_FENCING_TOKEN',
        `Invalid fencing token ${fencingToken} for lease "${id}" (expected ${stored.fencingToken})`,
        { details: { providedToken: fencingToken, requiredToken: stored.fencingToken } },
      );
    }

    const exclusiveFloor = this.repoExclusiveFencingFloor.get(stored.canonicalRepoKey);
    if (exclusiveFloor !== undefined && fencingToken < exclusiveFloor) {
      throw new SandboxError(
        'STALE_FENCING_TOKEN',
        `Fencing token ${fencingToken} superseded by exclusive lease token ${exclusiveFloor}`,
        { details: { providedToken: fencingToken, exclusiveFloor } },
      );
    }

    return this.toPublicRecord(stored);
  }

  async releaseLease(leaseId: string): Promise<ReleaseLeaseResult> {
    const id = validateLeaseId(leaseId);
    const stored = this.leases.get(id);
    if (!stored) {
      throw new SandboxError('NOT_FOUND', `Lease "${id}" does not exist`);
    }

    if (stored.status === 'released') {
      return {
        leaseId: id,
        status: 'released',
        releasedAt: stored.releasedAt ?? stored.updatedAt,
        alreadyReleased: true,
      };
    }

    await this.removeWorktree(stored);
    const releasedAt = new Date(this.now()).toISOString();
    stored.status = 'released';
    stored.releasedAt = releasedAt;
    stored.updatedAt = releasedAt;

    return {
      leaseId: id,
      status: 'released',
      releasedAt,
      alreadyReleased: false,
    };
  }

  getLease(leaseId: string): LeaseRecord {
    const id = validateLeaseId(leaseId);
    const stored = this.leases.get(id);
    if (!stored) {
      throw new SandboxError('NOT_FOUND', `Lease "${id}" does not exist`);
    }
    return this.toPublicRecord(stored);
  }

  listLeases(): LeaseRecord[] {
    return [...this.leases.values()].map((lease) => this.toPublicRecord(lease));
  }

  async reapExpiredLeases(): Promise<readonly string[]> {
    const nowMs = this.now();
    const expiredIds: string[] = [];
    for (const lease of this.leases.values()) {
      if (lease.status === 'active' && nowMs >= lease.expiresAtMs) {
        await this.expireLeaseInternal(lease, nowMs);
        expiredIds.push(lease.leaseId);
      }
    }
    return expiredIds;
  }

  async close(): Promise<void> {
    for (const lease of this.leases.values()) {
      if (lease.status === 'active') {
        await this.releaseLease(lease.leaseId).catch(() => undefined);
      }
    }
  }

  private async expireLeaseInternal(lease: StoredLease, nowMs: number): Promise<void> {
    await this.removeWorktree(lease);
    lease.status = 'expired';
    lease.updatedAt = new Date(nowMs).toISOString();
  }

  private async removeWorktree(lease: StoredLease): Promise<void> {
    await runGit(lease.repoPath, ['worktree', 'remove', '--force', lease.worktreePath]).catch(
      () => undefined,
    );
    await rm(lease.worktreePath, {
      recursive: true,
      force: true,
      maxRetries: 5,
      retryDelay: 50,
    }).catch(() => undefined);
    await runGit(lease.repoPath, ['worktree', 'prune']).catch(() => undefined);
  }
}
