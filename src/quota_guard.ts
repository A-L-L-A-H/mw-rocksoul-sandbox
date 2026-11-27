/**
 * Quota Guard & Stale Lease Reaper for Sandboxed Worktree Leases.
 *
 * Enforces:
 * - Max concurrent active leases
 * - Disk watermark guard (<2GB free disk space triggers rejection)
 * - Stale lease reaper for expired or abandoned worktrees
 */

import { statfs } from 'node:fs/promises';
import type { WorktreeLeaseManager, LeaseRecord } from './lease-manager.js';
import { SandboxError } from './errors.js';

export interface QuotaGuardOptions {
  readonly leaseManager: WorktreeLeaseManager;
  readonly maxConcurrentLeases?: number;
  readonly minFreeDiskBytes?: number; // default: 2GB (2 * 1024 * 1024 * 1024)
  readonly rootPath?: string;
}

export const TWO_GIGABYTES = 2 * 1024 * 1024 * 1024;
export const DEFAULT_MAX_CONCURRENT_LEASES = 16;

export class QuotaGuard {
  private readonly leaseManager: WorktreeLeaseManager;
  private readonly maxConcurrentLeases: number;
  private readonly minFreeDiskBytes: number;
  private readonly rootPath: string;

  constructor(options: QuotaGuardOptions) {
    this.leaseManager = options.leaseManager;
    this.maxConcurrentLeases = options.maxConcurrentLeases ?? DEFAULT_MAX_CONCURRENT_LEASES;
    this.minFreeDiskBytes = options.minFreeDiskBytes ?? TWO_GIGABYTES;
    this.rootPath = options.rootPath ?? process.cwd();
  }

  /**
   * Check available disk space on rootPath filesystem.
   */
  public async getAvailableDiskSpace(): Promise<number> {
    try {
      const stats = await statfs(this.rootPath);
      return Number(stats.bavail) * Number(stats.bsize);
    } catch {
      return 10 * TWO_GIGABYTES;
    }
  }

  /**
   * Validate quota limits before acquiring a lease.
   */
  public async checkQuota(): Promise<{ readonly allowed: boolean; readonly reason?: string }> {
    const activeLeases = this.leaseManager.listLeases().filter((l) => l.status === 'active');
    if (activeLeases.length >= this.maxConcurrentLeases) {
      throw new SandboxError(
        'CONFLICT',
        `Max concurrent lease quota reached: ${activeLeases.length}/${this.maxConcurrentLeases}`,
        { details: { reason: 'LEASE_QUOTA_EXCEEDED' } }
      );
    }

    const freeBytes = await this.getAvailableDiskSpace();
    if (freeBytes < this.minFreeDiskBytes) {
      throw new SandboxError(
        'CONFLICT',
        `Disk space below watermark: ${(freeBytes / (1024 * 1024)).toFixed(1)}MB free, required ${(this.minFreeDiskBytes / (1024 * 1024)).toFixed(1)}MB (<2GB guard)`,
        { details: { reason: 'DISK_WATERMARK_EXCEEDED' } }
      );
    }

    return { allowed: true };
  }

  /**
   * Reaps expired and abandoned leases, freeing resources and disk.
   */
  public async reapStaleLeases(): Promise<{ readonly reapedCount: number; readonly reapedLeaseIds: readonly string[] }> {
    const reapedIds = await this.leaseManager.reapExpiredLeases();
    return {
      reapedCount: reapedIds.length,
      reapedLeaseIds: reapedIds,
    };
  }
}
