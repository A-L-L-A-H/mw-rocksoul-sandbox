import { describe, expect, it } from 'bun:test';
import { WorktreeLeaseManager } from '../src/lease-manager.js';
import { QuotaGuard, TWO_GIGABYTES } from '../src/quota_guard.js';
import { SandboxError } from '../src/errors.js';
import path from 'node:path';
import os from 'node:os';

describe('QuotaGuard & Stale Lease Reaper', () => {
  it('enforces max concurrent lease limits', async () => {
    const tmp = path.join(os.tmpdir(), `sandbox-test-${Date.now()}`);
    const mgr = new WorktreeLeaseManager({ worktreesRoot: tmp });
    const guard = new QuotaGuard({ leaseManager: mgr, maxConcurrentLeases: 0 });

    try {
      await guard.checkQuota();
      expect(true).toBe(false); // Should have thrown
    } catch (err: unknown) {
      expect(err instanceof SandboxError).toBe(true);
      expect((err as SandboxError).code).toBe('CONFLICT');
      expect((err as SandboxError).details?.reason).toBe('LEASE_QUOTA_EXCEEDED');
    }
  });

  it('enforces min disk watermark guard (<2GB)', async () => {
    const tmp = path.join(os.tmpdir(), `sandbox-test-disk-${Date.now()}`);
    const mgr = new WorktreeLeaseManager({ worktreesRoot: tmp });
    // Require unrealistic 1000 TB free disk space to test watermark threshold failure
    const guard = new QuotaGuard({
      leaseManager: mgr,
      minFreeDiskBytes: 1_000 * 1_000 * TWO_GIGABYTES,
    });

    try {
      await guard.checkQuota();
      expect(true).toBe(false);
    } catch (err: unknown) {
      expect(err instanceof SandboxError).toBe(true);
      expect((err as SandboxError).code).toBe('CONFLICT');
      expect((err as SandboxError).details?.reason).toBe('DISK_WATERMARK_EXCEEDED');
      expect(String((err as SandboxError).details?.remediation)).toContain('mw-ww-cli');
    }
  });

  it('reaps stale/expired leases', async () => {
    const tmp = path.join(os.tmpdir(), `sandbox-test-reap-${Date.now()}`);
    let time = 100000;
    const mgr = new WorktreeLeaseManager({
      worktreesRoot: tmp,
      now: () => time,
    });

    const guard = new QuotaGuard({ leaseManager: mgr });
    const result = await guard.reapStaleLeases();
    expect(result.reapedCount).toBe(0);
  });
});
