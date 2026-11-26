import { describe, expect, it } from 'bun:test';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { WorktreeLeaseManager } from '../src/lease-manager.js';

async function createTempGitRepo(): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), 'rocksoul-sandbox-repo-'));
  const run = (args: string[]) => {
    const proc = Bun.spawnSync(['git', '-C', dir, ...args]);
    if (proc.exitCode !== 0) {
      throw new Error(`git ${args.join(' ')} failed: ${proc.stderr.toString()}`);
    }
  };
  run(['init', '-b', 'main']);
  run(['config', 'user.name', 'RockSoul Test']);
  run(['config', 'user.email', 'test@rocksoul.local']);
  await writeFile(path.join(dir, 'README.md'), '# Sandbox Fixture\n', 'utf8');
  run(['add', 'README.md']);
  run(['commit', '-m', 'init fixture']);
  return dir;
}

describe('WorktreeLeaseManager', () => {
  it('acquires ephemeral git worktrees with strictly monotonic fencing tokens and cleans up on release', async () => {
    const repoDir = await createTempGitRepo();
    const worktreesRoot = await mkdtemp(path.join(tmpdir(), 'rocksoul-sandbox-wt-'));
    const manager = new WorktreeLeaseManager({ worktreesRoot });

    try {
      const lease1 = await manager.acquireLease({
        repoPath: repoDir,
        ownerId: 'agent-alpha',
        label: 'slice-a',
      });
      const lease2 = await manager.acquireLease({
        repoPath: repoDir,
        ownerId: 'agent-beta',
        label: 'slice-b',
      });

      expect(lease1.fencingToken).toBe(1);
      expect(lease2.fencingToken).toBe(2);
      expect(lease1.status).toBe('active');
      expect(lease1.baseCommit).toMatch(/^[a-f0-9]{40}$/u);

      const wtContent = await readFile(path.join(lease1.worktreePath, 'README.md'), 'utf8');
      expect(wtContent.replace(/\r\n/gu, '\n')).toBe('# Sandbox Fixture\n');

      // Mutating lease1 worktree does not affect lease2 or main repo
      await writeFile(path.join(lease1.worktreePath, 'ephemeral.txt'), 'isolated', 'utf8');
      const existsInLease2 = await stat(path.join(lease2.worktreePath, 'ephemeral.txt')).catch(
        () => null,
      );
      expect(existsInLease2).toBeNull();

      // Valid access succeeds for both concurrent leases
      expect((await manager.validateLeaseAccess(lease1.leaseId, 1)).leaseId).toBe(lease1.leaseId);
      expect((await manager.validateLeaseAccess(lease2.leaseId, 2)).leaseId).toBe(lease2.leaseId);

      // Renewing lease1 advances its monotonic fencing token and invalidates stale token 1
      const renewed = await manager.renewLease({ leaseId: lease1.leaseId, fencingToken: 1 });
      expect(renewed.fencingToken).toBe(3);

      await expect(manager.validateLeaseAccess(lease1.leaseId, 1)).rejects.toMatchObject({
        code: 'STALE_FENCING_TOKEN',
        statusCode: 409,
      });
      expect((await manager.validateLeaseAccess(lease1.leaseId, 3)).fencingToken).toBe(3);

      // Releasing removes the ephemeral worktree and rejects further access
      const released = await manager.releaseLease(lease1.leaseId);
      expect(released.status).toBe('released');
      expect(released.alreadyReleased).toBe(false);
      expect(await stat(lease1.worktreePath).catch(() => null)).toBeNull();

      await expect(manager.validateLeaseAccess(lease1.leaseId, 3)).rejects.toMatchObject({
        code: 'LEASE_INACTIVE',
        statusCode: 409,
      });
    } finally {
      await manager.close();
      await rm(worktreesRoot, { recursive: true, force: true });
      await rm(repoDir, { recursive: true, force: true });
    }
  });

  it('rejects superseded leases when an exclusive lease advances the repository fencing floor', async () => {
    const repoDir = await createTempGitRepo();
    const worktreesRoot = await mkdtemp(path.join(tmpdir(), 'rocksoul-sandbox-wt-excl-'));
    const manager = new WorktreeLeaseManager({ worktreesRoot });

    try {
      const oldLease = await manager.acquireLease({
        repoPath: repoDir,
        ownerId: 'agent-old',
      });
      const exclusiveLease = await manager.acquireLease({
        repoPath: repoDir,
        ownerId: 'agent-exclusive',
        exclusive: true,
      });

      expect(exclusiveLease.fencingToken).toBeGreaterThan(oldLease.fencingToken);
      await expect(
        manager.validateLeaseAccess(oldLease.leaseId, oldLease.fencingToken),
      ).rejects.toMatchObject({
        code: 'STALE_FENCING_TOKEN',
        statusCode: 409,
      });
      expect(
        (await manager.validateLeaseAccess(exclusiveLease.leaseId, exclusiveLease.fencingToken))
          .leaseId,
      ).toBe(exclusiveLease.leaseId);
    } finally {
      await manager.close();
      await rm(worktreesRoot, { recursive: true, force: true });
      await rm(repoDir, { recursive: true, force: true });
    }
  });

  it('expires leases past TTL and cleans up their worktrees', async () => {
    const repoDir = await createTempGitRepo();
    const worktreesRoot = await mkdtemp(path.join(tmpdir(), 'rocksoul-sandbox-wt-exp-'));
    let clockMs = 1_700_000_000_000;
    const manager = new WorktreeLeaseManager({
      worktreesRoot,
      now: () => clockMs,
    });

    try {
      const lease = await manager.acquireLease({
        repoPath: repoDir,
        ownerId: 'agent-ttl',
        ttlMs: 1_000,
      });

      clockMs += 1_500;
      await expect(
        manager.validateLeaseAccess(lease.leaseId, lease.fencingToken),
      ).rejects.toMatchObject({
        code: 'LEASE_EXPIRED',
        statusCode: 410,
      });
      expect(await stat(lease.worktreePath).catch(() => null)).toBeNull();
    } finally {
      await manager.close();
      await rm(worktreesRoot, { recursive: true, force: true });
      await rm(repoDir, { recursive: true, force: true });
    }
  });
});
