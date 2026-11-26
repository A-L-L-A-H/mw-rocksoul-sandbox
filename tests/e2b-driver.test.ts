import { describe, expect, it } from 'bun:test';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { E2bExecutionDriver } from '../src/e2b-driver.js';
import { WorktreeLeaseManager } from '../src/lease-manager.js';
import { OtelTraceExporter, type OtlpExportTraceServiceRequest } from '../src/otel-exporter.js';

async function createTempGitRepo(): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), 'rocksoul-e2b-repo-'));
  const run = (args: string[]): void => {
    const proc = Bun.spawnSync(['git', '-C', dir, ...args]);
    if (proc.exitCode !== 0) {
      throw new Error(`git ${args.join(' ')} failed: ${proc.stderr.toString()}`);
    }
  };
  run(['init', '-b', 'main']);
  run(['config', 'user.name', 'RockSoul Test']);
  run(['config', 'user.email', 'test@rocksoul.local']);
  await writeFile(path.join(dir, 'README.md'), '# Fixture\n', 'utf8');
  run(['add', 'README.md']);
  run(['commit', '-m', 'init fixture']);
  return dir;
}

describe('E2bExecutionDriver', () => {
  it('dispatches to E2B with redaction, fencing validation and OTLP span; falls back locally without key', async () => {
    const repoDir = await createTempGitRepo();
    const worktreesRoot = await mkdtemp(path.join(tmpdir(), 'rocksoul-e2b-wt-'));
    const manager = new WorktreeLeaseManager({ worktreesRoot });
    try {
      const lease = await manager.acquireLease({ repoPath: repoDir, ownerId: 'agent-e2b' });

      const calls: string[] = [];
      const spans: OtlpExportTraceServiceRequest[] = [];
      const exporter = new OtelTraceExporter({
        fetchImpl: async (_input, init) => {
          spans.push(JSON.parse(String(init?.body)) as OtlpExportTraceServiceRequest);
          return new Response('{}', { status: 200 });
        },
      });
      const remote = new E2bExecutionDriver({
        leaseManager: manager,
        exporter,
        apiKey: 'e2b-test-key',
        baseUrl: 'https://e2b.test',
        fetchImpl: async (input, init) => {
          const method = init?.method ?? 'GET';
          calls.push(`${method} ${String(input)}`);
          if (String(input).endsWith('/sandboxes') && method === 'POST') {
            return new Response(JSON.stringify({ sandboxID: 'sbx1' }), { status: 200 });
          }
          if (String(input).endsWith('/commands')) {
            return new Response(
              JSON.stringify({ stdout: 'token ghp_abcdefghijklmnopqrstuvwxyz0123456789 ok', stderr: '', exitCode: 0 }),
              { status: 200 },
            );
          }
          return new Response('{}', { status: 200 });
        },
      });
      expect(remote.backend).toBe('e2b-firecracker');

      const result = await remote.execute({
        leaseId: lease.leaseId,
        fencingToken: lease.fencingToken,
        command: ['git', 'status'],
      });
      expect(result.backend).toBe('e2b-firecracker');
      expect(result.stdout).not.toContain('ghp_abcdefghijklmnopqrstuvwxyz0123456789');
      expect(result.redacted).toBe(true);
      expect(result.fencingToken).toBe(lease.fencingToken);
      expect(calls[calls.length - 1]).toBe('DELETE https://e2b.test/sandboxes/sbx1');
      expect(spans.length).toBe(1);

      await expect(
        remote.execute({ leaseId: lease.leaseId, fencingToken: lease.fencingToken + 99, command: ['git', 'status'] }),
      ).rejects.toThrow();
      await expect(
        remote.execute({ leaseId: lease.leaseId, fencingToken: lease.fencingToken, command: ['rm', '-rf', '/'] }),
      ).rejects.toThrow();

      const local = new E2bExecutionDriver({ leaseManager: manager, apiKey: '' });
      const previous = process.env.E2B_API_KEY;
      delete process.env.E2B_API_KEY;
      try {
        const fallback = new E2bExecutionDriver({ leaseManager: manager });
        expect(fallback.backend).toBe('local-worktree');
        const localResult = await fallback.execute({
          leaseId: lease.leaseId,
          fencingToken: lease.fencingToken,
          command: ['git', 'status'],
        });
        expect(localResult.backend).toBe('local-worktree');
        expect(localResult.exitCode).toBe(0);
        expect(local.backend).toBe('local-worktree');
      } finally {
        if (previous !== undefined) process.env.E2B_API_KEY = previous;
      }
    } finally {
      await manager.close();
      await rm(repoDir, { recursive: true, force: true });
      await rm(worktreesRoot, { recursive: true, force: true });
    }
  });
});
