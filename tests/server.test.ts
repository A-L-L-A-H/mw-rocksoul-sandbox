import { describe, expect, it } from 'bun:test';
import { mkdtemp, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { OtlpExportTraceServiceRequest } from '../src/otel-exporter.js';
import { createSandboxApplication, startSandboxServer } from '../src/server.js';

async function createTempGitRepo(): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), 'rocksoul-srv-repo-'));
  const run = (args: string[]) => {
    const proc = Bun.spawnSync(['git', '-C', dir, ...args]);
    if (proc.exitCode !== 0) {
      throw new Error(`git ${args.join(' ')} failed: ${proc.stderr.toString()}`);
    }
  };
  run(['init', '-b', 'main']);
  run(['config', 'user.name', 'RockSoul Test']);
  run(['config', 'user.email', 'test@rocksoul.local']);
  await writeFile(
    path.join(dir, 'sample.test.ts'),
    `import { expect, test } from 'bun:test';
test('echoes redacted secret', () => {
  console.log('user=dev@example.com key=sk-live-SecretValue1234567890');
  expect(2 + 2).toBe(4);
});
`,
    'utf8',
  );
  run(['add', 'sample.test.ts']);
  run(['commit', '-m', 'add sample test']);
  return dir;
}

describe('mw-rocksoul-sandbox HTTP daemon', () => {
  it('serves /health, POST /leases, POST /exec (with fencing & redaction & OTLP trace), and DELETE /leases/:id', async () => {
    const repoDir = await createTempGitRepo();
    const worktreesRoot = await mkdtemp(path.join(tmpdir(), 'rocksoul-srv-wt-'));
    const receivedTraces: OtlpExportTraceServiceRequest[] = [];

    const mockEchoCollector = Bun.serve({
      hostname: '127.0.0.1',
      port: 0,
      fetch: async (req) => {
        if (new URL(req.url).pathname === '/v1/traces') {
          receivedTraces.push((await req.json()) as OtlpExportTraceServiceRequest);
          return new Response(JSON.stringify({ ok: true }), { status: 200 });
        }
        return new Response('not found', { status: 404 });
      },
    });

    const app = createSandboxApplication({
      leaseManager: { worktreesRoot },
      otelExporter: { endpoint: `http://127.0.0.1:${mockEchoCollector.port}/v1/traces` },
    });
    const server = startSandboxServer(app, { host: '127.0.0.1', port: 0 });

    try {
      // 1. GET /health
      const healthRes = await fetch(`${server.url}/health`);
      expect(healthRes.status).toBe(200);
      const health = (await healthRes.json()) as {
        ok: boolean;
        service: string;
        activeLeases: number;
      };
      expect(health.ok).toBe(true);
      expect(health.service).toBe('mw-rocksoul-sandbox');
      expect(health.activeLeases).toBe(0);

      // 2. POST /leases
      const createRes = await fetch(`${server.url}/leases`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ repoPath: repoDir, ownerId: 'agent-1' }),
      });
      expect(createRes.status).toBe(201);
      const created = (await createRes.json()) as {
        ok: boolean;
        lease: { leaseId: string; fencingToken: number; worktreePath: string };
      };
      expect(created.ok).toBe(true);
      expect(created.lease.fencingToken).toBe(1);

      // 3. POST /exec with valid fencing token & allowlisted command
      const execRes = await fetch(`${server.url}/exec`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          leaseId: created.lease.leaseId,
          fencingToken: created.lease.fencingToken,
          command: ['bun', 'test', 'sample.test.ts'],
        }),
      });
      expect(execRes.status).toBe(200);
      const execBody = (await execRes.json()) as {
        ok: boolean;
        exitCode: number;
        redacted: boolean;
        stdout: string;
        traceId: string;
      };
      expect(execBody.ok).toBe(true);
      expect(execBody.exitCode).toBe(0);
      expect(execBody.redacted).toBe(true);
      expect(execBody.stdout).toContain('[REDACTED:EMAIL]');
      expect(execBody.stdout).toContain('[REDACTED:API_KEY]');
      expect(execBody.stdout).not.toContain('SecretValue1234567890');
      expect(execBody.traceId).toMatch(/^[a-f0-9]{32}$/u);

      // 4. POST /exec with disallowed command -> 403 COMMAND_NOT_ALLOWED
      const deniedRes = await fetch(`${server.url}/exec`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          leaseId: created.lease.leaseId,
          fencingToken: created.lease.fencingToken,
          command: ['sh', '-c', 'whoami'],
        }),
      });
      expect(deniedRes.status).toBe(403);
      const deniedBody = (await deniedRes.json()) as { error: { code: string } };
      expect(deniedBody.error.code).toBe('COMMAND_NOT_ALLOWED');

      // 5. Renew lease to advance monotonic fencing token, then verify old token rejected with 409
      const renewRes = await fetch(`${server.url}/leases/${created.lease.leaseId}/renew`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ fencingToken: 1 }),
      });
      expect(renewRes.status).toBe(200);
      const renewed = (await renewRes.json()) as { lease: { fencingToken: number } };
      expect(renewed.lease.fencingToken).toBe(2);

      const staleRes = await fetch(`${server.url}/exec`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          leaseId: created.lease.leaseId,
          fencingToken: 1,
          command: ['git', 'status'],
        }),
      });
      expect(staleRes.status).toBe(409);
      const staleBody = (await staleRes.json()) as { error: { code: string } };
      expect(staleBody.error.code).toBe('STALE_FENCING_TOKEN');

      // 6. DELETE /leases/:id releases worktree cleanly
      const delRes = await fetch(`${server.url}/leases/${created.lease.leaseId}`, {
        method: 'DELETE',
      });
      expect(delRes.status).toBe(200);
      const delBody = (await delRes.json()) as { ok: boolean; status: string };
      expect(delBody.ok).toBe(true);
      expect(delBody.status).toBe('released');
      expect(await stat(created.lease.worktreePath).catch(() => null)).toBeNull();

      // 7. Verify OTLP traces were delivered to mock mw-echo collector
      expect(receivedTraces.length).toBeGreaterThanOrEqual(4);
      const spanNames = receivedTraces.flatMap((t) =>
        t.resourceSpans.flatMap((rs) => rs.scopeSpans.flatMap((ss) => ss.spans.map((s) => s.name))),
      );
      expect(spanNames).toContain('sandbox.lease.acquire');
      expect(spanNames).toContain('sandbox.exec');
      expect(spanNames).toContain('sandbox.lease.release');
    } finally {
      await server.stop();
      mockEchoCollector.stop(true);
      await rm(worktreesRoot, { recursive: true, force: true });
      await rm(repoDir, { recursive: true, force: true });
    }
  });
});
