import { describe, expect, it } from 'bun:test';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { SandboxCommandRunner, buildSanitizedEnv } from '../src/command-runner.js';

describe('SandboxCommandRunner', () => {
  it('rejects disallowed binaries, unsafe subcommands, denied flags, and unsafe cwd paths', async () => {
    const runner = new SandboxCommandRunner();
    const dir = await mkdtemp(path.join(tmpdir(), 'rocksoul-cmd-deny-'));

    try {
      expect(() => runner.validateCommand(['sh', '-c', 'echo pwn'])).toThrow();
      expect(() => runner.validateCommand(['curl', 'https://example.com'])).toThrow();
      expect(() => runner.validateCommand(['/bin/git', 'status'])).toThrow();
      expect(() => runner.validateCommand(['git', 'push', 'origin', 'main'])).toThrow();
      expect(() => runner.validateCommand(['git', 'status', '-c', 'core.pager=sh'])).toThrow();
      expect(() => runner.validateCommand(['bun', '-e', 'console.log(1)'])).toThrow();
      expect(() => runner.validateCommand(['node', '--eval', 'process.exit(0)'])).toThrow();

      await expect(
        runner.run({ worktreePath: dir, command: ['bun', '--version'], cwd: '../outside' }),
      ).rejects.toMatchObject({ code: 'FORBIDDEN', statusCode: 403 });

      await expect(
        runner.run({ worktreePath: dir, command: ['bun', '--version'], cwd: '.env' }),
      ).rejects.toMatchObject({ code: 'FORBIDDEN', statusCode: 403 });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('strips host secret environment variables in buildSanitizedEnv', () => {
    const env = buildSanitizedEnv({
      PATH: '/usr/bin',
      AWS_SECRET_ACCESS_KEY: 'aws-secret',
      OPENAI_API_KEY: 'sk-123',
      ROCKSOUL_SANDBOX_TOKEN: 'secret-tok',
      CUSTOM_DB_PASSWORD: 'pw',
    });
    expect(env.PATH).toBe('/usr/bin');
    expect(env.CI).toBe('1');
    expect(env.AWS_SECRET_ACCESS_KEY).toBeUndefined();
    expect(env.OPENAI_API_KEY).toBeUndefined();
    expect(env.ROCKSOUL_SANDBOX_TOKEN).toBeUndefined();
    expect(env.CUSTOM_DB_PASSWORD).toBeUndefined();
  });

  it('executes allowlisted commands, redacts stdout/stderr secrets, enforces output bounds and timeouts', async () => {
    const runner = new SandboxCommandRunner();
    const dir = await mkdtemp(path.join(tmpdir(), 'rocksoul-cmd-exec-'));

    try {
      // 1. Fast allowlisted command
      const version = await runner.run({
        worktreePath: dir,
        command: ['bun', '--version'],
      });
      expect(version.exitCode).toBe(0);
      expect(version.timedOut).toBe(false);
      expect(version.truncated).toBe(false);
      expect(version.stdout.trim()).toMatch(/^\d+\.\d+/u);

      // 2. Redaction on stdout & stderr via allowlisted `bun test`
      await writeFile(
        path.join(dir, 'secret-leak.test.ts'),
        `import { test } from 'bun:test';
test('leak', () => {
  console.log('JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MiJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c');
  console.error('contact=ops@example.com key=sk-live-AbCdEfGhIjKlMnOpQrStUvWx');
});
`,
        'utf8',
      );
      const redactedRun = await runner.run({
        worktreePath: dir,
        command: ['bun', 'test', 'secret-leak.test.ts'],
      });
      expect(redactedRun.exitCode).toBe(0);
      expect(redactedRun.redacted).toBe(true);
      expect(redactedRun.stdout).toContain('[REDACTED:JWT]');
      expect(redactedRun.stdout).not.toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
      expect(redactedRun.stderr).toContain('[REDACTED:EMAIL]');
      expect(redactedRun.stderr).toContain('[REDACTED:API_KEY]');

      // 3. Output byte truncation bound
      await writeFile(
        path.join(dir, 'noisy.test.ts'),
        `import { test } from 'bun:test';
test('noisy', () => {
  for (let i = 0; i < 40; i += 1) console.log('X'.repeat(200));
});
`,
        'utf8',
      );
      const boundedRun = await runner.run({
        worktreePath: dir,
        command: ['bun', 'test', 'noisy.test.ts'],
        maxOutputBytes: 512,
      });
      expect(boundedRun.truncated).toBe(true);
      expect(boundedRun.exitCode).toBe(125);
      expect(boundedRun.stdoutBytes + boundedRun.stderrBytes).toBeLessThanOrEqual(512);

      // 4. Timeout enforcement
      await writeFile(
        path.join(dir, 'slow.test.ts'),
        `import { test } from 'bun:test';
test('slow', async () => {
  await new Promise((resolve) => setTimeout(resolve, 10000));
});
`,
        'utf8',
      );
      const timedOutRun = await runner.run({
        worktreePath: dir,
        command: ['bun', 'test', 'slow.test.ts'],
        timeoutMs: 250,
      });
      expect(timedOutRun.timedOut).toBe(true);
      expect(timedOutRun.exitCode).toBe(124);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
