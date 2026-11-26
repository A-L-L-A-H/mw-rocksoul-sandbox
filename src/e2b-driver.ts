import { SandboxError } from './errors.js';
import type { LeaseRecord } from './lease-manager.js';
import { WorktreeLeaseManager } from './lease-manager.js';
import { OtelTraceExporter, type FetchLike } from './otel-exporter.js';
import {
  SandboxCommandRunner,
  type CommandExecutionResult,
} from './command-runner.js';
import { redactText } from './redactor.js';

export const DEFAULT_E2B_API_BASE_URL = 'https://api.e2b.dev';

export type ExecutionBackend = 'e2b-firecracker' | 'local-worktree';

export interface E2bExecuteParams {
  readonly leaseId: string;
  readonly fencingToken: number;
  readonly command: readonly string[];
  readonly cwd?: string;
  readonly timeoutMs?: number;
}

export interface E2bExecutionResult extends CommandExecutionResult {
  readonly backend: ExecutionBackend;
  readonly fencingToken: number;
  readonly leaseId: string;
  readonly traceId: string;
}

export interface E2bDriverOptions {
  readonly leaseManager: WorktreeLeaseManager;
  readonly localRunner?: SandboxCommandRunner;
  readonly exporter?: OtelTraceExporter;
  readonly apiKey?: string;
  readonly baseUrl?: string;
  readonly fetchImpl?: FetchLike;
  readonly template?: string;
}

interface E2bCommandResponse {
  readonly stdout?: string;
  readonly stderr?: string;
  readonly exitCode?: number;
}

interface E2bSandboxResponse {
  readonly sandboxID?: string;
}

/**
 * Optional E2B Firecracker microVM driver. Falls back to the local worktree runner
 * when E2B_API_KEY is absent. Fencing tokens are validated before any dispatch and
 * all remote output is redacted before leaving the driver.
 */
export class E2bExecutionDriver {
  private readonly leaseManager: WorktreeLeaseManager;
  private readonly localRunner: SandboxCommandRunner;
  private readonly exporter: OtelTraceExporter;
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly fetchImpl: FetchLike;
  private readonly template: string;

  constructor(options: E2bDriverOptions) {
    this.leaseManager = options.leaseManager;
    this.localRunner = options.localRunner ?? new SandboxCommandRunner();
    this.exporter = options.exporter ?? new OtelTraceExporter({ enabled: false });
    this.apiKey = (options.apiKey ?? process.env.E2B_API_KEY ?? '').trim();
    this.baseUrl = (options.baseUrl ?? DEFAULT_E2B_API_BASE_URL).replace(/\/+$/, '');
    this.fetchImpl = options.fetchImpl ?? ((input, init) => fetch(input, init));
    this.template = options.template ?? 'base';
  }

  get backend(): ExecutionBackend {
    return this.apiKey === '' ? 'local-worktree' : 'e2b-firecracker';
  }

  async execute(params: E2bExecuteParams): Promise<E2bExecutionResult> {
    const lease: LeaseRecord = await this.leaseManager.validateLeaseAccess(
      params.leaseId,
      params.fencingToken,
    );
    const span = this.exporter.startSpan('sandbox.execute', {
      'sandbox.backend': this.backend,
      'sandbox.lease_id': lease.leaseId,
      'sandbox.fencing_token': lease.fencingToken,
    });
    try {
      const result =
        this.apiKey === ''
          ? await this.runLocal(lease, params)
          : await this.runRemote(lease, params);
      span.setAttribute('sandbox.exit_code', result.exitCode);
      await this.exporter.exportSpans([span.end({ ok: result.exitCode === 0 })]);
      return { ...result, backend: this.backend, fencingToken: lease.fencingToken, leaseId: lease.leaseId, traceId: span.traceId };
    } catch (error) {
      const failure = span.end({ ok: false, message: error instanceof Error ? error.message : 'unknown' });
      await this.exporter.exportSpans([failure]);
      throw error;
    }
  }

  private async runLocal(lease: LeaseRecord, params: E2bExecuteParams): Promise<CommandExecutionResult> {
    return this.localRunner.run({
      worktreePath: lease.worktreePath,
      command: params.command,
      ...(params.cwd !== undefined ? { cwd: params.cwd } : {}),
      ...(params.timeoutMs !== undefined ? { timeoutMs: params.timeoutMs } : {}),
    });
  }

  private async runRemote(lease: LeaseRecord, params: E2bExecuteParams): Promise<CommandExecutionResult> {
    // Allowlist validation applies identically to remote dispatch.
    const command = this.localRunner.validateCommand(params.command);
    const startedAt = Date.now();
    const headers = { 'X-API-Key': this.apiKey, 'Content-Type': 'application/json' };
    const created = await this.fetchImpl(`${this.baseUrl}/sandboxes`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ templateID: this.template, timeout: Math.ceil((params.timeoutMs ?? 60_000) / 1000) }),
    });
    if (!created.ok) {
      throw new SandboxError('INTERNAL', `E2B sandbox creation failed with status ${created.status}`);
    }
    const sandbox = (await created.json()) as E2bSandboxResponse;
    if (typeof sandbox.sandboxID !== 'string' || sandbox.sandboxID === '') {
      throw new SandboxError('INTERNAL', 'E2B sandbox creation returned no sandboxID');
    }
    try {
      const executed = await this.fetchImpl(
        `${this.baseUrl}/sandboxes/${encodeURIComponent(sandbox.sandboxID)}/commands`,
        {
          method: 'POST',
          headers,
          body: JSON.stringify({ cmd: command, cwd: params.cwd ?? '/home/user', fencingToken: lease.fencingToken }),
        },
      );
      if (!executed.ok) {
        throw new SandboxError('INTERNAL', `E2B command dispatch failed with status ${executed.status}`);
      }
      const payload = (await executed.json()) as E2bCommandResponse;
      const stdout = redactText(payload.stdout ?? '');
      const stderr = redactText(payload.stderr ?? '');
      const categories = [...new Set([...stdout.categories, ...stderr.categories])];
      return {
        command,
        cwd: params.cwd ?? '/home/user',
        exitCode: payload.exitCode ?? 0,
        durationMs: Date.now() - startedAt,
        timedOut: false,
        truncated: false,
        stdout: stdout.text,
        stderr: stderr.text,
        stdoutBytes: Buffer.byteLength(stdout.text),
        stderrBytes: Buffer.byteLength(stderr.text),
        redacted: stdout.redactionCount + stderr.redactionCount > 0,
        redactionCount: stdout.redactionCount + stderr.redactionCount,
        redactionCategories: categories,
      };
    } finally {
      await this.fetchImpl(`${this.baseUrl}/sandboxes/${encodeURIComponent(sandbox.sandboxID)}`, {
        method: 'DELETE',
        headers,
      }).catch(() => undefined);
    }
  }
}
