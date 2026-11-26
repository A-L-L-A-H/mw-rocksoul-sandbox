import { timingSafeEqual } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  SandboxCommandRunner,
  type CommandRunnerOptions,
} from './command-runner.js';
import { SandboxError, asSandboxError } from './errors.js';
import {
  WorktreeLeaseManager,
  type AcquireLeaseParams,
  type LeaseManagerOptions,
} from './lease-manager.js';
import {
  DEFAULT_OTLP_TRACES_ENDPOINT,
  OtelTraceExporter,
  type OtelExporterOptions,
} from './otel-exporter.js';

export const DEFAULT_SANDBOX_PORT = 4540;
export const DEFAULT_SANDBOX_HOST = '127.0.0.1';
export const SANDBOX_SERVICE_NAME = 'mw-rocksoul-sandbox';
export const SANDBOX_SERVICE_VERSION = '1.0.0';
const MAX_REQUEST_BYTES = 1_048_576;

export interface SandboxApplicationOptions {
  readonly leaseManager?: LeaseManagerOptions;
  readonly commandRunner?: CommandRunnerOptions;
  readonly otelExporter?: OtelExporterOptions;
  readonly authToken?: string;
}

export interface SandboxApplication {
  readonly leaseManager: WorktreeLeaseManager;
  readonly commandRunner: SandboxCommandRunner;
  readonly otelExporter: OtelTraceExporter;
  readonly authToken?: string;
  readonly close: () => Promise<void>;
}

export interface SandboxServerConfig {
  readonly host: string;
  readonly port: number;
  readonly worktreesRoot: string;
  readonly otlpEndpoint: string;
  readonly authToken?: string;
}

export interface RunningSandboxServer {
  readonly port: number;
  readonly hostname: string;
  readonly url: string;
  readonly stop: () => Promise<void>;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function assertSafeObject(value: unknown, label: string): Record<string, unknown> {
  if (!isPlainObject(value)) {
    throw new SandboxError('INVALID_REQUEST', `${label} must be a JSON object`);
  }
  const checkNested = (node: unknown): void => {
    if (!isPlainObject(node)) return;
    for (const key of Object.keys(node)) {
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        throw new SandboxError('INVALID_REQUEST', `${label} contains forbidden key "${key}"`);
      }
      checkNested(node[key]);
    }
  };
  checkNested(value);
  return value;
}

export function isAuthorizedBearer(
  header: string | null | undefined,
  expectedToken: string | undefined,
): boolean {
  if (expectedToken === undefined || expectedToken.length === 0) return true;
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) return false;
  const presented = Buffer.from(header.slice('Bearer '.length), 'utf8');
  const expected = Buffer.from(expectedToken, 'utf8');
  return presented.length === expected.length && timingSafeEqual(presented, expected);
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
    },
  });
}

async function parseBoundedJsonBody(request: Request): Promise<Record<string, unknown>> {
  const text = await request.text();
  if (Buffer.byteLength(text, 'utf8') > MAX_REQUEST_BYTES) {
    throw new SandboxError('OUTPUT_LIMIT', 'Request body exceeds 1 MiB limit', { statusCode: 413 });
  }
  if (text.trim().length === 0) {
    return {};
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new SandboxError('INVALID_REQUEST', 'Request body must be valid JSON');
  }
  return assertSafeObject(parsed, 'body');
}

function parseAcquireLeaseBody(body: Record<string, unknown>): AcquireLeaseParams {
  if (typeof body.repoPath !== 'string' || body.repoPath.trim() === '') {
    throw new SandboxError('INVALID_REQUEST', 'repoPath must be a non-empty string');
  }
  if (typeof body.ownerId !== 'string' || body.ownerId.trim() === '') {
    throw new SandboxError('INVALID_REQUEST', 'ownerId must be a non-empty string');
  }
  if (body.baseRef !== undefined && typeof body.baseRef !== 'string') {
    throw new SandboxError('INVALID_REQUEST', 'baseRef must be a string');
  }
  if (body.ttlMs !== undefined && typeof body.ttlMs !== 'number') {
    throw new SandboxError('INVALID_REQUEST', 'ttlMs must be a number');
  }
  if (body.exclusive !== undefined && typeof body.exclusive !== 'boolean') {
    throw new SandboxError('INVALID_REQUEST', 'exclusive must be a boolean');
  }
  if (body.label !== undefined && typeof body.label !== 'string') {
    throw new SandboxError('INVALID_REQUEST', 'label must be a string');
  }
  return {
    repoPath: body.repoPath,
    ownerId: body.ownerId,
    ...(body.baseRef !== undefined ? { baseRef: body.baseRef } : {}),
    ...(body.ttlMs !== undefined ? { ttlMs: body.ttlMs } : {}),
    ...(body.exclusive !== undefined ? { exclusive: body.exclusive } : {}),
    ...(body.label !== undefined ? { label: body.label } : {}),
  };
}

interface ExecBody {
  readonly leaseId: string;
  readonly fencingToken: number;
  readonly command: readonly string[];
  readonly cwd?: string;
  readonly timeoutMs?: number;
  readonly maxOutputBytes?: number;
}

function parseExecBody(body: Record<string, unknown>): ExecBody {
  if (typeof body.leaseId !== 'string' || body.leaseId.trim() === '') {
    throw new SandboxError('INVALID_REQUEST', 'leaseId must be a non-empty string');
  }
  if (typeof body.fencingToken !== 'number' || !Number.isSafeInteger(body.fencingToken)) {
    throw new SandboxError('INVALID_REQUEST', 'fencingToken must be an integer');
  }
  if (!Array.isArray(body.command) || !body.command.every((entry) => typeof entry === 'string')) {
    throw new SandboxError('INVALID_REQUEST', 'command must be an array of strings');
  }
  if (body.cwd !== undefined && typeof body.cwd !== 'string') {
    throw new SandboxError('INVALID_REQUEST', 'cwd must be a string');
  }
  if (body.timeoutMs !== undefined && typeof body.timeoutMs !== 'number') {
    throw new SandboxError('INVALID_REQUEST', 'timeoutMs must be a number');
  }
  if (body.maxOutputBytes !== undefined && typeof body.maxOutputBytes !== 'number') {
    throw new SandboxError('INVALID_REQUEST', 'maxOutputBytes must be a number');
  }
  return {
    leaseId: body.leaseId,
    fencingToken: body.fencingToken,
    command: body.command,
    ...(body.cwd !== undefined ? { cwd: body.cwd } : {}),
    ...(body.timeoutMs !== undefined ? { timeoutMs: body.timeoutMs } : {}),
    ...(body.maxOutputBytes !== undefined ? { maxOutputBytes: body.maxOutputBytes } : {}),
  };
}

export function createSandboxApplication(
  options: SandboxApplicationOptions = {},
): SandboxApplication {
  const worktreesRoot =
    options.leaseManager?.worktreesRoot ?? path.join(tmpdir(), 'mw-rocksoul-sandbox-worktrees');
  const leaseManager = new WorktreeLeaseManager({
    ...options.leaseManager,
    worktreesRoot,
  });
  const commandRunner = new SandboxCommandRunner(options.commandRunner);
  const otelExporter = new OtelTraceExporter(options.otelExporter);

  return {
    leaseManager,
    commandRunner,
    otelExporter,
    ...(options.authToken !== undefined ? { authToken: options.authToken } : {}),
    close: async () => {
      await leaseManager.close();
    },
  };
}

export function createSandboxFetchHandler(
  app: SandboxApplication,
  meta: { readonly port: number },
): (request: Request) => Promise<Response> {
  return async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    const pathname = url.pathname;

    if (request.method === 'GET' && pathname === '/health') {
      return jsonResponse({
        ok: true,
        service: SANDBOX_SERVICE_NAME,
        version: SANDBOX_SERVICE_VERSION,
        port: meta.port,
        activeLeases: app.leaseManager.activeLeaseCount,
        totalLeases: app.leaseManager.totalLeaseCount,
        currentFencingToken: app.leaseManager.currentFencingToken,
        telemetry: app.otelExporter.getStats(),
      });
    }

    if (!isAuthorizedBearer(request.headers.get('authorization'), app.authToken)) {
      return jsonResponse(
        {
          ok: false,
          error: {
            code: 'UNAUTHENTICATED',
            message: 'Invalid or missing sandbox bearer credential',
            retryable: false,
          },
        },
        401,
      );
    }

    try {
      // GET /leases
      if (request.method === 'GET' && pathname === '/leases') {
        const leases = app.leaseManager.listLeases();
        return jsonResponse({ ok: true, leases, count: leases.length }, 200);
      }

      // POST /leases
      if (request.method === 'POST' && pathname === '/leases') {
        const body = await parseBoundedJsonBody(request);
        const params = parseAcquireLeaseBody(body);
        const span = app.otelExporter.startSpan('sandbox.lease.acquire', {
          'sandbox.owner_id': params.ownerId,
          'sandbox.exclusive': params.exclusive === true,
        });
        try {
          const lease = await app.leaseManager.acquireLease(params);
          span.setAttribute('sandbox.lease_id', lease.leaseId);
          span.setAttribute('sandbox.fencing_token', lease.fencingToken);
          const finished = span.end({ ok: true });
          await app.otelExporter.exportSpans([finished]);
          return jsonResponse({ ok: true, lease, traceId: finished.traceId }, 201);
        } catch (error) {
          const sandboxError = asSandboxError(error);
          const finished = span.end({ ok: false, message: sandboxError.message });
          await app.otelExporter.exportSpans([finished]);
          throw sandboxError;
        }
      }

      // /leases/:id and /leases/:id/renew
      const leaseMatch = /^\/leases\/([^/]+)(\/renew)?$/u.exec(pathname);
      if (leaseMatch) {
        const leaseId = decodeURIComponent(leaseMatch[1]!);
        const isRenew = leaseMatch[2] === '/renew';

        if (!isRenew && request.method === 'GET') {
          const lease = app.leaseManager.getLease(leaseId);
          return jsonResponse({ ok: true, lease }, 200);
        }

        if (isRenew && request.method === 'POST') {
          const body = await parseBoundedJsonBody(request);
          if (typeof body.fencingToken !== 'number') {
            throw new SandboxError('INVALID_REQUEST', 'fencingToken must be a positive integer');
          }
          const ttlMs = typeof body.ttlMs === 'number' ? body.ttlMs : undefined;
          const lease = await app.leaseManager.renewLease({
            leaseId,
            fencingToken: body.fencingToken,
            ...(ttlMs !== undefined ? { ttlMs } : {}),
          });
          return jsonResponse({ ok: true, lease }, 200);
        }

        if (!isRenew && request.method === 'DELETE') {
          const span = app.otelExporter.startSpan('sandbox.lease.release', {
            'sandbox.lease_id': leaseId,
          });
          try {
            const released = await app.leaseManager.releaseLease(leaseId);
            const finished = span.end({ ok: true });
            await app.otelExporter.exportSpans([finished]);
            return jsonResponse({ ok: true, ...released, traceId: finished.traceId }, 200);
          } catch (error) {
            const sandboxError = asSandboxError(error);
            const finished = span.end({ ok: false, message: sandboxError.message });
            await app.otelExporter.exportSpans([finished]);
            throw sandboxError;
          }
        }

        return jsonResponse({ ok: false, error: { code: 'INVALID_REQUEST', message: 'Method not allowed', retryable: false } }, 405);
      }

      // POST /exec
      if (request.method === 'POST' && pathname === '/exec') {
        const body = await parseBoundedJsonBody(request);
        const execParams = parseExecBody(body);
        const span = app.otelExporter.startSpan('sandbox.exec', {
          'sandbox.lease_id': execParams.leaseId,
          'sandbox.fencing_token': execParams.fencingToken,
          'sandbox.binary': execParams.command[0] ?? '',
        });

        try {
          const lease = await app.leaseManager.validateLeaseAccess(
            execParams.leaseId,
            execParams.fencingToken,
          );
          const result = await app.commandRunner.run({
            worktreePath: lease.worktreePath,
            command: execParams.command,
            cwd: execParams.cwd,
            timeoutMs: execParams.timeoutMs,
            maxOutputBytes: execParams.maxOutputBytes,
          });

          span.setAttribute('sandbox.exit_code', result.exitCode);
          span.setAttribute('sandbox.duration_ms', result.durationMs);
          span.setAttribute('sandbox.timed_out', result.timedOut);
          span.setAttribute('sandbox.truncated', result.truncated);
          span.setAttribute('sandbox.redacted', result.redacted);
          span.setAttribute('sandbox.redaction_count', result.redactionCount);

          const finished = span.end(
            result.exitCode === 0
              ? { ok: true }
              : {
                  ok: false,
                  message: result.timedOut
                    ? 'command timed out'
                    : result.truncated
                      ? 'command output truncated'
                      : `exit code ${result.exitCode}`,
                },
          );
          await app.otelExporter.exportSpans([finished]);

          return jsonResponse(
            {
              ok: true,
              leaseId: lease.leaseId,
              fencingToken: lease.fencingToken,
              traceId: finished.traceId,
              ...result,
            },
            200,
          );
        } catch (error) {
          const sandboxError = asSandboxError(error);
          span.setAttribute('sandbox.error_code', sandboxError.code);
          const finished = span.end({ ok: false, message: sandboxError.message });
          await app.otelExporter.exportSpans([finished]);
          throw sandboxError;
        }
      }

      return jsonResponse(
        { ok: false, error: { code: 'NOT_FOUND', message: 'Not found', retryable: false } },
        404,
      );
    } catch (error) {
      const sandboxError = asSandboxError(error);
      return jsonResponse(
        {
          ok: false,
          error: {
            code: sandboxError.code,
            message: sandboxError.message,
            retryable: sandboxError.retryable,
            ...(sandboxError.details !== undefined ? { details: sandboxError.details } : {}),
          },
        },
        sandboxError.statusCode,
      );
    }
  };
}

export function startSandboxServer(
  app: SandboxApplication,
  options: { readonly host?: string; readonly port?: number } = {},
): RunningSandboxServer {
  const host = options.host ?? DEFAULT_SANDBOX_HOST;
  const requestedPort = options.port ?? DEFAULT_SANDBOX_PORT;

  let actualPort = requestedPort;
  const server = Bun.serve({
    hostname: host,
    port: requestedPort,
    fetch: (request) => createSandboxFetchHandler(app, { port: actualPort })(request),
  });
  actualPort = server.port ?? requestedPort;

  return {
    port: actualPort,
    hostname: server.hostname ?? host,
    url: `http://${server.hostname ?? host}:${actualPort}`,
    stop: async () => {
      server.stop(true);
      await app.close();
    },
  };
}

export function loadSandboxServerConfig(
  env: Readonly<Record<string, string | undefined>> = process.env,
): SandboxServerConfig {
  const host = env.ROCKSOUL_SANDBOX_HOST ?? DEFAULT_SANDBOX_HOST;
  const rawPort = Number(env.ROCKSOUL_SANDBOX_PORT ?? env.PORT ?? DEFAULT_SANDBOX_PORT);
  const port =
    Number.isInteger(rawPort) && rawPort >= 0 && rawPort <= 65535 ? rawPort : DEFAULT_SANDBOX_PORT;
  const worktreesRoot =
    env.ROCKSOUL_SANDBOX_WORKTREES_DIR && path.isAbsolute(env.ROCKSOUL_SANDBOX_WORKTREES_DIR)
      ? env.ROCKSOUL_SANDBOX_WORKTREES_DIR
      : path.join(tmpdir(), 'mw-rocksoul-sandbox-worktrees');
  const otlpEndpoint =
    env.MW_ECHO_OTLP_URL ?? env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT ?? DEFAULT_OTLP_TRACES_ENDPOINT;
  const authToken =
    typeof env.ROCKSOUL_SANDBOX_TOKEN === 'string' && env.ROCKSOUL_SANDBOX_TOKEN.trim().length > 0
      ? env.ROCKSOUL_SANDBOX_TOKEN.trim()
      : undefined;

  return {
    host,
    port,
    worktreesRoot,
    otlpEndpoint,
    ...(authToken !== undefined ? { authToken } : {}),
  };
}

if (import.meta.main) {
  const config = loadSandboxServerConfig();
  const app = createSandboxApplication({
    leaseManager: { worktreesRoot: config.worktreesRoot },
    otelExporter: { endpoint: config.otlpEndpoint },
    authToken: config.authToken,
  });
  const running = startSandboxServer(app, { host: config.host, port: config.port });
  process.stderr.write(`mw-rocksoul-sandbox listening on ${running.url}\n`);

  let stopping = false;
  const shutdown = (): void => {
    if (stopping) return;
    stopping = true;
    void running.stop().finally(() => process.exit(0));
  };
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);
}
