import { lstat, realpath } from 'node:fs/promises';
import path from 'node:path';
import { SandboxError } from './errors.js';
import { redactOutput, type RedactionCategory } from './redactor.js';

export interface CommandAllowlistRule {
  readonly binary: string;
  readonly allowedFirstArgs?: readonly string[];
  readonly deniedFlags?: readonly string[];
}

export interface CommandRunParams {
  readonly worktreePath: string;
  readonly command: readonly string[];
  readonly cwd?: string;
  readonly timeoutMs?: number;
  readonly maxOutputBytes?: number;
}

export interface CommandExecutionResult {
  readonly command: readonly string[];
  readonly cwd: string;
  readonly exitCode: number;
  readonly durationMs: number;
  readonly timedOut: boolean;
  readonly truncated: boolean;
  readonly stdout: string;
  readonly stderr: string;
  readonly stdoutBytes: number;
  readonly stderrBytes: number;
  readonly redacted: boolean;
  readonly redactionCount: number;
  readonly redactionCategories: readonly RedactionCategory[];
}

export interface CommandRunnerOptions {
  readonly allowlist?: readonly CommandAllowlistRule[];
  readonly defaultTimeoutMs?: number;
  readonly maxTimeoutMs?: number;
  readonly defaultMaxOutputBytes?: number;
  readonly maxOutputBytesCeiling?: number;
}

export const DEFAULT_COMMAND_ALLOWLIST: readonly CommandAllowlistRule[] = Object.freeze([
  {
    binary: 'git',
    allowedFirstArgs: [
      'status',
      'diff',
      'log',
      'rev-parse',
      'show',
      'branch',
      'ls-files',
      'grep',
      'add',
      'commit',
      'checkout',
      'restore',
      '--version',
    ],
    deniedFlags: [
      '-c',
      '--config-env',
      '--exec-path',
      '--git-dir',
      '--work-tree',
      '--upload-pack',
      '--receive-pack',
      '--ext-diff',
    ],
  },
  {
    binary: 'bun',
    allowedFirstArgs: ['test', 'run', 'build', '--version'],
    deniedFlags: ['-e', '--eval', '-p', '--print'],
  },
  {
    binary: 'node',
    allowedFirstArgs: ['--version', '--test', '--check'],
    deniedFlags: ['-e', '--eval', '-p', '--print', '-r', '--require', '--import'],
  },
  {
    binary: 'go',
    allowedFirstArgs: ['test', 'vet', 'build', 'version', 'list', 'fmt'],
  },
  {
    binary: 'cargo',
    allowedFirstArgs: ['test', 'check', 'clippy', 'build', '--version'],
  },
  {
    binary: 'tsc',
    allowedFirstArgs: ['--noEmit', '--version', '-p'],
  },
  { binary: 'echo' },
  { binary: 'pwd' },
  { binary: 'ls' },
  { binary: 'cat' },
  { binary: 'head' },
  { binary: 'tail' },
  { binary: 'wc' },
  { binary: 'grep' },
  { binary: 'rg' },
]);

const MIN_TIMEOUT_MS = 100;
const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_TIMEOUT_MS = 120_000;
const MIN_OUTPUT_BYTES = 256;
const DEFAULT_MAX_OUTPUT_BYTES = 65_536;
const MAX_OUTPUT_BYTES = 1_048_576;
const MAX_ARGS = 64;
const MAX_ARG_BYTES = 4096;
const SAFE_BINARY_NAME = /^[a-z0-9][a-z0-9._-]{0,31}$/u;
const SENSITIVE_SEGMENT =
  /^(?:\.git|\.env(?:\..*)?|\.npmrc|\.pypirc|\.netrc|_netrc|\.aws|\.ssh|\.gnupg|\.docker|\.kube|\.secrets|secrets|credentials(?:\.json)?|service-account[^/]*\.json|id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?)$/iu;
const SECRET_ENV_KEY_PATTERN =
  /^(?:AWS_|AZURE_|GOOGLE_|GCP_|OPENAI_|ANTHROPIC_|GEMINI_|GITHUB_|GH_|MW_.*(?:TOKEN|SECRET|KEY)|ROCKSOUL_.*(?:TOKEN|SECRET|KEY)|.*(?:SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|API_KEY|PRIVATE_KEY)).*$/iu;

function hasControlChar(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

export function buildSanitizedEnv(
  hostEnv: Readonly<Record<string, string | undefined>> = process.env,
): Record<string, string> {
  const sanitized: Record<string, string> = {
    CI: '1',
    NO_COLOR: '1',
    GIT_TERMINAL_PROMPT: '0',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null',
  };

  const safePassthroughKeys = new Set([
    'PATH',
    'Path',
    'PATHEXT',
    'SYSTEMROOT',
    'SystemRoot',
    'WINDIR',
    'COMSPEC',
    'ComSpec',
    'TEMP',
    'TMP',
    'TMPDIR',
    'HOME',
    'USERPROFILE',
    'LANG',
    'LC_ALL',
    'BUN_INSTALL',
    'GOPATH',
    'GOROOT',
    'CARGO_HOME',
    'RUSTUP_HOME',
  ]);

  for (const [key, value] of Object.entries(hostEnv)) {
    if (typeof value !== 'string') continue;
    if (SECRET_ENV_KEY_PATTERN.test(key)) continue;
    if (safePassthroughKeys.has(key)) {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

export async function resolveSafeSubdir(worktreePath: string, relativeCwd?: string): Promise<string> {
  const rootReal = await realpath(worktreePath);
  if (relativeCwd === undefined || relativeCwd === '' || relativeCwd === '.') {
    return rootReal;
  }

  if (
    hasControlChar(relativeCwd) ||
    relativeCwd.includes('\\') ||
    relativeCwd.includes(':') ||
    relativeCwd.startsWith('/') ||
    relativeCwd.startsWith('~') ||
    relativeCwd.includes('//')
  ) {
    throw new SandboxError('FORBIDDEN', 'cwd must be a safe relative path within the leased worktree');
  }

  const segments = relativeCwd.split('/');
  for (const segment of segments) {
    if (segment === '' || segment === '.' || segment === '..' || SENSITIVE_SEGMENT.test(segment)) {
      throw new SandboxError('FORBIDDEN', `cwd segment "${segment}" is forbidden`);
    }
  }

  let current = rootReal;
  for (const segment of segments) {
    current = path.join(current, segment);
    const info = await lstat(current).catch(() => null);
    if (!info) {
      throw new SandboxError('NOT_FOUND', `Requested cwd "${relativeCwd}" does not exist`);
    }
    if (info.isSymbolicLink()) {
      throw new SandboxError('FORBIDDEN', `cwd "${relativeCwd}" traverses a symbolic link`);
    }
  }

  const resolvedTarget = await realpath(current);
  const rel = path.relative(rootReal, resolvedTarget);
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new SandboxError('FORBIDDEN', 'Resolved cwd escapes the leased worktree');
  }
  return resolvedTarget;
}

export class SandboxCommandRunner {
  private readonly rulesByBinary: ReadonlyMap<string, CommandAllowlistRule>;
  private readonly defaultTimeoutMs: number;
  private readonly maxTimeoutMs: number;
  private readonly defaultMaxOutputBytes: number;
  private readonly maxOutputBytesCeiling: number;

  constructor(options: CommandRunnerOptions = {}) {
    const rules = options.allowlist ?? DEFAULT_COMMAND_ALLOWLIST;
    const map = new Map<string, CommandAllowlistRule>();
    for (const rule of rules) {
      map.set(rule.binary, rule);
    }
    this.rulesByBinary = map;
    this.maxTimeoutMs = Math.max(MIN_TIMEOUT_MS, Math.min(MAX_TIMEOUT_MS, options.maxTimeoutMs ?? MAX_TIMEOUT_MS));
    this.defaultTimeoutMs = Math.max(
      MIN_TIMEOUT_MS,
      Math.min(this.maxTimeoutMs, options.defaultTimeoutMs ?? DEFAULT_TIMEOUT_MS),
    );
    this.maxOutputBytesCeiling = Math.max(
      MIN_OUTPUT_BYTES,
      Math.min(MAX_OUTPUT_BYTES, options.maxOutputBytesCeiling ?? MAX_OUTPUT_BYTES),
    );
    this.defaultMaxOutputBytes = Math.max(
      MIN_OUTPUT_BYTES,
      Math.min(this.maxOutputBytesCeiling, options.defaultMaxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES),
    );
  }

  validateCommand(command: readonly string[]): readonly string[] {
    if (!Array.isArray(command) || command.length === 0 || command.length > MAX_ARGS) {
      throw new SandboxError(
        'INVALID_REQUEST',
        `command must be a non-empty array of 1..${MAX_ARGS} string arguments`,
      );
    }

    for (let i = 0; i < command.length; i += 1) {
      const arg = command[i];
      if (typeof arg !== 'string' || arg.length === 0 || Buffer.byteLength(arg, 'utf8') > MAX_ARG_BYTES) {
        throw new SandboxError('INVALID_REQUEST', `command[${i}] must be a bounded non-empty string`);
      }
      if (arg.includes('\0') || hasControlChar(arg)) {
        throw new SandboxError('FORBIDDEN', `command[${i}] contains forbidden control characters`);
      }
    }

    const binary = command[0]!;
    if (!SAFE_BINARY_NAME.test(binary)) {
      throw new SandboxError(
        'COMMAND_NOT_ALLOWED',
        `Binary "${binary}" is not a bare allowlisted command name`,
      );
    }

    const rule = this.rulesByBinary.get(binary);
    if (!rule) {
      throw new SandboxError(
        'COMMAND_NOT_ALLOWED',
        `Command binary "${binary}" is not in the sandbox allowlist`,
        { details: { binary } },
      );
    }

    if (rule.allowedFirstArgs && rule.allowedFirstArgs.length > 0) {
      const firstArg = command[1];
      if (firstArg === undefined || !rule.allowedFirstArgs.includes(firstArg)) {
        throw new SandboxError(
          'COMMAND_NOT_ALLOWED',
          `Subcommand "${firstArg ?? '<none>'}" is not allowed for binary "${binary}"`,
          { details: { binary, subcommand: firstArg ?? null, allowed: rule.allowedFirstArgs } },
        );
      }
    }

    if (rule.deniedFlags && rule.deniedFlags.length > 0) {
      for (let i = 1; i < command.length; i += 1) {
        const arg = command[i]!;
        for (const denied of rule.deniedFlags) {
          if (arg === denied || arg.startsWith(`${denied}=`)) {
            throw new SandboxError(
              'COMMAND_NOT_ALLOWED',
              `Flag "${arg}" is denied for binary "${binary}"`,
              { details: { binary, flag: arg } },
            );
          }
        }
      }
    }

    return [...command];
  }

  async run(params: CommandRunParams): Promise<CommandExecutionResult> {
    const validatedCommand = this.validateCommand(params.command);
    const resolvedCwd = await resolveSafeSubdir(params.worktreePath, params.cwd);

    const timeoutMs =
      params.timeoutMs === undefined
        ? this.defaultTimeoutMs
        : Math.max(MIN_TIMEOUT_MS, Math.min(this.maxTimeoutMs, Math.trunc(params.timeoutMs)));
    if (!Number.isFinite(timeoutMs)) {
      throw new SandboxError('INVALID_REQUEST', 'timeoutMs must be a finite number');
    }

    const maxOutputBytes =
      params.maxOutputBytes === undefined
        ? this.defaultMaxOutputBytes
        : Math.max(
            MIN_OUTPUT_BYTES,
            Math.min(this.maxOutputBytesCeiling, Math.trunc(params.maxOutputBytes)),
          );
    if (!Number.isFinite(maxOutputBytes)) {
      throw new SandboxError('INVALID_REQUEST', 'maxOutputBytes must be a finite number');
    }

    const spawnArgv = [...validatedCommand];
    if (
      spawnArgv[0] === 'bun' &&
      path.basename(process.execPath).toLowerCase().replace(/\.exe$/u, '') === 'bun'
    ) {
      spawnArgv[0] = process.execPath;
    }

    const startedAt = Date.now();
    const proc = Bun.spawn(spawnArgv, {
      cwd: resolvedCwd,
      stdin: 'ignore',
      stdout: 'pipe',
      stderr: 'pipe',
      env: buildSanitizedEnv(),
    });

    let timedOut = false;
    let truncated = false;
    let killed = false;
    const activeReaders: Array<ReadableStreamDefaultReader<Uint8Array>> = [];

    const killProcess = (): void => {
      if (killed) return;
      killed = true;
      if (process.platform === 'win32' && typeof proc.pid === 'number' && proc.pid > 0) {
        try {
          Bun.spawnSync(['taskkill', '/F', '/T', '/PID', String(proc.pid)], {
            stdin: 'ignore',
            stdout: 'ignore',
            stderr: 'ignore',
          });
        } catch {
          // Fallback to direct Bun process termination below.
        }
      }
      try {
        proc.kill(9);
      } catch {
        // Process already exited.
      }
      for (const reader of activeReaders) {
        void reader.cancel().catch(() => undefined);
      }
    };

    const timer = setTimeout(() => {
      timedOut = true;
      killProcess();
    }, timeoutMs);

    const stdoutChunks: Uint8Array[] = [];
    const stderrChunks: Uint8Array[] = [];
    let totalCapturedBytes = 0;

    const readBoundedStream = async (
      stream: ReadableStream<Uint8Array>,
      sink: Uint8Array[],
    ): Promise<void> => {
      const reader = stream.getReader();
      activeReaders.push(reader);
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (!value || value.byteLength === 0) continue;

          const remaining = Math.max(0, maxOutputBytes - totalCapturedBytes);
          if (value.byteLength > remaining) {
            if (remaining > 0) {
              sink.push(value.subarray(0, remaining));
              totalCapturedBytes += remaining;
            }
            truncated = true;
            killProcess();
            break;
          }

          sink.push(value);
          totalCapturedBytes += value.byteLength;
        }
      } catch {
        // Stream aborted after kill/timeout.
      } finally {
        reader.releaseLock();
      }
    };

    let rawExitCode = 0;
    try {
      const [, , exitCode] = await Promise.all([
        readBoundedStream(proc.stdout, stdoutChunks),
        readBoundedStream(proc.stderr, stderrChunks),
        proc.exited,
      ]);
      rawExitCode = exitCode;
    } finally {
      clearTimeout(timer);
    }

    const rawStdout = Buffer.concat(stdoutChunks).toString('utf8');
    const rawStderr = Buffer.concat(stderrChunks).toString('utf8');
    const redactedResult = redactOutput({ stdout: rawStdout, stderr: rawStderr });

    const exitCode = timedOut ? 124 : truncated ? 125 : rawExitCode;

    return {
      command: validatedCommand,
      cwd: params.cwd ?? '.',
      exitCode,
      durationMs: Math.max(0, Date.now() - startedAt),
      timedOut,
      truncated,
      stdout: redactedResult.stdout,
      stderr: redactedResult.stderr,
      stdoutBytes: Buffer.byteLength(redactedResult.stdout, 'utf8'),
      stderrBytes: Buffer.byteLength(redactedResult.stderr, 'utf8'),
      redacted: redactedResult.redacted,
      redactionCount: redactedResult.redactionCount,
      redactionCategories: redactedResult.categories,
    };
  }
}
