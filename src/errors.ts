export type SandboxErrorCode =
  | 'INVALID_REQUEST'
  | 'UNAUTHENTICATED'
  | 'FORBIDDEN'
  | 'NOT_FOUND'
  | 'CONFLICT'
  | 'STALE_FENCING_TOKEN'
  | 'LEASE_EXPIRED'
  | 'LEASE_INACTIVE'
  | 'COMMAND_NOT_ALLOWED'
  | 'TIMEOUT'
  | 'OUTPUT_LIMIT'
  | 'INTERNAL';

const STATUS_BY_CODE: Readonly<Record<SandboxErrorCode, number>> = {
  INVALID_REQUEST: 400,
  UNAUTHENTICATED: 401,
  FORBIDDEN: 403,
  COMMAND_NOT_ALLOWED: 403,
  NOT_FOUND: 404,
  TIMEOUT: 408,
  CONFLICT: 409,
  STALE_FENCING_TOKEN: 409,
  LEASE_INACTIVE: 409,
  LEASE_EXPIRED: 410,
  OUTPUT_LIMIT: 413,
  INTERNAL: 500,
};

export class SandboxError extends Error {
  readonly code: SandboxErrorCode;
  readonly statusCode: number;
  readonly retryable: boolean;
  readonly details?: Readonly<Record<string, unknown>>;

  constructor(
    code: SandboxErrorCode,
    message: string,
    options?: {
      readonly statusCode?: number;
      readonly retryable?: boolean;
      readonly details?: Readonly<Record<string, unknown>>;
    },
  ) {
    super(message);
    this.name = 'SandboxError';
    this.code = code;
    this.statusCode = options?.statusCode ?? STATUS_BY_CODE[code];
    this.retryable = options?.retryable ?? code === 'TIMEOUT';
    this.details = options?.details;
  }
}

export function asSandboxError(error: unknown): SandboxError {
  if (error instanceof SandboxError) return error;
  const message = error instanceof Error ? error.message : String(error);
  return new SandboxError('INTERNAL', message);
}
