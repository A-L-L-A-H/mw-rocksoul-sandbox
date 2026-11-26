export { SandboxError, asSandboxError, type SandboxErrorCode } from './errors.js';

export {
  WorktreeLeaseManager,
  isWithinRoot,
  type AcquireLeaseParams,
  type LeaseManagerOptions,
  type LeaseRecord,
  type LeaseStatus,
  type ReleaseLeaseResult,
  type RenewLeaseParams,
} from './lease-manager.js';

export {
  luhnCheck,
  redactOutput,
  redactText,
  redactUnknown,
  type RedactedStreamOutput,
  type RedactionCategory,
  type RedactionResult,
} from './redactor.js';

export {
  DEFAULT_COMMAND_ALLOWLIST,
  SandboxCommandRunner,
  buildSanitizedEnv,
  resolveSafeSubdir,
  type CommandAllowlistRule,
  type CommandExecutionResult,
  type CommandRunParams,
  type CommandRunnerOptions,
} from './command-runner.js';

export {
  DEFAULT_OTLP_TRACES_ENDPOINT,
  OtelTraceExporter,
  generateSpanId,
  generateTraceId,
  type ActiveSpan,
  type FetchLike,
  type OtelExportOutcome,
  type OtelExporterOptions,
  type OtelExporterStats,
  type OtlpAnyValue,
  type OtlpAttributePrimitive,
  type OtlpExportTraceServiceRequest,
  type OtlpKeyValue,
  type OtlpSpanRecord,
  type OtlpSpanStatus,
} from './otel-exporter.js';

export {
  DEFAULT_SANDBOX_HOST,
  DEFAULT_SANDBOX_PORT,
  SANDBOX_SERVICE_NAME,
  SANDBOX_SERVICE_VERSION,
  createSandboxApplication,
  createSandboxFetchHandler,
  isAuthorizedBearer,
  loadSandboxServerConfig,
  startSandboxServer,
  type RunningSandboxServer,
  type SandboxApplication,
  type SandboxApplicationOptions,
  type SandboxServerConfig,
} from './server.js';
