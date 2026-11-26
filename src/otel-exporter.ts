import { randomBytes } from 'node:crypto';
import { redactText } from './redactor.js';

export const DEFAULT_OTLP_TRACES_ENDPOINT = 'http://127.0.0.1:4310/v1/traces';

export type OtlpAttributePrimitive = string | number | boolean;

export type OtlpAnyValue =
  | { readonly stringValue: string }
  | { readonly intValue: string }
  | { readonly doubleValue: number }
  | { readonly boolValue: boolean };

export interface OtlpKeyValue {
  readonly key: string;
  readonly value: OtlpAnyValue;
}

export interface OtlpSpanStatus {
  readonly code: 0 | 1 | 2;
  readonly message?: string;
}

export interface OtlpSpanRecord {
  readonly traceId: string;
  readonly spanId: string;
  readonly parentSpanId?: string;
  readonly name: string;
  readonly kind: number;
  readonly startTimeUnixNano: string;
  readonly endTimeUnixNano: string;
  readonly attributes: readonly OtlpKeyValue[];
  readonly status: OtlpSpanStatus;
}

export interface OtlpExportTraceServiceRequest {
  readonly resourceSpans: readonly [
    {
      readonly resource: {
        readonly attributes: readonly OtlpKeyValue[];
      };
      readonly scopeSpans: readonly [
        {
          readonly scope: {
            readonly name: string;
            readonly version: string;
          };
          readonly spans: readonly OtlpSpanRecord[];
        },
      ];
    },
  ];
}

export type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export interface OtelExporterOptions {
  readonly endpoint?: string;
  readonly serviceName?: string;
  readonly serviceVersion?: string;
  readonly bearerToken?: string;
  readonly timeoutMs?: number;
  readonly enabled?: boolean;
  readonly fetchImpl?: FetchLike;
}

export interface OtelExportOutcome {
  readonly ok: boolean;
  readonly status: number;
  readonly spanCount: number;
  readonly error?: string;
}

export interface OtelExporterStats {
  readonly endpoint: string;
  readonly enabled: boolean;
  readonly exportedSpans: number;
  readonly droppedSpans: number;
  readonly lastExportStatus: number | null;
  readonly lastError: string | null;
}

export interface ActiveSpan {
  readonly traceId: string;
  readonly spanId: string;
  readonly name: string;
  setAttribute(key: string, value: OtlpAttributePrimitive): ActiveSpan;
  end(status?: { readonly ok: boolean; readonly message?: string }): OtlpSpanRecord;
}

function toOtlpValue(value: OtlpAttributePrimitive): OtlpAnyValue {
  if (typeof value === 'boolean') {
    return { boolValue: value };
  }
  if (typeof value === 'number') {
    if (Number.isInteger(value)) {
      return { intValue: String(value) };
    }
    return { doubleValue: value };
  }
  return { stringValue: redactText(value).text };
}

function attributesToOtlp(
  attributes: Readonly<Record<string, OtlpAttributePrimitive>>,
): OtlpKeyValue[] {
  return Object.entries(attributes).map(([key, val]) => ({
    key,
    value: toOtlpValue(val),
  }));
}

function nowUnixNano(): bigint {
  return BigInt(Date.now()) * 1_000_000n;
}

export function generateTraceId(): string {
  return randomBytes(16).toString('hex');
}

export function generateSpanId(): string {
  return randomBytes(8).toString('hex');
}

export class OtelTraceExporter {
  readonly endpoint: string;
  readonly serviceName: string;
  readonly serviceVersion: string;
  readonly enabled: boolean;
  private readonly bearerToken?: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: FetchLike;
  private exportedSpans = 0;
  private droppedSpans = 0;
  private lastExportStatus: number | null = null;
  private lastError: string | null = null;

  constructor(options: OtelExporterOptions = {}) {
    this.endpoint = options.endpoint ?? DEFAULT_OTLP_TRACES_ENDPOINT;
    this.serviceName = options.serviceName ?? 'mw-rocksoul-sandbox';
    this.serviceVersion = options.serviceVersion ?? '1.0.0';
    this.enabled = options.enabled ?? true;
    this.bearerToken = options.bearerToken;
    this.timeoutMs = Math.max(100, Math.min(30_000, options.timeoutMs ?? 2_000));
    this.fetchImpl = options.fetchImpl ?? ((input, init) => fetch(input, init));
  }

  startSpan(
    name: string,
    initialAttributes: Readonly<Record<string, OtlpAttributePrimitive>> = {},
    parent?: { readonly traceId: string; readonly spanId?: string },
  ): ActiveSpan {
    const traceId = parent?.traceId ?? generateTraceId();
    const spanId = generateSpanId();
    const startNano = nowUnixNano();
    const attrs: Record<string, OtlpAttributePrimitive> = { ...initialAttributes };
    let ended: OtlpSpanRecord | null = null;

    const span: ActiveSpan = {
      traceId,
      spanId,
      name,
      setAttribute(key: string, value: OtlpAttributePrimitive): ActiveSpan {
        if (!ended) {
          attrs[key] = value;
        }
        return span;
      },
      end(status?: { readonly ok: boolean; readonly message?: string }): OtlpSpanRecord {
        if (ended) return ended;
        const endRaw = nowUnixNano();
        const endNano = endRaw > startNano ? endRaw : startNano + 1_000n;
        const isError = status !== undefined && !status.ok;
        ended = {
          traceId,
          spanId,
          ...(parent?.spanId !== undefined ? { parentSpanId: parent.spanId } : {}),
          name,
          kind: 1,
          startTimeUnixNano: startNano.toString(),
          endTimeUnixNano: endNano.toString(),
          attributes: attributesToOtlp(attrs),
          status: isError
            ? {
                code: 2,
                message: redactText(status.message ?? 'error').text,
              }
            : { code: 1 },
        };
        return ended;
      },
    };

    return span;
  }

  buildOtlpPayload(spans: readonly OtlpSpanRecord[]): OtlpExportTraceServiceRequest {
    return {
      resourceSpans: [
        {
          resource: {
            attributes: attributesToOtlp({
              'service.name': this.serviceName,
              'service.version': this.serviceVersion,
              'telemetry.sdk.name': 'mw-rocksoul-sandbox-otlp',
            }),
          },
          scopeSpans: [
            {
              scope: {
                name: this.serviceName,
                version: this.serviceVersion,
              },
              spans: [...spans],
            },
          ],
        },
      ],
    };
  }

  async exportSpans(spans: readonly OtlpSpanRecord[]): Promise<OtelExportOutcome> {
    if (spans.length === 0) {
      return { ok: true, status: 204, spanCount: 0 };
    }
    if (!this.enabled) {
      this.droppedSpans += spans.length;
      return { ok: false, status: 0, spanCount: spans.length, error: 'OTLP exporter disabled' };
    }

    const payload = this.buildOtlpPayload(spans);
    const headers = new Headers();
    headers.set('content-type', 'application/json; charset=utf-8');
    headers.set('user-agent', `${this.serviceName}/${this.serviceVersion}`);
    if (this.bearerToken) {
      headers.set('authorization', `Bearer ${this.bearerToken}`);
    }

    const controller = new AbortController();
    const timer = setTimeout(() => {
      controller.abort(new Error(`OTLP export timed out after ${this.timeoutMs}ms`));
    }, this.timeoutMs);

    try {
      const response = await this.fetchImpl(this.endpoint, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
      this.lastExportStatus = response.status;
      if (response.ok) {
        this.exportedSpans += spans.length;
        this.lastError = null;
        return { ok: true, status: response.status, spanCount: spans.length };
      }
      const errMsg = `OTLP collector returned HTTP ${response.status}`;
      this.droppedSpans += spans.length;
      this.lastError = errMsg;
      return { ok: false, status: response.status, spanCount: spans.length, error: errMsg };
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : String(error);
      this.droppedSpans += spans.length;
      this.lastExportStatus = 0;
      this.lastError = errMsg;
      return { ok: false, status: 0, spanCount: spans.length, error: errMsg };
    } finally {
      clearTimeout(timer);
    }
  }

  getStats(): OtelExporterStats {
    return {
      endpoint: this.endpoint,
      enabled: this.enabled,
      exportedSpans: this.exportedSpans,
      droppedSpans: this.droppedSpans,
      lastExportStatus: this.lastExportStatus,
      lastError: this.lastError,
    };
  }
}
