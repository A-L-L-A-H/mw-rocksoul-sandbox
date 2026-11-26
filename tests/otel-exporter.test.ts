import { describe, expect, it } from 'bun:test';
import {
  DEFAULT_OTLP_TRACES_ENDPOINT,
  OtelTraceExporter,
  type OtlpExportTraceServiceRequest,
} from '../src/otel-exporter.js';

describe('OtelTraceExporter', () => {
  it('targets mw-echo :4310/v1/traces by default and exports mw-echo-compatible OTLP JSON with redacted attributes', async () => {
    expect(DEFAULT_OTLP_TRACES_ENDPOINT).toBe('http://127.0.0.1:4310/v1/traces');

    const captured: {
      url: string;
      body: OtlpExportTraceServiceRequest | null;
      auth: string | null;
    } = { url: '', body: null, auth: null };

    const exporter = new OtelTraceExporter({
      bearerToken: 'trace-token-123',
      fetchImpl: async (input, init) => {
        captured.url = String(input);
        captured.auth = new Headers(init?.headers).get('authorization');
        captured.body = JSON.parse(String(init?.body)) as OtlpExportTraceServiceRequest;
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      },
    });

    const span = exporter.startSpan('sandbox.exec', {
      'sandbox.lease_id': 'lease-1',
      'sandbox.exit_code': 0,
      'sandbox.secret_attr': 'Authorization: Bearer leak_should_be_redacted_999',
    });
    span.setAttribute('sandbox.redacted', true);
    const finished = span.end({ ok: true });

    const outcome = await exporter.exportSpans([finished]);
    expect(outcome).toEqual({ ok: true, status: 200, spanCount: 1 });
    expect(captured.url).toBe('http://127.0.0.1:4310/v1/traces');
    expect(captured.auth).toBe('Bearer trace-token-123');

    const payload = captured.body!;
    expect(payload.resourceSpans).toHaveLength(1);
    const resourceAttrs = payload.resourceSpans[0].resource.attributes;
    expect(
      resourceAttrs.some(
        (a) => a.key === 'service.name' && 'stringValue' in a.value && a.value.stringValue === 'mw-rocksoul-sandbox',
      ),
    ).toBe(true);

    const exportedSpan = payload.resourceSpans[0].scopeSpans[0].spans[0]!;
    expect(exportedSpan.traceId).toMatch(/^[a-f0-9]{32}$/u);
    expect(exportedSpan.spanId).toMatch(/^[a-f0-9]{16}$/u);
    expect(BigInt(exportedSpan.endTimeUnixNano)).toBeGreaterThan(
      BigInt(exportedSpan.startTimeUnixNano),
    );
    expect(exportedSpan.status.code).toBe(1);

    const secretAttr = exportedSpan.attributes.find((a) => a.key === 'sandbox.secret_attr');
    expect(secretAttr?.value).toEqual({ stringValue: 'Authorization: Bearer [REDACTED:TOKEN]' });
    expect(exporter.getStats().exportedSpans).toBe(1);
    expect(exporter.getStats().droppedSpans).toBe(0);
  });

  it('fails open when collector is unreachable and tracks dropped span stats', async () => {
    const exporter = new OtelTraceExporter({
      fetchImpl: async () => {
        throw new Error('ECONNREFUSED');
      },
    });
    const span = exporter.startSpan('sandbox.exec').end({ ok: false, message: 'failed run' });
    expect(span.status.code).toBe(2);

    const outcome = await exporter.exportSpans([span]);
    expect(outcome.ok).toBe(false);
    expect(outcome.status).toBe(0);
    expect(outcome.error).toContain('ECONNREFUSED');
    expect(exporter.getStats().droppedSpans).toBe(1);
    expect(exporter.getStats().lastError).toContain('ECONNREFUSED');
  });
});
