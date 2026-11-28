import { lookup } from 'node:dns/promises';
import { SandboxError } from './errors.js';

export interface DnsAddressRecord {
  readonly address: string;
  readonly family: number;
}

export type DnsLookupFn = (
  hostname: string,
  options: { readonly all: true; readonly verbatim: true },
) => Promise<readonly DnsAddressRecord[]>;

export type SsrfFetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export interface SsrfGuardOptions {
  readonly allowHttp?: boolean;
  readonly allowLoopback?: boolean;
  readonly allowPrivateCidrs?: boolean;
  readonly allowedHosts?: readonly string[];
  readonly maxRedirects?: number;
  readonly lookupFn?: DnsLookupFn;
  readonly fetchImpl?: SsrfFetchLike;
}

export class SsrfGuardError extends SandboxError {
  readonly reason: string;

  constructor(
    reason: string,
    message: string,
    details?: Readonly<Record<string, unknown>>,
  ) {
    super('FORBIDDEN', message, {
      statusCode: 403,
      retryable: false,
      details: { reason, ...details },
    });
    this.name = 'SsrfGuardError';
    this.reason = reason;
  }
}

const BLOCKED_EXACT_HOSTS = new Set([
  'metadata.google.internal',
  'metadata.goog',
  'metadata',
  'instance-data',
  'localhost.localdomain',
]);

const DEFAULT_DNS_LOOKUP: DnsLookupFn = async (hostname, options) => {
  const records = await lookup(hostname, options);
  return Array.isArray(records) ? records : [records];
};

function stripBracketsAndZone(rawHost: string): string {
  let host = rawHost.trim().toLowerCase();
  if (host.startsWith('[') && host.endsWith(']')) {
    host = host.slice(1, -1);
  }
  const zoneIdx = host.indexOf('%');
  if (zoneIdx !== -1) {
    host = host.slice(0, zoneIdx);
  }
  return host.replace(/\.+$/u, '');
}

function parseIpv4Part(part: string): number | null {
  if (part === '') return null;
  if (/^0x[0-9a-f]+$/iu.test(part)) {
    const val = Number.parseInt(part.slice(2), 16);
    return Number.isSafeInteger(val) && val >= 0 ? val : null;
  }
  if (/^0[0-7]+$/u.test(part)) {
    const val = Number.parseInt(part, 8);
    return Number.isSafeInteger(val) && val >= 0 ? val : null;
  }
  if (/^(?:0|[1-9]\d*)$/u.test(part)) {
    const val = Number.parseInt(part, 10);
    return Number.isSafeInteger(val) && val >= 0 ? val : null;
  }
  return null;
}

/**
 * Parses standard dotted-quad as well as single-integer / hex / octal IPv4 forms
 * into an unsigned 32-bit integer, or returns null if not an IPv4 literal.
 */
export function parseIpv4ToUint32(rawIp: string): number | null {
  const host = stripBracketsAndZone(rawIp);
  if (host === '') return null;

  const parts = host.split('.');
  if (parts.length === 1) {
    // Only interpret single token as integer IP when strictly numeric or 0x-hex.
    if (!/^(?:\d+|0x[0-9a-f]+)$/iu.test(host)) return null;
    const val = parseIpv4Part(host);
    if (val === null || val > 0xffff_ffff) return null;
    return val >>> 0;
  }

  if (parts.length > 4) return null;
  const nums: number[] = [];
  for (const part of parts) {
    const val = parseIpv4Part(part);
    if (val === null) return null;
    nums.push(val);
  }

  if (parts.length === 4) {
    if (nums.some((n) => n > 255)) return null;
    return (((nums[0]! << 24) | (nums[1]! << 16) | (nums[2]! << 8) | nums[3]!) >>> 0);
  }
  if (parts.length === 3) {
    if (nums[0]! > 255 || nums[1]! > 255 || nums[2]! > 0xffff) return null;
    return (((nums[0]! << 24) | (nums[1]! << 16) | nums[2]!) >>> 0);
  }
  // parts.length === 2
  if (nums[0]! > 255 || nums[1]! > 0xff_ffff) return null;
  return (((nums[0]! << 24) | nums[1]!) >>> 0);
}

function uint32ToDottedIpv4(value: number): string {
  return [
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ].join('.');
}

function parseIpv6Hextets(rawIp: string): readonly number[] | null {
  let host = stripBracketsAndZone(rawIp);
  if (!host.includes(':')) return null;

  // Handle trailing IPv4 inside IPv6 (e.g. ::ffff:169.254.169.254)
  const lastColon = host.lastIndexOf(':');
  const tail = host.slice(lastColon + 1);
  if (tail.includes('.')) {
    const ipv4Num = parseIpv4ToUint32(tail);
    if (ipv4Num === null) return null;
    const hi = ((ipv4Num >>> 16) & 0xffff).toString(16);
    const lo = (ipv4Num & 0xffff).toString(16);
    host = `${host.slice(0, lastColon + 1)}${hi}:${lo}`;
  }

  const doubleColonParts = host.split('::');
  if (doubleColonParts.length > 2) return null;

  const parseSegment = (segment: string): number[] | null => {
    if (segment === '') return [];
    const tokens = segment.split(':');
    const out: number[] = [];
    for (const token of tokens) {
      if (!/^[0-9a-f]{1,4}$/iu.test(token)) return null;
      out.push(Number.parseInt(token, 16));
    }
    return out;
  };

  if (doubleColonParts.length === 1) {
    const groups = parseSegment(doubleColonParts[0]!);
    return groups && groups.length === 8 ? groups : null;
  }

  const left = parseSegment(doubleColonParts[0]!);
  const right = parseSegment(doubleColonParts[1]!);
  if (!left || !right) return null;
  const missing = 8 - (left.length + right.length);
  if (missing < 1) return null;
  return [...left, ...new Array<number>(missing).fill(0), ...right];
}

function inIpv4Cidr(addr: number, baseOctets: readonly [number, number, number, number], prefixLen: number): boolean {
  const base =
    (((baseOctets[0] << 24) | (baseOctets[1] << 16) | (baseOctets[2] << 8) | baseOctets[3]) >>> 0);
  const mask = prefixLen === 0 ? 0 : (~0 << (32 - prefixLen)) >>> 0;
  return (addr & mask) === (base & mask);
}

export function classifyBlockedIpv4(
  rawIp: string,
  options: Pick<SsrfGuardOptions, 'allowLoopback' | 'allowPrivateCidrs'> = {},
): string | null {
  const addr = parseIpv4ToUint32(rawIp);
  if (addr === null) return null;

  // 169.254.169.254 (AWS/GCP/Azure IMDS) and 169.254.170.2 (AWS ECS metadata)
  if (addr === 0xa9fe_a9fe) return 'cloud_metadata_169_254_169_254';
  if (addr === 0xa9fe_aa02) return 'cloud_metadata_ecs_169_254_170_2';

  if (inIpv4Cidr(addr, [0, 0, 0, 0], 8)) return 'unspecified_ipv4_0_0_0_0_8';
  if (inIpv4Cidr(addr, [169, 254, 0, 0], 16)) return 'link_local_ipv4_169_254_0_0_16';
  if (inIpv4Cidr(addr, [127, 0, 0, 0], 8)) {
    return options.allowLoopback ? null : 'loopback_ipv4_127_0_0_0_8';
  }

  if (!options.allowPrivateCidrs) {
    if (inIpv4Cidr(addr, [10, 0, 0, 0], 8)) return 'rfc1918_10_0_0_0_8';
    if (inIpv4Cidr(addr, [172, 16, 0, 0], 12)) return 'rfc1918_172_16_0_0_12';
    if (inIpv4Cidr(addr, [192, 168, 0, 0], 16)) return 'rfc1918_192_168_0_0_16';
    if (inIpv4Cidr(addr, [100, 64, 0, 0], 10)) return 'cgnat_100_64_0_0_10';
    if (inIpv4Cidr(addr, [192, 0, 0, 0], 24)) return 'ietf_protocol_192_0_0_0_24';
    if (inIpv4Cidr(addr, [198, 18, 0, 0], 15)) return 'benchmark_198_18_0_0_15';
  }

  if (inIpv4Cidr(addr, [224, 0, 0, 0], 4)) return 'multicast_ipv4_224_0_0_0_4';
  if (inIpv4Cidr(addr, [240, 0, 0, 0], 4)) return 'reserved_ipv4_240_0_0_0_4';
  return null;
}

export function classifyBlockedIpv6(
  rawIp: string,
  options: Pick<SsrfGuardOptions, 'allowLoopback' | 'allowPrivateCidrs'> = {},
): string | null {
  const h = parseIpv6Hextets(rawIp);
  if (h === null) return null;

  const isAllZeroPrefix96 =
    h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0 && h[5] === 0;

  // ::/128 unspecified
  if (isAllZeroPrefix96 && h[6] === 0 && h[7] === 0) {
    return 'unspecified_ipv6';
  }
  // ::1/128 loopback
  if (isAllZeroPrefix96 && h[6] === 0 && h[7] === 1) {
    return options.allowLoopback ? null : 'loopback_ipv6';
  }

  // ::ffff:0:0/96 IPv4-mapped IPv6
  if (h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0 && h[5] === 0xffff) {
    const embedded = uint32ToDottedIpv4(((h[6]! << 16) | h[7]!) >>> 0);
    const v4Reason = classifyBlockedIpv4(embedded, options);
    return v4Reason ? `ipv4_mapped_${v4Reason}` : null;
  }

  // ::/96 deprecated IPv4-compatible IPv6
  if (isAllZeroPrefix96) {
    const embedded = uint32ToDottedIpv4(((h[6]! << 16) | h[7]!) >>> 0);
    const v4Reason = classifyBlockedIpv4(embedded, options);
    return v4Reason ? `ipv4_compat_${v4Reason}` : 'ipv4_compatible_ipv6';
  }

  // 64:ff9b::/96 (NAT64 well-known) and 64:ff9b:1::/48 (NAT64 local-use)
  if (h[0] === 0x0064 && h[1] === 0xff9b) {
    if (h[2] === 0 && h[3] === 0 && h[4] === 0 && h[5] === 0) {
      const embedded = uint32ToDottedIpv4(((h[6]! << 16) | h[7]!) >>> 0);
      const v4Reason = classifyBlockedIpv4(embedded, options);
      return v4Reason ? `nat64_${v4Reason}` : null;
    }
    if (h[2] === 1 && !options.allowPrivateCidrs) {
      return 'nat64_local_use_64_ff9b_1';
    }
  }

  // fe80::/10 link-local
  if ((h[0]! & 0xffc0) === 0xfe80) {
    return 'link_local_ipv6_fe80_10';
  }
  // fec0::/10 deprecated site-local
  if ((h[0]! & 0xffc0) === 0xfec0 && !options.allowPrivateCidrs) {
    return 'site_local_ipv6_fec0_10';
  }
  // fc00::/7 unique local addresses (includes AWS IPv6 metadata fd00:ec2::254)
  if ((h[0]! & 0xfe00) === 0xfc00 && !options.allowPrivateCidrs) {
    return 'ula_private_ipv6_fc00_7';
  }
  // ff00::/8 multicast
  if ((h[0]! & 0xff00) === 0xff00) {
    return 'multicast_ipv6_ff00_8';
  }

  return null;
}

export function classifyIpBlockReason(
  ip: string,
  options: Pick<SsrfGuardOptions, 'allowLoopback' | 'allowPrivateCidrs'> = {},
): string | null {
  const v4 = classifyBlockedIpv4(ip, options);
  if (v4 !== null) return v4;
  return classifyBlockedIpv6(ip, options);
}

export function isBlockedIp(
  ip: string,
  options: Pick<SsrfGuardOptions, 'allowLoopback' | 'allowPrivateCidrs'> = {},
): boolean {
  return classifyIpBlockReason(ip, options) !== null;
}

function isIpLiteral(hostname: string): boolean {
  return parseIpv4ToUint32(hostname) !== null || parseIpv6Hextets(hostname) !== null;
}

function isHostAllowlisted(normalizedHost: string, allowedHosts: readonly string[] | undefined): boolean {
  if (!allowedHosts || allowedHosts.length === 0) return false;
  return allowedHosts.some((entry) => stripBracketsAndZone(entry) === normalizedHost);
}

/**
 * Synchronous V37 outbound SSRF validation on raw URL syntax, scheme, credentials,
 * blocked internal/metadata hostnames, and literal IPv4/IPv6 CIDR blocks.
 */
export function validateOutboundUrl(rawUrl: string, options: SsrfGuardOptions = {}): URL {
  if (typeof rawUrl !== 'string' || rawUrl.trim() === '') {
    throw new SsrfGuardError('invalid_url', 'Outbound URL must be a non-empty string');
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new SsrfGuardError('invalid_url', `Invalid outbound URL "${rawUrl}"`, { url: rawUrl });
  }

  const allowHttp = options.allowHttp ?? true;
  if (parsed.protocol !== 'https:' && !(allowHttp && parsed.protocol === 'http:')) {
    throw new SsrfGuardError(
      'disallowed_scheme',
      `Disallowed outbound URL protocol "${parsed.protocol}"`,
      { url: parsed.toString(), protocol: parsed.protocol },
    );
  }

  if (parsed.username !== '' || parsed.password !== '') {
    throw new SsrfGuardError(
      'embedded_credentials',
      'Outbound URL must not contain embedded userinfo credentials',
      { url: parsed.origin },
    );
  }

  const normalizedHost = stripBracketsAndZone(parsed.hostname);
  if (normalizedHost === '') {
    throw new SsrfGuardError('missing_host', 'Outbound URL must specify a host', { url: rawUrl });
  }

  if (isHostAllowlisted(normalizedHost, options.allowedHosts)) {
    return parsed;
  }

  if (
    normalizedHost === 'localhost' ||
    normalizedHost.endsWith('.localhost') ||
    normalizedHost === 'localhost.localdomain'
  ) {
    if (!options.allowLoopback) {
      throw new SsrfGuardError(
        'loopback_hostname',
        `Outbound request to loopback hostname "${normalizedHost}" blocked by V37 SSRF guard`,
        { host: normalizedHost },
      );
    }
    return parsed;
  }

  if (
    BLOCKED_EXACT_HOSTS.has(normalizedHost) ||
    normalizedHost.endsWith('.internal') ||
    normalizedHost.endsWith('.local')
  ) {
    throw new SsrfGuardError(
      'blocked_internal_hostname',
      `Outbound request to internal/metadata host "${normalizedHost}" blocked by V37 SSRF guard`,
      { host: normalizedHost },
    );
  }

  const ipBlockReason = classifyIpBlockReason(normalizedHost, options);
  if (ipBlockReason !== null) {
    throw new SsrfGuardError(
      ipBlockReason,
      `Outbound request to blocked IP "${normalizedHost}" (${ipBlockReason}) rejected by V37 SSRF guard`,
      { host: normalizedHost, resolvedIp: normalizedHost },
    );
  }

  return parsed;
}

/**
 * Full async V37 outbound SSRF guard: validates URL syntax/literal IP and resolves
 * DNS records to block DNS-rebinding / private-A/AAAA target resolution.
 */
export async function assertSafeOutboundUrl(
  rawUrl: string,
  options: SsrfGuardOptions = {},
): Promise<URL> {
  const parsed = validateOutboundUrl(rawUrl, options);
  const normalizedHost = stripBracketsAndZone(parsed.hostname);

  if (isHostAllowlisted(normalizedHost, options.allowedHosts) || isIpLiteral(normalizedHost)) {
    return parsed;
  }
  if (
    options.allowLoopback &&
    (normalizedHost === 'localhost' || normalizedHost.endsWith('.localhost'))
  ) {
    return parsed;
  }

  const lookupFn = options.lookupFn ?? DEFAULT_DNS_LOOKUP;
  let records: readonly DnsAddressRecord[];
  try {
    records = await lookupFn(normalizedHost, { all: true, verbatim: true });
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new SsrfGuardError(
      'dns_lookup_failed',
      `Failed to resolve outbound host "${normalizedHost}": ${detail}`,
      { host: normalizedHost },
    );
  }

  if (records.length === 0) {
    throw new SsrfGuardError(
      'dns_no_records',
      `DNS lookup for "${normalizedHost}" returned zero address records`,
      { host: normalizedHost },
    );
  }

  for (const record of records) {
    const reason = classifyIpBlockReason(record.address, options);
    if (reason !== null) {
      throw new SsrfGuardError(
        reason,
        `DNS resolution for "${normalizedHost}" returned blocked IP "${record.address}" (${reason})`,
        { host: normalizedHost, resolvedIp: record.address },
      );
    }
  }

  return parsed;
}

const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);

/**
 * Wraps fetch with V37 SSRF enforcement on the initial URL and every HTTP redirect hop.
 */
export function createSsrfSafeFetch(options: SsrfGuardOptions = {}): SsrfFetchLike {
  const fetchImpl: SsrfFetchLike = options.fetchImpl ?? ((input, init) => fetch(input, init));
  const maxRedirects = Math.max(0, options.maxRedirects ?? 5);

  return async (input, init = {}) => {
    let currentUrl =
      typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    let currentInit: RequestInit = { ...init, redirect: 'manual' };

    for (let hop = 0; hop <= maxRedirects; hop += 1) {
      const safeUrl = await assertSafeOutboundUrl(currentUrl, options);
      const response = await fetchImpl(safeUrl.toString(), currentInit);
      const location = response.headers.get('location');
      if (!REDIRECT_STATUS_CODES.has(response.status) || !location) {
        return response;
      }

      if (hop >= maxRedirects) {
        throw new SsrfGuardError(
          'too_many_redirects',
          `Exceeded maximum SSRF-guarded redirects (${maxRedirects})`,
          { url: safeUrl.toString(), maxRedirects },
        );
      }

      const nextUrl = new URL(location, safeUrl);
      const nextHeaders = new Headers(currentInit.headers);
      if (nextUrl.origin !== safeUrl.origin) {
        nextHeaders.delete('authorization');
        nextHeaders.delete('x-api-key');
        nextHeaders.delete('cookie');
      }

      const method = (currentInit.method ?? 'GET').toUpperCase();
      const downgradeToGet =
        response.status === 303 ||
        ((response.status === 301 || response.status === 302) && method === 'POST');

      currentUrl = nextUrl.toString();
      currentInit = {
        ...currentInit,
        headers: nextHeaders,
        ...(downgradeToGet ? { method: 'GET', body: undefined } : {}),
        redirect: 'manual',
      };
    }

    throw new SsrfGuardError('too_many_redirects', 'Exceeded maximum redirects');
  };
}
