import { describe, expect, it } from 'bun:test';
import {
  SsrfGuardError,
  assertSafeOutboundUrl,
  classifyIpBlockReason,
  createSsrfSafeFetch,
  isBlockedIp,
  parseIpv4ToUint32,
  validateOutboundUrl,
  type DnsLookupFn,
} from '../src/ssrf-guard.js';

const PUBLIC_DNS: DnsLookupFn = async () => [{ address: '93.184.216.34', family: 4 }];

describe('V37 SSRF & Cloud Metadata Guard', () => {
  it('blocks cloud metadata IPs and internal metadata hostnames', () => {
    const blockedUrls = [
      'http://169.254.169.254/latest/meta-data/',
      'http://169.254.170.2/v2/credentials',
      'http://metadata.google.internal/computeMetadata/v1/',
      'http://metadata.goog/computeMetadata/v1/',
      'http://[fd00:ec2::254]/latest/meta-data/',
      'http://[::ffff:169.254.169.254]/latest/meta-data/',
      'http://internal-service.internal/secret',
      'http://printer.local/admin',
    ];

    for (const url of blockedUrls) {
      expect(() => validateOutboundUrl(url), url).toThrow(SsrfGuardError);
    }
  });

  it('blocks IPv4/IPv6 loopback, link-local, RFC1918 private CIDRs, and CGNAT', () => {
    const blockedIps = [
      '127.0.0.1',
      '127.255.255.254',
      '0.0.0.0',
      '10.0.0.1',
      '10.255.255.255',
      '172.16.0.1',
      '172.31.255.254',
      '192.168.0.1',
      '192.168.255.254',
      '169.254.0.1',
      '169.254.169.254',
      '100.64.0.1',
      '100.100.100.200',
      '224.0.0.1',
      '255.255.255.255',
      '::1',
      '::',
      'fe80::1',
      'fe80::1%eth0',
      'fc00::1',
      'fd12:3456:789a::1',
      '::ffff:127.0.0.1',
      '::ffff:10.1.2.3',
      '::ffff:192.168.1.10',
      '64:ff9b::169.254.169.254',
    ];

    for (const ip of blockedIps) {
      expect(isBlockedIp(ip), ip).toBe(true);
      expect(classifyIpBlockReason(ip), ip).not.toBeNull();
    }

    // Obfuscated IPv4 encodings (octal, hex, 32-bit decimal)
    expect(parseIpv4ToUint32('0177.0.0.1')).toBe(0x7f00_0001);
    expect(parseIpv4ToUint32('2130706433')).toBe(0x7f00_0001);
    expect(parseIpv4ToUint32('0xa9fea9fe')).toBe(0xa9fe_a9fe);
    expect(() => validateOutboundUrl('http://0177.0.0.1/admin')).toThrow(SsrfGuardError);
    expect(() => validateOutboundUrl('http://2130706433/admin')).toThrow(SsrfGuardError);
    expect(() => validateOutboundUrl('http://0xa9fea9fe/latest/meta-data/')).toThrow(SsrfGuardError);
  });

  it('allows public IPs and public HTTPS/HTTP URLs while blocking unsafe schemes and userinfo', async () => {
    expect(isBlockedIp('1.1.1.1')).toBe(false);
    expect(isBlockedIp('8.8.8.8')).toBe(false);
    expect(isBlockedIp('93.184.216.34')).toBe(false);
    expect(isBlockedIp('172.15.255.254')).toBe(false);
    expect(isBlockedIp('172.32.0.1')).toBe(false);
    expect(isBlockedIp('2606:4700:4700::1111')).toBe(false);

    const safe = await assertSafeOutboundUrl('https://api.e2b.dev/sandboxes', {
      lookupFn: PUBLIC_DNS,
    });
    expect(safe.hostname).toBe('api.e2b.dev');

    expect(() => validateOutboundUrl('file:///etc/passwd')).toThrow(SsrfGuardError);
    expect(() => validateOutboundUrl('gopher://example.com:80/_GET')).toThrow(SsrfGuardError);
    expect(() => validateOutboundUrl('https://user:pass@example.com/')).toThrow(SsrfGuardError);
    expect(() => validateOutboundUrl('http://example.com/', { allowHttp: false })).toThrow(SsrfGuardError);
  });

  it('blocks DNS rebinding / private DNS resolution results', async () => {
    const evilDns: DnsLookupFn = async () => [
      { address: '93.184.216.34', family: 4 },
      { address: '169.254.169.254', family: 4 },
    ];

    await expect(
      assertSafeOutboundUrl('https://rebind.attacker.example/hook', { lookupFn: evilDns }),
    ).rejects.toThrow(SsrfGuardError);

    const privateDns: DnsLookupFn = async () => [{ address: '10.20.30.40', family: 4 }];
    await expect(
      assertSafeOutboundUrl('https://corp.attacker.example/api', { lookupFn: privateDns }),
    ).rejects.toThrow(SsrfGuardError);
  });

  it('enforces V37 guard across HTTP redirect chains and strips cross-origin auth headers', async () => {
    let seenHeaders: Headers | undefined;
    const safeFetch = createSsrfSafeFetch({
      lookupFn: PUBLIC_DNS,
      fetchImpl: async (input, init) => {
        const url = String(input);
        if (url === 'https://public.example/start') {
          return new Response(null, {
            status: 302,
            headers: { location: 'https://cdn.other.example/final' },
          });
        }
        seenHeaders = new Headers(init?.headers);
        return new Response('ok', { status: 200 });
      },
    });

    const okRes = await safeFetch('https://public.example/start', {
      headers: { authorization: 'Bearer secret-token' },
    });
    expect(okRes.status).toBe(200);
    expect(seenHeaders?.get('authorization')).toBeNull();

    const redirectToMetadataFetch = createSsrfSafeFetch({
      lookupFn: PUBLIC_DNS,
      fetchImpl: async () =>
        new Response(null, {
          status: 302,
          headers: { location: 'http://169.254.169.254/latest/meta-data/iam' },
        }),
    });

    await expect(redirectToMetadataFetch('https://public.example/bounce')).rejects.toThrow(
      SsrfGuardError,
    );
  });
});
