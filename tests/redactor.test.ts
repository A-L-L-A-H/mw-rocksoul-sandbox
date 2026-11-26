import { describe, expect, it } from 'bun:test';
import { luhnCheck, redactOutput, redactText } from '../src/redactor.js';

describe('redactor', () => {
  it('redacts JWTs, API keys, AWS keys, Bearer tokens, PEM keys, DB credentials, and key=value secrets', () => {
    const sampleJwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEyMyIsInJvbGUiOiJhZG1pbiJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const sample = [
      `token=${sampleJwt}`,
      'Authorization: Bearer super_secret_bearer_token_98765',
      'openai=sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz123456',
      'github=ghp_1234567890abcdefghij1234567890abcd',
      'aws=AKIAIOSFODNN7EXAMPLE',
      'db=postgres://admin:UltraSecretP4ss@db.internal:5432/prod',
      'client_secret="top_secret_client_val"',
      '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAtestkeymaterial\n-----END RSA PRIVATE KEY-----',
    ].join('\n');

    const result = redactText(sample);
    expect(result.redacted).toBe(true);
    expect(result.text).not.toContain(sampleJwt);
    expect(result.text).not.toContain('super_secret_bearer_token_98765');
    expect(result.text).not.toContain('sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz123456');
    expect(result.text).not.toContain('ghp_1234567890abcdefghij1234567890abcd');
    expect(result.text).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(result.text).not.toContain('UltraSecretP4ss');
    expect(result.text).not.toContain('top_secret_client_val');
    expect(result.text).not.toContain('MIIEowIBAAKCAQEAtestkeymaterial');
    expect(result.text).toContain('[REDACTED:JWT]');
    expect(result.text).toContain('Bearer [REDACTED:TOKEN]');
    expect(result.text).toContain('[REDACTED:API_KEY]');
    expect(result.text).toContain('[REDACTED:AWS_KEY]');
    expect(result.text).toContain('postgres://admin:[REDACTED:SECRET]@');
    expect(result.text).toContain('[REDACTED:PRIVATE_KEY]');
    expect(result.categories).toContain('jwt');
    expect(result.categories).toContain('api_key');
    expect(result.categories).toContain('aws_key');
    expect(result.categories).toContain('private_key');
  });

  it('redacts PII (email, SSN, NIK, phone, Luhn-valid credit cards) while leaving non-Luhn IDs intact', () => {
    expect(luhnCheck('4111111111111111')).toBe(true);
    expect(luhnCheck('4111111111111112')).toBe(false);

    const out = redactOutput({
      stdout: 'User alice.smith@example.com SSN 123-45-6789 phone +62-812-3456-7890',
      stderr: 'nik=3171012345678901 card 4111-1111-1111-1111 buildId=4111111111111112',
    });

    expect(out.redacted).toBe(true);
    expect(out.stdout).toContain('[REDACTED:EMAIL]');
    expect(out.stdout).toContain('[REDACTED:SSN]');
    expect(out.stdout).toContain('[REDACTED:PHONE]');
    expect(out.stderr).toContain('nik=[REDACTED:NIK]');
    expect(out.stderr).toContain('[REDACTED:CARD]');
    expect(out.stderr).toContain('buildId=4111111111111112');
    expect(out.redactionCount).toBe(5);
  });

  it('returns unmodified clean output when no secrets or PII are present', () => {
    const clean = redactText('All 12 unit tests passed in 42ms.');
    expect(clean.redacted).toBe(false);
    expect(clean.redactionCount).toBe(0);
    expect(clean.categories).toEqual([]);
    expect(clean.text).toBe('All 12 unit tests passed in 42ms.');
  });
});
