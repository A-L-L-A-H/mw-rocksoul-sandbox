export type RedactionCategory =
  | 'jwt'
  | 'private_key'
  | 'bearer_token'
  | 'api_key'
  | 'aws_key'
  | 'db_credential'
  | 'secret_assignment'
  | 'email'
  | 'ssn'
  | 'nik'
  | 'credit_card'
  | 'phone';

export interface RedactionResult {
  readonly text: string;
  readonly redacted: boolean;
  readonly redactionCount: number;
  readonly categories: readonly RedactionCategory[];
}

export interface RedactedStreamOutput {
  readonly stdout: string;
  readonly stderr: string;
  readonly redacted: boolean;
  readonly redactionCount: number;
  readonly categories: readonly RedactionCategory[];
}

const PRIVATE_KEY_PATTERN =
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/gu;
const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/gu;
const BEARER_PATTERN = /\b(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/giu;
const BASIC_AUTH_PATTERN = /\b(Basic\s+)[A-Za-z0-9+/=]{8,}/giu;
const PROVIDER_API_KEY_PATTERN =
  /\b(?:sk-(?:proj-|ant-|live-|test-)?[A-Za-z0-9_-]{16,}|(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[0-9A-Za-z-]{10,})\b/gu;
const AWS_KEY_PATTERN = /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/gu;
const DB_URL_CRED_PATTERN =
  /\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/([^:\s/@]+):([^@\s/]+)@/giu;
const SECRET_ASSIGNMENT_PATTERN =
  /\b(password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key|auth[_-]?token|signing[_-]?key)(\s*[:=]\s*)(["']?)([^\s,"';\r\n]{6,})\3/giu;
const EMAIL_PATTERN = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/gu;
const SSN_PATTERN = /\b\d{3}-\d{2}-\d{4}\b/gu;
const NIK_PATTERN = /\b(nik\s*[:=]\s*)\d{16}\b/giu;
const CREDIT_CARD_CANDIDATE_PATTERN = /\b(?:\d[ -]*?){13,19}\b/gu;
const PHONE_E164_PATTERN = /(?<!\w)\+[1-9]\d{0,2}[-\s.]?\(?\d{2,4}\)?[-\s.]?\d{3,4}[-\s.]?\d{3,4}\b/gu;

export function luhnCheck(rawDigits: string): boolean {
  const digits = rawDigits.replace(/\D/gu, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    const digit = digits.charCodeAt(i) - 48;
    if (digit < 0 || digit > 9) return false;
    let value = digit;
    if (shouldDouble) {
      value *= 2;
      if (value > 9) value -= 9;
    }
    sum += value;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

export function redactText(input: string): RedactionResult {
  if (input.length === 0) {
    return { text: '', redacted: false, redactionCount: 0, categories: [] };
  }

  const foundCategories = new Set<RedactionCategory>();
  let redactionCount = 0;

  const replaceWith = (
    source: string,
    pattern: RegExp,
    category: RedactionCategory,
    replacer: (...args: string[]) => string,
  ): string =>
    source.replace(pattern, (...rawArgs: unknown[]) => {
      const stringArgs = rawArgs.filter((arg): arg is string => typeof arg === 'string');
      const fullMatch = stringArgs[0] ?? '';
      const replacement = replacer(...stringArgs);
      if (replacement !== fullMatch) {
        redactionCount += 1;
        foundCategories.add(category);
      }
      return replacement;
    });

  let sanitized = input;

  sanitized = replaceWith(sanitized, PRIVATE_KEY_PATTERN, 'private_key', () => '[REDACTED:PRIVATE_KEY]');
  sanitized = replaceWith(sanitized, JWT_PATTERN, 'jwt', () => '[REDACTED:JWT]');
  sanitized = replaceWith(
    sanitized,
    BEARER_PATTERN,
    'bearer_token',
    (_match, prefix = 'Bearer ') => `${prefix}[REDACTED:TOKEN]`,
  );
  sanitized = replaceWith(
    sanitized,
    BASIC_AUTH_PATTERN,
    'bearer_token',
    (_match, prefix = 'Basic ') => `${prefix}[REDACTED:TOKEN]`,
  );
  sanitized = replaceWith(
    sanitized,
    DB_URL_CRED_PATTERN,
    'db_credential',
    (_match, scheme = 'postgres', user = 'user') => `${scheme}://${user}:[REDACTED:SECRET]@`,
  );
  sanitized = replaceWith(sanitized, PROVIDER_API_KEY_PATTERN, 'api_key', () => '[REDACTED:API_KEY]');
  sanitized = replaceWith(sanitized, AWS_KEY_PATTERN, 'aws_key', () => '[REDACTED:AWS_KEY]');
  sanitized = replaceWith(
    sanitized,
    SECRET_ASSIGNMENT_PATTERN,
    'secret_assignment',
    (_match, key = 'secret', sep = '=', quote = '', val = '') => {
      if (val.startsWith('[REDACTED:')) return _match;
      return `${key}${sep}${quote}[REDACTED:SECRET]${quote}`;
    },
  );
  sanitized = replaceWith(sanitized, EMAIL_PATTERN, 'email', () => '[REDACTED:EMAIL]');
  sanitized = replaceWith(sanitized, SSN_PATTERN, 'ssn', () => '[REDACTED:SSN]');
  sanitized = replaceWith(
    sanitized,
    NIK_PATTERN,
    'nik',
    (_match, prefix = 'nik=') => `${prefix}[REDACTED:NIK]`,
  );
  sanitized = replaceWith(sanitized, CREDIT_CARD_CANDIDATE_PATTERN, 'credit_card', (match) => {
    const digitsOnly = match.replace(/\D/gu, '');
    if (digitsOnly.length >= 13 && digitsOnly.length <= 19 && luhnCheck(digitsOnly)) {
      return '[REDACTED:CARD]';
    }
    return match;
  });
  sanitized = replaceWith(sanitized, PHONE_E164_PATTERN, 'phone', () => '[REDACTED:PHONE]');

  return {
    text: sanitized,
    redacted: redactionCount > 0,
    redactionCount,
    categories: [...foundCategories].sort(),
  };
}

export function redactOutput(output: {
  readonly stdout: string;
  readonly stderr: string;
}): RedactedStreamOutput {
  const out = redactText(output.stdout);
  const err = redactText(output.stderr);
  const categories = [...new Set([...out.categories, ...err.categories])].sort();
  return {
    stdout: out.text,
    stderr: err.text,
    redacted: out.redacted || err.redacted,
    redactionCount: out.redactionCount + err.redactionCount,
    categories,
  };
}

export function redactUnknown(value: unknown): unknown {
  if (typeof value === 'string') {
    return redactText(value).text;
  }
  if (Array.isArray(value)) {
    return value.map((entry) => redactUnknown(entry));
  }
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = redactUnknown(v);
    }
    return out;
  }
  return value;
}
