/**
 * Redaction for process-level log lines (REQ-003 AC-P12-9, ADR-004 Karar 6).
 *
 * A fatal error is written as one log entry built from its name, message and
 * stack only (never the whole `pg` error object), after:
 * - the user-info part of every URL (user name and password before `@`) is masked, and
 * - the values of secret environment variables (`DATABASE_URL`, `PGPASSWORD`,
 *   `ENCRYPTION_KEY`, `NVD_API_KEY`, and the password inside `DATABASE_URL`)
 *   are replaced with `[REDACTED]`.
 *
 * The L-5 sanitizer of `scans.error_message` (ADR-002 Ek E3) is a separate,
 * later step; this module only guarantees that no secret reaches the log.
 */
const SECRET_ENV_VARS = ['DATABASE_URL', 'PGPASSWORD', 'ENCRYPTION_KEY', 'NVD_API_KEY'] as const;
const MIN_SECRET_LENGTH = 4;

// URL user info with or without a password (the user name can be sensitive too).
const CREDENTIAL_URL_RE = /\b([a-z][a-z0-9+.-]*:\/\/)[^\s/@'"]+@/gi;

function secretValues(env: NodeJS.ProcessEnv): string[] {
  const out = new Set<string>();
  for (const name of SECRET_ENV_VARS) {
    const value = env[name];
    if (value && value.length >= MIN_SECRET_LENGTH) out.add(value);
  }
  const url = env.DATABASE_URL;
  if (url) {
    try {
      const parsed = new URL(url);
      for (const part of [parsed.password, decodeURIComponent(parsed.password)]) {
        if (part && part.length >= MIN_SECRET_LENGTH) out.add(part);
      }
    } catch {
      // not a URL: the whole value is already in the list
    }
  }
  // Longest first so a secret containing another one is replaced whole.
  return [...out].sort((a, b) => b.length - a.length);
}

/** Masks credential URLs and secret env values in `text`. */
export function redactSecrets(text: string, env: NodeJS.ProcessEnv = process.env): string {
  let out = text;
  for (const secret of secretValues(env)) out = out.split(secret).join('[REDACTED]');
  return out.replace(CREDENTIAL_URL_RE, '$1[REDACTED]@');
}

/**
 * One log entry for an uncaught error: `<origin>: <name>: <message>\n<stack>`,
 * redacted. Non-Error values are stringified (also redacted).
 */
export function formatFatalError(origin: string, error: unknown, env: NodeJS.ProcessEnv = process.env): string {
  let body: string;
  if (error instanceof Error) {
    const code = (error as { code?: unknown }).code;
    const head = `${error.name}${typeof code === 'string' && code !== '' ? ` (${code})` : ''}: ${error.message}`;
    // The stack starts with "<name>: <message>"; keep only its frames.
    const frames = (error.stack ?? '').split('\n').filter((line) => /^\s+at\s/.test(line)).join('\n');
    body = frames ? `${head}\n${frames}` : head;
  } else {
    let text: string;
    try {
      text = typeof error === 'string' ? error : String(error);
    } catch {
      text = typeof error;
    }
    body = `non-Error value: ${text}`;
  }
  return redactSecrets(`${origin}: ${body}`, env);
}
