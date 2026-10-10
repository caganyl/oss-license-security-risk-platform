/**
 * Startup configuration checks (REQ-002 AC-P09-3).
 *
 * Only DATABASE_URL is required to start the API. ENCRYPTION_KEY is checked
 * where a token is actually decrypted (scanner worker, D-14), not here.
 * Messages name the variable but never print its value.
 */
export const REQUIRED_ENV_VARS = ['DATABASE_URL'] as const;

export class MissingConfigError extends Error {
  constructor(readonly variables: string[]) {
    super(
      `Missing required environment variable(s): ${variables.join(', ')}. ` +
        'Copy .env.example to .env and fill in the values (see README).',
    );
    this.name = 'MissingConfigError';
  }
}

export function assertRequiredEnv(env: NodeJS.ProcessEnv = process.env): void {
  const missing = REQUIRED_ENV_VARS.filter((name) => !env[name] || env[name]!.trim() === '');
  if (missing.length > 0) throw new MissingConfigError([...missing]);
}

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);

export function isLoopbackHost(host: string): boolean {
  return LOOPBACK_HOSTS.has(host.toLowerCase());
}

export const INVALID_PORT_MESSAGE = 'PORT geçersiz: 1 ile 65535 arasında bir tam sayı olmalı.';

function isListenPort(value: number): boolean {
  return Number.isInteger(value) && value >= 1 && value <= 65535;
}

/**
 * Start-up check of the PORT variable (REQ-003 security review I-1): unset or
 * blank is fine (default 3001); anything else must be an integer 1–65535.
 * `PORT=0` (a random port the user cannot know) is refused. Throws with a
 * message that names the variable but not its value.
 */
export function assertValidPortEnv(env: NodeJS.ProcessEnv = process.env): void {
  const raw = env.PORT;
  if (raw === undefined || raw.trim() === '') return;
  if (!/^\d+$/.test(raw.trim()) || !isListenPort(Number(raw.trim()))) throw new Error(INVALID_PORT_MESSAGE);
}

/**
 * Port from deps, else PORT env (1–65535), else 3001. An injected `port: 0`
 * (tests) is kept: `listenApp` then builds the Host/Origin allow-list from
 * the port actually bound.
 */
export function resolvePort(port: number | undefined, env: NodeJS.ProcessEnv = process.env): number {
  if (port !== undefined) return port;
  const fromEnv = Number(env.PORT);
  return isListenPort(fromEnv) ? fromEnv : 3001;
}

/** Bind host from deps, else HOST env, else loopback only (AC-P01-9). */
export function resolveHost(host: string | undefined, env: NodeJS.ProcessEnv = process.env): string {
  return host ?? (env.HOST && env.HOST.trim() !== '' ? env.HOST.trim() : '127.0.0.1');
}
