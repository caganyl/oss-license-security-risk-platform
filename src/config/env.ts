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

/** Port from deps, else PORT env, else 3001. */
export function resolvePort(port: number | undefined, env: NodeJS.ProcessEnv = process.env): number {
  if (port !== undefined) return port;
  const fromEnv = Number(env.PORT);
  return Number.isInteger(fromEnv) && fromEnv >= 0 ? fromEnv : 3001;
}

/** Bind host from deps, else HOST env, else loopback only (AC-P01-9). */
export function resolveHost(host: string | undefined, env: NodeJS.ProcessEnv = process.env): string {
  return host ?? (env.HOST && env.HOST.trim() !== '' ? env.HOST.trim() : '127.0.0.1');
}
