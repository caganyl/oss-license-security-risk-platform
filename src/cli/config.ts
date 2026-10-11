/**
 * Server address and API key rules (REQ-007 contract sections 3.1, 3.2;
 * ADR-009 Karar 2). Runs before the first network request; every failure is
 * exit 2. `.env` is never read and no server module is imported.
 */
import { CliError, EXIT_USAGE } from './exitCodes';
import { cleanText } from './output';

export const DEFAULT_URL = 'http://127.0.0.1:3001';
export const API_KEY_FILE_MAX_BYTES = 1024;

/**
 * Same pattern as the server's `API_KEY_RE` in `src/lib/apiKeys.ts`, kept as
 * a separate constant on purpose (the CLI must not import server modules); a
 * test compares the two source texts.
 */
export const CLI_API_KEY_RE = /^ossr_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$/;

const LOOPBACK_HOSTNAMES: ReadonlySet<string> = new Set(['127.0.0.1', 'localhost', '[::1]']);

export interface Target {
  protocol: 'http:' | 'https:';
  /** URL `hostname` form (`[::1]` keeps its brackets). */
  hostname: string;
  /** Host name for the socket connection (`::1` without brackets). */
  connectHost: string;
  port: number;
  loopback: boolean;
  /** `<protocol>//<hostname>:<effective port>`. */
  origin: string;
  /** Explicit `Host` header value; null → Node's default (non-loopback https). */
  hostHeader: string | null;
}

export type Env = Readonly<Record<string, string | undefined>>;

function envValue(env: Env, name: string): string | null {
  const v = env[name];
  return v === undefined || v === '' ? null : v;
}

/** Contract 3.1. `mode` 'bootstrap' also rejects every non-loopback address. */
export function resolveTarget(cliUrl: string | null, env: Env, mode: 'scan' | 'bootstrap'): Target {
  const raw = cliUrl ?? envValue(env, 'OSS_RISK_URL') ?? DEFAULT_URL;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new CliError('invalid_url', EXIT_USAGE, 'invalid server address');
  }
  if (
    (url.protocol !== 'http:' && url.protocol !== 'https:') ||
    url.username !== '' ||
    url.password !== '' ||
    url.search !== '' ||
    url.hash !== '' ||
    url.pathname !== '/'
  ) {
    throw new CliError(
      'invalid_url',
      EXIT_USAGE,
      'invalid server address: use http(s)://host[:port] without credentials, path, query or fragment',
    );
  }
  const protocol = url.protocol;
  const loopback = LOOPBACK_HOSTNAMES.has(url.hostname);
  if (mode === 'bootstrap' && !loopback) {
    throw new CliError('not_loopback', EXIT_USAGE, 'bootstrap only works with a loopback address (127.0.0.1, localhost, [::1])');
  }
  if (!loopback && protocol === 'http:') {
    throw new CliError('insecure_url', EXIT_USAGE, 'a non-loopback server address must use https');
  }
  const port = url.port !== '' ? Number(url.port) : protocol === 'https:' ? 443 : 80;
  const hostname = url.hostname;
  const connectHost = hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
  return {
    protocol,
    hostname,
    connectHost,
    port,
    loopback,
    origin: `${protocol}//${hostname}:${port}`,
    hostHeader: loopback && protocol === 'http:' ? `${hostname}:${port}` : null,
  };
}

export class KeyFileTooLargeError extends Error {}

/** Reads at most `maxBytes + 1` bytes; throws `KeyFileTooLargeError` above `maxBytes`. */
export type ReadKeyFile = (path: string, maxBytes: number) => Promise<Buffer>;

const keyConfigError = (message: string) => new CliError('invalid_api_key_config', EXIT_USAGE, message);

/** Contract 3.2 (scan only). The returned key is never printed. */
export async function resolveApiKey(env: Env, readKeyFile: ReadKeyFile): Promise<string> {
  const value = envValue(env, 'OSS_RISK_API_KEY');
  const file = envValue(env, 'OSS_RISK_API_KEY_FILE');
  if ((value === null) === (file === null)) {
    throw keyConfigError('set exactly one of OSS_RISK_API_KEY or OSS_RISK_API_KEY_FILE');
  }
  let key: string;
  if (file !== null) {
    let buf: Buffer;
    try {
      buf = await readKeyFile(file, API_KEY_FILE_MAX_BYTES);
    } catch (err) {
      if (err instanceof KeyFileTooLargeError) throw keyConfigError('API key file is larger than 1 KiB');
      throw keyConfigError(`cannot read API key file ${cleanText(file)}`);
    }
    if (buf.length > API_KEY_FILE_MAX_BYTES) throw keyConfigError('API key file is larger than 1 KiB');
    key = buf.toString('utf8').trim();
  } else {
    key = value as string; // only the file content is trimmed (contract 3.2)
  }
  if (!CLI_API_KEY_RE.test(key)) throw keyConfigError('API key has an invalid format');
  return key;
}

/** Secret part `S` of `ossr_<P>_<S>` (for output redaction). */
export function apiKeySecretPart(key: string): string {
  return key.slice(key.length - 43);
}
