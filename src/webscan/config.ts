/**
 * Web scan settings from the environment (REQ-008 contract section 1).
 * Read once at start-up by the runtime (API and worker share the result).
 */
import { boundedNumber } from '../lib/bounds';
import { type HostAllowlist, parseAllowedHosts } from './allowlist';
import { DEFAULT_PROBE_TIMEOUT_MS } from './probeClient';
import { type ZapConfig, parseZapConfig } from './zap';

export interface WebScanSettings {
  allowlist: HostAllowlist;
  timeoutMs: number;
  zap: ZapConfig | null;
}

/**
 * Throws `Error(ALLOWED_HOSTS_INVALID_MESSAGE)` for an invalid
 * `WEB_SCAN_ALLOWED_HOSTS` (start-up error, AC-P25-1); an invalid
 * `WEB_SCAN_TIMEOUT_MS` or `ZAP_API_URL` only warns (names, never values).
 */
export function loadWebScanSettings(
  env: Readonly<Record<string, string | undefined>> = process.env,
  warn: (message: string) => void = console.warn,
): WebScanSettings {
  return {
    allowlist: parseAllowedHosts(env.WEB_SCAN_ALLOWED_HOSTS),
    timeoutMs: boundedNumber(env.WEB_SCAN_TIMEOUT_MS, DEFAULT_PROBE_TIMEOUT_MS, {
      name: 'WEB_SCAN_TIMEOUT_MS',
      min: 1000,
      max: 120_000,
      integer: true,
      warn,
    }),
    zap: parseZapConfig(env, warn),
  };
}
