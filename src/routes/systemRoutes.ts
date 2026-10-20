import { Router, type Request, type Response } from 'express';
import { guard } from '../middleware/rbac';
import { enrichmentConfigFrom, vulnerabilityConfigFrom } from '../scanner/sandbox/runner.config';
import { parseWindowsAuthHosts } from '../scanner/workspace';
import { nvdApiKeyConfigured } from '../vulnerability/client';
import type { HostAllowlist } from '../webscan/allowlist';
import { parseZapConfig } from '../webscan/zap';

type Env = Readonly<Record<string, string | undefined>>;

/** Feature switches of the running application (contract REQ-010 system features 1.0.0). */
export interface SystemFeatures {
  local_scan: { enabled: boolean; roots: number };
  web_scan: { enabled: boolean; allowed_hosts: number };
  zap: { enabled: boolean };
  registry_enrichment: { enabled: boolean };
  vulnerability_lookup: { enabled: boolean };
  vulnerability_recheck: { enabled: boolean };
  nvd: { enabled: boolean; api_key: boolean };
  repo_tokens: { enabled: boolean };
  windows_git_auth: { enabled: boolean; hosts: number };
}

const quiet = (): void => undefined;

function present(value: string | undefined): boolean {
  return typeof value === 'string' && value.trim() !== '';
}

/**
 * Only booleans and counts (REQ-010 AC-P35-1): no setting value, host name,
 * path, key or token ever leaves this function. Parsers run with a silent
 * warn callback; invalid values were already reported at start-up.
 */
export function systemFeatures(env: Env, scanRoots: readonly string[], webAllowlist: HostAllowlist): SystemFeatures {
  const vulnerability = vulnerabilityConfigFrom(env, quiet);
  let windowsHosts = 0;
  try {
    windowsHosts = parseWindowsAuthHosts(env.GIT_WINDOWS_AUTH_HOSTS).size;
  } catch {
    windowsHosts = 0;
  }
  const webEntries = webAllowlist.empty ? 0 : (env.WEB_SCAN_ALLOWED_HOSTS ?? '').split(/[\s,]+/).filter((s) => s !== '').length;
  return {
    local_scan: { enabled: scanRoots.length > 0, roots: scanRoots.length },
    web_scan: { enabled: !webAllowlist.empty, allowed_hosts: webEntries },
    zap: { enabled: parseZapConfig(env, quiet) !== null },
    registry_enrichment: { enabled: enrichmentConfigFrom(env).enabled },
    vulnerability_lookup: { enabled: vulnerability.lookupEnabled },
    vulnerability_recheck: { enabled: vulnerability.recheckEnabled },
    nvd: { enabled: vulnerability.lookupEnabled && vulnerability.nvdEnabled, api_key: nvdApiKeyConfigured(env) },
    repo_tokens: { enabled: present(env.ENCRYPTION_KEY) },
    windows_git_auth: { enabled: windowsHosts > 0, hosts: windowsHosts },
  };
}

/**
 * System status route (REQ-010 P-35).
 *
 *   GET /api/system/features   read-only feature switches (settings:read)
 *
 * Mounted after the global authentication middleware, like the other `/api` routers.
 */
export function createSystemRouter(scanRoots: readonly string[], webAllowlist: HostAllowlist, env: Env = process.env): Router {
  const router = Router();
  router.get('/system/features', guard('settings:read'), (_req: Request, res: Response) => {
    res.json({ data: systemFeatures(env, scanRoots, webAllowlist) });
  });
  return router;
}

export default createSystemRouter;
