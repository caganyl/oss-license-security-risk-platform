/**
 * `oss-risk bootstrap --new-database` (REQ-007 contract section 3.3, ADR-009
 * Karar 6, X-1).
 *
 * Before any network request: usage (`--new-database` required, checked by
 * the parser), loopback address, key file reserved with `wx`/0600. Then:
 * setup (random unknown password) → API key → key written to the reserved
 * file → optional project (Bearer) → logout. The password, key, its secret
 * part and the cookie value never reach any output line. Text output only.
 */
import type { BootstrapArgs } from '../args';
import { ApiClient, isOk, mapHttpError, serverCode, serverMessage, type HttpResponse } from '../client';
import { apiKeySecretPart, CLI_API_KEY_RE, resolveTarget } from '../config';
import { CliError, EXIT_AUTH, EXIT_PASS, EXIT_RUNTIME, EXIT_USAGE } from '../exitCodes';
import type { CliDeps, KeyFileHandle } from '../main';
import { cleanText, type Output } from '../output';

const COOKIE_NAME_RE = /^[A-Za-z0-9_]+$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const UNUSABLE_SUFFIX = '; database is now initialised without a usable password; recreate the temporary database';

type Row = Record<string, unknown>;

function jsonData(res: HttpResponse): Row | null {
  try {
    const body = JSON.parse(res.body.toString('utf8')) as unknown;
    const data = body && typeof body === 'object' ? (body as Row).data : null;
    return data && typeof data === 'object' && !Array.isArray(data) ? (data as Row) : null;
  } catch {
    return null;
  }
}

function addressRejected(res: HttpResponse): CliError | null {
  const code = serverCode(res);
  if (res.status === 403 && (code === 'host_rejected' || code === 'origin_rejected')) {
    return new CliError('server_address_rejected', EXIT_USAGE, `server rejected the address or port (${code}); check --url`);
  }
  return null;
}

/** First `name=value` pair of the first `Set-Cookie` header, or null. */
function sessionCookie(res: HttpResponse): string | null {
  const header = res.headers['set-cookie'];
  const first = Array.isArray(header) ? header[0] : header;
  if (typeof first !== 'string') return null;
  const pair = first.split(';')[0];
  const eq = pair.indexOf('=');
  if (eq <= 0) return null;
  const name = pair.slice(0, eq).trim();
  const value = pair.slice(eq + 1).trim();
  return COOKIE_NAME_RE.test(name) && value.length > 0 ? `${name}=${value}` : null;
}

export async function runBootstrap(args: BootstrapArgs, deps: CliDeps, out: Output): Promise<number> {
  let handle: KeyFileHandle | null = null;
  let keyPath = '';
  let keyWritten = false;
  let cookie: string | null = null;
  let api: ApiClient | null = null;

  const removeKeyFile = async (): Promise<void> => {
    if (handle) await handle.close().catch(() => undefined);
    handle = null;
    await deps.unlink(keyPath).catch(() => undefined);
  };
  const logout = async (): Promise<void> => {
    if (!api || cookie === null) return;
    let ok = false;
    try {
      ok = isOk(await api.post('/api/auth/logout', { cookie, origin: true }));
    } catch {
      ok = false;
    }
    if (!ok) out.err('oss-risk: warning: logout failed; the session expires on its own');
  };

  try {
    // 2. Loopback only (zero connections otherwise).
    const target = resolveTarget(args.url, deps.env, 'bootstrap');

    // 3. Reserve the key file before the network.
    keyPath = deps.resolvePath(args.keyFile);
    try {
      handle = await deps.openExclusive(keyPath);
    } catch (err) {
      if ((err as NodeJS.ErrnoException)?.code === 'EEXIST') {
        throw new CliError('key_file_exists', EXIT_USAGE, `key file already exists: ${cleanText(keyPath)}`);
      }
      throw new CliError('usage_error', EXIT_USAGE, `cannot create key file ${cleanText(keyPath)}`);
    }
    if (deps.platform !== 'win32') {
      const mode = await handle.mode();
      if ((mode & 0o077) !== 0) {
        await removeKeyFile();
        throw new CliError('usage_error', EXIT_USAGE, 'key file permissions are not restricted to the owner (0600)');
      }
    }

    // 4. Random, never shown password.
    const password = deps.randomBytes(32).toString('base64url');
    out.addSecret(password);
    api = new ApiClient(target, deps.request, deps.version, deps.sleep);
    out.err(`oss-risk: initialising server ${target.origin}`);

    // 5. Setup.
    let setup: HttpResponse;
    try {
      setup = await api.post('/api/auth/setup', { origin: true, body: { password } });
    } catch (err) {
      await removeKeyFile();
      throw err;
    }
    if (setup.status !== 201) {
      await removeKeyFile();
      if (setup.status === 409 && serverCode(setup) === 'setup_already_done') {
        throw new CliError(
          'already_initialised',
          EXIT_AUTH,
          'database already initialised; bootstrap only works on an empty database',
        );
      }
      const rejected = addressRejected(setup);
      if (rejected) throw rejected;
      const redirect = setup.status >= 300 && setup.status < 400;
      throw redirect
        ? mapHttpError('POST', '/api/auth/setup', setup)
        : new CliError('unexpected_response', EXIT_RUNTIME, `POST /api/auth/setup failed: HTTP ${setup.status}`);
    }
    cookie = sessionCookie(setup);
    if (cookie === null) {
      await removeKeyFile();
      throw new CliError('unexpected_response', EXIT_RUNTIME, `POST /api/auth/setup returned no session cookie${UNUSABLE_SUFFIX}`);
    }
    out.addSecret(cookie.slice(cookie.indexOf('=') + 1));

    // 6. API key (session).
    let key: string;
    try {
      const created = await api.post('/api/auth/api-keys', { cookie, origin: true, body: { name: 'bootstrap' } });
      if (created.status !== 201) {
        const rejected = addressRejected(created);
        if (rejected) throw rejected;
        if (created.status === 401 || created.status === 403) {
          throw new CliError(created.status === 401 ? 'unauthorized' : 'forbidden', EXIT_AUTH, `POST /api/auth/api-keys failed: HTTP ${created.status}`);
        }
        throw mapHttpError('POST', '/api/auth/api-keys', created);
      }
      const value = jsonData(created)?.key;
      if (typeof value !== 'string' || !CLI_API_KEY_RE.test(value)) {
        throw new CliError('unexpected_response', EXIT_RUNTIME, 'POST /api/auth/api-keys returned an unexpected body');
      }
      key = value;
      out.addSecret(key);
      out.addSecret(apiKeySecretPart(key));

      // 7. Write the key (no trailing newline), fsync, close.
      try {
        await handle.writeAll(key);
        await handle.sync();
        await handle.close();
        handle = null;
        keyWritten = true;
      } catch {
        throw new CliError('unexpected_response', EXIT_RUNTIME, 'cannot write the API key file');
      }
    } catch (err) {
      if (err instanceof CliError) {
        await removeKeyFile();
        await logout();
        throw new CliError(err.code, err.exitCode, `${err.message}${UNUSABLE_SUFFIX}`);
      }
      throw err;
    }

    // 8. Optional project (Bearer, no Origin).
    let projectId: string | null = null;
    if (args.projectName !== null && args.projectPath !== null) {
      try {
        const res = await api.post('/api/projects', {
          bearer: key,
          body: { name: args.projectName, repoUrl: deps.resolvePath(args.projectPath), ecosystems: [] },
        });
        if (res.status === 400 || res.status === 404) {
          const msg = serverMessage(res);
          throw new CliError('project_rejected', EXIT_USAGE, `project rejected by the server${msg ? `: ${msg}` : ''}`);
        }
        if (!isOk(res)) throw mapHttpError('POST', '/api/projects', res);
        const id = jsonData(res)?.id;
        if (typeof id !== 'string' || !UUID_RE.test(id)) {
          throw new CliError('unexpected_response', EXIT_RUNTIME, 'POST /api/projects returned an unexpected body');
        }
        projectId = id;
      } catch (err) {
        await logout();
        if (err instanceof CliError) {
          throw new CliError(err.code, err.exitCode, `${err.message} (the API key was written to ${cleanText(keyPath)})`);
        }
        throw err;
      }
    }

    // 9. Logout (a failure is only a warning).
    await logout();
    out.out(`API key written to ${cleanText(keyPath)}`);
    if (projectId !== null) out.out(`Project ID: ${cleanText(projectId)}`);
    return EXIT_PASS;
  } catch (err) {
    if (!keyWritten && handle) await removeKeyFile();
    if (!(err instanceof CliError)) throw err;
    out.err(`oss-risk: error: ${err.message}`);
    return err.exitCode;
  }
}
