/**
 * REQ-004 · Loopback fake registry (ADR-006 "Test stratejisi"; AC-G-2, D-75).
 *
 * One `http` server on 127.0.0.1 serves npm version documents, PyPI version
 * JSON and archive downloads (the client accepts only `http://127.0.0.1:<port>`
 * test endpoints, so no TLS is needed). Every request is recorded with its
 * path and headers; `count(path)` / `total()` answer "how many requests".
 * Responses are programmable per path: status, headers, body, delay, hang,
 * socket reset, chunked oversize, gzip encoding, sequences (retry tests).
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import zlib from 'node:zlib';
import { sha256hex, sha512b64, tgz, type TarEntry } from './archiveBuilder';

export interface FakeResponse {
  status?: number;
  headers?: Record<string, string>;
  /** Object -> JSON (content-type application/json unless overridden). */
  body?: Buffer | string | Record<string, unknown>;
  delayMs?: number;
  /** Never answer (client timeout / abort tests). */
  hang?: boolean;
  /** Destroy the socket without a response (network error). */
  reset?: boolean;
  /** Send the body chunked (no Content-Length). */
  chunked?: boolean;
  /** gzip the body and set `Content-Encoding: gzip`. */
  gzip?: boolean;
}

export type FakeHandler = FakeResponse | FakeResponse[] | ((req: http.IncomingMessage) => FakeResponse);

export interface RecordedRequest {
  method: string;
  path: string;
  headers: http.IncomingHttpHeaders;
}

export interface NpmPackageSpec {
  license?: unknown;
  licenses?: unknown;
  /** Tarball entries (default: `package/package.json` + `package/LICENSE`). */
  tarball?: TarEntry[] | null;
  /** Override `dist.integrity` (null = omit). */
  integrity?: string | null;
  shasum?: string;
}

export interface PypiFileSpec {
  filename: string;
  packagetype: 'bdist_wheel' | 'sdist';
  bytes: Buffer;
  /** Override the published sha256. */
  sha256?: string;
}

export interface PypiPackageSpec {
  info: Record<string, unknown>;
  files?: PypiFileSpec[];
}

export class FakeRegistry {
  readonly requests: RecordedRequest[] = [];
  private readonly routes = new Map<string, FakeHandler>();
  private readonly sequencePos = new Map<string, number>();
  private active = 0;
  /** Highest number of simultaneously open requests seen. */
  maxActive = 0;

  constructor(
    private readonly server: http.Server,
    readonly origin: string,
  ) {}

  route(path: string, handler: FakeHandler): this {
    this.routes.set(path, handler);
    this.sequencePos.delete(path);
    return this;
  }

  count(path: string): number {
    return this.requests.filter((r) => r.path === path).length;
  }

  total(): number {
    return this.requests.length;
  }

  resetCounts(): void {
    this.requests.length = 0;
    this.maxActive = 0;
  }

  /** Version document + tarball of `name@version`; returns the tarball path. */
  addNpmPackage(name: string, version: string, spec: NpmPackageSpec = {}): { docPath: string; tarballPath: string; tarball: Buffer | null } {
    const segment = name.startsWith('@') ? name.replace('/', '%2F') : name;
    const base = name.startsWith('@') ? name.split('/')[1] : name;
    const docPath = `/${segment}/${version}`;
    const tarballPath = `/${name}/-/${base}-${version}.tgz`;
    const entries = spec.tarball === undefined
      ? [
          { name: 'package/package.json', data: JSON.stringify({ name, version }) },
          { name: 'package/LICENSE', data: `MIT License\n\nCopyright (c) 2020 ${base} authors\n` },
        ]
      : spec.tarball;
    const tarball = entries === null ? null : tgz(entries);
    const dist: Record<string, unknown> = { tarball: `${this.origin}${tarballPath}` };
    if (spec.integrity !== null) dist.integrity = spec.integrity ?? (tarball ? `sha512-${sha512b64(tarball)}` : undefined);
    if (spec.shasum !== undefined) dist.shasum = spec.shasum;
    const doc: Record<string, unknown> = { name, version, dist };
    if (spec.license !== undefined) doc.license = spec.license;
    if (spec.licenses !== undefined) doc.licenses = spec.licenses;
    this.route(docPath, { body: doc });
    if (tarball) this.route(tarballPath, { body: tarball, headers: { 'content-type': 'application/octet-stream' } });
    return { docPath, tarballPath, tarball };
  }

  /** PyPI version JSON (+ files under `/packages/`) of `name==version` (`name` already PEP 503). */
  addPypiPackage(name: string, version: string, spec: PypiPackageSpec): { docPath: string; filePaths: string[] } {
    const docPath = `/pypi/${name}/${version}/json`;
    const filePaths: string[] = [];
    const urls = (spec.files ?? []).map((f) => {
      const p = `/packages/${f.filename}`;
      filePaths.push(p);
      this.route(p, { body: f.bytes, headers: { 'content-type': 'application/octet-stream' } });
      return { url: `${this.origin}${p}`, filename: f.filename, packagetype: f.packagetype, size: f.bytes.length, digests: { sha256: f.sha256 ?? sha256hex(f.bytes) } };
    });
    this.route(docPath, { body: { info: spec.info, urls } });
    return { docPath, filePaths };
  }

  handle(req: http.IncomingMessage, res: http.ServerResponse): void {
    const path = (req.url ?? '/').split('?')[0];
    this.requests.push({ method: req.method ?? 'GET', path, headers: req.headers });
    this.active++;
    this.maxActive = Math.max(this.maxActive, this.active);
    let closed = false;
    const done = () => {
      if (!closed) {
        closed = true;
        this.active--;
      }
    };
    res.on('close', done);
    const handler = this.routes.get(path);
    let response: FakeResponse;
    if (handler === undefined) response = { status: 404, body: { error: 'Not found' } };
    else if (typeof handler === 'function') response = handler(req);
    else if (Array.isArray(handler)) {
      const pos = this.sequencePos.get(path) ?? 0;
      this.sequencePos.set(path, pos + 1);
      response = handler[Math.min(pos, handler.length - 1)];
    } else response = handler;

    const send = () => {
      if (response.hang) return;
      if (response.reset) {
        req.socket.destroy();
        return;
      }
      const headers: Record<string, string> = { ...(response.headers ?? {}) };
      let body: Buffer;
      if (response.body === undefined) body = Buffer.alloc(0);
      else if (Buffer.isBuffer(response.body)) body = response.body;
      else if (typeof response.body === 'string') body = Buffer.from(response.body, 'utf8');
      else {
        body = Buffer.from(JSON.stringify(response.body), 'utf8');
        headers['content-type'] ??= 'application/json';
      }
      if (response.gzip) {
        body = zlib.gzipSync(body);
        headers['content-encoding'] = 'gzip';
      }
      if (!response.chunked) headers['content-length'] = String(body.length);
      res.writeHead(response.status ?? 200, headers);
      if (response.chunked) {
        const step = 16 * 1024;
        for (let i = 0; i < body.length; i += step) res.write(body.subarray(i, i + step));
        res.end();
      } else {
        res.end(body);
      }
    };
    if (response.delayMs) setTimeout(send, response.delayMs);
    else send();
  }

  close(): Promise<void> {
    return new Promise((resolve) => {
      this.server.closeAllConnections();
      this.server.close(() => resolve());
    });
  }
}

export async function startFakeRegistry(): Promise<FakeRegistry> {
  let registry: FakeRegistry | null = null;
  const server = http.createServer((req, res) => registry?.handle(req, res));
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  registry = new FakeRegistry(server, `http://127.0.0.1:${port}`);
  return registry;
}
