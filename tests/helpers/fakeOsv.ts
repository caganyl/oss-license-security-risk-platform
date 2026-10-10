/**
 * REQ-005 · Loopback fake OSV (`/v1/querybatch`, `/v1/vulns/<id>`) and NVD
 * (`/rest/json/cves/2.0?cveId=`) server (ADR-007 "Test stratejisi"; AC-G-2).
 *
 * One `http` server on 127.0.0.1 (the vulnerability client accepts loopback
 * `http` origins injected from code only). Every request is recorded with its
 * method, path, query, headers and parsed JSON body. Default behaviour:
 * - querybatch answers each query from `vulns` (key `ecosystem|name|version`),
 *   paged by `pages` (one entry per page; `next_page_token` = `p<n>`);
 * - `/v1/vulns/<id>` answers `records` (404 otherwise);
 * - NVD answers `nvd` (`{ vulnerabilities: [] }` otherwise).
 * `override(path, handler)` replaces any route (sequences, errors, 429 with
 * `Retry-After`, redirects, oversize, hangs) like `fakeRegistry.ts`.
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import type { FakeHandler, FakeResponse } from './fakeRegistry';

export interface OsvRecordedRequest {
  method: string;
  path: string;
  query: string;
  headers: http.IncomingHttpHeaders;
  body: unknown;
}

export interface QuerybatchQuery {
  package: { ecosystem: string; name: string };
  version: string;
  page_token?: string;
}

export type OsvBatchVuln = { id: string; modified?: string } | Record<string, unknown>;

export const osvKey = (ecosystem: string, name: string, version: string): string => `${ecosystem}|${name}|${version}`;

export class FakeOsv {
  readonly requests: OsvRecordedRequest[] = [];
  /** Batch vulns per query key (single page). */
  readonly vulns = new Map<string, OsvBatchVuln[]>();
  /** Paged batch vulns per query key (page i answered for page token `p<i>`; first page without a token). */
  readonly pages = new Map<string, OsvBatchVuln[][]>();
  /** Detail records by id. */
  readonly records = new Map<string, Record<string, unknown>>();
  /** NVD response bodies by CVE id. */
  readonly nvd = new Map<string, Record<string, unknown>>();
  private readonly overrides = new Map<string, FakeHandler>();
  private readonly sequencePos = new Map<string, number>();

  constructor(
    private readonly server: http.Server,
    readonly origin: string,
  ) {}

  override(path: string, handler: FakeHandler): this {
    this.overrides.set(path, handler);
    this.sequencePos.delete(path);
    return this;
  }

  clearOverride(path: string): this {
    this.overrides.delete(path);
    return this;
  }

  count(path: string, method?: string): number {
    return this.requests.filter((r) => r.path === path && (method === undefined || r.method === method)).length;
  }

  batches(): QuerybatchQuery[][] {
    return this.requests
      .filter((r) => r.path === '/v1/querybatch')
      .map((r) => ((r.body as { queries?: QuerybatchQuery[] } | null)?.queries ?? []));
  }

  detailCount(): number {
    return this.requests.filter((r) => r.path.startsWith('/v1/vulns/')).length;
  }

  nvdCount(): number {
    return this.requests.filter((r) => r.path === '/rest/json/cves/2.0').length;
  }

  resetCounts(): void {
    this.requests.length = 0;
  }

  /** A full OSV record (with a CVSS v3 vector unless `severity: []`). */
  addRecord(id: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
    const record = {
      id,
      summary: `${id} summary`,
      modified: '2026-01-01T00:00:00Z',
      published: '2025-12-01T00:00:00Z',
      severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
      references: [{ type: 'ADVISORY', url: `https://osv.dev/vulnerability/${id}` }],
      ...extra,
    };
    this.records.set(id, record);
    return record;
  }

  private defaultBatch(body: unknown): FakeResponse {
    const queries = (body as { queries?: QuerybatchQuery[] } | null)?.queries;
    if (!Array.isArray(queries)) return { status: 400, body: { error: 'bad body' } };
    const results = queries.map((q) => {
      const key = osvKey(q.package.ecosystem, q.package.name, q.version);
      const paged = this.pages.get(key);
      if (paged) {
        const index = q.page_token === undefined ? 0 : Number(q.page_token.slice(1));
        const entry: Record<string, unknown> = { vulns: paged[index] ?? [] };
        if (index + 1 < paged.length) entry.next_page_token = `p${index + 1}`;
        return entry;
      }
      const list = this.vulns.get(key);
      return list && list.length > 0 ? { vulns: list } : {};
    });
    return { body: { results } };
  }

  private defaultResponse(method: string, path: string, query: URLSearchParams, body: unknown): FakeResponse {
    if (path === '/v1/querybatch' && method === 'POST') return this.defaultBatch(body);
    const detail = /^\/v1\/vulns\/([^/]+)$/.exec(path);
    if (detail && method === 'GET') {
      const record = this.records.get(decodeURIComponent(detail[1]));
      return record ? { body: record } : { status: 404, body: { code: 5, message: 'Bug not found.' } };
    }
    if (path === '/rest/json/cves/2.0' && method === 'GET') {
      const cve = query.get('cveId') ?? '';
      return { body: this.nvd.get(cve) ?? { resultsPerPage: 0, vulnerabilities: [] } };
    }
    return { status: 404, body: { error: 'Not found' } };
  }

  handle(req: http.IncomingMessage, res: http.ServerResponse): void {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const url = new URL(req.url ?? '/', this.origin);
      const raw = Buffer.concat(chunks).toString('utf8');
      let body: unknown = null;
      if (raw !== '') {
        try {
          body = JSON.parse(raw);
        } catch {
          body = raw;
        }
      }
      const method = req.method ?? 'GET';
      this.requests.push({ method, path: url.pathname, query: url.search, headers: req.headers, body });
      const handler = this.overrides.get(url.pathname);
      let response: FakeResponse;
      if (handler === undefined) response = this.defaultResponse(method, url.pathname, url.searchParams, body);
      else if (typeof handler === 'function') response = handler(req);
      else if (Array.isArray(handler)) {
        const pos = this.sequencePos.get(url.pathname) ?? 0;
        this.sequencePos.set(url.pathname, pos + 1);
        const step = handler[Math.min(pos, handler.length - 1)];
        response = (step as FakeResponse & { passthrough?: boolean }).passthrough ? this.defaultResponse(method, url.pathname, url.searchParams, body) : step;
      } else response = handler;
      this.send(req, res, response);
    });
  }

  private send(req: http.IncomingMessage, res: http.ServerResponse, response: FakeResponse): void {
    const go = () => {
      if (response.hang) return;
      if (response.reset) {
        req.socket.destroy();
        return;
      }
      const headers: Record<string, string> = { ...(response.headers ?? {}) };
      let out: Buffer;
      if (response.body === undefined) out = Buffer.alloc(0);
      else if (Buffer.isBuffer(response.body)) out = response.body;
      else if (typeof response.body === 'string') out = Buffer.from(response.body, 'utf8');
      else {
        out = Buffer.from(JSON.stringify(response.body), 'utf8');
        headers['content-type'] ??= 'application/json';
      }
      if (!response.chunked) headers['content-length'] = String(out.length);
      res.writeHead(response.status ?? 200, headers);
      if (response.chunked) {
        const step = 64 * 1024;
        for (let i = 0; i < out.length; i += step) res.write(out.subarray(i, i + step));
        res.end();
      } else res.end(out);
    };
    if (response.delayMs) setTimeout(go, response.delayMs);
    else go();
  }

  close(): Promise<void> {
    return new Promise((resolve) => {
      this.server.closeAllConnections();
      this.server.close(() => resolve());
    });
  }
}

/** Sequence step that falls back to the default route behaviour. */
export const PASSTHROUGH = { passthrough: true } as FakeResponse;

export async function startFakeOsv(): Promise<FakeOsv> {
  let fake: FakeOsv | null = null;
  const server = http.createServer((req, res) => fake?.handle(req, res));
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  fake = new FakeOsv(server, `http://127.0.0.1:${port}`);
  return fake;
}

/** NVD 2.0 body with one CVSS v3.1 metric. */
export function nvdBody(cve: string, score: number, severity = 'HIGH'): Record<string, unknown> {
  return {
    vulnerabilities: [
      {
        cve: {
          id: cve,
          metrics: { cvssMetricV31: [{ cvssData: { version: '3.1', baseScore: score, baseSeverity: severity, vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' } }] },
        },
      },
    ],
  };
}
