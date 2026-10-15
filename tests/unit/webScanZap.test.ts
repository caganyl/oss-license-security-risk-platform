/**
 * REQ-008 P-28 (AC-P28-1, AC-P28-5; contract sections 1 and 7): ZAP settings
 * and alert mapping; the proxy tunnel guard of the safe HTTP core.
 */
import { EventEmitter } from 'node:events';
import { describe, expect, it, vi } from 'vitest';
import { guardProxyTunnelErrors } from '../../src/lib/http/safeHttpClient';
import { parseAllowedHosts } from '../../src/webscan/allowlist';
import { ZAP_URL_INVALID_WARNING, mapZapAlerts, owaspFromTags, parseZapConfig } from '../../src/webscan/zap';

describe('AC-P28-1: ZAP_API_URL / ZAP_API_KEY', () => {
  it('blank -> no ZAP, no warning', () => {
    const warn = vi.fn();
    expect(parseZapConfig({}, warn)).toBeNull();
    expect(parseZapConfig({ ZAP_API_URL: '  ' }, warn)).toBeNull();
    expect(warn).not.toHaveBeenCalled();
  });

  it('https or loopback http; localhost -> 127.0.0.1; path dropped; key trimmed', () => {
    expect(parseZapConfig({ ZAP_API_URL: 'http://localhost:8090/', ZAP_API_KEY: ' k ' })).toEqual({ origin: 'http://127.0.0.1:8090', apiKey: 'k' });
    expect(parseZapConfig({ ZAP_API_URL: 'https://zap.sirket.local/JSON' })).toEqual({ origin: 'https://zap.sirket.local', apiKey: null });
    expect(parseZapConfig({ ZAP_API_URL: 'http://[::1]:8080' })).toEqual({ origin: 'http://[::1]:8080', apiKey: null });
  });

  it.each(['http://zap.sirket.local:8080', 'ftp://127.0.0.1', 'not a url', 'https://u:p@zap.local'])('%j -> warning naming the variable, ZAP off', (value) => {
    const warn = vi.fn();
    expect(parseZapConfig({ ZAP_API_URL: value, ZAP_API_KEY: 'secret-key' }, warn)).toBeNull();
    expect(warn).toHaveBeenCalledWith(ZAP_URL_INVALID_WARNING);
    expect(JSON.stringify(warn.mock.calls)).not.toContain('secret-key');
  });
});

describe('AC-P28-5: alert mapping', () => {
  const list = parseAllowedHosts('app.local');
  const alert = (over: Record<string, unknown>) => ({
    pluginId: '40012', alert: 'Cross Site Scripting (Reflected)', riskcode: '3', confidence: '2',
    url: 'https://app.local/search?q=x', description: 'XSS desc', solution: 'Encode output', cweid: '79',
    tags: { OWASP_2021_A03: 'https://owasp.org/Top10/A03_2021-Injection/', CWE_79: 'x' }, ...over,
  });

  it('groups by plugin id, keeps the most severe, lists unique example URLs without query, maps CWE/OWASP', () => {
    const findings = mapZapAlerts([
      alert({}),
      alert({ url: 'https://app.local/search?q=y' }),
      alert({ url: 'https://app.local/other', riskcode: '2' }),
      alert({ pluginId: '10021', alert: 'X-Content-Type-Options Header Missing', riskcode: '1', confidence: '2', cweid: '693', tags: {} }),
    ], list);
    expect(findings).toHaveLength(2);
    const xss = findings.find((f) => f.ruleId === 'ZAP-40012');
    expect(xss).toMatchObject({
      source: 'zap', category: 'zap', severity: 'high', confidence: 'medium', title: 'Cross Site Scripting (Reflected)',
      description: 'XSS desc', recommendation: 'Encode output', location: 'https://app.local/search', cweId: 79, owasp: 'A03:2021', key: 'zap:40012',
    });
    expect(xss?.evidence).toBe('2 adres: https://app.local/search, https://app.local/other');
    expect(findings.find((f) => f.ruleId === 'ZAP-10021')).toMatchObject({ severity: 'low', owasp: null, cweId: 693 });
  });

  it('drops false positives, URLs outside the allowlist and invalid plugin ids; risk names work without riskcode', () => {
    expect(mapZapAlerts([alert({ confidence: '0' }), alert({ confidence: 'False Positive' })], list)).toEqual([]);
    expect(mapZapAlerts([alert({ url: 'https://evil.example/x' })], list)).toEqual([]);
    expect(mapZapAlerts([alert({ pluginId: 'abc' })], list)).toEqual([]);
    expect(mapZapAlerts([alert({ riskcode: undefined, risk: 'Informational' })], list)[0].severity).toBe('info');
  });

  it('texts are cleaned and capped; at most 10 example URLs', () => {
    const urls = Array.from({ length: 15 }, (_, i) => alert({ url: `https://app.local/p${i}` }));
    const [f] = mapZapAlerts([...urls, alert({ description: `a\u0007b${'x'.repeat(5000)}` })], list);
    expect(f.evidence).toMatch(/^16 adres: .*, …$/);
    expect(f.description.length).toBeLessThanOrEqual(4000);
    expect(f.description).not.toContain('\u0007');
  });

  it('owaspFromTags', () => {
    expect(owaspFromTags({ OWASP_2021_A05: 'x', OWASP_2017_A06: 'y' })).toBe('A05:2021');
    expect(owaspFromTags({ OWASP_2021_A10: 'x' })).toBe('A10:2021');
    expect(owaspFromTags(null)).toBeNull();
    expect(owaspFromTags({ OWASP_2021_A11: 'x' })).toBeNull();
  });
});

describe('guardProxyTunnelErrors (Node proxyEnv: a refused CONNECT must not crash the process)', () => {
  it('a failed tunnel socket gets an error listener and is destroyed; the callback still gets the error', () => {
    const socket = Object.assign(new EventEmitter(), { destroy: vi.fn() });
    const agent = { createConnection: (_opts: unknown, cb: (err: unknown, s: unknown) => void) => cb(Object.assign(new Error('tunnel'), { code: 'ERR_PROXY_TUNNEL', statusCode: 403 }), socket) };
    guardProxyTunnelErrors(agent as never);
    const cb = vi.fn();
    (agent.createConnection as (o: unknown, c: unknown) => void)({}, cb);
    expect(cb).toHaveBeenCalledWith(expect.objectContaining({ code: 'ERR_PROXY_TUNNEL' }), socket);
    expect(socket.destroy).toHaveBeenCalled();
    // The late reset no longer throws (EventEmitter throws on an unhandled 'error').
    expect(() => socket.emit('error', Object.assign(new Error('reset'), { code: 'ECONNRESET' }))).not.toThrow();
  });

  it('a successful connection is passed through untouched', () => {
    const socket = Object.assign(new EventEmitter(), { destroy: vi.fn() });
    const agent = { createConnection: (_opts: unknown, cb: (err: unknown, s: unknown) => void) => { cb(null, socket); return 'ret'; } };
    guardProxyTunnelErrors(agent as never);
    const cb = vi.fn();
    expect((agent.createConnection as (o: unknown, c: unknown) => unknown)({}, cb)).toBe('ret');
    expect(cb).toHaveBeenCalledWith(null, socket);
    expect(socket.destroy).not.toHaveBeenCalled();
    expect(socket.listenerCount('error')).toBe(0);
  });
});
