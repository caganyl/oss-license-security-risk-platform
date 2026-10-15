/**
 * REQ-008 P-25 (AC-P25-1, AC-P25-3, AC-P25-8): WEB_SCAN_ALLOWED_HOSTS parsing
 * and matching, webUrl rule, per-request URL gate, finding locations.
 */
import { describe, expect, it } from 'vitest';
import {
  ALLOWED_HOSTS_INVALID_MESSAGE,
  WebUrlError,
  isAllowedRequestUrl,
  locationOf,
  normalizeWebUrl,
  parseAllowedHosts,
} from '../../src/webscan/allowlist';

describe('AC-P25-1: WEB_SCAN_ALLOWED_HOSTS', () => {
  it('empty / undefined -> closed', () => {
    expect(parseAllowedHosts(undefined).empty).toBe(true);
    expect(parseAllowedHosts('  ').empty).toBe(true);
    expect(parseAllowedHosts('').allows('localhost')).toBe(false);
  });

  it('exact host, wildcard (subdomains only), IPv4, IPv6; comma and/or space separated; case-insensitive; trailing dot', () => {
    const list = parseAllowedHosts('Portal.Sirket.Local, *.sirket.com.tr 10.1.2.3,[fd00::1]');
    expect(list.empty).toBe(false);
    expect(list.allows('portal.sirket.local')).toBe(true);
    expect(list.allows('PORTAL.sirket.local.')).toBe(true);
    expect(list.allows('a.sirket.com.tr')).toBe(true);
    expect(list.allows('a.b.sirket.com.tr')).toBe(true);
    expect(list.allows('sirket.com.tr')).toBe(false);
    expect(list.allows('kotusirket.com.tr')).toBe(false);
    expect(list.allows('10.1.2.3')).toBe(true);
    expect(list.allows('10.1.2.4')).toBe(false);
    expect(list.allows('[fd00::1]')).toBe(true);
    expect(list.allows('fd00::1')).toBe(true);
    expect(list.allows('other.local')).toBe(false);
  });

  it('a wildcard never matches an IP literal', () => {
    expect(parseAllowedHosts('*.0.0.1').allows('127.0.0.1')).toBe(false);
  });

  it.each(['https://a.local', 'a.local:8080', 'a.local/path', '*', '*.com', '*.*.a.com', 'user@a.local', '[not-ipv6]', 'bad_host!', 'a..b'])(
    'invalid entry %j -> start-up error naming the variable only',
    (entry) => {
      expect(() => parseAllowedHosts(`ok.local,${entry}`)).toThrow(ALLOWED_HOSTS_INVALID_MESSAGE);
      try {
        parseAllowedHosts(entry);
      } catch (err) {
        expect((err as Error).message).not.toContain(entry);
      }
    },
  );
});

describe('AC-P25-3: webUrl rule', () => {
  const list = parseAllowedHosts('app.local,127.0.0.1');
  it('valid http/https URLs are normalized with new URL().href', () => {
    expect(normalizeWebUrl('https://APP.local', list)).toBe('https://app.local/');
    expect(normalizeWebUrl('http://127.0.0.1:8080/Portal/Login.aspx?x=1', list)).toBe('http://127.0.0.1:8080/Portal/Login.aspx?x=1');
  });

  it.each([
    ['not a string', 42],
    ['empty', ''],
    ['leading space', ' https://app.local/'],
    ['control char', 'https://app.local/\u0007'],
    ['whitespace inside', 'https://app.local/a b'],
    ['fragment', 'https://app.local/#x'],
    ['ftp scheme', 'ftp://app.local/'],
    ['javascript scheme', 'javascript:alert(1)'],
    ['user info', 'https://user:pass@app.local/'],
    ['empty user info', 'https://@app.local/'],
    ['no scheme', 'app.local'],
    ['too long', `https://app.local/${'a'.repeat(2100)}`],
  ])('%s -> 400 web_url_invalid', (_label, value) => {
    try {
      normalizeWebUrl(value, list);
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(WebUrlError);
      expect((err as WebUrlError).code).toBe('web_url_invalid');
      expect((err as WebUrlError).statusCode).toBe(400);
      expect((err as Error).message).not.toContain('app.local');
    }
  });

  it('a valid URL whose host is not listed -> 400 web_url_not_allowed (message without URL or list)', () => {
    try {
      normalizeWebUrl('https://evil.example/', list);
      expect.unreachable();
    } catch (err) {
      expect((err as WebUrlError).code).toBe('web_url_not_allowed');
      expect((err as Error).message).not.toMatch(/evil|app\.local/);
    }
  });

  it('closed allowlist rejects every URL', () => {
    expect(() => normalizeWebUrl('https://app.local/', parseAllowedHosts(''))).toThrow(WebUrlError);
  });
});

describe('AC-P25-8: per-request gate and locations', () => {
  const list = parseAllowedHosts('app.local');
  it('only http(s) URLs of allowed hosts without credentials', () => {
    expect(isAllowedRequestUrl('https://app.local/.env', list)).toBe(true);
    expect(isAllowedRequestUrl('http://app.local:81/', list)).toBe(true);
    expect(isAllowedRequestUrl('https://cdn.example/x.js', list)).toBe(false);
    expect(isAllowedRequestUrl('https://u:p@app.local/', list)).toBe(false);
    expect(isAllowedRequestUrl('file:///etc/passwd', list)).toBe(false);
    expect(isAllowedRequestUrl('not a url', list)).toBe(false);
  });

  it('locationOf drops query, fragment and credentials', () => {
    expect(locationOf('https://u:p@app.local/a/b?token=secret#frag')).toBe('https://app.local/a/b');
    expect(locationOf('nonsense')).toBe('');
  });
});
