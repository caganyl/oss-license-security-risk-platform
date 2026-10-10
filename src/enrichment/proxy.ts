/**
 * Compatibility re-export (ADR-007 Karar 1): the proxy module moved to
 * `src/lib/http/proxy.ts`, shared by the registry and vulnerability clients.
 * Existing imports and tests keep working unchanged.
 */
export { nodeSupportsProxyEnv, resolveProxy, shouldUseProxy, type ProxySettings } from '../lib/http/proxy';
