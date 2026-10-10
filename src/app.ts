import express from 'express';
import http from 'http';
import path from 'path';
import type { Pool } from 'pg';
import { assertRequiredEnv, isLoopbackHost, resolveHost, resolvePort } from './config/env';
import { AuthController } from './controllers/authController';
import { LoginThrottle } from './lib/loginThrottle';
import { statusLabel } from './lib/httpError';
import { canonicalizeScanRoots, parseScanRoots } from './lib/scanSource';
import { authenticate } from './middleware/authenticate';
import { apiNotFound, errorHandler } from './middleware/errorHandler';
import {
  buildAllowedOrigins,
  requireAllowedHost,
  requireSameOrigin,
  requireSameOriginForSessionWrites,
} from './middleware/requestGuards';
import { securityHeaders } from './middleware/securityHeaders';
import { createAuthRouter, createPublicAuthRouter } from './routes/authRoutes';
import createUserRouter from './routes/userRoutes';
import createSbomRouter from './routes/sbomRoutes';
import createReportRouter from './routes/reportRoutes';
import createWorkflowRouter from './routes/workflowRoutes';
import createProjectRouter from './routes/projectRoutes';
import createScanRouter from './routes/scanRoutes';

export interface AppDeps {
  /** Required; the app never falls back to the global pool. */
  db: Pool;
  /** Port for the Host/Origin allow-list and for listen (default: PORT env or 3001). */
  port?: number;
  /** Bind host, also allowed in Host/Origin (default: HOST env or 127.0.0.1). */
  host?: string;
  /** Allowed local scan roots (P-04); default: parseScanRoots(process.env.SCAN_ROOTS). */
  scanRoots?: string[];
}

const PUBLIC_DIR = path.join(__dirname, '../public');
const JSON_BODY_LIMIT = '1mb';

/**
 * Builds the Express app without listening. Middleware order follows
 * ADR-001 karar 8 (security headers, K13, come first): Host -> static and /health -> login/setup -> cookie/Bearer
 * authentication -> CSRF (Origin) -> routers and RBAC -> /api 404 -> JSON
 * error handler. All in-memory state (login throttle) belongs to this instance.
 */
export function createApp(deps: AppDeps): express.Express {
  const { db } = deps;
  // P-04: undefined/blank SCAN_ROOTS -> no local path is accepted (AC-P04-6).
  const scanRoots = deps.scanRoots ?? parseScanRoots(process.env.SCAN_ROOTS);
  const allowed = buildAllowedOrigins(resolvePort(deps.port), resolveHost(deps.host));
  const jsonBody = express.json({ limit: JSON_BODY_LIMIT });
  const authController = new AuthController(db, new LoginThrottle());

  const app = express();
  app.disable('x-powered-by');
  // K13: first in the chain, before the Host check, so every response
  // (including 403 host_rejected and express.static files) carries them.
  app.use(securityHeaders());
  app.use(requireAllowedHost(allowed));

  app.get('/health', async (_req, res) => {
    try {
      await db.query('SELECT 1');
      res.json({ status: 'healthy', database: 'connected' });
    } catch (err) {
      // The raw driver message can carry host/user names; log the class only (AC-G-9).
      const code = (err as { code?: unknown })?.code;
      console.error(`Health check failed: database unavailable${typeof code === 'string' ? ` (${code})` : ''}`);
      // Fixed contract body (not sendError, whose generic 5xx text differs).
      res.status(500).json({
        status: 'unhealthy',
        database: 'disconnected',
        error: statusLabel(500),
        message: 'Database unavailable',
        code: 'internal_error',
      });
    }
  });

  app.use(express.static(PUBLIC_DIR));
  app.get('/', (_req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
  });

  const api = express.Router();
  api.use(createPublicAuthRouter(authController, requireSameOrigin(allowed), jsonBody));
  api.use(authenticate(db));
  api.use(requireSameOriginForSessionWrites(allowed));
  api.use(jsonBody);
  api.use('/auth', createAuthRouter(authController));
  api.use('/users', createUserRouter(db));
  api.use(createSbomRouter(db));
  api.use(createReportRouter(db));
  api.use('/findings', createWorkflowRouter(db));
  api.use(createProjectRouter(db, scanRoots));
  api.use(createScanRouter(db, scanRoots));
  api.use(apiNotFound());

  app.use('/api', api);
  app.use(errorHandler());
  return app;
}

/**
 * Creates the app and listens on `host:port` (default 127.0.0.1, AC-P01-9).
 * Resolves once the server is listening. Refuses to start without the
 * required configuration (AC-P09-3).
 */
export async function startServer(options: AppDeps): Promise<http.Server> {
  assertRequiredEnv();
  return listenApp(options);
}

/**
 * `startServer` without the environment check: the runtime (src/runtime.ts)
 * has already checked its own environment (ADR-004 Karar 2 adım 1) and calls
 * this as step 6. `env` resolves PORT/HOST/SCAN_ROOTS defaults.
 */
export async function listenApp(options: AppDeps, env: NodeJS.ProcessEnv = process.env): Promise<http.Server> {
  const port = resolvePort(options.port, env);
  const host = resolveHost(options.host, env);
  if (!isLoopbackHost(host)) {
    console.warn(
      `Warning: HOST=${host} exposes the API beyond this machine over plain HTTP; ` +
        'session cookies and API keys travel unencrypted. Use 127.0.0.1 unless you know why.',
    );
  }
  // An invalid SCAN_ROOTS entry is an explicit startup error (ADR-002 karar 4).
  const scanRoots = await canonicalizeScanRoots(options.scanRoots ?? parseScanRoots(env.SCAN_ROOTS));
  const server = http.createServer();
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.off('error', reject);
      // The Host/Origin allow-list comes from the port the socket is really
      // bound to (an injected `port: 0` gets a free port; security review
      // I-1), never from a request. The handler is attached in the
      // `listening` callback, before any connection can be accepted.
      const bound = server.address();
      const boundPort = bound && typeof bound === 'object' ? bound.port : port;
      server.on('request', createApp({ ...options, port: boundPort, host, scanRoots }));
      resolve();
    });
  });
  return server;
}

// The process entry point is src/main.ts (`npm start` = node dist/main.js,
// REQ-003 AC-P12-3); this module only builds and listens.
