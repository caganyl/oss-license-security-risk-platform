/**
 * OPTIONAL Vitest globalSetup: one embedded PostgreSQL cluster for the whole
 * run instead of one per DB-backed test file.
 *
 * Not active yet — tests/ is the only path QA may write. To enable, add to
 * vitest.config.ts (owner: main session):
 *
 *   test: { globalSetup: ['tests/helpers/pgGlobalSetup.ts'], ... }
 *
 * tests/helpers/db.ts picks the shared cluster up via inject() and falls back
 * to a per-file cluster when this setup is not registered.
 */
import { startCluster } from './pgCluster';

interface ProvideTarget {
  provide(key: 'ossrTestPgCluster', value: import('./pgCluster').ClusterInfo): void;
}

export default async function setup(project: ProvideTarget): Promise<() => Promise<void>> {
  const cluster = await startCluster();
  project.provide('ossrTestPgCluster', cluster.info);
  return async () => {
    await cluster.stop();
  };
}
