import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    environment: 'node',
    // REQ-004 AC-G-2 / D-75 (ADR-006 test strategy): REGISTRY_ENRICHMENT=off and no non-loopback network.
    setupFiles: ['tests/setup/networkGuard.ts'],
    passWithNoTests: true,
  },
});
