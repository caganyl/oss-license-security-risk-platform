/**
 * Time budget and per-scan download quota of registry enrichment (REQ-004
 * AC-P14-14, AC-P15-5; ADR-006 Karar 2, 6).
 *
 *   budgetMs = min(timeoutMs / 2, remainingMs - timeoutMs / 4)
 *
 * The second term leaves at least a quarter of the scan time limit for the
 * result write, so enrichment never pushes the scan past its own limit.
 */

/** Enrichment budget of a scan whose limit is `timeoutMs` and which has `remainingMs` left. */
export function computeBudgetMs(timeoutMs: number, remainingMs: number): number {
  return Math.min(timeoutMs / 2, remainingMs - timeoutMs / 4);
}

/** Abort reason of the budget signal (distinguishes it from a job abort in logs). */
export class EnrichmentBudgetExceeded extends Error {
  constructor() {
    super('Kayıt defteri zenginleştirme bütçesi doldu.');
    this.name = 'EnrichmentBudgetExceeded';
  }
}

/** Signal that aborts after `budgetMs` (already aborted when `budgetMs <= 0`). */
export function createBudgetSignal(budgetMs: number): AbortSignal {
  if (!(budgetMs > 0)) return AbortSignal.abort(new EnrichmentBudgetExceeded());
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new EnrichmentBudgetExceeded()), Math.ceil(budgetMs));
  timer.unref?.();
  return controller.signal;
}

/** Per-scan archive download quota (2 GiB): reserve before, settle to the real size after. */
export class DownloadQuota {
  private used = 0;

  constructor(private readonly limitBytes: number) {}

  /** Reserves `bytes`; false when the quota would be exceeded. */
  reserve(bytes: number): boolean {
    if (this.used + bytes > this.limitBytes) return false;
    this.used += bytes;
    return true;
  }

  /** Replaces a reservation with the bytes actually downloaded. */
  settle(reserved: number, actual: number): void {
    this.used = Math.max(0, this.used - reserved + actual);
  }
}
