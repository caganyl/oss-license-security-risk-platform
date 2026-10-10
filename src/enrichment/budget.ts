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

/**
 * Process-wide budget of archive bytes held in memory at once (REQ-004
 * security review L-4). The per-scan `DownloadQuota` bounds bytes over time;
 * this bounds the bytes alive at the same moment across all scans, so memory
 * stays ≈ `limitBytes` regardless of scan count × registry concurrency.
 *
 * Semantics (conservative choice, documented per L-4): a download that does
 * not fit WAITS in FIFO order until earlier downloads release their bytes; it
 * is not failed. Failing soft (`download_failed`) would make NOTICE results
 * depend on timing between unrelated scans, while waiting keeps them
 * deterministic and is still bounded: the wait aborts with the enrichment
 * signal (time budget or job abort), which the enricher already classifies
 * as `budget_exceeded`/abort exactly like a slow download (ADR-006 Karar 2).
 * One request never exceeds `limitBytes` (it is clamped), so a lone request
 * always proceeds and the queue cannot deadlock.
 */
export class InFlightByteBudget {
  private used = 0;
  private readonly waiters: Array<{ bytes: number; grant: () => void }> = [];

  constructor(readonly limitBytes: number) {}

  /** Bytes currently held (for diagnostics and tests). */
  get inUse(): number {
    return this.used;
  }

  /**
   * Waits until `bytes` fit and holds them; resolves to an idempotent release
   * function. Rejects with the signal's reason when `signal` aborts first.
   */
  acquire(bytes: number, signal?: AbortSignal): Promise<() => void> {
    const amount = Math.min(Math.max(0, Math.ceil(bytes)), this.limitBytes);
    signal?.throwIfAborted();
    if (this.waiters.length === 0 && this.used + amount <= this.limitBytes) {
      this.used += amount;
      return Promise.resolve(this.releaser(amount));
    }
    return new Promise((resolve, reject) => {
      const waiter = {
        bytes: amount,
        grant: () => {
          signal?.removeEventListener('abort', onAbort);
          resolve(this.releaser(amount));
        },
      };
      const onAbort = (): void => {
        const index = this.waiters.indexOf(waiter);
        if (index !== -1) this.waiters.splice(index, 1);
        reject(signal?.reason);
        this.drain();
      };
      signal?.addEventListener('abort', onAbort, { once: true });
      this.waiters.push(waiter);
    });
  }

  /**
   * Accounts `bytes` more for an already granted holder without waiting (a
   * download larger than its declared size, at most the per-archive cap).
   * Returns its idempotent release function.
   */
  grow(bytes: number): () => void {
    const amount = Math.max(0, Math.ceil(bytes));
    this.used += amount;
    return this.releaser(amount);
  }

  private releaser(amount: number): () => void {
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.used = Math.max(0, this.used - amount);
      this.drain();
    };
  }

  /** Grants waiting requests in FIFO order while they fit. */
  private drain(): void {
    while (this.waiters.length > 0 && this.used + this.waiters[0].bytes <= this.limitBytes) {
      const next = this.waiters.shift()!;
      this.used += next.bytes;
      next.grant();
    }
  }
}

let processBudget: InFlightByteBudget | null = null;

/** The process-wide archive byte budget (created on first use). */
export function processInFlightBudget(limitBytes: number): InFlightByteBudget {
  if (processBudget === null) processBudget = new InFlightByteBudget(limitBytes);
  return processBudget;
}
