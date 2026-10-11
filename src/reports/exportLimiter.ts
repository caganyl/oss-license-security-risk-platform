/**
 * Process-wide cap on synchronous PDF/XLSX/CSV export generation (REQ-007
 * AC-P24-7, D-185; ADR-009 Karar 7).
 *
 * pdfkit/exceljs rendering blocks the event loop and cannot be interrupted,
 * so an API-key loop could otherwise pin the server. State lives in the
 * instance (`LoginThrottle` precedent): every `createApp()` gets its own
 * limiter and tests do not affect each other. NOTICE is outside the cap.
 */

/** Maximum concurrent exports across the three export endpoints (contract 6.6). */
export const EXPORT_CONCURRENCY_LIMIT = 2;

/** `Retry-After` value of the `429 export_busy` answer, in seconds (contract 6.5). */
export const EXPORT_RETRY_AFTER_SECONDS = 5;

export class ExportLimiter {
  private active = 0;

  constructor(private readonly max: number = EXPORT_CONCURRENCY_LIMIT) {}

  /**
   * Takes a slot. Returns its release function, or `null` when every slot is
   * in use. Release is idempotent so a `finally` block can always call it.
   */
  tryAcquire(): (() => void) | null {
    if (this.active >= this.max) return null;
    this.active += 1;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.active -= 1;
    };
  }

  /** Slots currently held (diagnostics and tests). */
  get inUse(): number {
    return this.active;
  }
}
