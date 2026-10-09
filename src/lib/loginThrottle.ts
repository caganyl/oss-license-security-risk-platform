/**
 * In-memory brute-force slowdown for the single local login (ADR-001 karar 11).
 *
 * After 5 consecutive failures every attempt is refused for 30 s; each further
 * failure after a lock doubles the wait (cap 900 s). A successful login resets
 * the counter. State lives in the instance, so every createApp() gets its own
 * counter and a restart clears it (accepted by the ADR).
 */
export class LoginThrottle {
  private failures = 0;
  private lockedUntil = 0;

  constructor(
    private readonly maxFailures = 5,
    private readonly baseDelaySeconds = 30,
    private readonly maxDelaySeconds = 900,
    private readonly now: () => number = Date.now,
  ) {}

  /** Seconds to wait before the next attempt, or 0 when attempts are allowed. */
  retryAfterSeconds(): number {
    const remaining = this.lockedUntil - this.now();
    return remaining > 0 ? Math.ceil(remaining / 1000) : 0;
  }

  recordFailure(): void {
    this.failures += 1;
    if (this.failures >= this.maxFailures) {
      const exponent = this.failures - this.maxFailures;
      const delay = Math.min(this.baseDelaySeconds * 2 ** exponent, this.maxDelaySeconds);
      this.lockedUntil = this.now() + delay * 1000;
    }
  }

  reset(): void {
    this.failures = 0;
    this.lockedUntil = 0;
  }
}
