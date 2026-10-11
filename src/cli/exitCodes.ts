/**
 * Exit codes and the CLI error type (REQ-007 contract section 5.1, ADR-009
 * Karar 1). Every failure inside the CLI is a `CliError`: a CLI-specific code
 * (contract 5.6 catalogue, plus the bootstrap-only codes), the exit code and
 * a message that is already safe to print (no key, password, cookie, header
 * or request object).
 */

export const EXIT_PASS = 0;
export const EXIT_FAIL = 1;
export const EXIT_USAGE = 2;
export const EXIT_RUNTIME = 3;
export const EXIT_AUTH = 4;
export const EXIT_INCOMPLETE = 5;

export type ExitCode = 0 | 1 | 2 | 3 | 4 | 5;

export class CliError extends Error {
  constructor(
    readonly code: string,
    readonly exitCode: ExitCode,
    message: string,
  ) {
    super(message);
    this.name = 'CliError';
  }
}

/**
 * Usage error (exit 2) raised by the argument parser. Carries what had been
 * parsed when it happened: `--format json` switches the error output to JSON
 * only if it was parsed before the error (contract 2.2, 5.6).
 */
export class UsageError extends CliError {
  constructor(
    code: string,
    message: string,
    /** Command for the `(see: oss-risk <command> --help)` hint; null → general help. */
    readonly command: 'scan' | 'bootstrap' | null,
    readonly format: 'text' | 'json' = 'text',
    readonly failOn: string | null = null,
  ) {
    super(code, EXIT_USAGE, message);
    this.name = 'UsageError';
  }
}
