/**
 * CLI entry logic (REQ-007 contract section 2, ADR-009 Karar 1).
 *
 * `main(deps)` returns the exit code; every side effect (environment,
 * stdout/stderr, clock, sleep, file system, randomness, HTTP) comes from
 * `deps`, so tests run without real waits or network. Import boundary:
 * Node built-ins, `src/cli/**` and `src/lib/outputText.ts` only.
 */
import { BOOTSTRAP_HELP, GENERAL_HELP, parseArgs, SCAN_HELP, type ParsedArgs } from './args';
import type { RequestFn } from './client';
import type { Env, ReadKeyFile } from './config';
import { runBootstrap } from './commands/bootstrap';
import { runScan } from './commands/scan';
import { EXIT_PASS, EXIT_RUNTIME, UsageError } from './exitCodes';
import { cleanText, formatJson, Output, usageErrorLine, type Writer } from './output';

/** Reserved key file (bootstrap); opened with `wx` and 0600. */
export interface KeyFileHandle {
  /** `st_mode` of the open file (POSIX permission check). */
  mode(): Promise<number>;
  writeAll(text: string): Promise<void>;
  sync(): Promise<void>;
  close(): Promise<void>;
}

export interface CliDeps {
  /** Arguments after the node executable and the script path. */
  argv: readonly string[];
  env: Env;
  stdout: Writer;
  stderr: Writer;
  /** CLI version (read from package.json at run time by the real deps). */
  version: string;
  platform: string;
  now(): number;
  sleep(ms: number): Promise<void>;
  readKeyFile: ReadKeyFile;
  /** Creates the file exclusively (`wx`, 0600); rejects with `code: 'EEXIST'` if it exists. */
  openExclusive(path: string): Promise<KeyFileHandle>;
  unlink(path: string): Promise<void>;
  resolvePath(path: string): string;
  randomBytes(size: number): Buffer;
  request: RequestFn;
}

function helpText(parsed: Extract<ParsedArgs, { kind: 'help' }>): string {
  if (parsed.command === 'scan') return SCAN_HELP;
  if (parsed.command === 'bootstrap') return BOOTSTRAP_HELP;
  return GENERAL_HELP;
}

export async function main(deps: CliDeps): Promise<number> {
  const out = new Output(deps.stdout, deps.stderr);
  let parsed: ParsedArgs;
  try {
    parsed = parseArgs(deps.argv);
  } catch (err) {
    if (!(err instanceof UsageError)) throw err;
    if (err.format === 'json') {
      const failOn = err.failOn as 'none' | 'low' | 'medium' | 'high' | 'critical' | null;
      out.out(
        formatJson({
          result: 'error',
          exitCode: err.exitCode,
          project: null,
          scan: null,
          failOn,
          vulnerabilityDataStatus: null,
          counts: null,
          breaching: [],
          warnings: [],
          error: { code: err.code, message: cleanText(err.message, 600) },
        }),
      );
    } else {
      out.err(usageErrorLine(err.message, err.command));
    }
    return err.exitCode;
  }

  if (parsed.kind === 'help') {
    deps.stdout.write(helpText(parsed));
    return EXIT_PASS;
  }
  if (parsed.kind === 'version') {
    deps.stdout.write(`${deps.version}\n`);
    return EXIT_PASS;
  }
  try {
    return parsed.kind === 'scan' ? await runScan(parsed, deps, out) : await runBootstrap(parsed, deps, out);
  } catch {
    // Unexpected programming error: the error object is not printed (it may
    // reference request data); exit 3.
    out.err('oss-risk: error: unexpected internal error');
    return EXIT_RUNTIME;
  }
}
