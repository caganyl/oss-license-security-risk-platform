/**
 * Hand-written argument parser (REQ-007 contract section 2.2, ADR-009 Karar 1).
 *
 * Order of checks: `--api-key`/`--key`/`--token` (any form, anywhere) first,
 * then `--help`/`-h`, then `--version`/`-V`, then the command grammar. No
 * network, file or environment access happens here. Option values are never
 * copied into messages; only option names (sanitized) may appear.
 */
import { UsageError } from './exitCodes';
import { cleanText } from './output';

export type FailOn = 'none' | 'low' | 'medium' | 'high' | 'critical';
export type Format = 'text' | 'json';
export type CommandName = 'scan' | 'bootstrap';

export interface ScanArgs {
  kind: 'scan';
  project: string;
  url: string | null;
  failOn: FailOn;
  format: Format;
  timeoutSeconds: number;
  allowIncomplete: boolean;
}

export interface BootstrapArgs {
  kind: 'bootstrap';
  keyFile: string;
  url: string | null;
  projectName: string | null;
  projectPath: string | null;
}

export type ParsedArgs =
  | { kind: 'help'; command: CommandName | null }
  | { kind: 'version' }
  | ScanArgs
  | BootstrapArgs;

export const API_KEY_ARGUMENT_MESSAGE = 'API key must be provided via OSS_RISK_API_KEY or OSS_RISK_API_KEY_FILE';

const REJECTED_KEY_OPTIONS: readonly string[] = ['--api-key', '--key', '--token'];
const FAIL_ON_VALUES: readonly FailOn[] = ['none', 'low', 'medium', 'high', 'critical'];
const FORMAT_VALUES: readonly Format[] = ['text', 'json'];

/** Option table per command: `true` = flag (takes no value). */
const OPTION_TABLE: Readonly<Record<CommandName, Readonly<Record<string, boolean>>>> = {
  scan: { url: false, project: false, 'fail-on': false, format: false, timeout: false, 'allow-incomplete': true },
  bootstrap: { url: false, 'new-database': true, 'key-file': false, 'project-name': false, 'project-path': false },
};

const DEFAULT_TIMEOUT_SECONDS = 1800;
const MIN_TIMEOUT_SECONDS = 10;
const MAX_TIMEOUT_SECONDS = 86_400;

function isRejectedKeyArgument(arg: string): boolean {
  return REJECTED_KEY_OPTIONS.some((opt) => arg === opt || arg.startsWith(`${opt}=`));
}

function isCommand(value: string | undefined): value is CommandName {
  return value === 'scan' || value === 'bootstrap';
}

function optionLabel(name: string): string {
  return `--${cleanText(name, 64)}`;
}

/** Parses `argv` (without the node executable and script path). Throws `UsageError`. */
export function parseArgs(argv: readonly string[]): ParsedArgs {
  const first = argv[0];
  const knownCommand: CommandName | null = isCommand(first) ? first : null;

  // 1. API key on the command line: rejected before anything else; text output.
  if (argv.some(isRejectedKeyArgument)) {
    throw new UsageError('api_key_argument_rejected', API_KEY_ARGUMENT_MESSAGE, knownCommand);
  }
  // 2. Help wins over version and over every other usage problem.
  if (argv.some((a) => a === '--help' || a === '-h')) return { kind: 'help', command: knownCommand };
  // 3. Version.
  if (argv.some((a) => a === '--version' || a === '-V')) return { kind: 'version' };

  if (first === undefined) throw new UsageError('usage_error', 'missing command', null);
  if (knownCommand === null) {
    throw new UsageError('usage_error', first.startsWith('-') ? 'missing command' : 'unknown command', null);
  }

  const command = knownCommand;
  const table = OPTION_TABLE[command];
  const values = new Map<string, string | true>();
  let format: Format = 'text';
  let failOn: FailOn | null = null;
  // Explicitly typed so that calls narrow control flow (TS assertion rule).
  const fail: (code: string, message: string) => never = (code, message) => {
    throw new UsageError(code, message, command, format, failOn);
  };

  for (let i = 1; i < argv.length; i++) {
    const token = argv[i];
    if (token === '--') fail('usage_error', "'--' is not supported");
    if (!token.startsWith('--')) {
      fail('usage_error', token.startsWith('-') ? 'unknown option' : 'unexpected argument');
    }
    const eq = token.indexOf('=');
    const name = eq === -1 ? token.slice(2) : token.slice(2, eq);
    const inline = eq === -1 ? null : token.slice(eq + 1);
    if (!(name in table)) {
      const other: CommandName = command === 'scan' ? 'bootstrap' : 'scan';
      if (name in OPTION_TABLE[other]) fail('usage_error', `option ${optionLabel(name)} is not valid for ${command}`);
      fail('usage_error', `unknown option ${optionLabel(name)}`);
    }
    if (values.has(name)) fail('usage_error', `option ${optionLabel(name)} is repeated`);
    let value: string | true;
    if (table[name]) {
      if (inline !== null) fail('usage_error', `option ${optionLabel(name)} takes no value`);
      value = true;
    } else if (inline !== null) {
      if (inline.length === 0) fail('usage_error', `option ${optionLabel(name)} requires a value`);
      value = inline;
    } else {
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('-')) fail('usage_error', `option ${optionLabel(name)} requires a value`);
      value = next;
      i++;
    }
    values.set(name, value);

    // Validated as soon as seen so that a later error can still be reported as JSON.
    if (name === 'format') {
      if (!FORMAT_VALUES.includes(value as Format)) fail('usage_error', 'invalid value for --format (text, json)');
      format = value as Format;
    } else if (name === 'fail-on') {
      if (!FAIL_ON_VALUES.includes(value as FailOn)) {
        fail('usage_error', 'invalid value for --fail-on (none, low, medium, high, critical)');
      }
      failOn = value as FailOn;
    }
  }

  const str = (name: string): string | null => {
    const v = values.get(name);
    return typeof v === 'string' ? v : null;
  };

  if (command === 'scan') {
    let timeoutSeconds = DEFAULT_TIMEOUT_SECONDS;
    const rawTimeout = str('timeout');
    if (rawTimeout !== null) {
      const n = /^[0-9]+$/.test(rawTimeout) ? Number(rawTimeout) : NaN;
      if (!(n >= MIN_TIMEOUT_SECONDS && n <= MAX_TIMEOUT_SECONDS)) {
        fail('usage_error', `invalid value for --timeout (${MIN_TIMEOUT_SECONDS}-${MAX_TIMEOUT_SECONDS} seconds)`);
      }
      timeoutSeconds = n;
    }
    const project = str('project');
    if (project === null) fail('usage_error', 'missing required option --project');
    return {
      kind: 'scan',
      project: project as string,
      url: str('url'),
      failOn: failOn ?? 'high',
      format,
      timeoutSeconds,
      allowIncomplete: values.get('allow-incomplete') === true,
    };
  }

  if (values.get('new-database') !== true) {
    fail(
      'new_database_required',
      'bootstrap requires --new-database: it sets an unknown admin password and is meant only for a new, temporary database',
    );
  }
  const keyFile = str('key-file');
  if (keyFile === null) fail('usage_error', 'missing required option --key-file');
  const projectName = str('project-name');
  const projectPath = str('project-path');
  if ((projectName === null) !== (projectPath === null)) {
    fail('usage_error', '--project-name and --project-path must be given together');
  }
  return { kind: 'bootstrap', keyFile: keyFile as string, url: str('url'), projectName, projectPath };
}

export const GENERAL_HELP = `Usage: oss-risk <command> [options]

Commands:
  scan        Start a scan of an existing project, wait for it and evaluate --fail-on
  bootstrap   Initialise a NEW, temporary server database and write an API key file

Global options:
  -h, --help     Show help (oss-risk <command> --help for command options)
  -V, --version  Show the CLI version

The API key is read only from OSS_RISK_API_KEY or OSS_RISK_API_KEY_FILE.
Exit codes: 0 pass, 1 threshold breached, 2 usage/configuration, 3 scan or
network error, 4 authentication/authorisation, 5 incomplete vulnerability data.
`;

export const SCAN_HELP = `Usage: oss-risk scan --project <id|name> [options]

Options:
  --project <id|name>       Project UUID or exact project name (required)
  --url <address>           Server address (default: OSS_RISK_URL or http://127.0.0.1:3001)
  --fail-on <level>         none | low | medium | high | critical (default: high)
  --format <format>         text | json (default: text)
  --timeout <seconds>       Wait budget for the scan, 10-86400 (default: 1800)
  --allow-incomplete        Incomplete vulnerability data does not change the exit code
  -h, --help                Show this help

Environment (exactly one is required):
  OSS_RISK_API_KEY          API key value
  OSS_RISK_API_KEY_FILE     Path to a file containing the API key (max 1 KiB)
  OSS_RISK_URL              Server address (optional)
`;

export const BOOTSTRAP_HELP = `Usage: oss-risk bootstrap --new-database --key-file <path> [options]

Initialises a NEW, EMPTY, TEMPORARY server database (for CI): sets an unknown
random admin password, creates an API key and writes it to --key-file. Never
run it against a database that holds real data.

Options:
  --new-database            Required confirmation that the database is new and temporary
  --key-file <path>         File to create for the API key (must not exist)
  --url <address>           Loopback server address (default: OSS_RISK_URL or http://127.0.0.1:3001)
  --project-name <name>     Also create a project (together with --project-path)
  --project-path <folder>   Local folder of the project (together with --project-name)
  -h, --help                Show this help
`;
