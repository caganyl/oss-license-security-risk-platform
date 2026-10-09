import fs from 'node:fs';
import path from 'node:path';

export interface ExpandedScript {
  /** Plain SQL, runnable through node-postgres (simple query protocol). */
  sql: string;
  /** Text of the dropped \echo lines, in order. */
  echoes: string[];
  /** Files inlined through \ir, in order (absolute paths). */
  included: string[];
}

/**
 * Turns a psql script into plain SQL so it can run without psql (the embedded
 * PostgreSQL used by the tests ships no psql binary):
 *   \ir <file>  -> file content inlined (path relative to the including file)
 *   \set ...    -> dropped (ON_ERROR_STOP is implicit: pg rejects on error)
 *   \echo ...   -> dropped, text returned in `echoes`
 * Any other meta-command is rejected so the conversion never silently changes
 * the meaning of a script.
 */
export function expandPsqlScript(file: string, depth = 0): ExpandedScript {
  if (depth > 10) throw new Error(`\\ir nesting too deep at ${file}`);
  const out: string[] = [];
  const echoes: string[] = [];
  const included: string[] = [];
  const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);

  for (const line of lines) {
    const trimmed = line.trimStart();
    if (!trimmed.startsWith('\\')) {
      out.push(line);
      continue;
    }
    const include = /^\\ir\s+(\S+)\s*$/.exec(trimmed);
    if (include) {
      const target = path.resolve(path.dirname(file), include[1]);
      const nested = expandPsqlScript(target, depth + 1);
      included.push(target, ...nested.included);
      echoes.push(...nested.echoes);
      out.push(`-- >>> \\ir ${include[1]}`, nested.sql, `-- <<< \\ir ${include[1]}`);
      continue;
    }
    if (/^\\set\b/.test(trimmed)) continue;
    const echo = /^\\echo\s+(.*)$/.exec(trimmed);
    if (echo) {
      echoes.push(echo[1].replace(/^'(.*)'$/, '$1'));
      continue;
    }
    throw new Error(`unsupported psql meta-command in ${file}: ${trimmed.split(/\s/)[0]}`);
  }
  return { sql: out.join('\n'), echoes, included };
}
