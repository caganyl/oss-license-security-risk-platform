#!/usr/bin/env node
/**
 * `oss-risk` executable (REQ-007 contract 2.1, ADR-009 Karar 1). Wires the
 * real dependencies and sets `process.exitCode`; `process.exit()` is never
 * called so piped stdout is not cut off (Windows).
 */
import { randomBytes } from 'node:crypto';
import { promises as fsp, readFileSync } from 'node:fs';
import * as path from 'node:path';
import { nodeRequest } from './client';
import { KeyFileTooLargeError } from './config';
import { main, type CliDeps, type KeyFileHandle } from './main';

/** `version` of package.json, read at run time (`dist/cli` and `src/cli` both resolve to the repo root). */
function readVersion(): string {
  try {
    const pkg = JSON.parse(readFileSync(path.join(__dirname, '..', '..', 'package.json'), 'utf8')) as { version?: unknown };
    return typeof pkg.version === 'string' ? pkg.version : 'unknown';
  } catch {
    return 'unknown';
  }
}

async function readKeyFile(file: string, maxBytes: number): Promise<Buffer> {
  const fh = await fsp.open(file, 'r');
  try {
    const { size } = await fh.stat();
    if (size > maxBytes) throw new KeyFileTooLargeError();
    const buf = Buffer.alloc(maxBytes + 1);
    const { bytesRead } = await fh.read(buf, 0, maxBytes + 1, 0);
    if (bytesRead > maxBytes) throw new KeyFileTooLargeError();
    return buf.subarray(0, bytesRead);
  } finally {
    await fh.close();
  }
}

async function openExclusive(file: string): Promise<KeyFileHandle> {
  const fh = await fsp.open(file, 'wx', 0o600);
  return {
    mode: async () => (await fh.stat()).mode,
    writeAll: async (text: string) => {
      await fh.writeFile(text, 'utf8');
    },
    sync: () => fh.sync(),
    close: () => fh.close(),
  };
}

function realDeps(): CliDeps {
  return {
    argv: process.argv.slice(2),
    env: process.env,
    stdout: process.stdout,
    stderr: process.stderr,
    version: readVersion(),
    platform: process.platform,
    now: () => Date.now(),
    sleep: (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)),
    readKeyFile,
    openExclusive,
    unlink: (file: string) => fsp.unlink(file),
    resolvePath: (p: string) => path.resolve(p),
    randomBytes: (size: number) => randomBytes(size),
    request: nodeRequest,
  };
}

main(realDeps()).then(
  (code) => {
    process.exitCode = code;
  },
  () => {
    process.stderr.write('oss-risk: error: unexpected internal error\n');
    process.exitCode = 3;
  },
);
