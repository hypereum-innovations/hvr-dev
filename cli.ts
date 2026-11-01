#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * `hvr-dev` CLI — Starts a standalone local in-memory SCITT Transparency Service
 * with a 3-of-5 dev witness quorum and `/dev/tamper` playground helper.
 */
import { pathToFileURL } from 'node:url';
import { startHvrDevServer } from './index.js';

function getArg(argv: string[], flagName: string): string | undefined {
  const idx = argv.indexOf(`--${flagName}`);
  return idx >= 0 ? argv[idx + 1] : undefined;
}

export async function runHvrDevCli(argv: string[] = process.argv.slice(2)): Promise<void> {
  const port = Number(getArg(argv, 'port') ?? process.env.HVR_DEV_PORT ?? 8788);
  const host = getArg(argv, 'host') ?? process.env.HVR_DEV_HOST ?? '127.0.0.1';
  const origin = getArg(argv, 'origin') ?? process.env.HVR_DEV_ORIGIN ?? 'hvr-dev.local/log/v1';

  const started = await startHvrDevServer({ port, host, origin });
  console.log(`hvr-dev listening on ${started.url} (origin: ${started.service.origin})`);
  console.log(`  Discovery:  ${started.url}/.well-known/transparency-configuration`);
  console.log(`  Entries:    POST ${started.url}/entries`);
  console.log(`  Checkpoint: GET  ${started.url}/checkpoint`);
  console.log(`  Tamper:     POST ${started.url}/dev/tamper`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  void runHvrDevCli().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
