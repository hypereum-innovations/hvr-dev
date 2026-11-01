// SPDX-License-Identifier: Apache-2.0
/**
 * @hypereum/hvr-dev — Local in-memory SCITT Transparency Service for
 * zero-dependency developer testing (no network, no tenancy, no Postgres, no TEE).
 *
 * Endpoints:
 *  - POST /entries
 *  - GET  /entries/:id
 *  - GET  /entries/:id/receipt
 *  - GET  /checkpoint
 *  - GET  /.well-known/transparency-configuration
 *  - POST /dev/tamper
 *  - GET  /health
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { randomBytes } from 'node:crypto';
import {
  attachReceipts,
  CONTENT_TYPE_CAPSULE,
  CONTENT_TYPE_SCITT_RECEIPT,
  coseSign1,
  issueReceipt,
  MEDIA_TYPE_SCITT_STATEMENT,
  parseSign1,
  statementLeafBytes,
} from './core/cose.js';
import { cborEncode } from './core/cbor.js';
import { buildCapsule, type VerdictClass } from './core/capsule.js';
import { cosignCheckpoint, signCheckpoint } from './core/checkpoint.js';
import { LocalSigner, type ReceiptSigner } from './core/keys.js';
import { inclusionProof, leafHash, mth, tileHash } from './core/merkle.js';
import { encodeEntryBundle, normalizeTileName, TILE_WIDTH } from './core/tile-helpers.js';
import { createProductionTrustRoots, type TrustFileShape } from './core/trust.js';
import { verifyReceiptBundle, type TrustRoots, type VerifyReport } from './core/verify.js';

export const MEDIA_TYPE_HVR = 'application/vnd.hivemind.receipt+cose';

export interface DevEntryRecord {
  id: string;
  index: number;
  statementBytes: Buffer;
  leafDigest: Buffer;
  registeredAt: number;
}

export interface HvrDevOptions {
  origin?: string;
  port?: number;
  host?: string;
}

export interface TamperResult {
  tampered: Buffer;
  flippedOffset: number;
  originalByte: number;
  tamperedByte: number;
  verifyReport: VerifyReport;
}

export class HvrDevService {
  readonly origin: string;
  readonly logSigner: ReceiptSigner;
  readonly defaultIssuer: ReceiptSigner;
  readonly witnesses: Array<{ name: string; signer: ReceiptSigner }>;
  private readonly entries: DevEntryRecord[] = [];
  private readonly leaves: Buffer[] = [];
  private readonly dynamicIssuers = new Map<string, { signer?: ReceiptSigner; tier: 'T0' | 'T1' | 'T2' | 'T3'; display: string }>();
  private currentCheckpoint = '';

  constructor(opts: HvrDevOptions = {}) {
    this.origin = opts.origin ?? 'hvr-dev.local/log/v1';
    this.logSigner = LocalSigner.generate('Ed25519');
    this.defaultIssuer = LocalSigner.generate('ES256');
    this.witnesses = [1, 2, 3, 4, 5].map((n) => ({
      name: `w${n}.hvr-dev.local`,
      signer: LocalSigner.generate('Ed25519'),
    }));
    this.dynamicIssuers.set(this.defaultIssuer.kid, {
      signer: this.defaultIssuer,
      tier: 'T1',
      display: 'dev.local',
    });
  }

  /** Register an external issuer signer for local verification in hvr-dev. */
  registerDevIssuer(signer: ReceiptSigner, tier: 'T0' | 'T1' | 'T2' | 'T3' = 'T1', display = 'dev.local'): void {
    this.dynamicIssuers.set(signer.kid, { signer, tier, display });
  }

  /** Return TrustRoots and serialized TrustFileShape for offline verifiers. */
  getTrust(): { trustRoots: TrustRoots; trustFile: TrustFileShape } {
    const issuers = [...this.dynamicIssuers.values()]
      .filter((i): i is { signer: ReceiptSigner; tier: 'T0' | 'T1' | 'T2' | 'T3'; display: string } => Boolean(i.signer));
    return createProductionTrustRoots({
      issuers,
      logSigner: this.logSigner,
      logName: this.origin,
      witnesses: this.witnesses,
      quorum: 3,
    });
  }

  private async rebuildCheckpoint(): Promise<string> {
    const root = mth(this.leaves);
    const now = Math.floor(Date.now() / 1000);
    let cp = await signCheckpoint(this.origin, this.leaves.length, root, this.logSigner, this.origin);
    for (const w of this.witnesses) {
      cp = await cosignCheckpoint(cp, w.signer, w.name, now);
    }
    this.currentCheckpoint = cp;
    return cp;
  }

  /** Return current cosigned checkpoint (initializing an empty-tree checkpoint if needed). */
  async getCheckpoint(): Promise<string> {
    if (!this.currentCheckpoint) {
      await this.rebuildCheckpoint();
    }
    return this.currentCheckpoint;
  }

  /** Append a signed COSE_Sign1 statement to the in-memory Merkle log and return an anchored .hvr receipt bundle. */
  async registerStatement(rawStatement: Uint8Array): Promise<{
    entryId: string;
    index: number;
    treeSize: number;
    receipt: Buffer;
    transparentStatement: Buffer;
    checkpoint: string;
  }> {
    const parsed = parseSign1(rawStatement);
    const cleanStatement = statementLeafBytes(rawStatement);
    const leaf = leafHash(cleanStatement);
    const index = this.entries.length;
    const entryId = String(index);

    this.leaves.push(leaf);
    this.entries.push({
      id: entryId,
      index,
      statementBytes: cleanStatement,
      leafDigest: leaf,
      registeredAt: Math.floor(Date.now() / 1000),
    });

    const checkpoint = await this.rebuildCheckpoint();
    const root = mth(this.leaves);
    const proof = inclusionProof(index, this.leaves);
    const receipt = await issueReceipt(this.logSigner, cleanStatement, proof, root, {
      issuerOrigin: this.origin,
      iat: Math.floor(Date.now() / 1000),
    });
    const transparentStatement = attachReceipts(cleanStatement, [receipt]);
    void parsed;

    return {
      entryId,
      index,
      treeSize: this.leaves.length,
      receipt,
      transparentStatement,
      checkpoint,
    };
  }

  /** Convenience helper for local playground: build, sign, and register a synthetic capsule. */
  async issueAndRegisterDevCapsule(opts: {
    actionId?: string;
    subject?: string;
    method?: string;
    target?: string;
    verdictClass?: VerdictClass;
    request?: unknown;
    response?: unknown;
  } = {}): Promise<{
    entryId: string;
    index: number;
    treeSize: number;
    receipt: Buffer;
    transparentStatement: Buffer;
    checkpoint: string;
    trustFile: TrustFileShape;
  }> {
    const verdict = opts.verdictClass ?? 'executed';
    const built = buildCapsule({
      actionId: opts.actionId ?? '01JDEV00000000000000000001',
      agent: { spiffe_id: 'spiffe://dev.local/agent/playground' },
      principalSubject: opts.subject ?? 'user:dev@local',
      operation: {
        kind: 'mcp',
        method: opts.method ?? 'tools/call:filesystem.write',
        target: opts.target ?? '/tmp/demo.txt',
        risk_tier: 'write',
      },
      requestArgs: opts.request ?? { path: '/tmp/demo.txt' },
      verdict,
      ...(verdict === 'executed'
        ? {
            observedResponse: opts.response ?? { status: 200, written: true },
            effectSummary: 'dev playground execution',
          }
        : {}),
      disposition: { authority: 'cedar:dev.local' },
      ledgerMode: 'anchored',
      attestationMode: 'none',
      disclosurePolicyId: 'hash-only',
      salt: randomBytes(32),
      issuedAt: new Date().toISOString(),
    });
    const payload = cborEncode(built.capsule);
    const signed = await coseSign1(this.defaultIssuer, payload, {
      contentType: CONTENT_TYPE_CAPSULE,
      cwt: {
        iss: 'https://dev.local',
        sub: 'spiffe://dev.local/agent/playground',
        iat: Math.floor(Date.now() / 1000),
      },
    });
    const reg = await this.registerStatement(signed);
    return {
      ...reg,
      trustFile: this.getTrust().trustFile,
    };
  }

  /** Lookup an entry by numeric index or string id. */
  getEntry(id: string): DevEntryRecord | null {
    const idx = Number(id);
    if (!Number.isSafeInteger(idx) || idx < 0 || idx >= this.entries.length) {
      return null;
    }
    return this.entries[idx] ?? null;
  }

  /** Issue a fresh inclusion receipt against the current tree root for entry `id`. */
  async getFreshReceipt(id: string): Promise<{ receipt: Buffer; transparentStatement: Buffer; treeSize: number } | null> {
    const entry = this.getEntry(id);
    if (!entry) return null;
    const root = mth(this.leaves);
    const proof = inclusionProof(entry.index, this.leaves);
    const receipt = await issueReceipt(this.logSigner, entry.statementBytes, proof, root, {
      issuerOrigin: this.origin,
      iat: entry.registeredAt,
    });
    const transparentStatement = attachReceipts(entry.statementBytes, [receipt]);
    return { receipt, transparentStatement, treeSize: this.leaves.length };
  }

  /**
   * Serve C2SP tlog-tiles (`tile/<level>/<path>[.p/<w>]` and `tile/entries/<path>[.p/<w>]`)
   * as well as `sumdb/tlog` height-prefixed tile paths (`tile/8/<level>/<path>[.p/<w>]`
   * and `tile/8/data/<path>[.p/<w>]`).
   */
  getTile(rawName: string): Buffer | null {
    const normalized = normalizeTileName(rawName);
    if (!normalized.startsWith('tile/')) return null;
    const rest = normalized.slice('tile/'.length);

    const parseCoordAndWidth = (coordStr: string): { tileIndex: number; width: number } | null => {
      let coordPart = coordStr;
      let width = TILE_WIDTH;
      const partialIdx = coordStr.indexOf('.p/');
      if (partialIdx >= 0) {
        coordPart = coordStr.slice(0, partialIdx);
        const wStr = coordStr.slice(partialIdx + 3);
        if (!/^\d+$/.test(wStr)) return null;
        width = Number(wStr);
        if (!Number.isSafeInteger(width) || width < 1 || width >= TILE_WIDTH) return null;
      }
      const groups = coordPart.split('/');
      if (groups.length === 0) return null;
      let tileIndex = 0;
      for (let i = 0; i < groups.length; i++) {
        const g = groups[i]!;
        const isLast = i === groups.length - 1;
        if (isLast) {
          if (!/^\d{3}$/.test(g)) return null;
          tileIndex = tileIndex * 1000 + Number(g);
        } else {
          if (!/^x\d{3}$/.test(g)) return null;
          tileIndex = tileIndex * 1000 + Number(g.slice(1));
        }
      }
      return { tileIndex, width };
    };

    if (rest.startsWith('entries/')) {
      const parsed = parseCoordAndWidth(rest.slice('entries/'.length));
      if (!parsed) return null;
      const start = parsed.tileIndex * TILE_WIDTH;
      const end = start + parsed.width;
      if (end > this.entries.length) return null;
      const slice = this.entries.slice(start, end);
      return encodeEntryBundle(
        slice.map((e) => ({ atSeconds: e.registeredAt, statement: e.statementBytes })),
      );
    }

    const slashIdx = rest.indexOf('/');
    if (slashIdx <= 0) return null;
    const levelStr = rest.slice(0, slashIdx);
    if (!/^\d+$/.test(levelStr)) return null;
    const level = Number(levelStr);
    const parsed = parseCoordAndWidth(rest.slice(slashIdx + 1));
    if (!parsed) return null;

    let hashes: Buffer[] = this.leaves;
    for (let l = 0; l < level; l++) {
      const fullTiles = Math.floor(hashes.length / TILE_WIDTH);
      const next: Buffer[] = [];
      for (let t = 0; t < fullTiles; t++) {
        next.push(tileHash(hashes.slice(t * TILE_WIDTH, (t + 1) * TILE_WIDTH)));
      }
      hashes = next;
    }

    const start = parsed.tileIndex * TILE_WIDTH;
    const end = start + parsed.width;
    if (end > hashes.length) return null;
    return Buffer.concat(hashes.slice(start, end));
  }

  /**
   * Playground tamper helper (`POST /dev/tamper`):
   * deterministically flips a byte inside a receipt or transparent statement
   * and executes Class-1 offline verification to demonstrate immediate failure.
   */
  async tamperStatement(
    statementBytes: Uint8Array,
    opts: { byteOffset?: number; xorMask?: number } = {},
  ): Promise<TamperResult> {
    const buf = Buffer.from(statementBytes);
    if (buf.length < 8) {
      throw new Error('statement too short to tamper');
    }
    // Flip a byte inside the COSE signature/payload body without breaking outer CBOR tag framing
    const defaultOffset = Math.max(4, buf.length - 12);
    const flippedOffset =
      opts.byteOffset !== undefined && opts.byteOffset >= 0 && opts.byteOffset < buf.length
        ? opts.byteOffset
        : defaultOffset;
    const xorMask = opts.xorMask ?? 0xff;
    const originalByte = buf[flippedOffset]!;
    const tamperedByte = (originalByte ^ xorMask) & 0xff;
    buf[flippedOffset] = tamperedByte;

    const checkpoint = await this.getCheckpoint();
    const { trustRoots } = this.getTrust();
    const verifyReport = verifyReceiptBundle(
      {
        statement: buf,
        checkpoint,
      },
      trustRoots,
    );

    return {
      tampered: buf,
      flippedOffset,
      originalByte,
      tamperedByte,
      verifyReport,
    };
  }

  /** Transparency configuration discovery document (`/.well-known/transparency-configuration`). */
  getTransparencyConfiguration(baseUrl = 'http://127.0.0.1:8788'): Record<string, unknown> {
    const base = baseUrl.replace(/\/$/, '');
    return {
      issuer: this.origin,
      registration_endpoint: `${base}/entries`,
      entries_endpoint: `${base}/entries`,
      receipt_endpoint: `${base}/entries/{entry_id}/receipt`,
      checkpoint_endpoint: `${base}/checkpoint`,
      tamper_playground_endpoint: `${base}/dev/tamper`,
      cose_sign_algorithms_supported: [-7, -8, -49],
      verifiable_data_structures_supported: [1],
      media_types_supported: [
        MEDIA_TYPE_HVR,
        MEDIA_TYPE_SCITT_STATEMENT,
        CONTENT_TYPE_SCITT_RECEIPT,
      ],
      witness_quorum: 3,
      witness_total: this.witnesses.length,
      trust_file: this.getTrust().trustFile,
    };
  }
}

async function readRequestBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

function sendJson(res: ServerResponse, status: number, payload: unknown, headers: Record<string, string> = {}): void {
  const body = JSON.stringify(payload, null, 2) + '\n';
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    ...headers,
  });
  res.end(body);
}

export async function handleHvrDevHttp(
  service: HvrDevService,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  try {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? '127.0.0.1'}`);
    const path = url.pathname;
    const method = req.method ?? 'GET';

    if (method === 'GET' && path === '/health') {
      const cp = await service.getCheckpoint();
      sendJson(res, 200, {
        status: 'ok',
        service: 'hvr-dev',
        origin: service.origin,
        checkpoint_ready: Boolean(cp),
      });
      return;
    }

    if (method === 'GET' && path === '/.well-known/transparency-configuration') {
      const baseUrl = `http://${req.headers.host ?? '127.0.0.1'}`;
      sendJson(res, 200, service.getTransparencyConfiguration(baseUrl));
      return;
    }

    if (method === 'GET' && (path === '/checkpoint' || path === '/transparency/checkpoint')) {
      const cp = await service.getCheckpoint();
      res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
      res.end(cp);
      return;
    }

    if (method === 'GET' && path.startsWith('/tile/')) {
      const tileData = service.getTile(path.slice(1));
      if (!tileData) {
        sendJson(res, 404, { error: 'tile_not_found', path });
        return;
      }
      res.writeHead(200, {
        'content-type': 'application/octet-stream',
        'cache-control': 'public, max-age=31536000, immutable',
      });
      res.end(tileData);
      return;
    }

    if (method === 'POST' && path === '/entries') {
      const rawBody = await readRequestBody(req);
      const contentType = req.headers['content-type'] ?? '';
      let result: Awaited<ReturnType<HvrDevService['registerStatement']>>;

      if (contentType.includes('application/json') || (rawBody.length > 0 && rawBody[0] === 0x7b)) {
        const parsedJson = rawBody.length > 0 ? (JSON.parse(rawBody.toString('utf8')) as Record<string, unknown>) : {};
        if (typeof parsedJson.statement_base64 === 'string') {
          result = await service.registerStatement(Buffer.from(parsedJson.statement_base64, 'base64'));
        } else {
          result = await service.issueAndRegisterDevCapsule({
            ...(typeof parsedJson.action_id === 'string' ? { actionId: parsedJson.action_id } : {}),
            ...(typeof parsedJson.method === 'string' ? { method: parsedJson.method } : {}),
          });
        }
      } else if (rawBody.length > 0) {
        result = await service.registerStatement(rawBody);
      } else {
        result = await service.issueAndRegisterDevCapsule();
      }

      const accept = req.headers.accept ?? '';
      if (accept.includes(MEDIA_TYPE_SCITT_STATEMENT) || accept.includes(MEDIA_TYPE_HVR) || accept.includes('application/cose')) {
        res.writeHead(201, {
          'content-type': MEDIA_TYPE_HVR,
          location: `/entries/${result.entryId}`,
        });
        res.end(result.transparentStatement);
        return;
      }

      sendJson(
        res,
        201,
        {
          entry_id: result.entryId,
          leaf_index: result.index,
          receipt_base64: result.receipt.toString('base64'),
          transparent_statement_base64: result.transparentStatement.toString('base64'),
          checkpoint: result.checkpoint,
        },
        { location: `/entries/${result.entryId}` },
      );
      return;
    }

    const entryReceiptMatch = /^\/entries\/([^/]+)\/receipt$/.exec(path);
    if (method === 'GET' && entryReceiptMatch) {
      const entryId = entryReceiptMatch[1]!;
      const fresh = await service.getFreshReceipt(entryId);
      if (!fresh) {
        sendJson(res, 404, { error: 'entry_not_found', entry_id: entryId });
        return;
      }
      if ((req.headers.accept ?? '').includes('application/json')) {
        sendJson(res, 200, {
          entry_id: entryId,
          tree_size: fresh.treeSize,
          receipt_base64: fresh.receipt.toString('base64'),
          transparent_statement_base64: fresh.transparentStatement.toString('base64'),
        });
        return;
      }
      res.writeHead(200, { 'content-type': CONTENT_TYPE_SCITT_RECEIPT });
      res.end(fresh.receipt);
      return;
    }

    const entryMatch = /^\/entries\/([^/]+)$/.exec(path);
    if (method === 'GET' && entryMatch) {
      const entryId = entryMatch[1]!;
      const entry = service.getEntry(entryId);
      const fresh = await service.getFreshReceipt(entryId);
      if (!entry || !fresh) {
        sendJson(res, 404, { error: 'entry_not_found', entry_id: entryId });
        return;
      }
      if ((req.headers.accept ?? '').includes('application/json')) {
        sendJson(res, 200, {
          entry_id: entry.id,
          leaf_index: entry.index,
          registered_at: entry.registeredAt,
          statement_base64: entry.statementBytes.toString('base64'),
          transparent_statement_base64: fresh.transparentStatement.toString('base64'),
        });
        return;
      }
      res.writeHead(200, { 'content-type': MEDIA_TYPE_HVR });
      res.end(fresh.transparentStatement);
      return;
    }

    if (method === 'POST' && path === '/dev/tamper') {
      const rawBody = await readRequestBody(req);
      let targetBytes: Buffer;
      let byteOffset: number | undefined;
      let xorMask: number | undefined;

      const contentType = req.headers['content-type'] ?? '';
      if (contentType.includes('application/json') || (rawBody.length > 0 && rawBody[0] === 0x7b)) {
        const parsed = JSON.parse(rawBody.toString('utf8')) as {
          statement_base64?: string;
          receipt_base64?: string;
          entry_id?: string;
          byte_offset?: number;
          xor_mask?: number;
        };
        if (parsed.statement_base64) {
          targetBytes = Buffer.from(parsed.statement_base64, 'base64');
        } else if (parsed.receipt_base64) {
          targetBytes = Buffer.from(parsed.receipt_base64, 'base64');
        } else if (parsed.entry_id !== undefined) {
          const fresh = await service.getFreshReceipt(String(parsed.entry_id));
          if (!fresh) {
            sendJson(res, 404, { error: 'entry_not_found', entry_id: parsed.entry_id });
            return;
          }
          targetBytes = fresh.transparentStatement;
        } else {
          const issued = await service.issueAndRegisterDevCapsule();
          targetBytes = issued.transparentStatement;
        }
        byteOffset = parsed.byte_offset;
        xorMask = parsed.xor_mask;
      } else if (rawBody.length > 0) {
        targetBytes = rawBody;
      } else {
        const issued = await service.issueAndRegisterDevCapsule();
        targetBytes = issued.transparentStatement;
      }

      const tampered = await service.tamperStatement(targetBytes, {
        ...(byteOffset !== undefined ? { byteOffset } : {}),
        ...(xorMask !== undefined ? { xorMask } : {}),
      });
      sendJson(res, 200, {
        tampered_base64: tampered.tampered.toString('base64'),
        flipped_offset: tampered.flippedOffset,
        original_byte: tampered.originalByte,
        tampered_byte: tampered.tamperedByte,
        verdict: tampered.verifyReport.verdict,
        checks: tampered.verifyReport.checks,
      });
      return;
    }

    sendJson(res, 404, { error: 'not_found', path });
  } catch (err) {
    sendJson(res, 400, {
      error: 'bad_request',
      message: (err as Error).message,
    });
  }
}

export async function startHvrDevServer(opts: HvrDevOptions = {}): Promise<{
  service: HvrDevService;
  server: Server;
  url: string;
  close: () => Promise<void>;
}> {
  const service = new HvrDevService(opts);
  const host = opts.host ?? '127.0.0.1';
  const port = opts.port ?? 0;
  const server = createServer((req, res) => {
    void handleHvrDevHttp(service, req, res);
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => resolve());
  });

  const addr = server.address();
  const actualPort = typeof addr === 'object' && addr ? addr.port : port;
  const url = `http://${host}:${actualPort}`;

  return {
    service,
    server,
    url,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}
