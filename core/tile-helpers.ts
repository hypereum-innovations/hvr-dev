// SPDX-License-Identifier: Apache-2.0
/**
 * Open C2SP tlog-tiles entry bundle and tile path helpers.
 */
export const TILE_WIDTH = 256;
export const MAX_ENTRY_BYTES = 0xffff;

export function tilePath(index: number, width = TILE_WIDTH): string {
  const s = String(index);
  const groups: string[] = [];
  let rest = s;
  while (rest.length > 3) {
    groups.unshift('x' + rest.slice(-3).padStart(3, '0'));
    rest = rest.slice(0, -3);
  }
  groups.push(rest.padStart(3, '0'));
  const base = groups.join('/');
  return width === TILE_WIDTH ? base : `${base}.p/${width}`;
}

export function normalizeTileName(name: string): string {
  const trimmed = name.replace(/^\/+/, '');
  if (trimmed.startsWith('tile/8/data/')) {
    return `tile/entries/${trimmed.slice('tile/8/data/'.length)}`;
  }
  const heightMatch = /^tile\/8\/(\d+\/.+)$/.exec(trimmed);
  if (heightMatch) {
    return `tile/${heightMatch[1]!}`;
  }
  return trimmed;
}

export function encodeEntryBundle(entries: Array<{ atSeconds: number; statement: Buffer }>): Buffer {
  const parts: Buffer[] = [];
  for (const e of entries) {
    if (e.statement.length > MAX_ENTRY_BYTES) {
      throw new Error(`entry exceeds the tlog-tiles ${MAX_ENTRY_BYTES}-byte bundle limit`);
    }
    const head = Buffer.alloc(2);
    head.writeUInt16BE(e.statement.length, 0);
    parts.push(head, e.statement);
  }
  return Buffer.concat(parts);
}
