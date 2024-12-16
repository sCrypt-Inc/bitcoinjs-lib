/**
 * Script tools, including decompile, compile, toASM, fromASM, toStack, isCanonicalPubKey, isCanonicalScriptSignature
 * @packageDocumentation
 */
import * as bip66 from './bip66.js';
import { isOpSuccess, OPS, REVERSE_OPS } from './ops.js';
import { Stack } from './payments/index.js';
import * as pushdata from './push_data.js';
import * as scriptNumber from './script_number.js';
import * as scriptSignature from './script_signature.js';
import * as types from './types.js';
import * as tools from 'uint8array-tools';
import * as v from 'valibot';

const OP_INT_BASE = OPS.OP_RESERVED; // OP_1 - 1
export { OPS };

const StackSchema = v.array(v.union([v.instance(Uint8Array), v.number()]));

function isOPInt(value: number): boolean {
  return (
    v.is(v.number(), value) &&
    (value === OPS.OP_0 ||
      (value >= OPS.OP_1 && value <= OPS.OP_16) ||
      value === OPS.OP_1NEGATE)
  );
}

function isPushOnlyChunk(value: number | Uint8Array): boolean {
  return v.is(types.BufferSchema, value) || isOPInt(value as number);
}

export function isPushOnly(value: Stack | Uint8Array): boolean {
  if (value instanceof Uint8Array) {
    const res = decompile(value);
    if (res === null) {
      throw new Error('script is invalid!');
    }
    value = res;
  }
  return v.is(
    v.pipe(v.any(), v.everyItem(isPushOnlyChunk as (x: any) => boolean)),
    value,
  );
}

export function isScriptHashOut(value: Uint8Array): boolean {
  return (
    value.length === 23 &&
    value[0] === OPS.OP_HASH160 &&
    value[1] === 0x14 &&
    value[value.length - 1] === OPS.OP_EQUAL
  );
}

export function countNonPushOnlyOPs(value: Stack): number {
  return value.length - value.filter(isPushOnlyChunk).length;
}

export function asMinimalOP(buffer: Uint8Array): number | void {
  if (buffer.length === 0) return OPS.OP_0;
  if (buffer.length !== 1) return;
  if (buffer[0] >= 1 && buffer[0] <= 16) return OP_INT_BASE + buffer[0];
  if (buffer[0] === 0x81) return OPS.OP_1NEGATE;
}

function chunksIsBuffer(buf: Uint8Array | Stack): buf is Uint8Array {
  return buf instanceof Uint8Array;
}

function chunksIsArray(buf: Uint8Array | Stack): buf is Stack {
  return v.is(StackSchema, buf);
}

function singleChunkIsBuffer(buf: number | Uint8Array): buf is Uint8Array {
  return buf instanceof Uint8Array;
}

/**
 * Compiles an array of chunks into a Buffer.
 *
 * @param chunks - The array of chunks to compile.
 * @returns The compiled Buffer.
 * @throws Error if the compilation fails.
 */
export function compile(chunks: Uint8Array | Stack): Uint8Array {
  // TODO: remove me
  if (chunksIsBuffer(chunks)) return chunks;

  v.parse(StackSchema, chunks);

  const bufferSize = chunks.reduce((accum: number, chunk) => {
    // data chunk
    if (singleChunkIsBuffer(chunk)) {
      // adhere to BIP62.3, minimal push policy
      if (chunk.length === 1 && asMinimalOP(chunk) !== undefined) {
        return accum + 1;
      }

      return accum + pushdata.encodingLength(chunk.length) + chunk.length;
    }

    // opcode
    return accum + 1;
  }, 0.0);

  const buffer = new Uint8Array(bufferSize);
  let offset = 0;

  chunks.forEach(chunk => {
    // data chunk
    if (singleChunkIsBuffer(chunk)) {
      // adhere to BIP62.3, minimal push policy
      const opcode = asMinimalOP(chunk);
      if (opcode !== undefined) {
        tools.writeUInt8(buffer, offset, opcode);
        offset += 1;
        return;
      }

      offset += pushdata.encode(buffer, chunk.length, offset);
      buffer.set(chunk, offset);
      offset += chunk.length;

      // opcode
    } else {
      tools.writeUInt8(buffer, offset, chunk);
      offset += 1;
    }
  });

  if (offset !== buffer.length) throw new Error('Could not decode chunks');
  return buffer;
}

export function decompile(
  buffer: Uint8Array | Array<number | Uint8Array>,
): Array<number | Uint8Array> | null {
  // TODO: remove me
  if (chunksIsArray(buffer)) return buffer;

  v.parse(types.BufferSchema, buffer);

  const chunks: Array<number | Uint8Array> = [];
  let i = 0;

  while (i < buffer.length) {
    const opcode = buffer[i];

    // data chunk
    if (opcode > OPS.OP_0 && opcode <= OPS.OP_PUSHDATA4) {
      const d = pushdata.decode(buffer, i);

      // did reading a pushDataInt fail?
      if (d === null) return null;
      i += d.size;

      // attempt to read too much data?
      if (i + d.number > buffer.length) return null;

      const data = buffer.slice(i, i + d.number);
      i += d.number;

      // decompile minimally
      const op = asMinimalOP(data);
      if (op !== undefined) {
        chunks.push(op);
      } else {
        chunks.push(data);
      }

      // opcode
    } else {
      chunks.push(opcode);

      if (isOpSuccess(opcode)) {
        chunks.push(buffer.slice(i + 1));
        break;
      }

      i += 1;
    }
  }

  return chunks;
}

/**
 * Converts the given chunks into an ASM (Assembly) string representation.
 * If the chunks parameter is a Buffer, it will be decompiled into a Stack before conversion.
 * @param chunks - The chunks to convert into ASM.
 * @returns The ASM string representation of the chunks.
 */
export function toASM(chunks: Uint8Array | Array<number | Uint8Array>): string {
  if (chunksIsBuffer(chunks)) {
    chunks = decompile(chunks) as Stack;
  }
  if (!chunks) {
    throw new Error('Could not convert invalid chunks to ASM');
  }
  return (chunks as Stack)
    .map(chunk => {
      // data?
      if (singleChunkIsBuffer(chunk)) {
        const op = asMinimalOP(chunk);
        if (op === undefined) return tools.toHex(chunk);
        chunk = op as number;
      }

      // opcode!
      return REVERSE_OPS[chunk];
    })
    .join(' ');
}

/**
 * Converts an ASM string to a Buffer.
 * @param asm The ASM string to convert.
 * @returns The converted Buffer.
 */
export function fromASM(asm: string): Uint8Array {
  v.parse(v.string(), asm);

  if (asm === '') {
    return Uint8Array.from([]);
  }

  return compile(
    asm.split(' ').map(chunkStr => {
      // opcode?
      if (OPS[chunkStr] !== undefined) return OPS[chunkStr];

      try {
        v.parse(types.HexSchema, chunkStr);

        // data!
        return tools.fromHex(chunkStr);
      } catch (error) {}

      v.parse(types.x0HexSchema, chunkStr);

      // data!
      return tools.fromHex(chunkStr.slice(2));
    }),
  );
}

/**
 * Converts the given chunks into a stack of buffers.
 *
 * @param chunks - The chunks to convert.
 * @returns The stack of buffers.
 */
export function toStack(
  chunks: Uint8Array | Array<number | Uint8Array>,
): Uint8Array[] {
  chunks = decompile(chunks) as Stack;
  v.parse(v.custom(isPushOnly as (x: any) => boolean), chunks);

  return chunks.map(op => {
    if (singleChunkIsBuffer(op)) return op;
    if (op === OPS.OP_0) return new Uint8Array(0);

    return scriptNumber.encode(op - OP_INT_BASE);
  });
}

export function isCanonicalPubKey(buffer: Uint8Array): boolean {
  return types.isPoint(buffer);
}

export function isUncompressedPubkey(buffer: Uint8Array): boolean {
  if (
    buffer instanceof Uint8Array &&
    buffer.length === 65 &&
    buffer[0] === 0x04 &&
    types.isPoint(buffer)
  ) {
    return true;
  } else {
    return false;
  }
}

export function isDefinedHashType(hashType: number): boolean {
  const hashTypeMod = hashType & ~0x80;

  return hashTypeMod > 0x00 && hashTypeMod < 0x04;
}

export function isCanonicalScriptSignature(buffer: Uint8Array): boolean {
  if (!(buffer instanceof Uint8Array)) return false;
  if (!isDefinedHashType(buffer[buffer.length - 1])) return false;

  return bip66.check(buffer.slice(0, -1));
}

export function isMinimalPush(opcodenum: number, buf: Uint8Array) {
  if (buf.length === 0) {
    // Could have used OP_0.
    return opcodenum === OPS.OP_0;
  } else if (buf.length === 1 && buf[0] >= 1 && buf[0] <= 16) {
    // Could have used OP_1 .. OP_16.
    return opcodenum === OPS.OP_1 + (buf[0] - 1);
  } else if (buf.length === 1 && buf[0] === 0x81) {
    // Could have used OP_1NEGATE
    return opcodenum === OPS.OP_1NEGATE;
  } else if (buf.length <= 75) {
    // Could have used a direct push (opcode indicating number of bytes pushed + those bytes).
    return opcodenum === buf.length;
  } else if (buf.length <= 255) {
    // Could have used OP_PUSHDATA.
    return opcodenum === OPS.OP_PUSHDATA1;
  } else if (buf.length <= 65535) {
    // Could have used OP_PUSHDATA2.
    return opcodenum === OPS.OP_PUSHDATA2;
  }
  return true;
}

function decodeOpN(opcode: number) {
  if (opcode === OPS.OP_0) {
    return 0;
  }
  return opcode - (OPS.OP_1 - 1);
}

export function createWitnessProgram(buf: Uint8Array):
  | false
  | {
      version: number;
      program: Uint8Array;
    } {
  if (buf.length < 4 || buf.length > 42) {
    return false;
  }
  if (buf[0] !== OPS.OP_0 && !(buf[0] >= OPS.OP_1 && buf[0] <= OPS.OP_16)) {
    return false;
  }

  if (buf.length === buf[1] + 2) {
    return {
      version: decodeOpN(buf[0]),
      program: buf.slice(2, buf.length),
    };
  }

  return false;
}

/**
 * Analogous to bitcoind's FindAndDelete. Find and delete equivalent chunks,
 * typically used with push data chunks.  Note that this will find and delete
 * not just the same data, but the same data with the same push data op as
 * produced by default. i.e., if a pushdata in a tx does not use the minimal
 * pushdata op, then when you try to remove the data it is pushing, it will not
 * be removed, because they do not use the same pushdata op.
 */
export function findAndDelete(
  script: Array<number | Uint8Array>,
  subScript: Uint8Array,
) {
  let nFound = 0;
  if (subScript.length === 0) {
    return nFound;
  }

  let pc = 0;

  do {
    const chunk = script[pc];
    if (chunk instanceof Uint8Array && tools.compare(chunk, subScript) === 0) {
      script.splice(pc, 1);
      ++nFound;
    }
  } while (pc++ < script.length);
  return nFound;
}

export const number = scriptNumber;
export const signature = scriptSignature;
