import * as tools from 'uint8array-tools';

function bn2BigEndianBuf(bn: bigint): Uint8Array {
  let hex = bn.toString(16);
  if (hex.length % 2 !== 0) {
    hex = '0' + hex;
  }

  return Uint8Array.from(
    hex.match(/[\da-fA-F]{2}/g)!.map(h => {
      return parseInt(h, 16);
    }),
  );
}

function bigEndianBuf2Bn(buf: Uint8Array): bigint {
  let ret = 0n;
  const bits = 8n;
  for (const i of buf.values()) {
    const bi = BigInt(i);
    ret = (ret << bits) + bi;
  }
  return ret;
}

function toSMBigEndian(bn: bigint) {
  let buf: Uint8Array;
  if (bn < BigInt(0)) {
    buf = bn2BigEndianBuf(-bn);
    if (buf[0] & 0x80) {
      buf = tools.concat([Uint8Array.from([0x80]), buf]);
    } else {
      buf[0] = buf[0] | 0x80;
    }
  } else {
    buf = bn2BigEndianBuf(bn);
    if (buf[0] & 0x80) {
      buf = tools.concat([Uint8Array.from([0x00]), buf]);
    }
  }

  if (buf.length === 1 && buf[0] === 0) {
    buf = Buffer.from([]);
  }
  return buf;
}

export function bn2Buf(bn: bigint): Uint8Array {
  return toSMBigEndian(bn).reverse();
}

export function buf2BN(
  buf: Uint8Array,
  fRequireMinimal: boolean,
  size?: number,
): bigint {
  const nMaxNumSize = size || 4;
  if (buf.length > nMaxNumSize) {
    throw new Error('script number overflow');
  }

  if (fRequireMinimal && buf.length > 0) {
    // Check that the number is encoded with the minimum possible
    // number of bytes.
    //
    // If the most-significant-byte - excluding the sign bit - is zero
    // then we're not minimal. Note how this test also rejects the
    // negative-zero encoding, 0x80.
    if ((buf[buf.length - 1] & 0x7f) === 0) {
      // One exception: if there's more than one byte and the most
      // significant bit of the second-most-significant-byte is set
      // it would conflict with the sign bit. An example of this case
      // is +-255, which encode to 0xff00 and 0xff80 respectively.
      // (big-endian).
      if (buf.length <= 1 || (buf[buf.length - 2] & 0x80) === 0) {
        throw new Error('non-minimally encoded script number');
      }
    }
  }

  if (buf.length === 0) {
    return BigInt(0);
  }

  buf.reverse();

  let ret = 0n;

  if (buf[0] & 0x80) {
    buf[0] = buf[0] & 0x7f;
    ret = bigEndianBuf2Bn(buf);
    ret = -ret;
  } else {
    ret = bigEndianBuf2Bn(buf);
  }
  return ret;
}
