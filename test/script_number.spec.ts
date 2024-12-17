import * as assert from 'assert';
import { describe, it } from 'mocha';
import { scriptNumber } from '@scrypt-inc/bitcoinjs-lib';
import fixtures from './fixtures/script_number.json';
import * as tools from 'uint8array-tools';

describe('script-number', () => {
  describe('decode', () => {
    fixtures.forEach(f => {
      it(f.hex + ' returns ' + f.number, () => {
        const actual = scriptNumber.decode(Buffer.from(f.hex, 'hex'), f.bytes);

        assert.strictEqual(actual, f.number);
      });
    });
  });

  describe('encode', () => {
    fixtures.forEach(f => {
      it(f.number + ' returns ' + f.hex, () => {
        const actual = scriptNumber.encode(f.number);

        assert.strictEqual(tools.toHex(actual), f.hex);
      });
    });
  });
});
