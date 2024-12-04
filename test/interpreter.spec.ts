import * as assert from 'assert';
import { beforeEach, describe, it } from 'mocha';
import {
  bn2Buf,
  Interpreter,
  script as bscript,
  Transaction,
  BufferWriter,
} from 'bitcoinjs-lib';
import * as tools from 'uint8array-tools';
import script_tests from './fixtures/scripts/script_tests.json';
import sinon from 'sinon';

//the script string format used in bitcoind data tests
function fromBitcoindString(str: string): Uint8Array {
  if (str === '') {
    return Uint8Array.from([]);
  }
  const bw = BufferWriter.withCapacity(1000);
  const tokens = str.split(' ');
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (token === '') {
      continue;
    }

    let opstr;
    let opcodenum;
    if (token[0] === '0' && token[1] === 'x') {
      const hex = token.slice(2);
      bw.writeSlice(tools.fromHex(hex));
    } else if (token[0] === "'") {
      const tstr = token.slice(1, token.length - 1);
      const cbuf = tools.fromUtf8(tstr);
      bw.writeVarSlice(cbuf);
    } else if (typeof bscript.OPS['OP_' + token] !== 'undefined') {
      opstr = 'OP_' + token;
      opcodenum = bscript.OPS[opstr];
      bw.writeUInt8(opcodenum);
    } else if (typeof bscript.OPS[token] === 'number') {
      opstr = token;
      opcodenum = bscript.OPS[opstr];
      bw.writeUInt8(opcodenum);
    } else if (!isNaN(parseInt(token))) {
      bw.writeVarSlice(bn2Buf(BigInt(token)));
    } else {
      throw new Error('Could not determine type of script value');
    }
  }
  return bw.buffer.slice(0, bw.offset);
}

describe('Interpreter', () => {
  it('should make a new interp', () => {
    const interp = new Interpreter();
    assert.strictEqual(interp instanceof Interpreter, true);
    assert.strictEqual(interp.isInitialized(), true);
  });

  describe('@castToBool', () => {
    it('should cast these bufs to bool correctly', () => {
      assert.strictEqual(Interpreter.castToBool(bn2Buf(0n)), false);
      assert.strictEqual(Interpreter.castToBool(tools.fromHex('0080')), false);
      assert.strictEqual(Interpreter.castToBool(bn2Buf(1n)), true);
      assert.strictEqual(Interpreter.castToBool(bn2Buf(-1n)), true);
      assert.strictEqual(Interpreter.castToBool(tools.fromHex('00')), false);
    });
  });

  describe('#verifyWitnessProgram', () => {
    it('will return true if witness program greater than 0', function () {
      const si = new Interpreter();
      const version = 1;
      const program = tools.fromHex(
        'bcbd1db07ce89d1f4050645c26c90ce78b67eff78460002a4d5c10410958e064',
      );
      const witness = [
        tools.fromHex(
          'bda0eeeb166c8bfeaee88dedc8efa82d3bea35aac5be253902f59d52908bfe25',
        ),
      ];
      const satoshis = 1;
      const flags = 0;
      assert.strictEqual(
        si.verifyWitnessProgram(version, program, witness, satoshis, flags),
        true,
      );
    });
    it('will return false with error if witness length is 0', function () {
      const si = new Interpreter();
      const version = 0;
      const program = tools.fromHex(
        'bcbd1db07ce89d1f4050645c26c90ce78b67eff78460002a4d5c10410958e064',
      );
      const witness: Uint8Array[] = [];
      const satoshis = 1;
      const flags = 0;
      assert.strictEqual(
        si.verifyWitnessProgram(version, program, witness, satoshis, flags),
        false,
      );
      assert.strictEqual(
        si.getErr(),
        'SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY',
      );
    });
    it('will return false if program hash mismatch (version 0, 32 byte program)', function () {
      const si = new Interpreter();
      const version = 0;
      const program = tools.fromHex(
        '0000000000000000000000000000000000000000000000000000000000000000',
      );
      const witness = [
        tools.fromHex(
          '0000000000000000000000000000000000000000000000000000000000000000',
        ),
        tools.fromHex(
          '0000000000000000000000000000000000000000000000000000000000000000',
        ),
      ];
      const satoshis = 1;
      const flags = 0;
      assert.strictEqual(
        si.verifyWitnessProgram(version, program, witness, satoshis, flags),
        false,
      );
      assert.strictEqual(si.getErr(), 'SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH');
    });
    it("will return false if witness stack doesn't have two items (version 0, 20 byte program)", function () {
      const si = new Interpreter();
      const version = 0;
      const program = tools.fromHex('b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc6');
      const witness = [
        tools.fromHex(
          '0000000000000000000000000000000000000000000000000000000000000000',
        ),
        tools.fromHex(
          '0000000000000000000000000000000000000000000000000000000000000000',
        ),
        tools.fromHex(
          '0000000000000000000000000000000000000000000000000000000000000000',
        ),
      ];
      const satoshis = 1;
      const flags = 0;
      assert.strictEqual(
        si.verifyWitnessProgram(version, program, witness, satoshis, flags),
        false,
      );
      assert.strictEqual(si.getErr(), 'SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH');
    });
    it('will return false if program wrong length for version 0', function () {
      const si = new Interpreter();
      const version = 0;
      const program = tools.fromHex('b8bcb07f6344b42ab04250c86a6e8b75d3');
      const witness = [
        tools.fromHex(
          '0000000000000000000000000000000000000000000000000000000000000000',
        ),
      ];
      const satoshis = 1;
      const flags = 0;
      assert.strictEqual(
        si.verifyWitnessProgram(version, program, witness, satoshis, flags),
        false,
      );
      assert.strictEqual(
        si.getErr(),
        'SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH',
      );
    });
    it('will return false with discourage upgradable witness program', function () {
      const si = new Interpreter();
      const version = 1;
      const program = tools.fromHex('b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc6');
      const witness = [
        tools.fromHex(
          '0000000000000000000000000000000000000000000000000000000000000000',
        ),
        tools.fromHex(
          '0000000000000000000000000000000000000000000000000000000000000000',
        ),
      ];
      const satoshis = 1;
      const flags =
        Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM;
      assert.strictEqual(
        si.verifyWitnessProgram(version, program, witness, satoshis, flags),
        false,
      );
      assert.strictEqual(
        si.getErr(),
        'SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM',
      );
    });
    it("will return false with error if stack doesn't have exactly one item", function () {
      const si = new Interpreter();
      si.evaluate = sinon.stub().returns(true);
      const version = 0;
      const program = tools.fromHex('b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc6');
      const witness = [
        tools.fromHex(
          '0000000000000000000000000000000000000000000000000000000000000000',
        ),
        tools.fromHex(
          '0000000000000000000000000000000000000000000000000000000000000000',
        ),
      ];
      const satoshis = 1;
      const flags = 0;
      assert.strictEqual(
        si.verifyWitnessProgram(version, program, witness, satoshis, flags),
        false,
      );
      assert.strictEqual(si.getErr(), 'SCRIPT_ERR_EVAL_FALSE');
    });
    it('will return false if last item in stack casts to false', function () {
      const si = new Interpreter();
      si.evaluate = function () {
        si.setStack([tools.fromHex('00')]);
        return true;
      };
      const version = 0;
      const program = tools.fromHex('b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc6');
      const witness = [
        tools.fromHex(
          '0000000000000000000000000000000000000000000000000000000000000000',
        ),
        tools.fromHex(
          '0000000000000000000000000000000000000000000000000000000000000000',
        ),
      ];
      const satoshis = 1;
      const flags = 0;
      assert.strictEqual(
        si.verifyWitnessProgram(version, program, witness, satoshis, flags),
        false,
      );
      assert.strictEqual(si.getErr(), 'SCRIPT_ERR_EVAL_FALSE_IN_STACK');
    });
  });

  describe('#verify', () => {
    it('should verify these trivial scripts', () => {
      let verified;
      const si = new Interpreter();
      verified = si.verify(bscript.fromASM('OP_1'), bscript.fromASM('OP_1'));
      assert.strictEqual(verified, true);
      verified = new Interpreter().verify(
        bscript.fromASM('OP_1'),
        bscript.fromASM('OP_0'),
      );
      assert.strictEqual(verified, false);
      verified = new Interpreter().verify(
        bscript.fromASM('OP_0'),
        bscript.fromASM('OP_1'),
      );
      assert.strictEqual(verified, true);
      verified = new Interpreter().verify(
        bscript.fromASM('OP_CODESEPARATOR'),
        bscript.fromASM('OP_1'),
      );
      assert.strictEqual(verified, true);
      verified = new Interpreter().verify(
        bscript.fromASM(''),
        bscript.fromASM('OP_DEPTH OP_0 OP_EQUAL'),
      );
      assert.strictEqual(verified, true);
      verified = new Interpreter().verify(
        bscript.fromASM('OP_1 OP_2'),
        bscript.fromASM('OP_2 OP_EQUALVERIFY OP_1 OP_EQUAL'),
      );
      assert.strictEqual(verified, true);
      verified = new Interpreter().verify(
        bscript.fromASM('09 0x000000000000000010'),
        bscript.fromASM(''),
      );
      assert.strictEqual(verified, true);
      verified = new Interpreter().verify(
        bscript.fromASM('OP_1'),
        bscript.fromASM('OP_15 OP_ADD OP_16 OP_EQUAL'),
      );
      assert.strictEqual(verified, true);
      verified = new Interpreter().verify(
        bscript.fromASM('OP_0'),
        bscript.fromASM('OP_IF OP_VER OP_ELSE OP_1 OP_ENDIF'),
      );
      assert.strictEqual(verified, true);

      // 106n + 9999999n = 10000105n
      verified = new Interpreter().verify(
        bscript.fromASM('6a 7f969800'),
        bscript.fromASM('OP_ADD e9969800 OP_NUMEQUAL'),
      );
      assert.strictEqual(verified, true);
    });

    // it('should verify these simple transaction', function() {
    //   // first we create a transaction
    //   var privateKey = new PrivateKey('cSBnVM4xvxarwGQuAfQFwqDg9k5tErHUHzgWsEfD4zdwUasvqRVY');
    //   var publicKey = privateKey.publicKey;
    //   var fromAddress = publicKey.toAddress();
    //   var toAddress = 'mrU9pEmAx26HcbKVrABvgL7AwA5fjNFoDc';
    //   var scriptPubkey = bscript.fromASM.buildPublicKeyHashOut(fromAddress);
    //   var utxo = {
    //     address: fromAddress,
    //     txId: 'a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458',
    //     outputIndex: 0,
    //     script: scriptPubkey,
    //     satoshis: 100000
    //   };
    //   var tx = new Transaction()
    //     .from(utxo)
    //     .to(toAddress, 100000)
    //     .sign(privateKey);

    //   // we then extract the signature from the first input
    //   var inputIndex = 0;
    //   var signature = tx.getSignatures(privateKey)[inputIndex].signature;

    //   var scriptSig = bscript.fromASM.buildPublicKeyHashIn(publicKey, signature);
    //   var flags = Interpreter.SCRIPT_VERIFY_P2SH | Interpreter.SCRIPT_VERIFY_STRICTENC;
    //   var verified = Interpreter().verify(scriptSig, scriptPubkey, tx, inputIndex, flags);
    //   assert.strictEqual(verified, true);
    // });
  });

  const FLAG_MAP: any = {
    NONE: Interpreter.SCRIPT_VERIFY_NONE,
    P2SH: Interpreter.SCRIPT_VERIFY_P2SH,
    STRICTENC: Interpreter.SCRIPT_VERIFY_STRICTENC,
    DERSIG: Interpreter.SCRIPT_VERIFY_DERSIG,
    LOW_S: Interpreter.SCRIPT_VERIFY_LOW_S,
    SIGPUSHONLY: Interpreter.SCRIPT_VERIFY_SIGPUSHONLY,
    MINIMALDATA: Interpreter.SCRIPT_VERIFY_MINIMALDATA,
    NULLDUMMY: Interpreter.SCRIPT_VERIFY_NULLDUMMY,
    DISCOURAGE_UPGRADABLE_NOPS:
      Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
    CLEANSTACK: Interpreter.SCRIPT_VERIFY_CLEANSTACK,
    MINIMALIF: Interpreter.SCRIPT_VERIFY_MINIMALIF,
    NULLFAIL: Interpreter.SCRIPT_VERIFY_NULLFAIL,
    CHECKLOCKTIMEVERIFY: Interpreter.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
    CHECKSEQUENCEVERIFY: Interpreter.SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
    WITNESS: Interpreter.SCRIPT_VERIFY_WITNESS,
    DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM:
      Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    // DISCOURAGE_UPGRADABLE_WITNESS: Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    WITNESS_PUBKEYTYPE: Interpreter.SCRIPT_VERIFY_WITNESS_PUBKEYTYPE,
    CONST_SCRIPTCODE: Interpreter.SCRIPT_VERIFY_CONST_SCRIPTCODE,
    TAPROOT: Interpreter.SCRIPT_VERIFY_TAPROOT,
    DISCOURAGE_UPGRADABLE_PUBKEYTYPE:
      Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
    DISCOURAGE_OP_SUCCESS: Interpreter.SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS,
    DISCOURAGE_UPGRADABLE_TAPROOT_VERSION:
      Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
  };

  const getFlags = function getFlags(flagstr: string) {
    let flags = 0;

    for (let flag of flagstr.split(',')) {
      flag = flag.trim();
      if (FLAG_MAP[flag] === undefined) {
        throw new Error('Unknown flag: ' + flag);
      }
      flags |= FLAG_MAP[flag];
    }
    return flags;
  };

  const testFixture = function (
    vector: string[],
    expected: boolean,
    witness: Uint8Array[],
    amount: number,
  ) {
    amount = amount || 0;
    const scriptSig = fromBitcoindString(vector[0]);
    const scriptPubkey = fromBitcoindString(vector[1]);
    const flags = getFlags(vector[2]);

    const hashbuf = Buffer.alloc(32);
    hashbuf.fill(0);
    const credtx = new Transaction();
    credtx.version = 1;
    credtx.addInput(
      tools.fromHex(
        '0000000000000000000000000000000000000000000000000000000000000000',
      ),
      0xffffffff,
      0xffffffff,
      bscript.fromASM('OP_0 OP_0'),
    );
    credtx.addOutput(scriptPubkey, BigInt(amount));
    const id = credtx.getId();

    const spendtx = new Transaction();
    spendtx.version = 1;
    spendtx.addInput(tools.fromHex(id), 0, 0xffffffff, scriptSig);

    spendtx.addOutput(Uint8Array.from([]), BigInt(amount));

    const interp = new Interpreter();
    const verified = interp.verify(
      scriptSig,
      scriptPubkey,
      spendtx,
      0,
      flags,
      witness,
      amount,
    );
    assert.strictEqual(verified, expected);
  };

  describe('bitcoind script evaluation fixtures', () => {
    const testAllFixtures = function (set: Array<any>) {
      let c = 0;
      set.forEach(function (vector) {
        if (vector.length === 1) {
          return;
        }
        c++;

        let witness, amount;
        if (Array.isArray(vector[0])) {
          const extra = vector.shift();
          amount = extra.pop() * 1e8;
          witness = extra.map(function (x: string) {
            return tools.fromHex(x);
          });
        } else {
          return;
        }

        const fullScriptString = vector[0] + ' ' + vector[1];
        const expected = vector[3] == 'OK';
        const descstr = vector[4];

        const comment = descstr ? ' (' + descstr + ')' : '';
        it(
          'should ' +
            vector[3] +
            ' script_tests ' +
            'vector #' +
            c +
            ': ' +
            fullScriptString +
            comment,
          function () {
            testFixture(vector, expected, witness, amount);
          },
        );
      });
    };
    testAllFixtures(script_tests);
  });
});
