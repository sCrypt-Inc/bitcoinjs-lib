import * as bscript from './script.js';
import { decode, isTxDER, SignatureVersion } from './script_signature.js';
import {
  isFinal,
  Transaction,
  varSliceSize,
  vectorSize,
  Output,
} from './transaction.js';
import { toPushdataCode } from './push_data.js';
import { bn2Buf, buf2BN } from './bn.js';
import { sha1 } from '@noble/hashes/sha1';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 } from '@noble/hashes/sha256';
import * as tools from 'uint8array-tools';
import { hash160, hash256 } from './crypto.js';
import { isOpSuccess } from './ops.js';
import { BufferWriter } from './bufferutils.js';
import { isUint8Array } from 'util/types';
import { rootHashFromPath, tapleafHash, tweakKey } from './payments/bip341.js';
import { ECPairFactory } from 'ecpair';
import { decodeSchnorrSignature } from './psbt/bip371.js';
import { getEccLib } from './ecc_lib.js';

function requireTrue(res: boolean, message: string) {
  if (!res) {
    throw new Error(message);
  }
}

export enum InterpreterErr {
  NONE = '',
  SCRIPT_ERR_SCRIPT_SIZE = 'SCRIPT_ERR_SCRIPT_SIZE',
  SCRIPT_ERR_DECOMPILE = 'SCRIPT_ERR_DECOMPILE',
  SCRIPT_ERR_SIG_PUSHONLY = 'SCRIPT_ERR_SIG_PUSHONLY',
  SCRIPT_ERR_EVAL_FALSE_NO_RESULT = 'SCRIPT_ERR_EVAL_FALSE_NO_RESULT',
  SCRIPT_ERR_UNBALANCED_CONDITIONAL = 'SCRIPT_ERR_UNBALANCED_CONDITIONAL',

  SCRIPT_ERR_CLEANSTACK = 'SCRIPT_ERR_CLEANSTACK',

  SCRIPT_ERR_WITNESS_UNEXPECTED = 'SCRIPT_ERR_WITNESS_UNEXPECTED',
  SCRIPT_ERR_UNDEFINED_OPCODE = 'SCRIPT_ERR_UNDEFINED_OPCODE',

  SCRIPT_ERR_PUSH_SIZE = 'SCRIPT_ERR_PUSH_SIZE',

  SCRIPT_ERR_OP_COUNT = 'SCRIPT_ERR_OP_COUNT',
  SCRIPT_ERR_DISABLED_OPCODE = 'SCRIPT_ERR_DISABLED_OPCODE',

  SCRIPT_ERR_OP_CODESEPARATOR = 'SCRIPT_ERR_OP_CODESEPARATOR',

  SCRIPT_ERR_MINIMALDATA = 'SCRIPT_ERR_MINIMALDATA',

  SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS = 'SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS',

  SCRIPT_ERR_INVALID_STACK_OPERATION = 'SCRIPT_ERR_INVALID_STACK_OPERATION',

  SCRIPT_ERR_NEGATIVE_LOCKTIME = 'SCRIPT_ERR_NEGATIVE_LOCKTIME',

  SCRIPT_ERR_UNSATISFIED_LOCKTIME = 'SCRIPT_ERR_UNSATISFIED_LOCKTIME',

  SCRIPT_ERR_TAPSCRIPT_MINIMALIF = 'SCRIPT_ERR_TAPSCRIPT_MINIMALIF',

  SCRIPT_ERR_MINIMALIF = 'SCRIPT_ERR_MINIMALIF',

  SCRIPT_ERR_VERIFY = 'SCRIPT_ERR_VERIFY',

  SCRIPT_ERR_OP_RETURN = 'SCRIPT_ERR_OP_RETURN',

  SCRIPT_ERR_EQUALVERIFY = 'SCRIPT_ERR_EQUALVERIFY',

  SCRIPT_ERR_NUMEQUALVERIFY = 'SCRIPT_ERR_NUMEQUALVERIFY',

  SCRIPT_ERR_INVALID_ALTSTACK_OPERATION = 'SCRIPT_ERR_INVALID_ALTSTACK_OPERATION',

  SCRIPT_ERR_CHECKSIGVERIFY = 'SCRIPT_ERR_CHECKSIGVERIFY',
  SCRIPT_ERR_BAD_OPCODE = 'SCRIPT_ERR_BAD_OPCODE',
  SCRIPT_ERR_PUBKEY_COUNT = 'SCRIPT_ERR_PUBKEY_COUNT',
  SCRIPT_ERR_SIG_COUNT = 'SCRIPT_ERR_SIG_COUNT',
  SCRIPT_ERR_NULLFAIL = 'SCRIPT_ERR_NULLFAIL',
  SCRIPT_ERR_SIG_NULLDUMMY = 'SCRIPT_ERR_SIG_NULLDUMMY',
  SCRIPT_ERR_CHECKMULTISIGVERIFY = 'SCRIPT_ERR_CHECKMULTISIGVERIFY',
  SCRIPT_ERR_SIG_NULLFAIL = 'SCRIPT_ERR_SIG_NULLFAIL',
  SCRIPT_ERR_SIG_FINDANDDELETE = 'SCRIPT_ERR_SIG_FINDANDDELETE',

  SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT = 'SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT',
  SCRIPT_ERR_PUBKEYTYPE = 'SCRIPT_ERR_PUBKEYTYPE',
  SCRIPT_ERR_SCHNORR_SIG = 'SCRIPT_ERR_SCHNORR_SIG',
  SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE = 'SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE',
  SCRIPT_ERR_WITNESS_PUBKEYTYPE = 'SCRIPT_ERR_WITNESS_PUBKEYTYPE',
  SCRIPT_ERR_SIG_HASHTYPE = 'SCRIPT_ERR_SIG_HASHTYPE',
  SCRIPT_ERR_SIG_DER_HIGH_S = 'SCRIPT_ERR_SIG_DER_HIGH_S',
  SCRIPT_ERR_SIG_DER_INVALID_FORMAT = 'SCRIPT_ERR_SIG_DER_INVALID_FORMAT',
  SCRIPT_ERR_WITNESS_MALLEATED = 'SCRIPT_ERR_WITNESS_MALLEATED',
  SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY = 'SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY',
  SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH = 'SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH',
  SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH = 'SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH',
  SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE = 'SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE',

  SCRIPT_ERR_DISCOURAGE_OP_SUCCESS = 'SCRIPT_ERR_DISCOURAGE_OP_SUCCESS',
  SCRIPT_ERR_STACK_SIZE = 'SCRIPT_ERR_STACK_SIZE',

  SCRIPT_ERR_EVAL_FALSE = 'SCRIPT_ERR_EVAL_FALSE',
  SCRIPT_ERR_EVAL_FALSE_IN_STACK = 'SCRIPT_ERR_EVAL_FALSE_IN_STACK',
  SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = 'SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM',
  SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION = 'SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION',
  SCRIPT_ERR_SCHNORR_SIG_SIZE = 'SCRIPT_ERR_SCHNORR_SIG_SIZE',
  SCRIPT_ERR_SCHNORR_SIG_HASHTYPE = 'SCRIPT_ERR_SCHNORR_SIG_HASHTYPE',
  SCRIPT_ERR_SCHNORR_SIG_NO_PREVOUTS = 'SCRIPT_ERR_SCHNORR_SIG_NO_PREVOUTS',
  SCRIPT_ERR_EVAL_FALSE_NO_P2SH_STACK = 'SCRIPT_ERR_EVAL_FALSE_NO_P2SH_STACK',
  SCRIPT_ERR_EVAL_FALSE_IN_P2SH_STACK = 'SCRIPT_ERR_EVAL_FALSE_IN_P2SH_STACK',
  SCRIPT_ERR_WITNESS_MALLEATED_P2SH = 'SCRIPT_ERR_WITNESS_MALLEATED_P2SH',
  SCRIPT_ERR_UNKNOWN_ERROR = 'SCRIPT_ERR_UNKNOWN_ERROR',
}

export class Interpreter {
  static readonly MAX_SCRIPT_SIZE = 10000;
  static readonly MAX_STACK_SIZE = 1000;
  static readonly MAX_SCRIPT_ELEMENT_SIZE = 520;

  static readonly LOCKTIME_THRESHOLD = 500000000;

  // flags taken from bitcoind
  // bitcoind commit: b5d1b1092998bc95313856d535c632ea5a8f9104
  static readonly SCRIPT_VERIFY_NONE = 0;

  // Evaluate P2SH subscripts (softfork safe, BIP16).
  static readonly SCRIPT_VERIFY_P2SH = 1 << 0;

  // Passing a non-strict-DER signature or one with undefined hashtype to a checksig operation causes script failure.
  // Passing a pubkey that is not (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes) to checksig causes that pubkey to be
  // skipped (not softfork safe: this flag can widen the validity of OP_CHECKSIG OP_NOT).
  static readonly SCRIPT_VERIFY_STRICTENC = 1 << 1;

  // Passing a non-strict-DER signature to a checksig operation causes script failure (softfork safe, BIP62 rule 1)
  static readonly SCRIPT_VERIFY_DERSIG = 1 << 2;

  // Passing a non-strict-DER signature or one with S > order/2 to a checksig operation causes script failure
  // (softfork safe, BIP62 rule 5).
  static readonly SCRIPT_VERIFY_LOW_S = 1 << 3;

  // verify dummy stack item consumed by CHECKMULTISIG is of zero-length (softfork safe, BIP62 rule 7).
  static readonly SCRIPT_VERIFY_NULLDUMMY = 1 << 4;

  // Using a non-push operator in the scriptSig causes script failure (softfork safe, BIP62 rule 2).
  static readonly SCRIPT_VERIFY_SIGPUSHONLY = 1 << 5;

  // Require minimal encodings for all push operations (OP_0... OP_16, OP_1NEGATE where possible, direct
  // pushes up to 75 bytes, OP_PUSHDATA up to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating
  // any other push causes the script to fail (BIP62 rule 3).
  // In addition, whenever a stack element is interpreted as a number, it must be of minimal length (BIP62 rule 4).
  // (softfork safe)
  static readonly SCRIPT_VERIFY_MINIMALDATA = 1 << 6;

  // Discourage use of NOPs reserved for upgrades (NOP1-10)
  //
  // Provided so that nodes can avoid accepting or mining transactions
  // containing executed NOP's whose meaning may change after a soft-fork,
  // thus rendering the script invalid; with this flag set executing
  // discouraged NOPs fails the script. This verification flag will never be
  // a mandatory flag applied to scripts in a block. NOPs that are not
  // executed, e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
  static readonly SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = 1 << 7;

  // Require that only a single stack element remains after evaluation. This
  // changes the success criterion from "At least one stack element must
  // remain, and when interpreted as a boolean, it must be true" to "Exactly
  // one stack element must remain, and when interpreted as a boolean, it must
  // be true".
  // (softfork safe, BIP62 rule 6)
  // Note: CLEANSTACK should never be used without P2SH or WITNESS.
  static readonly SCRIPT_VERIFY_CLEANSTACK = 1 << 8;

  // Verify CHECKLOCKTIMEVERIFY
  //
  // See BIP65 for details.
  static readonly SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = 1 << 9;

  // support CHECKSEQUENCEVERIFY opcode
  //
  // See BIP112 for details
  static readonly SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = 1 << 10;

  // Support segregated witness
  //
  static readonly SCRIPT_VERIFY_WITNESS = 1 << 11;

  // Making v1-v16 witness program non-standard
  //
  static readonly SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = 1 << 12;

  //
  // Segwit script only: Require the argument of OP_IF/NOTIF to be exactly
  // 0x01 or empty vector
  //
  static readonly SCRIPT_VERIFY_MINIMALIF = 1 << 13;

  // Signature(s) must be empty vector if an CHECK(MULTI)SIG operation failed
  //
  static readonly SCRIPT_VERIFY_NULLFAIL = 1 << 14;

  // Public keys in scripts must be compressed
  //
  static readonly SCRIPT_VERIFY_WITNESS_PUBKEYTYPE = 1 << 15;

  // Do we accept signature using SIGHASH_FORKID
  //
  static readonly SCRIPT_ENABLE_SIGHASH_FORKID = 1 << 16;

  // Do we accept activate replay protection using a different fork id.
  //
  static readonly SCRIPT_ENABLE_REPLAY_PROTECTION = 1 << 17;

  // Making OP_CODESEPARATOR and FindAndDelete fail any non-segwit scripts
  //
  static readonly SCRIPT_VERIFY_CONST_SCRIPTCODE = 1 << 16;

  // Verify taproot script
  //
  static readonly SCRIPT_VERIFY_TAPROOT = 1 << 17;

  // Making unknown Taproot leaf versions non-standard
  //
  static readonly SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION = 1 << 18;

  // Making unknown OP_SUCCESS non-standard
  static readonly SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS = 1 << 19;

  // Making unknown public key versions (in BIP 342 scripts) non-standard
  static readonly SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE = 1 << 20;

  /* Below flags apply in the context of BIP 68*/
  /**
   * If this flag set, CTxIn::nSequence is NOT interpreted as a relative
   * lock-time.
   */
  static readonly SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31;

  /**
   * If CTxIn::nSequence encodes a relative lock-time and this flag is set,
   * the relative lock-time has units of 512 seconds, otherwise it specifies
   * blocks with a granularity of 1.
   */
  static readonly SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22;

  /**
   * If CTxIn::nSequence encodes a relative lock-time, this mask is applied to
   * extract that lock-time from the sequence field.
   */
  static readonly SEQUENCE_LOCKTIME_MASK = 0x0000ffff;

  /** Signature hash sizes */
  static readonly WITNESS_V0_SCRIPTHASH_SIZE = 32;
  static readonly WITNESS_V0_KEYHASH_SIZE = 20;
  static readonly WITNESS_V1_TAPROOT_SIZE = 32;

  static readonly TAPROOT_LEAF_MASK = 0xfe;
  static readonly TAPROOT_LEAF_TAPSCRIPT = 0xc0;
  static readonly TAPROOT_CONTROL_BASE_SIZE = 33;
  static readonly TAPROOT_CONTROL_NODE_SIZE = 32;
  static readonly TAPROOT_CONTROL_MAX_NODE_COUNT = 128;

  // Validation weight per passing signature (Tapscript only, see BIP 342).
  static readonly VALIDATION_WEIGHT_PER_SIGOP_PASSED = 50;
  // How much weight budget is added to the witness size (Tapscript only, see BIP 342).
  static readonly VALIDATION_WEIGHT_OFFSET = 50;
  // Tag for input annex. If there are at least two witness elements for a transaction input,
  // and the first byte of the last element is 0x50, this last element is called annex, and
  // has meanings independent of the script
  static readonly ANNEX_TAG = 0x50;

  static readonly TRUE = Uint8Array.from([1]);
  static readonly FALSE = Uint8Array.from([]);

  static readonly TAPROOT_CONTROL_MAX_SIZE =
    Interpreter.TAPROOT_CONTROL_BASE_SIZE +
    Interpreter.TAPROOT_CONTROL_NODE_SIZE *
      Interpreter.TAPROOT_CONTROL_MAX_NODE_COUNT;

  // Conceptually, this doesn't really belong with the Interpreter, but I haven't found a better place for it.
  static readonly PROTOCOL_VERSION = 70016;
  private sigversion: SignatureVersion = SignatureVersion.BASE;
  private errstr: InterpreterErr = InterpreterErr.NONE;

  private stack: Uint8Array[] = [];

  private altstack: Uint8Array[] = [];

  private vfExec: boolean[] = [];

  private pc: number = 0;

  private pbegincodehash: number = 0;

  private satoshis: number = 0;
  private nOpCount: number = 0;

  private flags: number = 0;

  private execdata: any = {};

  private script: Array<number | Uint8Array> = [];

  private tx: Transaction = new Transaction();

  private prevOuts: Output[] | undefined = undefined;

  private nin: number = 0;

  constructor() {
    this.initialize();
  }

  getErr(): InterpreterErr {
    return this.errstr;
  }

  initialize() {
    this.stack = [];
    this.altstack = [];
    this.pc = 0;
    this.sigversion = SignatureVersion.BASE;
    this.satoshis = 0;
    this.pbegincodehash = 0;
    this.nOpCount = 0;
    this.vfExec = [];
    this.errstr = InterpreterErr.NONE;
    this.flags = 0;
    this.execdata = {};
  }

  setScript(script: Uint8Array | Array<number | Uint8Array>) {
    if (script instanceof Uint8Array) {
      const res = bscript.decompile(script);
      if (res === null) {
        return false;
      }
      this.script = res;
    } else {
      this.script = script;
    }
    return true;
  }

  setTx(tx: Transaction) {
    this.tx = tx;
  }

  setPrevOuts(prevOuts: Output[] | undefined) {
    if (Array.isArray(prevOuts)) {
      this.prevOuts = prevOuts;
    } else {
      this.prevOuts = undefined;
    }
  }

  setNin(nin: number) {
    this.nin = nin;
  }

  setFlags(flags: number) {
    this.flags = flags;
  }

  setStack(stack: Uint8Array[]) {
    this.stack = stack;
  }

  setSigversion(sigversion: SignatureVersion) {
    this.sigversion = sigversion;
  }

  setSatoshis(satoshis: number) {
    this.satoshis = satoshis;
  }

  setExecdata(execdata: any) {
    this.execdata = execdata;
  }

  verify(
    scriptSig: Uint8Array,
    scriptPubkey: Uint8Array,
    tx: Transaction = new Transaction(),
    nin: number = 0,
    flags: number = 0,
    witness: Uint8Array[] = [],
    satoshis: number = 0,
    prevOuts?: Output[],
  ) {
    if (!this.setScript(scriptSig)) {
      return false;
    }

    this.setTx(tx);
    this.setNin(nin);
    this.setFlags(flags);
    this.setPrevOuts(prevOuts);

    let stackCopy: Uint8Array[] = [];

    if (
      (flags & Interpreter.SCRIPT_VERIFY_SIGPUSHONLY) !== 0 &&
      !bscript.isPushOnly(this.script)
    ) {
      this.errstr = InterpreterErr.SCRIPT_ERR_SIG_PUSHONLY;
      return false;
    }

    // evaluate scriptSig
    if (!this.evaluate()) {
      return false;
    }

    if (flags & Interpreter.SCRIPT_VERIFY_P2SH) {
      stackCopy = this.stack.slice();
    }

    let stack = this.stack;
    this.initialize();
    this.setStack(stack);
    this.setTx(tx);
    this.setPrevOuts(prevOuts);
    this.setNin(nin);
    this.setFlags(flags);

    if (!this.setScript(scriptPubkey)) {
      return false;
    }

    // evaluate scriptPubkey
    if (!this.evaluate()) {
      return false;
    }

    if (this.stack.length === 0) {
      this.errstr = InterpreterErr.SCRIPT_ERR_EVAL_FALSE_NO_RESULT;
      return false;
    }

    const buf = this.stack[this.stack.length - 1];
    if (!Interpreter.castToBool(buf)) {
      this.errstr = InterpreterErr.SCRIPT_ERR_EVAL_FALSE_NO_RESULT;
      return false;
    }

    // SCRIPT_VERIFY_WITNESS
    let hadWitness = false;
    if (flags & Interpreter.SCRIPT_VERIFY_WITNESS) {
      const witnessProgram = bscript.createWitnessProgram(scriptPubkey);
      if (witnessProgram) {
        hadWitness = true;
        if (scriptSig.length !== 0) {
          this.errstr = InterpreterErr.SCRIPT_ERR_WITNESS_MALLEATED;
          return false;
        }
        if (
          !this.verifyWitnessProgram(
            witnessProgram.version,
            witnessProgram.program,
            witness,
            satoshis,
            this.flags,
            /* isP2SH */ false,
          )
        ) {
          return false;
        }
      }
    }
    // Additional validation for spend-to-script-hash transactions:
    if (
      flags & Interpreter.SCRIPT_VERIFY_P2SH &&
      bscript.isScriptHashOut(scriptPubkey)
    ) {
      // scriptSig must be literals-only or validation fails
      if (!bscript.isPushOnly(scriptSig)) {
        this.errstr = InterpreterErr.SCRIPT_ERR_SIG_PUSHONLY;
        return false;
      }

      // stackCopy cannot be empty here, because if it was the
      // P2SH  HASH <> EQUAL  scriptPubKey would be evaluated with
      // an empty stack and the EvalScript above would return false.
      if (stackCopy.length === 0) {
        throw new Error('internal error - stack copy empty');
      }

      const redeemScript = stackCopy[stackCopy.length - 1];
      stackCopy.pop();

      this.initialize();
      this.setScript(redeemScript);
      this.setStack(stackCopy);
      this.setTx(tx);
      this.setPrevOuts(prevOuts);
      this.setNin(nin);
      this.setFlags(flags);

      // evaluate redeemScript
      if (!this.evaluate()) {
        return false;
      }

      if (stackCopy.length === 0) {
        this.errstr = InterpreterErr.SCRIPT_ERR_EVAL_FALSE_NO_P2SH_STACK;
        return false;
      }

      if (!Interpreter.castToBool(stackCopy[stackCopy.length - 1])) {
        this.errstr = InterpreterErr.SCRIPT_ERR_EVAL_FALSE_IN_P2SH_STACK;
        return false;
      }
      if (flags & Interpreter.SCRIPT_VERIFY_WITNESS) {
        const p2shWitnessValues = bscript.createWitnessProgram(redeemScript);
        if (p2shWitnessValues) {
          hadWitness = true;
          const bw = BufferWriter.withCapacity(varSliceSize(redeemScript));
          bw.writeVarSlice(redeemScript);
          if (tools.toHex(scriptSig) !== tools.toHex(bw.end())) {
            this.errstr = InterpreterErr.SCRIPT_ERR_WITNESS_MALLEATED_P2SH;
            return false;
          }

          if (
            !this.verifyWitnessProgram(
              p2shWitnessValues.version,
              p2shWitnessValues.program,
              witness,
              satoshis,
              this.flags,
              /* isP2SH */ true,
            )
          ) {
            return false;
          }
          // Bypass the cleanstack check at the end. The actual stack is obviously not clean
          // for witness programs.
          stack = [stack[0]];
        }
      }
    }
    // The CLEANSTACK check is only performed after potential P2SH evaluation,
    // as the non-P2SH evaluation of a P2SH script will obviously not result in
    // a clean stack (the P2SH inputs remain). The same holds for witness
    // evaluation.
    if ((this.flags & Interpreter.SCRIPT_VERIFY_CLEANSTACK) != 0) {
      // Disallow CLEANSTACK without P2SH, as otherwise a switch
      // CLEANSTACK->P2SH+CLEANSTACK would be possible, which is not a
      // softfork (and P2SH should be one).
      if (
        (this.flags & Interpreter.SCRIPT_VERIFY_P2SH) == 0 ||
        (this.flags & Interpreter.SCRIPT_VERIFY_WITNESS) == 0
      ) {
        throw 'flags & SCRIPT_VERIFY_P2SH';
      }

      if (stackCopy.length != 1) {
        this.errstr = InterpreterErr.SCRIPT_ERR_CLEANSTACK;
        return false;
      }
    }

    if (this.flags & Interpreter.SCRIPT_VERIFY_WITNESS) {
      if (!hadWitness && witness.length > 0) {
        this.errstr = InterpreterErr.SCRIPT_ERR_WITNESS_UNEXPECTED;
        return false;
      }
    }

    return true;
  }

  verifyWitnessProgram(
    version: number,
    program: Uint8Array,
    witness: Uint8Array[],
    satoshis: number,
    flags: number,
    isP2SH: boolean = false,
  ) {
    let scriptPubKey: Array<number | Uint8Array> = [];
    let stack: Array<Uint8Array> = [];

    if (version === 0) {
      if (program.length === Interpreter.WITNESS_V0_SCRIPTHASH_SIZE) {
        if (witness.length === 0) {
          this.errstr = InterpreterErr.SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY;
          return false;
        }

        const scriptPubKeyBuffer = witness[witness.length - 1];
        const res = bscript.decompile(scriptPubKeyBuffer);
        if (res === null) {
          this.errstr = InterpreterErr.SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY;
          return false;
        }
        scriptPubKey = res;
        const hash = sha256(scriptPubKeyBuffer);
        if (tools.toHex(hash) !== tools.toHex(program)) {
          this.errstr = InterpreterErr.SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH;
          return false;
        }

        stack = witness.slice(0, -1);
        return this.executeWitnessScript(
          scriptPubKey,
          stack,
          SignatureVersion.WITNESS_V0,
          satoshis,
          flags,
          {},
        );
      } else if (program.length === Interpreter.WITNESS_V0_KEYHASH_SIZE) {
        if (witness.length !== 2) {
          this.errstr = InterpreterErr.SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH;
          return false;
        }

        scriptPubKey.push(bscript.OPS.OP_DUP);
        scriptPubKey.push(bscript.OPS.OP_HASH160);
        scriptPubKey.push(program);
        scriptPubKey.push(bscript.OPS.OP_EQUALVERIFY);
        scriptPubKey.push(bscript.OPS.OP_CHECKSIG);

        stack = witness;
        return this.executeWitnessScript(
          scriptPubKey,
          stack,
          SignatureVersion.WITNESS_V0,
          satoshis,
          flags,
          {},
        );
      } else {
        this.errstr = InterpreterErr.SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH;
        return false;
      }
    } else if (
      version === 1 &&
      program.length == Interpreter.WITNESS_V1_TAPROOT_SIZE &&
      !isP2SH
    ) {
      const execdata = {
        annexPresent: false,
        annex: Uint8Array.from([]),
        annexInit: false,
        tapleafHash: Uint8Array.from([]),
        tapleafHashInit: false,
        validationWeightLeft: 0,
        validationWeightLeftInit: false,
      };
      // BIP341 Taproot: 32-byte non-P2SH witness v1 program (which encodes a P2C-tweaked pubkey)
      if (!(flags & Interpreter.SCRIPT_VERIFY_TAPROOT)) {
        return true;
      }
      stack = Array.from(witness);
      if (stack.length == 0) {
        this.errstr = InterpreterErr.SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY;
        return false;
      }
      if (
        stack.length >= 2 &&
        stack[stack.length - 1].length &&
        stack[stack.length - 1][0] === Interpreter.ANNEX_TAG
      ) {
        // Drop annex (this is non-standard; see IsWitnessStandard)
        const annex = stack.pop() as Uint8Array;
        execdata.annex = annex;
        execdata.annexPresent = true;
      }
      execdata.annexInit = true;
      if (stack.length === 1) {
        // Key path spending (stack size is 1 after removing optional annex)
        return this.checkSchnorrSignature(
          stack[0],
          program,
          SignatureVersion.TAPROOT,
          execdata,
        );
      } else {
        // Script path spending (stack size is >1 after removing optional annex)
        const control = stack.pop() as Uint8Array;
        const scriptPubKeyBuf = stack.pop() as Uint8Array;

        if (
          control.length < Interpreter.TAPROOT_CONTROL_BASE_SIZE ||
          control.length > Interpreter.TAPROOT_CONTROL_MAX_SIZE ||
          (control.length - Interpreter.TAPROOT_CONTROL_BASE_SIZE) %
            Interpreter.TAPROOT_CONTROL_NODE_SIZE !=
            0
        ) {
          this.errstr = InterpreterErr.SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE;
          return false;
        }
        execdata.tapleafHash = Interpreter.computeTapleafHash(
          control[0] & Interpreter.TAPROOT_LEAF_MASK,
          scriptPubKeyBuf,
        );
        if (
          !Interpreter.verifyTaprootCommitment(
            control,
            program,
            execdata.tapleafHash,
          )
        ) {
          this.errstr = InterpreterErr.SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH;
          return false;
        }
        execdata.tapleafHashInit = true;
        if (
          (control[0] & Interpreter.TAPROOT_LEAF_MASK) ===
          Interpreter.TAPROOT_LEAF_TAPSCRIPT
        ) {
          // Tapscript (leaf version 0xc0)
          let witnessSize;
          {
            const bw = BufferWriter.withCapacity(vectorSize(witness));
            bw.writeVarInt(witness.length);
            for (const element of witness) {
              bw.writeVarSlice(element);
            }
            witnessSize = bw.end().length;
          }

          const res = bscript.decompile(scriptPubKeyBuf);
          if (res === null) {
            // Note how this condition would not be reached if an unknown OP_SUCCESSx was found
            this.errstr = InterpreterErr.SCRIPT_ERR_BAD_OPCODE;
            return false;
          }

          scriptPubKey = res;

          execdata.validationWeightLeft =
            witnessSize + Interpreter.VALIDATION_WEIGHT_OFFSET;
          execdata.validationWeightLeftInit = true;
          return this.executeWitnessScript(
            scriptPubKey,
            stack,
            SignatureVersion.TAPSCRIPT,
            satoshis,
            flags,
            execdata,
          );
        }
        // If none of the above conditions are met then this must be an upgraded taproot version.
        if (
          flags &
          Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
        ) {
          this.errstr =
            InterpreterErr.SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION;
          return false;
        }
        // Future softfork compatibility
        return true;
      }
    } else if (
      flags & Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
    ) {
      this.errstr =
        InterpreterErr.SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM;
      return false;
    }
    // Other version/size/p2sh combinations return true for future softfork compatibility
    return true;
  }

  executeWitnessScript(
    scriptPubKey: Array<number | Uint8Array>,
    stack: Array<Uint8Array>,
    sigversion: SignatureVersion,
    satoshis: number,
    flags: number,
    execdata: any,
  ) {
    if (sigversion === SignatureVersion.TAPSCRIPT) {
      for (const chunk of scriptPubKey) {
        // New opcodes will be listed here. May use a different sigversion to modify existing opcodes.
        if (typeof chunk === 'number' && isOpSuccess(chunk)) {
          if (flags & Interpreter.SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS) {
            this.errstr = InterpreterErr.SCRIPT_ERR_DISCOURAGE_OP_SUCCESS;
            return false;
          }
          return true;
        }
      }

      // Tapscript enforces initial stack size limits (altstack is empty here)
      if (stack.length > Interpreter.MAX_STACK_SIZE) {
        this.errstr = InterpreterErr.SCRIPT_ERR_STACK_SIZE;
        return false;
      }
    }

    // Disallow stack item size > MAX_SCRIPT_ELEMENT_SIZE in witness stack
    if (
      stack.length &&
      stack.some(elem => elem.length > Interpreter.MAX_SCRIPT_ELEMENT_SIZE)
    ) {
      this.errstr = InterpreterErr.SCRIPT_ERR_PUSH_SIZE;
      return false;
    }

    this.initialize();

    this.setScript(scriptPubKey);
    this.setStack(stack);
    this.setSigversion(sigversion);
    this.setSatoshis(satoshis);
    this.setFlags(flags);
    this.setExecdata(execdata);

    if (!this.evaluate()) {
      return false;
    }

    if (this.stack.length !== 1) {
      this.errstr = InterpreterErr.SCRIPT_ERR_EVAL_FALSE;
      return false;
    }

    const buf = this.stack[this.stack.length - 1];
    if (!Interpreter.castToBool(buf)) {
      this.errstr = InterpreterErr.SCRIPT_ERR_EVAL_FALSE_IN_STACK;
      return false;
    }

    return true;
  }

  /**
   * Based on bitcoind's EvalScript function, with the inner loop moved to
   * static readonly prototype.step()
   * bitcoind commit: b5d1b1092998bc95313856d535c632ea5a8f9104
   */
  evaluate() {
    // sigversion cannot be TAPROOT here, as it admits no script execution.
    requireTrue(
      this.sigversion == SignatureVersion.BASE ||
        this.sigversion == SignatureVersion.WITNESS_V0 ||
        this.sigversion == SignatureVersion.TAPSCRIPT,
      'invalid sigversion',
    );

    if (
      (this.sigversion == SignatureVersion.BASE ||
        this.sigversion == SignatureVersion.WITNESS_V0) &&
      this.script.length > Interpreter.MAX_SCRIPT_SIZE
    ) {
      this.errstr = InterpreterErr.SCRIPT_ERR_SCRIPT_SIZE;
      return false;
    }

    try {
      while (this.pc < this.script.length) {
        const fSuccess = this.step();
        if (!fSuccess) {
          return false;
        }
      }
    } catch (e) {
      this.errstr = InterpreterErr.SCRIPT_ERR_UNKNOWN_ERROR;
      return false;
    }

    if (this.vfExec.length > 0) {
      this.errstr = InterpreterErr.SCRIPT_ERR_UNBALANCED_CONDITIONAL;
      return false;
    }

    return true;
  }

  static castToBool(buf: Uint8Array) {
    for (let i = 0; i < buf.length; i++) {
      if (buf[i] !== 0) {
        // can be negative zero
        if (i === buf.length - 1 && buf[i] === 0x80) {
          return false;
        }
        return true;
      }
    }
    return false;
  }

  step() {
    const fRequireMinimal =
      (this.flags & Interpreter.SCRIPT_VERIFY_MINIMALDATA) !== 0;

    //bool fExec = !count(vfExec.begin(), vfExec.end(), false);
    const fExec = this.vfExec.indexOf(false) === -1;
    let buf: Uint8Array,
      buf1: Uint8Array,
      buf2: Uint8Array,
      spliced,
      n,
      x1,
      x2,
      bn: bigint,
      bn1: bigint,
      bn2: bigint,
      bufSig: Uint8Array,
      bufPubkey: Uint8Array;
    //let sig, pubkey;
    let fValue, fSuccess;
    this.execdata = this.execdata || {};
    if (!this.execdata.codeseparatorPosInit) {
      this.execdata.codeseparatorPos = 0xffffffff;
      this.execdata.codeseparatorPosInit = true;
    }

    // Read instruction
    const chunk = this.script[this.pc];
    this.pc++;

    if (!(chunk instanceof Uint8Array || typeof chunk === 'number')) {
      this.errstr = InterpreterErr.SCRIPT_ERR_UNDEFINED_OPCODE;
      return false;
    }

    if (
      chunk instanceof Uint8Array &&
      chunk.length > Interpreter.MAX_SCRIPT_ELEMENT_SIZE
    ) {
      this.errstr = InterpreterErr.SCRIPT_ERR_PUSH_SIZE;
      return false;
    }
    const opcodenum =
      chunk instanceof Uint8Array ? toPushdataCode(chunk.length) : chunk;
    if (
      this.sigversion === SignatureVersion.BASE ||
      this.sigversion === SignatureVersion.WITNESS_V0
    ) {
      // Note how Opcode.OP_RESERVED does not count towards the opcode limit.
      if (opcodenum > bscript.OPS.OP_16 && ++this.nOpCount > 201) {
        this.errstr = InterpreterErr.SCRIPT_ERR_OP_COUNT;
        return false;
      }
    }

    if (
      opcodenum === bscript.OPS.OP_SUBSTR ||
      opcodenum === bscript.OPS.OP_LEFT ||
      opcodenum === bscript.OPS.OP_RIGHT ||
      opcodenum === bscript.OPS.OP_INVERT ||
      opcodenum === bscript.OPS.OP_AND ||
      opcodenum === bscript.OPS.OP_OR ||
      opcodenum === bscript.OPS.OP_XOR ||
      opcodenum === bscript.OPS.OP_2MUL ||
      opcodenum === bscript.OPS.OP_2DIV ||
      opcodenum === bscript.OPS.OP_MUL ||
      opcodenum === bscript.OPS.OP_DIV ||
      opcodenum === bscript.OPS.OP_MOD ||
      opcodenum === bscript.OPS.OP_LSHIFT ||
      opcodenum === bscript.OPS.OP_RSHIFT
    ) {
      this.errstr = InterpreterErr.SCRIPT_ERR_DISABLED_OPCODE;
      return false;
    }

    // With SCRIPT_VERIFY_CONST_SCRIPTCODE, OP_CODESEPARATOR in non-segwit script is rejected even in an unexecuted branch
    if (
      opcodenum == bscript.OPS.OP_CODESEPARATOR &&
      this.sigversion === SignatureVersion.BASE &&
      this.flags & Interpreter.SCRIPT_VERIFY_CONST_SCRIPTCODE
    ) {
      this.errstr = InterpreterErr.SCRIPT_ERR_OP_CODESEPARATOR;
      return false;
    }

    if (fExec && 0 <= opcodenum && opcodenum <= bscript.OPS.OP_PUSHDATA4) {
      if (chunk instanceof Uint8Array) {
        this.stack.push(chunk);
      } else if (opcodenum === 0) {
        this.stack.push(Interpreter.FALSE);
      } else {
        this.errstr = InterpreterErr.SCRIPT_ERR_MINIMALDATA;
        return false;
      }
    } else if (
      fExec ||
      (bscript.OPS.OP_IF <= opcodenum && opcodenum <= bscript.OPS.OP_ENDIF)
    ) {
      switch (opcodenum) {
        // Push value
        case bscript.OPS.OP_1NEGATE:
        case bscript.OPS.OP_1:
        case bscript.OPS.OP_2:
        case bscript.OPS.OP_3:
        case bscript.OPS.OP_4:
        case bscript.OPS.OP_5:
        case bscript.OPS.OP_6:
        case bscript.OPS.OP_7:
        case bscript.OPS.OP_8:
        case bscript.OPS.OP_9:
        case bscript.OPS.OP_10:
        case bscript.OPS.OP_11:
        case bscript.OPS.OP_12:
        case bscript.OPS.OP_13:
        case bscript.OPS.OP_14:
        case bscript.OPS.OP_15:
        case bscript.OPS.OP_16:
          {
            // ( -- value)
            // ScriptNum bn((int)opcode - (int)(Opcode.OP_1 - 1));
            n = opcodenum - (bscript.OPS.OP_1 - 1);
            buf = bn2Buf(BigInt(n));
            this.stack.push(buf);
            // The result of these opcodes should always be the minimal way to push the data
            // they push, so no need for a CheckMinimalPush here.
          }
          break;

        //
        // Control
        //
        case bscript.OPS.OP_NOP:
          break;

        case bscript.OPS.OP_NOP2:
        case bscript.OPS.OP_CHECKLOCKTIMEVERIFY:
          if (!(this.flags & Interpreter.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)) {
            // not enabled; treat as a NOP2
            if (
              this.flags & Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS
            ) {
              this.errstr =
                InterpreterErr.SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS;
              return false;
            }
            break;
          }

          if (this.stack.length < 1) {
            this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
            return false;
          }

          // Note that elsewhere numeric opcodes are limited to
          // operands in the range -2**31+1 to 2**31-1, however it is
          // legal for opcodes to produce results exceeding that
          // range. This limitation is implemented by CScriptNum's
          // default 4-byte limit.
          //
          // If we kept to that limit we'd have a year 2038 problem,
          // even though the nLockTime field in transactions
          // themselves is uint32 which only becomes meaningless
          // after the year 2106.
          //
          // Thus as a special case we tell CScriptNum to accept up
          // to 5-byte bignums, which are good until 2**39-1, well
          // beyond the 2**32-1 limit of the nLockTime field itself.
          const nLockTime = buf2BN(
            this.stack[this.stack.length - 1],
            fRequireMinimal,
            5,
          );

          // In the rare event that the argument may be < 0 due to
          // some arithmetic being done first, you can always use
          // 0 MAX CHECKLOCKTIMEVERIFY.
          if (nLockTime < BigInt(0)) {
            this.errstr = InterpreterErr.SCRIPT_ERR_NEGATIVE_LOCKTIME;
            return false;
          }

          // Actually compare the specified lock time with the transaction.
          if (!this.checkLockTime(nLockTime)) {
            this.errstr = InterpreterErr.SCRIPT_ERR_UNSATISFIED_LOCKTIME;
            return false;
          }
          break;

        case bscript.OPS.OP_NOP3:
        case bscript.OPS.OP_CHECKSEQUENCEVERIFY:
          if (!(this.flags & Interpreter.SCRIPT_VERIFY_CHECKSEQUENCEVERIFY)) {
            // not enabled; treat as a NOP3
            if (
              this.flags & Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS
            ) {
              this.errstr =
                InterpreterErr.SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS;
              return false;
            }
            break;
          }

          if (this.stack.length < 1) {
            this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
            return false;
          }

          // nSequence, like nLockTime, is a 32-bit unsigned
          // integer field. See the comment in CHECKLOCKTIMEVERIFY
          // regarding 5-byte numeric operands.

          const nSequence = buf2BN(
            this.stack[this.stack.length - 1],
            fRequireMinimal,
            5,
          );

          // In the rare event that the argument may be < 0 due to
          // some arithmetic being done first, you can always use
          // 0 MAX CHECKSEQUENCEVERIFY.
          if (nSequence < BigInt(0)) {
            this.errstr = InterpreterErr.SCRIPT_ERR_NEGATIVE_LOCKTIME;
            return false;
          }

          // To provide for future soft-fork extensibility, if the
          // operand has the disabled lock-time flag set,
          // CHECKSEQUENCEVERIFY behaves as a NOP.
          if (
            (Number(nSequence) & Interpreter.SEQUENCE_LOCKTIME_DISABLE_FLAG) !=
            0
          ) {
            break;
          }

          // Actually compare the specified lock time with the transaction.
          if (!this.checkSequence(nSequence)) {
            this.errstr = InterpreterErr.SCRIPT_ERR_UNSATISFIED_LOCKTIME;
            return false;
          }
          break;

        case bscript.OPS.OP_NOP1:
        case bscript.OPS.OP_NOP4:
        case bscript.OPS.OP_NOP5:
        case bscript.OPS.OP_NOP6:
        case bscript.OPS.OP_NOP7:
        case bscript.OPS.OP_NOP8:
        case bscript.OPS.OP_NOP9:
        case bscript.OPS.OP_NOP10:
          {
            if (
              this.flags & Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS
            ) {
              this.errstr =
                InterpreterErr.SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS;
              return false;
            }
          }
          break;

        case bscript.OPS.OP_IF:
        case bscript.OPS.OP_NOTIF:
          {
            // <expression> if [statements] [else [statements]] endif
            // bool fValue = false;
            fValue = false;
            if (fExec) {
              if (this.stack.length < 1) {
                this.errstr = InterpreterErr.SCRIPT_ERR_UNBALANCED_CONDITIONAL;
                return false;
              }

              buf = this.stack[this.stack.length - 1];

              // Tapscript requires minimal IF/NOTIF inputs as a consensus rule.
              if (this.sigversion === SignatureVersion.TAPSCRIPT) {
                // The input argument to the OP_IF and OP_NOTIF opcodes must be either
                // exactly 0 (the empty vector) or exactly 1 (the one-byte vector with value 1).
                if (buf.length > 1 || (buf.length === 1 && buf[0] !== 1)) {
                  this.errstr = InterpreterErr.SCRIPT_ERR_TAPSCRIPT_MINIMALIF;
                  return false;
                }
              }
              // Under witness v0 rules it is only a policy rule, enabled through SCRIPT_VERIFY_MINIMALIF.
              if (
                this.sigversion === SignatureVersion.WITNESS_V0 &&
                this.flags & Interpreter.SCRIPT_VERIFY_MINIMALIF
              ) {
                buf = this.stack[this.stack.length - 1];
                if (buf.length > 1) {
                  this.errstr = InterpreterErr.SCRIPT_ERR_MINIMALIF;
                  return false;
                }
                if (buf.length == 1 && buf[0] != 1) {
                  this.errstr = InterpreterErr.SCRIPT_ERR_MINIMALIF;
                  return false;
                }
              }
              fValue = Interpreter.castToBool(buf);
              if (opcodenum === bscript.OPS.OP_NOTIF) {
                fValue = !fValue;
              }
              this.stack.pop();
            }
            this.vfExec.push(fValue);
          }
          break;

        case bscript.OPS.OP_ELSE:
          {
            if (this.vfExec.length === 0) {
              this.errstr = InterpreterErr.SCRIPT_ERR_UNBALANCED_CONDITIONAL;
              return false;
            }
            this.vfExec[this.vfExec.length - 1] =
              !this.vfExec[this.vfExec.length - 1];
          }
          break;

        case bscript.OPS.OP_ENDIF:
          {
            if (this.vfExec.length === 0) {
              this.errstr = InterpreterErr.SCRIPT_ERR_UNBALANCED_CONDITIONAL;
              return false;
            }
            this.vfExec.pop();
          }
          break;

        case bscript.OPS.OP_VERIFY:
          {
            // (true -- ) or
            // (false -- false) and return
            if (this.stack.length < 1) {
              this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
              return false;
            }
            buf = this.stack[this.stack.length - 1];
            fValue = Interpreter.castToBool(buf);
            if (fValue) {
              this.stack.pop();
            } else {
              this.errstr = InterpreterErr.SCRIPT_ERR_VERIFY;
              return false;
            }
          }
          break;

        case bscript.OPS.OP_RETURN:
          {
            this.errstr = InterpreterErr.SCRIPT_ERR_OP_RETURN;
            return false;
          }
          break;

        //
        // Stack ops
        //
        case bscript.OPS.OP_TOALTSTACK:
          {
            if (this.stack.length < 1) {
              this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
              return false;
            }
            this.altstack.push(this.stack.pop() as Uint8Array);
          }
          break;

        case bscript.OPS.OP_FROMALTSTACK:
          {
            if (this.altstack.length < 1) {
              this.errstr =
                InterpreterErr.SCRIPT_ERR_INVALID_ALTSTACK_OPERATION;
              return false;
            }
            this.stack.push(this.altstack.pop() as Uint8Array);
          }
          break;

        case bscript.OPS.OP_2DROP:
          {
            // (x1 x2 -- )
            if (this.stack.length < 2) {
              this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
              return false;
            }
            this.stack.pop();
            this.stack.pop();
          }
          break;

        case bscript.OPS.OP_2DUP:
          {
            // (x1 x2 -- x1 x2 x1 x2)
            if (this.stack.length < 2) {
              this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
              return false;
            }
            buf1 = this.stack[this.stack.length - 2];
            buf2 = this.stack[this.stack.length - 1];
            this.stack.push(buf1);
            this.stack.push(buf2);
          }
          break;

        case bscript.OPS.OP_3DUP:
          {
            // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
            if (this.stack.length < 3) {
              this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
              return false;
            }
            buf1 = this.stack[this.stack.length - 3];
            buf2 = this.stack[this.stack.length - 2];
            const buf3 = this.stack[this.stack.length - 1];
            this.stack.push(buf1);
            this.stack.push(buf2);
            this.stack.push(buf3);
          }
          break;

        case bscript.OPS.OP_2OVER:
          {
            // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
            if (this.stack.length < 4) {
              this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
              return false;
            }
            buf1 = this.stack[this.stack.length - 4];
            buf2 = this.stack[this.stack.length - 3];
            this.stack.push(buf1);
            this.stack.push(buf2);
          }
          break;

        case bscript.OPS.OP_2ROT:
          {
            // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
            if (this.stack.length < 6) {
              this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
              return false;
            }
            spliced = this.stack.splice(this.stack.length - 6, 2);
            this.stack.push(spliced[0]);
            this.stack.push(spliced[1]);
          }
          break;

        case bscript.OPS.OP_2SWAP:
          {
            // (x1 x2 x3 x4 -- x3 x4 x1 x2)
            if (this.stack.length < 4) {
              this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
              return false;
            }
            spliced = this.stack.splice(this.stack.length - 4, 2);
            this.stack.push(spliced[0]);
            this.stack.push(spliced[1]);
          }
          break;

        case bscript.OPS.OP_IFDUP:
          {
            // (x - 0 | x x)
            if (this.stack.length < 1) {
              this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
              return false;
            }
            buf = this.stack[this.stack.length - 1];
            fValue = Interpreter.castToBool(buf);
            if (fValue) {
              this.stack.push(buf);
            }
          }
          break;

        case bscript.OPS.OP_DEPTH:
          {
            // -- stacksize
            buf = bn2Buf(BigInt(this.stack.length));
            this.stack.push(buf);
          }
          break;

        case bscript.OPS.OP_DROP:
          {
            // (x -- )
            if (this.stack.length < 1) {
              this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
              return false;
            }
            this.stack.pop();
          }
          break;

        case bscript.OPS.OP_DUP:
          {
            // (x -- x x)
            if (this.stack.length < 1) {
              this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
              return false;
            }
            this.stack.push(this.stack[this.stack.length - 1]);
          }
          break;

        case bscript.OPS.OP_NIP:
          {
            // (x1 x2 -- x2)
            if (this.stack.length < 2) {
              this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
              return false;
            }
            this.stack.splice(this.stack.length - 2, 1);
          }
          break;

        case bscript.OPS.OP_OVER:
          {
            // (x1 x2 -- x1 x2 x1)
            if (this.stack.length < 2) {
              this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
              return false;
            }
            this.stack.push(this.stack[this.stack.length - 2]);
          }
          break;

        case bscript.OPS.OP_PICK:
        case bscript.OPS.OP_ROLL:
          {
            // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
            // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
            if (this.stack.length < 2) {
              this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
              return false;
            }
            buf = this.stack[this.stack.length - 1];
            bn = buf2BN(buf, fRequireMinimal);
            n = Number(bn);
            this.stack.pop();
            if (n < 0 || n >= this.stack.length) {
              this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
              return false;
            }
            buf = this.stack[this.stack.length - n - 1];
            if (opcodenum === bscript.OPS.OP_ROLL) {
              this.stack.splice(this.stack.length - n - 1, 1);
            }
            this.stack.push(buf);
          }
          break;

        case bscript.OPS.OP_ROT:
          {
            // (x1 x2 x3 -- x2 x3 x1)
            //  x2 x1 x3  after first swap
            //  x2 x3 x1  after second swap
            if (this.stack.length < 3) {
              this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
              return false;
            }
            x1 = this.stack[this.stack.length - 3];
            x2 = this.stack[this.stack.length - 2];
            const x3 = this.stack[this.stack.length - 1];
            this.stack[this.stack.length - 3] = x2;
            this.stack[this.stack.length - 2] = x3;
            this.stack[this.stack.length - 1] = x1;
          }
          break;

        case bscript.OPS.OP_SWAP:
          {
            // (x1 x2 -- x2 x1)
            if (this.stack.length < 2) {
              this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
              return false;
            }
            x1 = this.stack[this.stack.length - 2];
            x2 = this.stack[this.stack.length - 1];
            this.stack[this.stack.length - 2] = x2;
            this.stack[this.stack.length - 1] = x1;
          }
          break;

        case bscript.OPS.OP_TUCK:
          {
            // (x1 x2 -- x2 x1 x2)
            if (this.stack.length < 2) {
              this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
              return false;
            }
            this.stack.splice(
              this.stack.length - 2,
              0,
              this.stack[this.stack.length - 1],
            );
          }
          break;

        case bscript.OPS.OP_SIZE:
          {
            // (in -- in size)
            if (this.stack.length < 1) {
              this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
              return false;
            }
            bn = BigInt(this.stack[this.stack.length - 1].length);
            this.stack.push(bn2Buf(bn));
          }
          break;

        //
        // Bitwise logic
        //
        case bscript.OPS.OP_EQUAL:
        case bscript.OPS.OP_EQUALVERIFY:
          //case Opcode.OP_NOTEQUAL: // use Opcode.OP_NUMNOTEQUAL
          {
            // (x1 x2 - bool)
            if (this.stack.length < 2) {
              this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
              return false;
            }
            buf1 = this.stack[this.stack.length - 2];
            buf2 = this.stack[this.stack.length - 1];
            const fEqual = tools.toHex(buf1) === tools.toHex(buf2);
            this.stack.pop();
            this.stack.pop();
            this.stack.push(fEqual ? Interpreter.TRUE : Interpreter.FALSE);
            if (opcodenum === bscript.OPS.OP_EQUALVERIFY) {
              if (fEqual) {
                this.stack.pop();
              } else {
                this.errstr = InterpreterErr.SCRIPT_ERR_EQUALVERIFY;
                return false;
              }
            }
          }
          break;

        //
        // Numeric
        //
        case bscript.OPS.OP_1ADD:
        case bscript.OPS.OP_1SUB:
        case bscript.OPS.OP_NEGATE:
        case bscript.OPS.OP_ABS:
        case bscript.OPS.OP_NOT:
        case bscript.OPS.OP_0NOTEQUAL:
          {
            // (in -- out)
            if (this.stack.length < 1) {
              this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
              return false;
            }
            buf = this.stack[this.stack.length - 1];
            bn = buf2BN(buf, fRequireMinimal);
            switch (opcodenum) {
              case bscript.OPS.OP_1ADD:
                bn = bn + BigInt(1);
                break;
              case bscript.OPS.OP_1SUB:
                bn = bn - BigInt(1);
                break;
              case bscript.OPS.OP_NEGATE:
                bn = bn * BigInt(-1);
                break;
              case bscript.OPS.OP_ABS:
                if (bn < BigInt(0)) {
                  bn = bn * BigInt(-1);
                }
                break;
              case bscript.OPS.OP_NOT:
                bn = bn === BigInt(0) ? BigInt(1) : BigInt(0);
                break;
              case bscript.OPS.OP_0NOTEQUAL:
                bn = bn !== BigInt(0) ? BigInt(1) : BigInt(0);
                break;
              //default:      assert(!'invalid opcode'); break; // TODO: does this ever occur?
            }
            this.stack.pop();
            this.stack.push(bn2Buf(bn));
          }
          break;

        case bscript.OPS.OP_ADD:
        case bscript.OPS.OP_SUB:
        case bscript.OPS.OP_BOOLAND:
        case bscript.OPS.OP_BOOLOR:
        case bscript.OPS.OP_NUMEQUAL:
        case bscript.OPS.OP_NUMEQUALVERIFY:
        case bscript.OPS.OP_NUMNOTEQUAL:
        case bscript.OPS.OP_LESSTHAN:
        case bscript.OPS.OP_GREATERTHAN:
        case bscript.OPS.OP_LESSTHANOREQUAL:
        case bscript.OPS.OP_GREATERTHANOREQUAL:
        case bscript.OPS.OP_MIN:
        case bscript.OPS.OP_MAX:
          {
            // (x1 x2 -- out)
            if (this.stack.length < 2) {
              this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
              return false;
            }
            bn1 = buf2BN(this.stack[this.stack.length - 2], fRequireMinimal);
            bn2 = buf2BN(this.stack[this.stack.length - 1], fRequireMinimal);
            bn = BigInt(0);

            switch (opcodenum) {
              case bscript.OPS.OP_ADD:
                bn = bn1 + bn2;
                break;

              case bscript.OPS.OP_SUB:
                bn = bn1 - bn2;
                break;

              // case Opcode.OP_BOOLAND:       bn = (bn1 != bnZero && bn2 != bnZero); break;
              case bscript.OPS.OP_BOOLAND:
                bn =
                  bn1 !== BigInt(0) && bn2 !== BigInt(0)
                    ? BigInt(1)
                    : BigInt(0);
                break;
              // case Opcode.OP_BOOLOR:        bn = (bn1 != bnZero || bn2 != bnZero); break;
              case bscript.OPS.OP_BOOLOR:
                bn =
                  bn1 !== BigInt(0) || bn2 !== BigInt(0)
                    ? BigInt(1)
                    : BigInt(0);
                break;
              // case Opcode.OP_NUMEQUAL:      bn = (bn1 == bn2); break;
              case bscript.OPS.OP_NUMEQUAL:
                bn = bn1 === bn2 ? BigInt(1) : BigInt(0);
                break;
              // case Opcode.OP_NUMEQUALVERIFY:    bn = (bn1 == bn2); break;
              case bscript.OPS.OP_NUMEQUALVERIFY:
                bn = bn1 === bn2 ? BigInt(1) : BigInt(0);
                break;
              // case Opcode.OP_NUMNOTEQUAL:     bn = (bn1 != bn2); break;
              case bscript.OPS.OP_NUMNOTEQUAL:
                bn = bn1 !== bn2 ? BigInt(1) : BigInt(0);
                break;
              // case Opcode.OP_LESSTHAN:      bn = (bn1 < bn2); break;
              case bscript.OPS.OP_LESSTHAN:
                bn = bn1 < bn2 ? BigInt(1) : BigInt(0);
                break;
              // case Opcode.OP_GREATERTHAN:     bn = (bn1 > bn2); break;
              case bscript.OPS.OP_GREATERTHAN:
                bn = bn1 > bn2 ? BigInt(1) : BigInt(0);
                break;
              // case Opcode.OP_LESSTHANOREQUAL:   bn = (bn1 <= bn2); break;
              case bscript.OPS.OP_LESSTHANOREQUAL:
                bn = bn1 <= bn2 ? BigInt(1) : BigInt(0);
                break;
              // case Opcode.OP_GREATERTHANOREQUAL:  bn = (bn1 >= bn2); break;
              case bscript.OPS.OP_GREATERTHANOREQUAL:
                bn = bn1 >= bn2 ? BigInt(1) : BigInt(0);
                break;
              case bscript.OPS.OP_MIN:
                bn = bn1 < bn2 ? bn1 : bn2;
                break;
              case bscript.OPS.OP_MAX:
                bn = bn1 > bn2 ? bn1 : bn2;
                break;
              // default:           assert(!'invalid opcode'); break; //TODO: does this ever occur?
            }
            this.stack.pop();
            this.stack.pop();
            this.stack.push(bn2Buf(bn));

            if (opcodenum === bscript.OPS.OP_NUMEQUALVERIFY) {
              // if (CastToBool(stacktop(-1)))
              if (Interpreter.castToBool(this.stack[this.stack.length - 1])) {
                this.stack.pop();
              } else {
                this.errstr = InterpreterErr.SCRIPT_ERR_NUMEQUALVERIFY;
                return false;
              }
            }
          }
          break;

        case bscript.OPS.OP_WITHIN:
          {
            // (x min max -- out)
            if (this.stack.length < 3) {
              this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
              return false;
            }
            bn1 = buf2BN(this.stack[this.stack.length - 3], fRequireMinimal);
            bn2 = buf2BN(this.stack[this.stack.length - 2], fRequireMinimal);
            const bn3 = buf2BN(
              this.stack[this.stack.length - 1],
              fRequireMinimal,
            );
            //bool fValue = (bn2 <= bn1 && bn1 < bn3);
            fValue = bn2 <= bn1 && bn1 < bn3;
            this.stack.pop();
            this.stack.pop();
            this.stack.pop();
            this.stack.push(fValue ? Interpreter.TRUE : Interpreter.FALSE);
          }
          break;

        //
        // Slicing
        //
        case bscript.OPS.OP_CAT: {
          if (this.stack.length < 2) {
            this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
            return false;
          }
          buf1 = this.stack[this.stack.length - 2];
          buf2 = this.stack[this.stack.length - 1];
          if (buf1.length + buf2.length > Interpreter.MAX_SCRIPT_ELEMENT_SIZE) {
            this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
            return false;
          }
          this.stack.pop();
          this.stack.pop();
          this.stack.push(tools.concat([buf1, buf2]));
          break;
        }

        //
        // Crypto
        //
        case bscript.OPS.OP_RIPEMD160:
        case bscript.OPS.OP_SHA1:
        case bscript.OPS.OP_SHA256:
        case bscript.OPS.OP_HASH160:
        case bscript.OPS.OP_HASH256:
          {
            // (in -- hash)
            if (this.stack.length < 1) {
              this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
              return false;
            }
            buf = this.stack[this.stack.length - 1];
            //valtype vchHash((opcode == Opcode.OP_RIPEMD160 ||
            //                 opcode == Opcode.OP_SHA1 || opcode == Opcode.OP_HASH160) ? 20 : 32);
            let bufHash: Uint8Array;
            if (opcodenum === bscript.OPS.OP_RIPEMD160) {
              bufHash = ripemd160(buf);
            } else if (opcodenum === bscript.OPS.OP_SHA1) {
              bufHash = sha1(buf);
            } else if (opcodenum === bscript.OPS.OP_SHA256) {
              bufHash = sha256(buf);
            } else if (opcodenum === bscript.OPS.OP_HASH160) {
              bufHash = hash160(buf);
            } else if (opcodenum === bscript.OPS.OP_HASH256) {
              bufHash = hash256(buf);
            } else {
              this.errstr = InterpreterErr.SCRIPT_ERR_UNDEFINED_OPCODE;
              return false;
            }
            this.stack.pop();
            this.stack.push(bufHash);
          }
          break;

        case bscript.OPS.OP_CODESEPARATOR:
          {
            // Hash starts after the code separator
            this.pbegincodehash = this.pc;
            this.execdata.codeseparatorPos = this.pc - 1;
          }
          break;

        case bscript.OPS.OP_CHECKSIG:
        case bscript.OPS.OP_CHECKSIGVERIFY:
          {
            // (sig pubkey -- bool)
            if (this.stack.length < 2) {
              this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
              return false;
            }

            bufSig = this.stack[this.stack.length - 2];
            bufPubkey = this.stack[this.stack.length - 1];

            const { success: fSuccess, result } = this._evalCheckSig(
              bufSig,
              bufPubkey,
            );
            if (!result) {
              return false;
            }

            this.stack.pop();
            this.stack.pop();

            // stack.push_back(fSuccess ? vchTrue : vchFalse);
            this.stack.push(fSuccess ? Interpreter.TRUE : Interpreter.FALSE);
            if (opcodenum === bscript.OPS.OP_CHECKSIGVERIFY) {
              if (fSuccess) {
                this.stack.pop();
              } else {
                this.errstr = InterpreterErr.SCRIPT_ERR_CHECKSIGVERIFY;
                return false;
              }
            }
          }
          break;
        case bscript.OPS.OP_CHECKSIGADD:
          {
            // OP_CHECKSIGADD is only available in Tapscript
            if (
              this.sigversion == SignatureVersion.BASE ||
              this.sigversion == SignatureVersion.WITNESS_V0
            ) {
              this.errstr = InterpreterErr.SCRIPT_ERR_BAD_OPCODE;
              return false;
            }

            // (sig num pubkey -- num)
            if (this.stack.length < 3) {
              this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
              return false;
            }

            const sig = this.stack[this.stack.length - 3];
            const num = this.stack[this.stack.length - 2];
            const pubkey = this.stack[this.stack.length - 1];

            bn = buf2BN(num, fRequireMinimal);

            const { success, result } = this._evalCheckSig(sig, pubkey);
            if (!result) {
              return false;
            }

            bn = bn + (success ? BigInt(1) : BigInt(0));

            this.stack.pop();
            this.stack.pop();
            this.stack.pop();
            this.stack.push(bn2Buf(bn));
          }
          break;
        case bscript.OPS.OP_CHECKMULTISIG:
        case bscript.OPS.OP_CHECKMULTISIGVERIFY:
          {
            // ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)

            let i = 1;
            if (this.stack.length < i) {
              this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
              return false;
            }

            let nKeysCount = Number(
              buf2BN(this.stack[this.stack.length - i], fRequireMinimal),
            );
            if (nKeysCount < 0 || nKeysCount > 20) {
              this.errstr = InterpreterErr.SCRIPT_ERR_PUBKEY_COUNT;
              return false;
            }
            this.nOpCount += nKeysCount;
            if (this.nOpCount > 201) {
              this.errstr = InterpreterErr.SCRIPT_ERR_OP_COUNT;
              return false;
            }
            // int ikey = ++i;
            let ikey = ++i;
            i += nKeysCount;

            // ikey2 is the position of last non-signature item in
            // the stack. Top stack item = 1. With
            // SCRIPT_VERIFY_NULLFAIL, this is used for cleanup if
            // operation fails.
            let ikey2 = nKeysCount + 2;

            if (this.stack.length < i) {
              this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
              return false;
            }

            let nSigsCount = Number(
              buf2BN(this.stack[this.stack.length - i], fRequireMinimal),
            );
            if (nSigsCount < 0 || nSigsCount > nKeysCount) {
              this.errstr = InterpreterErr.SCRIPT_ERR_SIG_COUNT;
              return false;
            }
            // int isig = ++i;
            let isig = ++i;
            i += nSigsCount;
            if (this.stack.length < i) {
              this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
              return false;
            }

            // Subset of script starting at the most recent codeseparator
            const subscript = this.script.slice(this.pbegincodehash);

            // Drop the signatures, since there's no way for a signature to sign itself
            for (let k = 0; k < nSigsCount; k++) {
              bufSig = this.stack[this.stack.length - isig - k];
              bscript.findAndDelete(subscript, bufSig);
            }

            fSuccess = true;
            while (fSuccess && nSigsCount > 0) {
              // valtype& vchSig  = stacktop(-isig);
              bufSig = this.stack[this.stack.length - isig];
              // valtype& vchPubKey = stacktop(-ikey);
              bufPubkey = this.stack[this.stack.length - ikey];

              if (
                !this.checkSignatureEncoding(bufSig) ||
                !this.checkPubkeyEncoding(bufPubkey)
              ) {
                return false;
              }

              let fOk;
              try {
                fOk = this.verifySignature(
                  bufSig,
                  bufPubkey,
                  subscript,
                  this.sigversion,
                  this.execdata,
                );
              } catch (e) {
                //invalid sig or pubkey
                fOk = false;
              }

              if (fOk) {
                isig++;
                nSigsCount--;
              }
              ikey++;
              nKeysCount--;

              // If there are more signatures left than keys left,
              // then too many signatures have failed
              if (nSigsCount > nKeysCount) {
                fSuccess = false;
              }
            }

            // Clean up stack of actual arguments
            while (i-- > 1) {
              if (
                !fSuccess &&
                this.flags & Interpreter.SCRIPT_VERIFY_NULLFAIL &&
                !ikey2 &&
                this.stack[this.stack.length - 1].length
              ) {
                this.errstr = InterpreterErr.SCRIPT_ERR_NULLFAIL;
                return false;
              }

              if (ikey2 > 0) {
                ikey2--;
              }

              this.stack.pop();
            }

            // A bug causes CHECKMULTISIG to consume one extra argument
            // whose contents were not checked in any way.
            //
            // Unfortunately this is a potential source of mutability,
            // so optionally verify it is exactly equal to zero prior
            // to removing it from the stack.
            if (this.stack.length < 1) {
              this.errstr = InterpreterErr.SCRIPT_ERR_INVALID_STACK_OPERATION;
              return false;
            }
            if (
              this.flags & Interpreter.SCRIPT_VERIFY_NULLDUMMY &&
              this.stack[this.stack.length - 1].length
            ) {
              this.errstr = InterpreterErr.SCRIPT_ERR_SIG_NULLDUMMY;
              return false;
            }
            this.stack.pop();

            this.stack.push(fSuccess ? Interpreter.TRUE : Interpreter.FALSE);

            if (opcodenum === bscript.OPS.OP_CHECKMULTISIGVERIFY) {
              if (fSuccess) {
                this.stack.pop();
              } else {
                this.errstr = InterpreterErr.SCRIPT_ERR_CHECKMULTISIGVERIFY;
                return false;
              }
            }
          }
          break;

        default:
          this.errstr = InterpreterErr.SCRIPT_ERR_BAD_OPCODE;
          return false;
      }
    }

    // Size limits
    if (this.stack.length + this.altstack.length > Interpreter.MAX_STACK_SIZE) {
      this.errstr = InterpreterErr.SCRIPT_ERR_STACK_SIZE;
      return false;
    }

    return true;
  }

  /**
   * Checks a locktime parameter with the transaction's locktime.
   * There are two times of nLockTime: lock-by-blockheight and lock-by-blocktime,
   * distinguished by whether nLockTime < LOCKTIME_THRESHOLD = 500000000
   *
   * See the corresponding code on bitcoin core:
   * https://github.com/bitcoin/bitcoin/blob/ffd75adce01a78b3461b3ff05bcc2b530a9ce994/src/script/interpreter.cpp#L1129
   *
   * @param {BN} nLockTime the locktime read from the script
   * @return {boolean} true if the transaction's locktime is less than or equal to
   *                   the transaction's locktime
   */
  checkLockTime(nLockTime: bigint) {
    // We want to compare apples to apples, so fail the script
    // unless the type of nLockTime being tested is the same as
    // the nLockTime in the transaction.
    const LOCKTIME_THRESHOLD_BN = BigInt(Interpreter.LOCKTIME_THRESHOLD);
    if (
      !(
        (this.tx.locktime < Interpreter.LOCKTIME_THRESHOLD &&
          nLockTime < LOCKTIME_THRESHOLD_BN) ||
        (this.tx.locktime >= Interpreter.LOCKTIME_THRESHOLD &&
          nLockTime >= LOCKTIME_THRESHOLD_BN)
      )
    ) {
      return false;
    }

    // Now that we know we're comparing apples-to-apples, the
    // comparison is a simple numeric one.
    if (nLockTime > BigInt(this.tx.locktime)) {
      return false;
    }

    // Finally the nLockTime feature can be disabled and thus
    // CHECKLOCKTIMEVERIFY bypassed if every txin has been
    // finalized by setting nSequence to maxint. The
    // transaction would be allowed into the blockchain, making
    // the opcode ineffective.
    //
    // Testing if this vin is not final is sufficient to
    // prevent this condition. Alternatively we could test all
    // inputs, but testing just this input minimizes the data
    // required to prove correct CHECKLOCKTIMEVERIFY execution.
    if (!isFinal(this.tx.ins[this.nin].sequence)) {
      return false;
    }

    return true;
  }

  /**
   * Checks a sequence parameter with the transaction's sequence.
   * @param {BN} nSequence the sequence read from the script
   * @return {boolean} true if the transaction's sequence is less than or equal to
   *                   the transaction's sequence
   */
  checkSequence(nSequence: bigint) {
    // Relative lock times are supported by comparing the passed in operand to
    // the sequence number of the input.
    const txToSequence = this.tx.ins[this.nin].sequence;

    // Fail if the transaction's version number is not set high enough to
    // trigger BIP 68 rules.
    if (this.tx.version < 2) {
      return false;
    }

    // Sequence numbers with their most significant bit set are not consensus
    // constrained. Testing that the transaction's sequence number do not have
    // this bit set prevents using this property to get around a
    // CHECKSEQUENCEVERIFY check.
    if (txToSequence & Interpreter.SEQUENCE_LOCKTIME_DISABLE_FLAG) {
      return false;
    }

    // Mask off any bits that do not have consensus-enforced meaning before
    // doing the integer comparisons
    const nLockTimeMask =
      Interpreter.SEQUENCE_LOCKTIME_TYPE_FLAG |
      Interpreter.SEQUENCE_LOCKTIME_MASK;
    const txToSequenceMasked = BigInt(txToSequence & nLockTimeMask);
    const nSequenceMasked = nSequence & BigInt(nLockTimeMask);

    // There are two kinds of nSequence: lock-by-blockheight and
    // lock-by-blocktime, distinguished by whether nSequenceMasked <
    // CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG.
    //
    // We want to compare apples to apples, so fail the script unless the type
    // of nSequenceMasked being tested is the same as the nSequenceMasked in the
    // transaction.
    const SEQUENCE_LOCKTIME_TYPE_FLAG_BN = BigInt(
      Interpreter.SEQUENCE_LOCKTIME_TYPE_FLAG,
    );

    if (
      !(
        (txToSequenceMasked < SEQUENCE_LOCKTIME_TYPE_FLAG_BN &&
          nSequenceMasked < SEQUENCE_LOCKTIME_TYPE_FLAG_BN) ||
        (txToSequenceMasked >= SEQUENCE_LOCKTIME_TYPE_FLAG_BN &&
          nSequenceMasked >= SEQUENCE_LOCKTIME_TYPE_FLAG_BN)
      )
    ) {
      return false;
    }

    // Now that we know we're comparing apples-to-apples, the comparison is a
    // simple numeric one.
    return nSequenceMasked <= txToSequenceMasked;
  }

  /**
   * Based on bitcoind's EvalChecksig function
   * bitcoind commit: a0988140b71485ad12c3c3a4a9573f7c21b1eff8
   * @returns {{ success: Boolean, verified: Boolean }}
   */
  _evalCheckSig(bufSig: Uint8Array, bufPubkey: Uint8Array) {
    switch (this.sigversion) {
      case SignatureVersion.BASE:
      case SignatureVersion.WITNESS_V0:
        // const verified = this._evalChecksigPreTapscript(bufSig, bufPubkey);
        // return { success: verified, verified }; // This is to keep the same return format as _evalCheckSigTapscript
        return this._evalChecksigPreTapscript(bufSig, bufPubkey);
      case SignatureVersion.TAPSCRIPT:
        return this._evalChecksigTapscript(bufSig, bufPubkey);
      case SignatureVersion.TAPROOT:
        // Key path spending in Taproot has no script, so this is unreachable.
        throw new Error(
          'Called evalCheckSig with a TAPROOT sigversion. Check your implementation',
        );
    }
  }

  /**
   * Based on bitcoind's EvalChecksigPreTapscript function
   * bitcoind commit: a0988140b71485ad12c3c3a4a9573f7c21b1eff8
   */
  _evalChecksigPreTapscript(bufSig: Uint8Array, bufPubkey: Uint8Array) {
    requireTrue(
      this.sigversion === SignatureVersion.BASE ||
        this.sigversion === SignatureVersion.WITNESS_V0,
      'sigversion must be base or witness_v0',
    );

    // Success signifies if the signature is valid.
    // Result signifies the result of this funciton, which also takes flags into account.
    const retVal = { success: false, result: false };

    const subscript = this.script.slice(this.pbegincodehash);

    // Drop the signature in pre-segwit scripts but not segwit scripts
    if (this.sigversion === SignatureVersion.BASE) {
      // Drop the signature, since there's no way for a signature to sign itself
      const found = bscript.findAndDelete(subscript, bufSig);
      if (
        found > 0 &&
        this.flags & Interpreter.SCRIPT_VERIFY_CONST_SCRIPTCODE
      ) {
        this.errstr = InterpreterErr.SCRIPT_ERR_SIG_FINDANDDELETE;
        return retVal;
      }
    }

    if (
      !this.checkSignatureEncoding(bufSig) ||
      !this.checkPubkeyEncoding(bufPubkey)
    ) {
      return retVal;
    }

    try {
      //const sig = Signature.fromTxFormat(bufSig);
      //const pubkey = PublicKey.fromBuffer(bufPubkey, false);

      retVal.success = this.verifySignature(
        bufSig,
        bufPubkey,
        subscript,
        this.sigversion,
        {},
      );
    } catch (e) {
      //invalid sig or pubkey
      retVal.success = false;
    }

    if (
      !retVal.success &&
      this.flags & Interpreter.SCRIPT_VERIFY_NULLFAIL &&
      bufSig.length
    ) {
      this.errstr = InterpreterErr.SCRIPT_ERR_SIG_NULLFAIL;
      return retVal;
    }

    // If it reaches here, then true
    retVal.result = true;
    return retVal;
  }

  /**
   * Based on bitcoind's EvalChecksigTapscript function
   * bitcoind commit: a0988140b71485ad12c3c3a4a9573f7c21b1eff8
   */
  _evalChecksigTapscript(bufSig: Uint8Array, bufPubkey: Uint8Array) {
    requireTrue(
      this.sigversion == SignatureVersion.TAPSCRIPT,
      'this.sigversion must by TAPSCRIPT',
    );

    /*
     *  The following validation sequence is consensus critical. Please note how --
     *    upgradable public key versions precede other rules;
     *    the script execution fails when using empty signature with invalid public key;
     *    the script execution fails when using non-empty invalid signature.
     */

    // Success signifies if the signature is valid.
    // Result signifies the result of this funciton, which also takes flags into account.
    const retVal = {
      success: bufSig.length > 0,
      result: false,
    };
    if (retVal.success) {
      // Implement the sigops/witnesssize ratio test.
      // Passing with an upgradable public key version is also counted.
      requireTrue(
        this.execdata.validationWeightLeftInit,
        'validationWeightLeftInit is false',
      );
      this.execdata.validationWeightLeft -=
        Interpreter.VALIDATION_WEIGHT_PER_SIGOP_PASSED;
      if (this.execdata.validationWeightLeft < 0) {
        this.errstr = InterpreterErr.SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT;
        return retVal;
      }
    }
    if (bufPubkey.length === 0) {
      this.errstr = InterpreterErr.SCRIPT_ERR_PUBKEYTYPE;
      return retVal;
    } else if (bufPubkey.length == 32) {
      if (
        retVal.success &&
        !this.checkSchnorrSignature(
          bufSig,
          bufPubkey,
          this.sigversion,
          this.execdata,
        )
      ) {
        this.errstr = InterpreterErr.SCRIPT_ERR_SCHNORR_SIG;
        return retVal;
      }
    } else {
      /*
       *  New public key version softforks should be defined before this `else` block.
       *  Generally, the new code should not do anything but failing the script execution. To avoid
       *  consensus bugs, it should not modify any existing values (including `success`).
       */
      if (
        (this.flags &
          Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE) !=
        0
      ) {
        this.errstr =
          InterpreterErr.SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE;
        return retVal;
      }
    }

    // If it reaches here, then true
    retVal.result = true;
    return retVal;
  }

  /**
   * Verifies Schnorr signature
   * @param {Signature|Buffer} sig
   * @param {PublicKey|Buffer} pubkey
   * @param {Number} sigversion
   * @param {Object} execdata
   * @returns {Boolean}
   */
  checkSchnorrSignature(
    sig: Uint8Array,
    pubkey: Uint8Array,
    sigversion: SignatureVersion,
    execdata: any,
  ) {
    requireTrue(sig && isUint8Array(sig), 'Missing sig');
    requireTrue(pubkey && isUint8Array(sig), 'Missing pubkey');
    requireTrue(sigversion !== undefined, 'Missing sigversion');
    requireTrue(execdata, 'Missing execdata');

    requireTrue(
      pubkey.length === 32,
      'Schnorr signatures have 32-byte public keys. The caller is responsible for enforcing this.',
    );
    // Note that in Tapscript evaluation, empty signatures are treated specially (invalid signature that does not
    // abort script execution). This is implemented in EvalChecksigTapscript, which won't invoke
    // CheckSchnorrSignature in that case. In other contexts, they are invalid like every other signature with
    // size different from 64 or 65.
    if (!(sig.length === 64 || sig.length === 65)) {
      this.errstr = InterpreterErr.SCRIPT_ERR_SCHNORR_SIG_SIZE;
      return false;
    }

    if (
      sig.length === 65 &&
      sig[sig.length - 1] === Transaction.SIGHASH_DEFAULT
    ) {
      this.errstr = InterpreterErr.SCRIPT_ERR_SCHNORR_SIG_HASHTYPE;
      return false;
    }

    if (!Array.isArray(this.prevOuts)) {
      this.errstr = InterpreterErr.SCRIPT_ERR_SCHNORR_SIG_NO_PREVOUTS;
      return false;
    }
    const decodedSig = decodeSchnorrSignature(sig);

    requireTrue(execdata.annexInit, 'missing or invalid annexInit');

    if (sigversion === SignatureVersion.TAPSCRIPT) {
      requireTrue(
        execdata.tapleafHashInit,
        'missing or invalid tapleafHashInit',
      );
      requireTrue(
        execdata.codeseparatorPosInit,
        'missing or invalid codeseparatorPosInit',
      );
    }

    const msghash = this.tx.hashForWitnessV1(
      this.nin,
      this.prevOuts.map(out => out.script),
      this.prevOuts.map(out => out.value),
      decodedSig.hashType,
      sigversion === SignatureVersion.TAPSCRIPT
        ? execdata.tapleafHash
        : undefined,
      execdata.annexPresent ? execdata.annex : undefined,
      sigversion === SignatureVersion.TAPSCRIPT
        ? execdata.codeseparatorPos
        : undefined,
    );
    const ecc = getEccLib();

    const verified = ecc.verifySchnorr!(msghash, pubkey, decodedSig.signature);
    return verified;
  }

  static computeTapleafHash(
    leafVersion: number,
    scriptBuf: Uint8Array,
  ): Uint8Array {
    return tapleafHash({
      version: leafVersion,
      output: scriptBuf,
    });
  }

  static verifyTaprootCommitment(
    control: Uint8Array,
    program: Uint8Array,
    tapleafHash: Uint8Array,
  ) {
    requireTrue(
      control.length >= Interpreter.TAPROOT_CONTROL_BASE_SIZE,
      'control too short',
    );
    requireTrue(program.length >= 32, 'program is too short');

    try {
      //! The internal pubkey (x-only, so no Y coordinate parity).
      const p = control.slice(1, Interpreter.TAPROOT_CONTROL_BASE_SIZE);
      //! The output pubkey (taken from the scriptPubKey).
      const q = program;
      // Compute the Merkle root from the leaf and the provided path.
      const merkleRoot = rootHashFromPath(control, tapleafHash);
      // Verify that the output pubkey matches the tweaked internal pubkey, after correcting for parity.

      const tweak = tweakKey(p, merkleRoot);

      if (tweak === null) {
        throw new Error('tweakKey null');
      }

      // this.point.x.eq(Q.x) && Q.y.mod(new BN(2)).eq(new BN(control[0] & 1));
      return tools.compare(q, tweak.x) === 0;
    } catch (err) {
      return false;
    }
  }

  /**
   * Translated from bitcoind's CheckSignatureEncoding
   */
  checkSignatureEncoding(buf: Uint8Array) {
    // TODO: let sig;

    // Empty signature. Not strictly DER encoded, but allowed to provide a
    // compact way to provide an invalid signature for use with CHECK(MULTI)SIG
    if (buf.length == 0) {
      return true;
    }

    if (
      (this.flags &
        (Interpreter.SCRIPT_VERIFY_DERSIG |
          Interpreter.SCRIPT_VERIFY_LOW_S |
          Interpreter.SCRIPT_VERIFY_STRICTENC)) !==
        0 &&
      !isTxDER(buf)
    ) {
      this.errstr = InterpreterErr.SCRIPT_ERR_SIG_DER_INVALID_FORMAT;
      return false;
    } else if ((this.flags & Interpreter.SCRIPT_VERIFY_LOW_S) !== 0) {
      //TODO: sig = Signature.fromTxFormat(buf);
      // if (!sig.hasLowS()) {
      //   this.errstr = InterpreterErr.SCRIPT_ERR_SIG_DER_HIGH_S;
      //   return false;
      // }
    } else if ((this.flags & Interpreter.SCRIPT_VERIFY_STRICTENC) !== 0) {
      //TODO: sig = Signature.fromTxFormat(buf);
      // if (!sig.hasDefinedHashtype()) {
      //   this.errstr = InterpreterErr.SCRIPT_ERR_SIG_HASHTYPE;
      //   return false;
      // }
    }

    return true;
  }

  /**
   * Translated from bitcoind's CheckPubKeyEncoding
   */
  checkPubkeyEncoding(buf: Uint8Array) {
    if (
      (this.flags & Interpreter.SCRIPT_VERIFY_STRICTENC) !== 0 &&
      !bscript.isCanonicalPubKey(buf)
    ) {
      this.errstr = InterpreterErr.SCRIPT_ERR_PUBKEYTYPE;
      return false;
    }

    // Only compressed keys are accepted in segwit
    if (
      (this.flags & Interpreter.SCRIPT_VERIFY_WITNESS_PUBKEYTYPE) != 0 &&
      this.sigversion == SignatureVersion.WITNESS_V0 &&
      bscript.isUncompressedPubkey(buf)
    ) {
      this.errstr = InterpreterErr.SCRIPT_ERR_WITNESS_PUBKEYTYPE;
      return false;
    }

    return true;
  }

  isInitialized(): boolean {
    requireTrue(this.stack.length === 0, 'invalid stack');
    requireTrue(this.altstack.length === 0, 'invalid altstack');
    requireTrue(this.pc === 0, 'invalid pc');
    requireTrue(
      this.sigversion === SignatureVersion.BASE,
      'invalid sigversion',
    );
    requireTrue(this.satoshis === 0, 'invalid satoshis');
    requireTrue(this.nOpCount === 0, 'invalid nOpCount');
    requireTrue(this.vfExec.length === 0, 'invalid nOpCount');
    requireTrue(this.errstr === InterpreterErr.NONE, 'invalid errstr');
    requireTrue(this.flags === 0, 'invalid flags');
    requireTrue(
      typeof this.execdata === 'object' &&
        Object.keys(this.execdata).length === 0,
      'invalid execdata',
    );

    return true;
  }

  /**
   * This is here largely for legacy reasons. However, if the sig type
   * is already known (via sigversion), then it would be better to call
   * checkEcdsaSignature or checkSchnorrSignature directly.
   * @param {Signature|Buffer} sig Signature to verify
   * @param {PublicKey|Buffer} pubkey Public key used to verify sig
   * @param {Number} nin Tx input index to verify signature against
   * @param {Script} subscript ECDSA only
   * @param {Number} sigversion See Signature.Version for valid versions (default: 0 or Signature.Version.BASE)
   * @param {Number} satoshis ECDSA only
   * @param {Object} execdata Schnorr only
   * @returns {Boolean} whether the signature is valid for this transaction input
   */
  verifySignature(
    sig: Uint8Array,
    pubkey: Uint8Array,
    subscript: Array<number | Uint8Array>,
    sigversion: SignatureVersion,
    execdata: any,
  ) {
    switch (sigversion) {
      case SignatureVersion.WITNESS_V0:
        return this.checkEcdsaSignature(sig, pubkey, subscript);
      case SignatureVersion.TAPROOT:
      case SignatureVersion.TAPSCRIPT:
        return this.checkSchnorrSignature(sig, pubkey, sigversion, execdata);
      case SignatureVersion.BASE:
      default: {
        const decodedSig = decode(sig, false);

        const msghash = this.tx.hashForSignature(
          this.nin,
          bscript.compile(subscript),
          decodedSig.hashType,
        );

        const ECPair = ECPairFactory(getEccLib() as any);

        const success = ECPair.fromPublicKey(pubkey).verify(
          msghash,
          decodedSig.signature,
        );

        return success;
      }
    }
  }

  /**
   * Verify ECDSA signature
   * @param {Signature} _sig
   * @param {PublicKey} _pubkey
   * @param {Number} _nin
   * @param {Script} _subscript
   * @param {Number} _satoshis
   * @returns {Boolean}
   */
  checkEcdsaSignature(
    sig: Uint8Array,
    pubkey: Uint8Array,
    subscript: Array<number | Uint8Array>,
  ) {
    const decodedSig = decode(sig, false);

    const msghash = this.tx.hashForWitnessV0(
      this.nin,
      bscript.compile(subscript),
      BigInt(this.satoshis),
      decodedSig.hashType,
    );
    const ECPair = ECPairFactory(getEccLib() as any);

    const success = ECPair.fromPublicKey(pubkey).verify(
      msghash,
      decodedSig.signature,
    );
    return success;
  }
}
