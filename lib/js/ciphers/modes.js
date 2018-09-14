/*!
 * modes.js - cipher modes for bcrypto
 * Copyright (c) 2016-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {assert, enforce} = require('bsert');

/*
 * Constants
 */

const EMPTY = Buffer.alloc(0);

/**
 * Cipher
 */

class Cipher {
  /**
   * Create a cipher.
   * @param {Object} ctx
   * @param {Boolean} [padding=false]
   */

  constructor(ctx, padding = false) {
    assert(ctx && typeof ctx.encrypt === 'function');
    assert(typeof ctx.blockSize === 'number');
    assert(typeof padding === 'boolean');

    this.ctx = ctx;
    this.padding = padding;
    this.block = Buffer.allocUnsafe(ctx.blockSize);
    this.bpos = -1;
    this.last = EMPTY;
  }

  /**
   * Get block size.
   * @returns {Number}
   */

  get blockSize() {
    return this.block.length;
  }

  /**
   * Initialize the cipher.
   * @param {Buffer} key
   * @returns {Cipher}
   */

  init(key) {
    enforce(Buffer.isBuffer(key), 'key', 'buffer');

    this.ctx.init(key);
    this.bpos = 0;
    this.last = EMPTY;
    this._init.apply(this, arguments);

    return this;
  }

  /**
   * Encipher blocks of data.
   * @param {Buffer} input
   * @returns {Buffer}
   */

  update(input) {
    enforce(Buffer.isBuffer(input), 'input', 'buffer');

    if (this.bpos === -1)
      throw new Error('Cipher not initialized.');

    const bs = this.block.length;

    let bpos = this.bpos;
    let ilen = input.length;
    let olen = ilen - (ilen % bs);
    let ipos = 0;
    let opos = 0;

    this.bpos = (this.bpos + ilen) % bs;

    if (bpos > 0) {
      let want = bs - bpos;

      if (want > ilen)
        want = ilen;

      input.copy(this.block, bpos, ipos, ipos + want);

      bpos += want;
      ilen -= want;
      ipos += want;

      if (bpos < bs)
        return EMPTY;

      olen += bs;
    }

    const output = Buffer.allocUnsafe(olen);

    if (ipos) {
      this._update(this.block, 0, output, opos);
      opos += bs;
    }

    while (ilen >= bs) {
      this._update(input, ipos, output, opos);
      opos += bs;
      ipos += bs;
      ilen -= bs;
    }

    if (ilen > 0)
      input.copy(this.block, 0, ipos, ipos + ilen);

    if (!this.padding)
      return output;

    this.last = output;

    return output.slice(0, olen - bs);
  }

  /**
   * Finalize the cipher.
   * @returns {Buffer}
   */

  final() {
    if (this.bpos === -1)
      throw new Error('Cipher not initialized.');

    const ret = this._final();

    this.last = EMPTY;
    this.bpos = -1;
    this.ctx.destroy();

    return ret;
  }

  /**
   * Intialize.
   */

  _init() {
    return this;
  }

  /**
   * Update.
   */

  _update() {
    throw new Error('Unimplemented.');
  }

  /**
   * Finalize.
   */

  _final() {
    return EMPTY;
  }
}

/**
 * Block Cipher
 * @extends Cipher
 */

class BlockCipher extends Cipher {
  /**
   * Create a block cipher.
   * @param {Object} ctx
   * @param {Boolean} [chain=false]
   */

  constructor(ctx, chain = false) {
    assert(typeof chain === 'boolean');

    super(ctx, false);

    this.chain = chain;
    this.prev = null;
    this.ppos = 0;
  }

  _init(key, iv = null) {
    if (this.chain) {
      enforce(Buffer.isBuffer(iv), 'iv', 'buffer');
      assert(iv.length === this.blockSize);
    } else {
      enforce(iv === null, 'iv', 'null');
    }

    this.prev = iv;
    this.ppos = 0;

    return this;
  }

  _update(input, ipos, output, opos) {
    if (this.chain) {
      const bs = this.blockSize;

      for (let i = 0; i < bs; i++)
        output[opos + i] = input[ipos + i] ^ this.prev[this.ppos + i];

      this.ctx.encrypt(output, opos, output, opos);

      this.prev = output;
      this.ppos = opos;
    } else {
      this.ctx.encrypt(input, ipos, output, opos);
    }

    return this;
  }

  _final() {
    const bs = this.blockSize;
    const left = bs - this.bpos;
    const block = Buffer.from(this.block);

    block.fill(left, this.bpos, bs);

    this._update(block, 0, block, 0);

    for (let i = 0; i < bs; i++)
      this.block[i] = 0;

    this.prev = null;

    return block;
  }
}

/**
 * Block Decipher
 * @extends Cipher
 */

class BlockDecipher extends Cipher {
  /**
   * Create a block decipher.
   * @param {Object} ctx
   * @param {Boolean} [chain=false]
   */

  constructor(ctx, chain = false) {
    super(ctx, true);

    this.chain = chain;
    this.prev = null;
    this.ppos = 0;
  }

  _init(key, iv = null) {
    if (this.chain) {
      enforce(Buffer.isBuffer(iv), 'iv', 'buffer');
      assert(iv.length === this.blockSize);
    } else {
      enforce(iv === null, 'iv', 'null');
    }

    this.prev = iv;
    this.ppos = 0;

    return this;
  }

  _update(input, ipos, output, opos) {
    if (this.chain) {
      const bs = this.blockSize;

      this.ctx.decrypt(input, ipos, output, opos);

      for (let i = 0; i < bs; i++)
        output[opos + i] = output[opos + i] ^ this.prev[this.ppos + i];

      this.prev = input;
      this.ppos = ipos;
    } else {
      this.ctx.decrypt(input, ipos, output, opos);
    }

    return this;
  }

  _final() {
    const bs = this.blockSize;

    for (let i = 0; i < bs; i++)
      this.block[i] = 0;

    this.prev = null;

    if (!this.last)
      throw new Error('Bad decrypt (no data).');

    const block = this.last;

    this.last = null;

    if (this.bpos !== 0)
      throw new Error('Bad decrypt (trailing bytes).');

    const start = block.length - bs;

    let end = block.length;

    const left = block[end - 1];

    if (left === 0 || left > bs)
      throw new Error('Bad decrypt (padding).');

    for (let i = 0; i < left; i++) {
      end -= 1;
      if (block[end] !== left)
        throw new Error('Bad decrypt (padding).');
    }

    return block.slice(start, end);
  }
}

/**
 * ECB Cipher
 * @extends BlockCipher
 */

class ECBCipher extends BlockCipher {
  constructor(ctx) {
    super(ctx, false);
  }
}

/**
 * ECB Decipher
 * @extends BlockDecipher
 */

class ECBDecipher extends BlockDecipher {
  constructor(ctx) {
    super(ctx, false);
  }
}

/**
 * CBC Cipher
 * @extends BlockCipher
 */

class CBCCipher extends BlockCipher {
  constructor(ctx) {
    super(ctx, true);
  }
}

/**
 * CBC Decipher
 * @extends BlockDecipher
 */

class CBCDecipher extends BlockDecipher {
  constructor(ctx) {
    super(ctx, true);
  }
}

/**
 * CTR
 * @extends Cipher
 */

class CTR extends Cipher {
  constructor(ctx) {
    super(ctx, false);
  }

  _init(key, iv) {
    enforce(Buffer.isBuffer(iv), 'iv', 'buffer');
    assert(iv.length === this.blockSize);

    this.ctr = Buffer.from(iv);
    this.out = Buffer.allocUnsafe(this.blockSize);

    return this;
  }

  increment() {
    for (let i = this.ctr.length - 1; i >= 0; i--) {
      if (this.ctr[i] !== 0xff) {
        this.ctr[i] += 1;
        break;
      }

      this.ctr[i] = 0x00;
    }
  }

  _update(input, ipos, output, opos) {
    const bs = this.blockSize;

    this.ctx.encrypt(this.ctr, 0, this.out, 0);
    this.increment();

    for (let i = 0; i < bs; i++)
      output[opos + i] = input[ipos + i] ^ this.out[i];

    return this;
  }

  _final() {
    this.ctx.encrypt(this.ctr, 0, this.out, 0);

    const out = Buffer.allocUnsafe(this.bpos);

    for (let i = 0; i < this.bpos; i++)
      out[i] = this.block[i] ^ this.out[i];

    return out;
  }
}

/**
 * CTR Cipher
 * @extends CTR
 */

class CTRCipher extends CTR {
  constructor(ctx) {
    super(ctx);
  }
}

/**
 * CTR Decipher
 * @extends CTR
 */

class CTRDecipher extends CTR {
  constructor(ctx) {
    super(ctx);
  }
}

/**
 * CFB
 * @extends Cipher
 */

class CFB extends Cipher {
  constructor(ctx, decrypt = false) {
    assert(typeof decrypt === 'boolean');
    super(ctx, false);
    this.decrypt = decrypt;
    this.prev = null;
    this.ppos = 0;
  }

  _init(key, iv) {
    enforce(Buffer.isBuffer(iv), 'iv', 'buffer');
    assert(iv.length === this.blockSize);

    this.out = Buffer.alloc(this.blockSize);
    this.prev = Buffer.from(iv);
    this.ppos = 0;

    return this;
  }

  _update(input, ipos, output, opos) {
    const bs = this.blockSize;

    this.ctx.encrypt(this.prev, this.ppos, this.out, 0);

    for (let i = 0; i < bs; i++)
      output[opos + i] = input[ipos + i] ^ this.out[i];

    if (this.decrypt) {
      this.prev = input;
      this.ppos = ipos;
    } else {
      this.prev = output;
      this.ppos = opos;
    }

    return this;
  }

  _final() {
    this.ctx.encrypt(this.prev, this.ppos, this.out, 0);

    const out = Buffer.allocUnsafe(this.bpos);

    for (let i = 0; i < this.bpos; i++)
      out[i] = this.block[i] ^ this.out[i];

    return out;
  }
}

/**
 * CFB Cipher
 * @extends CFB
 */

class CFBCipher extends CFB {
  constructor(ctx) {
    super(ctx, false);
  }
}

/**
 * CFB Decipher
 * @extends CFB
 */

class CFBDecipher extends CFB {
  constructor(ctx) {
    super(ctx, true);
  }
}

/**
 * OFB
 * @extends Cipher
 */

class OFB extends Cipher {
  constructor(ctx) {
    super(ctx, false);
    this.state = null;
  }

  _init(key, iv) {
    enforce(Buffer.isBuffer(iv), 'iv', 'buffer');
    assert(iv.length === this.blockSize);

    this.state = Buffer.from(iv);

    return this;
  }

  _update(input, ipos, output, opos) {
    const bs = this.blockSize;

    this.ctx.encrypt(this.state, 0, this.state, 0);

    for (let i = 0; i < bs; i++)
      output[opos + i] = input[ipos + i] ^ this.state[i];

    return this;
  }

  _final() {
    this.ctx.encrypt(this.state, 0, this.state, 0);

    const out = Buffer.allocUnsafe(this.bpos);

    for (let i = 0; i < this.bpos; i++)
      out[i] = this.block[i] ^ this.state[i];

    return out;
  }
}

/**
 * OFB Cipher
 * @extends OFB
 */

class OFBCipher extends OFB {
  constructor(ctx) {
    super(ctx);
  }
}

/**
 * OFB Decipher
 * @extends OFB
 */

class OFBDecipher extends OFB {
  constructor(ctx) {
    super(ctx);
  }
}

/*
 * Helpers
 */

function get(name, encrypt = true) {
  assert(typeof name === 'string');
  assert(typeof encrypt === 'boolean');

  switch (name) {
    case 'ecb':
    case 'ECB':
      return encrypt ? ECBCipher : ECBDecipher;
    case 'cbc':
    case 'CBC':
      return encrypt ? CBCCipher : CBCDecipher;
    case 'ctr':
    case 'CTR':
      return encrypt ? CTRCipher : CTRDecipher;
    case 'cfb':
    case 'CFB':
      return encrypt ? CFBCipher : CFBDecipher;
    case 'ofb':
    case 'OFB':
      return encrypt ? OFBCipher : OFBDecipher;
    default:
      throw new Error(`Unknown mode: ${name}.`);
  }
}

/*
 * Expose
 */

exports.Cipher = Cipher;
exports.BlockCipher = BlockCipher;
exports.BlockDecipher = BlockDecipher;
exports.ECBCipher = ECBCipher;
exports.ECBDecipher = ECBDecipher;
exports.CBCCipher = CBCCipher;
exports.CBCDecipher = CBCDecipher;
exports.CTR = CTR;
exports.CTRCipher = CTRCipher;
exports.CTRDecipher = CTRDecipher;
exports.CFB = CFB;
exports.CFBCipher = CFBCipher;
exports.CFBDecipher = CFBDecipher;
exports.OFB = OFB;
exports.OFBCipher = OFBCipher;
exports.OFBDecipher = OFBDecipher;
exports.get = get;
