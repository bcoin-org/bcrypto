/*!
 * modes.js - cipher modes for bcrypto
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
 */

'use strict';

const assert = require('../../internal/assert');
const GHASH = require('./ghash');

/*
 * Constants
 */

const EMPTY = Buffer.alloc(0);

/*
 * Mode
 */

class Mode {
  constructor(ctx) {
    assert(ctx && typeof ctx.encrypt === 'function');
    assert(typeof ctx.blockSize === 'number');

    this.ctx = ctx;
  }

  get blockSize() {
    return this.ctx.blockSize;
  }

  init(key, iv) {
    throw new Error('Not implemented.');
  }

  update(data) {
    throw new Error('Not implemented.');
  }

  final() {
    throw new Error('Not implemented.');
  }

  destroy() {
    throw new Error('Not implemented.');
  }

  setAutoPadding(padding) {
    assert(typeof padding === 'boolean');

    this._setAutoPadding(padding);

    return this;
  }

  setAAD(data) {
    assert(Buffer.isBuffer(data));
    this._setAAD(data);
    return this;
  }

  setCCM(msgLen, tagLen, aad) {
    assert((msgLen >>> 0) === msgLen);
    assert((tagLen >>> 0) === tagLen);
    assert(aad == null || Buffer.isBuffer(aad));

    this._setCCM(msgLen, tagLen, aad);

    return this;
  }

  getAuthTag() {
    return this._getAuthTag();
  }

  setAuthTag(tag) {
    assert(Buffer.isBuffer(tag));
    this._setAuthTag(tag);
    return this;
  }

  _setAutoPadding(padding) {
    throw new Error('Not available.');
  }

  _setAAD(data) {
    throw new Error('Cipher is not authenticated.');
  }

  _setCCM(msgLen, tagLen, aad) {
    throw new Error('Not available.');
  }

  _getAuthTag() {
    throw new Error('Cipher is not authenticated.');
  }

  _setAuthTag(tag) {
    throw new Error('Cipher is not authenticated.');
  }
}

/**
 * Block Mode
 */

class Block extends Mode {
  constructor(ctx, unpad) {
    super(ctx);

    this.padding = true;
    this.unpad = unpad;
    this.block = Buffer.alloc(ctx.blockSize);
    this.blockPos = -1;
    this.last = null;
    this.lastSize = 0;

    if (unpad)
      this.last = Buffer.alloc(ctx.blockSize);
  }

  init(key, iv) {
    if (iv == null)
      iv = EMPTY;

    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(iv));

    this.ctx.init(key);

    this.blockPos = 0;
    this.lastSize = 0;

    this._init(key, iv);

    return this;
  }

  update(input) {
    assert(Buffer.isBuffer(input));

    if (this.blockPos === -1)
      throw new Error('Cipher is not initialized.');

    const bs = this.block.length;

    let bpos = this.blockPos;
    let ilen = input.length;
    let olen = 0;
    let ipos = 0;
    let opos = 0;

    this.blockPos = (this.blockPos + ilen) % bs;

    if (this.unpad)
      olen += this.lastSize;

    if (bpos > 0) {
      let want = bs - bpos;

      if (want > ilen)
        want = ilen;

      input.copy(this.block, bpos, ipos, ipos + want);

      bpos += want;
      ilen -= want;
      ipos += want;

      if (bpos < bs)
        return Buffer.alloc(0);

      olen += bs;
    }

    olen += ilen - (ilen % bs);

    const output = Buffer.alloc(olen);

    if (this.unpad)
      opos += this.last.copy(output, opos, 0, this.lastSize);

    if (bpos > 0) {
      this._update(output, opos, this.block, 0);
      opos += bs;
    }

    while (ilen >= bs) {
      this._update(output, opos, input, ipos);
      opos += bs;
      ipos += bs;
      ilen -= bs;
    }

    if (ilen > 0)
      input.copy(this.block, 0, ipos, ipos + ilen);

    if (this.unpad && olen > 0) {
      this.lastSize = output.copy(this.last, 0, olen - bs, olen);
      return output.slice(0, olen - bs);
    }

    return output;
  }

  final() {
    if (this.blockPos === -1)
      throw new Error('Cipher is not initialized.');

    try {
      return this._final();
    } finally {
      this.destroy();
    }
  }

  destroy() {
    this.ctx.destroy();

    this.blockPos = -1;
    this.lastSize = 0;

    for (let i = 0; i < this.blockSize; i++)
      this.block[i] = 0;

    if (this.unpad) {
      for (let i = 0; i < this.blockSize; i++)
        this.last[i] = 0;
    }

    this._destroy();

    return this;
  }

  _init(key, iv) {
    throw new Error('Not implemented.');
  }

  _update(output, opos, input, ipos) {
    throw new Error('Not implemented.');
  }

  _final() {
    throw new Error('Not implemented.');
  }

  _destroy() {
    throw new Error('Not implemented.');
  }
}

/*
 * Stream Mode
 */

class Stream extends Mode {
  constructor(ctx) {
    super(ctx);
    this.pos = -1;
  }

  init(key, iv) {
    if (iv == null)
      iv = EMPTY;

    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(iv));

    this.ctx.init(key);

    this.pos = 0;

    this._init(key, iv);

    return this;
  }

  update(input) {
    assert(Buffer.isBuffer(input));

    if (this.pos === -1)
      throw new Error('Cipher is not initialized.');

    const output = Buffer.alloc(input.length);

    this._crypt(output, input);

    return output;
  }

  final() {
    if (this.pos === -1)
      throw new Error('Cipher is not initialized.');

    try {
      return this._final();
    } finally {
      this.destroy();
    }
  }

  destroy() {
    this.ctx.destroy();

    this.pos = -1;

    this._destroy();

    return this;
  }

  _init(key, iv) {
    throw new Error('Not implemented.');
  }

  _crypt(output, input) {
    throw new Error('Not implemented.');
  }

  _final() {
    throw new Error('Not implemented.');
  }

  _destroy() {
    throw new Error('Not implemented.');
  }
}

/**
 * Raw Cipher
 */

class RawCipher extends Block {
  constructor(ctx) {
    super(ctx, false);
  }

  _init(key, iv) {
    assert(iv.length === 0);
  }

  _update(output, opos, input, ipos) {
    this.ctx.encrypt(output, opos, input, ipos);
  }

  _final() {
    if (this.blockPos !== 0)
      throw new Error('Bad encrypt (trailing bytes).');

    return Buffer.alloc(0);
  }

  _destroy() {
    return;
  }
}

/**
 * Raw Decipher
 */

class RawDecipher extends Block {
  constructor(ctx) {
    super(ctx, false);
  }

  _init(key, iv) {
    assert(iv.length === 0);
  }

  _update(output, opos, input, ipos) {
    this.ctx.decrypt(output, opos, input, ipos);
  }

  _final() {
    if (this.blockPos !== 0)
      throw new Error('Bad decrypt (trailing bytes).');

    return Buffer.alloc(0);
  }

  _destroy() {
    return;
  }
}

/**
 * Block Cipher
 */

class BlockCipher extends Block {
  constructor(ctx) {
    super(ctx, false);
  }

  _final() {
    if (!this.padding) {
      if (this.blockPos !== 0)
        throw new Error('Bad encrypt (trailing bytes).');

      return Buffer.alloc(0);
    }

    const left = this.blockSize - this.blockPos;
    const block = Buffer.from(this.block);

    for (let i = this.blockPos; i < this.blockSize; i++)
      block[i] = left;

    this._update(block, 0, block, 0);

    return block;
  }

  _setAutoPadding(padding) {
    this.padding = padding;
  }
}

/**
 * Block Decipher
 */

class BlockDecipher extends Block {
  constructor(ctx) {
    super(ctx, true);
  }

  _final() {
    if (this.blockPos !== 0)
      throw new Error('Bad decrypt (trailing bytes).');

    if (!this.padding)
      return Buffer.alloc(0);

    if (this.lastSize === 0)
      throw new Error('Bad decrypt (no data).');

    assert(this.lastSize === this.last.length);
    assert(this.lastSize === this.blockSize);

    const block = Buffer.from(this.last);

    let left = block[block.length - 1];
    let res = 1;

    // left != 0
    res &= ((left - 1) >>> 31) ^ 1;

    // left <= block_size
    res &= (left - this.blockSize - 1) >>> 31;

    // left = 0 if left == 0 or left > block_size
    left &= -res;

    // Verify padding in constant time.
    const end = this.blockSize - left;

    for (let i = 0; i < this.blockSize; i++) {
      const ch = block[i];

      // i < end or ch == left
      res &= ((i - end) >>> 31) | (((ch ^ left) - 1) >>> 31);
    }

    if (!res)
      throw new Error('Bad decrypt (padding).');

    return block.slice(0, end);
  }

  _setAutoPadding(padding) {
    if (this.lastSize !== 0 || this.blockPos !== 0)
      throw new Error('Cannot set auto padding.');

    this.padding = padding;
    this.unpad = padding;
  }
}

/**
 * ECB Cipher
 */

class ECBCipher extends BlockCipher {
  constructor(ctx) {
    super(ctx);
  }

  _init(key, iv) {
    assert(iv.length === 0);
  }

  _update(output, opos, input, ipos) {
    this.ctx.encrypt(output, opos, input, ipos);
  }

  _destroy() {
    return;
  }
}

/**
 * ECB Decipher
 */

class ECBDecipher extends BlockDecipher {
  constructor(ctx) {
    super(ctx);
  }

  _init(key, iv) {
    assert(iv.length === 0);
  }

  _update(output, opos, input, ipos) {
    this.ctx.decrypt(output, opos, input, ipos);
  }

  _destroy() {
    return;
  }
}

/**
 * CBC Cipher
 */

class CBCCipher extends BlockCipher {
  constructor(ctx) {
    super(ctx);

    this.prev = Buffer.alloc(this.blockSize);
  }

  _init(key, iv) {
    assert(iv.length === this.blockSize);
    iv.copy(this.prev, 0);
  }

  _update(output, opos, input, ipos) {
    for (let i = 0; i < this.blockSize; i++)
      this.prev[i] ^= input[ipos + i];

    this.ctx.encrypt(output, opos, this.prev, 0);

    output.copy(this.prev, 0, opos, opos + this.blockSize);
  }

  _destroy() {
    for (let i = 0; i < this.blockSize; i++)
      this.prev[i] = 0;
  }
}

/**
 * CBC Decipher
 */

class CBCDecipher extends BlockDecipher {
  constructor(ctx) {
    super(ctx);

    this.prev = Buffer.alloc(this.blockSize);
    this.tmp = Buffer.alloc(this.blockSize);
  }

  _init(key, iv) {
    assert(iv.length === this.blockSize);
    iv.copy(this.prev, 0);
  }

  _update(output, opos, input, ipos) {
    if (output === input && opos === ipos) {
      this.prev.copy(this.tmp, 0);

      input.copy(this.prev, 0, ipos, ipos + this.blockSize);

      this.ctx.decrypt(output, opos, input, ipos);

      for (let i = 0; i < this.blockSize; i++)
        output[opos + i] ^= this.tmp[i];
    } else {
      this.ctx.decrypt(output, opos, input, ipos);

      for (let i = 0; i < this.blockSize; i++)
        output[opos + i] ^= this.prev[i];

      input.copy(this.prev, 0, ipos, ipos + this.blockSize);
    }
  }

  _destroy() {
    for (let i = 0; i < this.blockSize; i++) {
      this.prev[i] = 0;
      this.tmp[i] = 0;
    }
  }
}

/**
 * CTR
 */

class CTR extends Stream {
  constructor(ctx) {
    super(ctx);

    this.state = Buffer.alloc(this.blockSize);
    this.ctr = Buffer.alloc(this.blockSize);
  }

  _init(key, iv) {
    assert(iv.length === this.blockSize);

    iv.copy(this.ctr, 0);
  }

  _increment() {
    for (let i = this.ctr.length - 1; i >= 0; i--) {
      this.ctr[i] += 1;

      if (this.ctr[i] !== 0x00)
        break;
    }
  }

  _crypt(output, input) {
    const mask = this.blockSize - 1;

    for (let i = 0; i < input.length; i++) {
      if ((this.pos & mask) === 0) {
        this.ctx.encrypt(this.state, 0, this.ctr, 0);
        this._increment();
        this.pos = 0;
      }

      output[i] = input[i] ^ this.state[this.pos++];
    }
  }

  _final() {
    return Buffer.alloc(0);
  }

  _destroy() {
    for (let i = 0; i < this.blockSize; i++) {
      this.state[i] = 0;
      this.ctr[i] = 0;
    }
  }
}

/**
 * CTR Cipher
 */

class CTRCipher extends CTR {
  constructor(ctx) {
    super(ctx);
  }
}

/**
 * CTR Decipher
 */

class CTRDecipher extends CTR {
  constructor(ctx) {
    super(ctx);
  }
}

/**
 * CFB
 */

class CFB extends Stream {
  constructor(ctx, encrypt) {
    super(ctx);

    this.encrypt = encrypt;
    this.state = Buffer.alloc(this.blockSize);
    this.prev = Buffer.alloc(this.blockSize);
  }

  _init(key, iv) {
    assert(iv.length === this.blockSize);

    iv.copy(this.prev, 0);
  }

  _encrypt(output, input) {
    const mask = this.blockSize - 1;

    for (let i = 0; i < input.length; i++) {
      if ((this.pos & mask) === 0) {
        this.ctx.encrypt(this.state, 0, this.prev, 0);
        this.pos = 0;
      }

      output[i] = input[i] ^ this.state[this.pos];

      this.prev[this.pos] = output[i];

      this.pos += 1;
    }
  }

  _decrypt(output, input) {
    const mask = this.blockSize - 1;

    for (let i = 0; i < input.length; i++) {
      if ((this.pos & mask) === 0) {
        this.ctx.encrypt(this.state, 0, this.prev, 0);
        this.pos = 0;
      }

      this.prev[this.pos] = input[i];

      output[i] = input[i] ^ this.state[this.pos];

      this.pos += 1;
    }
  }

  _crypt(output, input) {
    if (this.encrypt)
      this._encrypt(output, input);
    else
      this._decrypt(output, input);
  }

  _final() {
    return Buffer.alloc(0);
  }

  _destroy() {
    for (let i = 0; i < this.blockSize; i++) {
      this.state[i] = 0;
      this.prev[i] = 0;
    }
  }
}

/**
 * CFB Cipher
 */

class CFBCipher extends CFB {
  constructor(ctx) {
    super(ctx, true);
  }
}

/**
 * CFB Decipher
 */

class CFBDecipher extends CFB {
  constructor(ctx) {
    super(ctx, false);
  }
}

/**
 * OFB
 */

class OFB extends Stream {
  constructor(ctx) {
    super(ctx);

    this.state = Buffer.alloc(this.blockSize);
  }

  _init(key, iv) {
    assert(Buffer.isBuffer(iv));
    assert(iv.length === this.blockSize);

    iv.copy(this.state, 0);
  }

  _crypt(output, input) {
    const mask = this.blockSize - 1;

    for (let i = 0; i < input.length; i++) {
      if ((this.pos & mask) === 0) {
        this.ctx.encrypt(this.state, 0, this.state, 0);
        this.pos = 0;
      }

      output[i] = input[i] ^ this.state[this.pos++];
    }
  }

  _final() {
    return Buffer.alloc(0);
  }

  _destroy() {
    for (let i = 0; i < this.blockSize; i++)
      this.state[i] = 0;
  }
}

/**
 * OFB Cipher
 */

class OFBCipher extends OFB {
  constructor(ctx) {
    super(ctx);
  }
}

/**
 * OFB Decipher
 */

class OFBDecipher extends OFB {
  constructor(ctx) {
    super(ctx);
  }
}

/**
 * GCM
 */

class GCM extends Stream {
  constructor(ctx, encrypt) {
    assert(ctx.blockSize === 16);

    super(ctx);

    this.encrypt = encrypt;
    this.hash = new GHASH();
    this.ctr = Buffer.alloc(16);
    this.state = Buffer.alloc(16);
    this.key = Buffer.alloc(16);
    this.mask = Buffer.alloc(16);
    this.tag = null;
    this.mac = null;
  }

  _init(key, iv) {
    for (let i = 0; i < 16; i++) {
      this.ctr[i] = 0;
      this.key[i] = 0;
      this.mask[i] = 0;
    }

    this._encipher(this.key, this.key);

    this.hash.init(this.key);

    // Full round of ghash with same key.
    if (iv.length !== 12) {
      this.hash.update(iv);
      iv = this.hash.final();
      this.hash.init(this.key);
    }

    iv.copy(this.ctr, 0);

    if (iv.length === 12) {
      this.ctr[12] = 0x00;
      this.ctr[13] = 0x00;
      this.ctr[14] = 0x00;
      this.ctr[15] = 0x01;
    }

    this._encipher(this.mask, this.mask);

    this.tag = null;
    this.mac = null;

    return this;
  }

  _increment() {
    let cy = 1;
    let i = 4;

    while (i--) {
      cy += this.ctr[12 + i];
      this.ctr[12 + i] = cy;
      cy >>= 8;
    }
  }

  _encipher(output, input) {
    for (let i = 0; i < input.length; i++) {
      if ((this.pos & 15) === 0) {
        this.ctx.encrypt(this.state, 0, this.ctr, 0);
        this._increment();
        this.pos = 0;
      }

      output[i] = input[i] ^ this.state[this.pos++];
    }
  }

  _crypt(output, input) {
    if (this.encrypt) {
      this._encipher(output, input);
      this.hash.update(output);
    } else {
      this.hash.update(input);
      this._encipher(output, input);
    }
  }

  _final() {
    const mac = this.hash.final();

    for (let i = 0; i < 16; i++)
      mac[i] ^= this.mask[i];

    if (this.encrypt) {
      this.mac = mac;
      return Buffer.alloc(0);
    }

    if (!this.tag)
      throw new Error('No tag provided.');

    let z = 0;

    for (let i = 0; i < this.tag.length; i++)
      z |= mac[i] ^ this.tag[i];

    if (z !== 0)
      throw new Error('Invalid tag.');

    return Buffer.alloc(0);
  }

  _destroy() {
    this.hash.destroy();

    for (let i = 0; i < 16; i++) {
      this.ctr[i] = 0;
      this.state[i] = 0;
      this.key[i] = 0;
      this.mask[i] = 0;
    }

    if (this.tag) {
      for (let i = 0; i < this.tag.length; i++)
        this.tag[i] = 0;

      this.tag = null;
    }
  }

  _setAAD(data) {
    this.hash.aad(data);
    return this;
  }

  _getAuthTag() {
    if (!this.encrypt)
      throw new Error('Must be a cipher context.');

    if (!this.mac)
      throw new Error('Cipher is not finalized.');

    return Buffer.from(this.mac);
  }

  _setAuthTag(tag) {
    if (this.encrypt)
      throw new Error('Must be a decipher context.');

    if (this.pos === -1)
      throw new Error('Cipher is not initialized.');

    if (tag.length !== 4 && tag.length !== 8
        && (tag.length < 12 || tag.length > 16)) {
      throw new RangeError('Invalid tag size.');
    }

    this.tag = Buffer.from(tag);

    return this;
  }
}

/**
 * GCM Cipher
 */

class GCMCipher extends GCM {
  constructor(ctx) {
    super(ctx, true);
  }
}

/**
 * GCM Decipher
 */

class GCMDecipher extends GCM {
  constructor(ctx) {
    super(ctx, false);
  }
}

/**
 * CBC-MAC
 */

class CBCMAC {
  constructor(ctx) {
    this.ctx = ctx;
    this.size = ctx.blockSize;
    this.mac = Buffer.alloc(this.size);
    this.pos = -1;
  }

  init() {
    this.mac.fill(0);
    this.pos = 0;
    return this;
  }

  update(data) {
    assert(Buffer.isBuffer(data));

    if (this.pos === -1)
      throw new Error('Context is not initialized.');

    const mask = this.size - 1;

    for (let i = 0; i < data.length; i++) {
      this.mac[this.pos++] ^= data[i];

      if ((this.pos & mask) === 0) {
        this.ctx.encrypt(this.mac, 0, this.mac, 0);
        this.pos = 0;
      }
    }
  }

  pad() {
    if (this.pos > 0) {
      this.ctx.encrypt(this.mac, 0, this.mac, 0);
      this.pos = 0;
    }
  }

  final() {
    if (this.pos === -1)
      throw new Error('Context is not initialized.');

    this.pad();
    this.pos = -1;

    return Buffer.from(this.mac);
  }
}

/**
 * CCM
 * https://tools.ietf.org/html/rfc3610
 */

class CCM extends Stream {
  constructor(ctx, encrypt) {
    assert(ctx.blockSize === 16);

    super(ctx);

    this.encrypt = encrypt;
    this.hash = new CBCMAC(ctx);
    this.state = Buffer.alloc(16);
    this.ctr = Buffer.alloc(16);
    this.tagLen = 0;
    this.iv = null;
    this.mac = null;
    this.tag = null;
  }

  _increment() {
    for (let i = 15; i >= 1; i--) {
      this.ctr[i] += 1;

      if (this.ctr[i] !== 0x00)
        break;
    }
  }

  _encipher(output, input) {
    for (let i = 0; i < input.length; i++) {
      if ((this.pos & 15) === 0) {
        this.ctx.encrypt(this.state, 0, this.ctr, 0);
        this._increment();
        this.pos = 0;
      }

      output[i] = input[i] ^ this.state[this.pos++];
    }
  }

  _init(key, iv) {
    // sjcl compat: no upper limit on l(N).
    if (iv.length < 7)
      throw new RangeError('Invalid nonce length.');

    if (iv.length > 13)
      iv = iv.slice(0, 13);

    this.iv = Buffer.from(iv);
    this.pos = -1;
    this.tagLen = 0;
    this.mac = null;
    this.tag = null;
  }

  _setCCM(msgLen, tagLen, aad) {
    if (!this.iv)
      throw new Error('Cipher is not initialized.');

    // Compute L, M, and N.
    let lm = msgLen;
    let L = Math.ceil((32 - Math.clz32(lm)) / 8);

    if (L < 2)
      L = 2;

    const M = tagLen;
    const N = 15 - L;
    const Adata = (aad && aad.length > 0) | 0;
    const block = Buffer.alloc(16);

    if (M < 4 || M > 16 || (M & 1) !== 0)
      throw new RangeError('Invalid tag length.');

    // Compute flags.
    block[0] = 64 * Adata + 8 * ((M - 2) / 2) + (L - 1);

    // sjcl compat: clamp nonces to 15-L.
    this.iv.copy(block, 1, 0, Math.min(N, this.iv.length));

    // Serialize message length.
    for (let i = 15; i >= 1 + N; i--) {
      block[i] = lm & 0xff;
      lm >>>= 8;
    }

    assert(lm === 0);

    this.hash.init();
    this.hash.update(block);

    if (Adata) {
      if (aad.length < 0xff00) {
        const buf = Buffer.alloc(2);

        buf[0] = aad.length >>> 8;
        buf[1] = aad.length >>> 0;

        this.hash.update(buf);
      } else if (aad.length < 0xffffffff) {
        const buf = Buffer.alloc(6);

        buf[0] = 0xff;
        buf[1] = 0xfe;
        buf[2] = aad.length >>> 24;
        buf[3] = aad.length >>> 16;
        buf[4] = aad.length >>> 8;
        buf[5] = aad.length >>> 0;

        this.hash.update(buf);
      } else {
        throw new RangeError('Invalid AAD length.');
      }

      this.hash.update(aad);
      this.hash.pad();
    }

    block[0] &= 7;
    block[15] = 1;

    for (let i = 14; i >= 1 + N; i--)
      block[i] = 0;

    block.copy(this.ctr, 0);

    this.pos = 0;
    this.tagLen = M;
    this.iv = null;
  }

  _crypt(output, input) {
    if (this.encrypt) {
      this.hash.update(input);
      this._encipher(output, input);
    } else {
      this._encipher(output, input);
      this.hash.update(output);
    }
  }

  _final() {
    const mac = this.hash.final();

    // Recreate S_0.
    let i = 16 - ((this.ctr[0] & 7) + 1);

    while (i < 16)
      this.ctr[i++] = 0;

    this.pos = 0;
    this._encipher(mac, mac);

    if (this.encrypt) {
      this.mac = mac.slice(0, this.tagLen);
      return Buffer.alloc(0);
    }

    if (!this.tag)
      throw new Error('No tag provided.');

    let z = 0;

    for (let i = 0; i < this.tagLen; i++)
      z |= mac[i] ^ this.tag[i];

    if (z !== 0)
      throw new Error('Invalid tag.');

    return Buffer.alloc(0);
  }

  _destroy() {
    for (let i = 0; i < 16; i++) {
      this.state[i] = 0;
      this.ctr[i] = 0;
    }

    this.tagLen = 0;
    this.iv = null;
    this.tag = null;
  }

  _getAuthTag() {
    if (!this.encrypt)
      throw new Error('Must be a cipher context.');

    if (!this.mac)
      throw new Error('Cipher is not finalized.');

    return Buffer.from(this.mac);
  }

  _setAuthTag(tag) {
    if (this.encrypt)
      throw new Error('Must be a decipher context.');

    if (this.pos === -1)
      throw new Error('Cipher is not initialized.');

    if (tag.length !== this.tagLen)
      throw new RangeError('Invalid tag size.');

    this.tag = Buffer.from(tag);

    return this;
  }
}

/*
 * CCM Cipher
 */

class CCMCipher extends CCM {
  constructor(ctx) {
    super(ctx, true);
  }
}

/*
 * CCM Decipher
 */

class CCMDecipher extends CCM {
  constructor(ctx) {
    super(ctx, false);
  }
}

/*
 * Helpers
 */

function get(name, encrypt = true) {
  assert(typeof name === 'string');
  assert(typeof encrypt === 'boolean');

  switch (name) {
    case 'RAW':
      return encrypt ? RawCipher : RawDecipher;
    case 'ECB':
      return encrypt ? ECBCipher : ECBDecipher;
    case 'CBC':
      return encrypt ? CBCCipher : CBCDecipher;
    case 'CTR':
      return encrypt ? CTRCipher : CTRDecipher;
    case 'CFB':
      return encrypt ? CFBCipher : CFBDecipher;
    case 'OFB':
      return encrypt ? OFBCipher : OFBDecipher;
    case 'GCM':
      return encrypt ? GCMCipher : GCMDecipher;
    case 'CCM':
      return encrypt ? CCMCipher : CCMDecipher;
    default:
      throw new Error(`Unknown mode: ${name}.`);
  }
}

/*
 * Expose
 */

exports.Mode = Mode;
exports.Block = Block;
exports.Stream = Stream;
exports.RawCipher = RawCipher;
exports.RawDecipher = RawDecipher;
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
exports.GCM = GCM;
exports.GCMCipher = GCMCipher;
exports.GCMDecipher = GCMDecipher;
exports.CCM = CCM;
exports.CCMCipher = CCMCipher;
exports.CCMDecipher = CCMDecipher;
exports.get = get;
