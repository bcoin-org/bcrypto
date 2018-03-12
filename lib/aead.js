/*!
 * aead.js - aead for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const ChaCha20 = require('./chacha20');
const Poly1305 = require('./poly1305');

class AEAD {
  /**
   * AEAD (used for bip151)
   * @alias module:crypto.AEAD
   * @constructor
   * @see https://github.com/openssh/openssh-portable
   * @see https://tools.ietf.org/html/rfc7539#section-2.8
   */

  constructor() {
    this.chacha20 = new ChaCha20();
    this.poly1305 = new Poly1305();
    this.aadLen = 0;
    this.cipherLen = 0;
    this.hasCipher = false;
    this.polyKey = null;
  }

  /**
   * Initialize the AEAD with a key and iv.
   * @param {Buffer} key
   * @param {Buffer} iv - IV / packet sequence number.
   */

  init(key, iv) {
    const polyKey = Buffer.alloc(32, 0x00);

    this.chacha20.init(key, iv);
    this.chacha20.encrypt(polyKey);
    this.poly1305.init(polyKey);

    // We need to encrypt a full block
    // to get the cipher in the correct state.
    this.chacha20.encrypt(Buffer.alloc(32, 0x00));

    // Counter should be one.
    assert(this.chacha20.getCounter() === 1);

    // Expose for debugging.
    this.polyKey = polyKey;

    this.aadLen = 0;
    this.cipherLen = 0;
    this.hasCipher = false;
  }

  /**
   * Update the aad (will be finalized
   * on an encrypt/decrypt call).
   * @param {Buffer} aad
   */

  aad(data) {
    assert(!this.hasCipher, 'Cannot update aad.');
    this.poly1305.update(data);
    this.aadLen += data.length;
  }

  /**
   * Encrypt a piece of data.
   * @param {Buffer} data
   */

  encrypt(data) {
    if (!this.hasCipher)
      this.pad16(this.aadLen);

    this.chacha20.encrypt(data);
    this.poly1305.update(data);

    this.cipherLen += data.length;
    this.hasCipher = true;

    return data;
  }

  /**
   * Decrypt a piece of data.
   * @param {Buffer} data
   */

  decrypt(data) {
    if (!this.hasCipher)
      this.pad16(this.aadLen);

    this.cipherLen += data.length;
    this.hasCipher = true;

    this.poly1305.update(data);
    this.chacha20.encrypt(data);

    return data;
  }

  /**
   * Authenticate data without decrypting.
   * @param {Buffer} data
   */

  auth(data) {
    if (!this.hasCipher)
      this.pad16(this.aadLen);

    this.cipherLen += data.length;
    this.hasCipher = true;

    this.poly1305.update(data);

    return data;
  }

  /**
   * Finalize the aead and generate a MAC.
   * @returns {Buffer} MAC
   */

  final() {
    const len = Buffer.allocUnsafe(16);
    let lo, hi;

    // The RFC says these are supposed to be
    // uint32le, but their own fucking test
    // cases fail unless they are uint64le's.
    lo = this.aadLen % 0x100000000;
    hi = (this.aadLen - lo) / 0x100000000;
    len.writeUInt32LE(lo, 0, true);
    len.writeUInt32LE(hi, 4, true);

    lo = this.cipherLen % 0x100000000;
    hi = (this.cipherLen - lo) / 0x100000000;
    len.writeUInt32LE(lo, 8, true);
    len.writeUInt32LE(hi, 12, true);

    if (!this.hasCipher)
      this.pad16(this.aadLen);

    this.pad16(this.cipherLen);
    this.poly1305.update(len);

    return this.poly1305.final();
  }

  /**
   * Pad a chunk before updating mac.
   * @private
   * @param {Number} size
   */

  pad16(size) {
    size %= 16;

    if (size === 0)
      return;

    const pad = Buffer.allocUnsafe(16 - size);
    pad.fill(0);

    this.poly1305.update(pad);
  }
}

/*
 * Expose
 */

module.exports = AEAD;
