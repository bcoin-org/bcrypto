/*!
 * keccak224.js - Keccak-224 implementation for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const Keccak = require('./keccak');

/**
 * Keccak224
 */

class Keccak224 extends Keccak {
  /**
   * Create a Keccak224 context.
   * @constructor
   */

  constructor() {
    super();
  }

  init() {
    return super.init(224);
  }

  final() {
    return super.final(false);
  }

  static hash() {
    return new Keccak224();
  }

  static hmac() {
    throw new Error('Not implemented.');
  }

  static digest(data) {
    return super.digest(data, 224, false);
  }

  static root(left, right) {
    return super.root(left, right, 224, false);
  }

  static multi(one, two, three) {
    return super.multi(one, two, three, 224, false);
  }

  static mac(data) {
    throw new Error('Not implemented.');
  }
}

Keccak224.native = Keccak.native;
Keccak224.id = 'KECCAK224';
Keccak224.size = 28;
Keccak224.bits = 224;
Keccak224.blockSize = 144;
Keccak224.zero = Buffer.alloc(28, 0x00);
Keccak224.ctx = new Keccak224();

/*
 * Expose
 */

module.exports = Keccak224;
