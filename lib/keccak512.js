/*!
 * keccak512.js - Keccak-512 implementation for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const Keccak = require('./keccak');

/**
 * Keccak512
 */

class Keccak512 extends Keccak {
  /**
   * Create a Keccak512 context.
   * @constructor
   */

  constructor() {
    super();
  }

  init() {
    return super.init(512);
  }

  final() {
    return super.final(0x01, null);
  }

  static hash() {
    return new Keccak512();
  }

  static hmac() {
    return super.hmac(512, 0x01);
  }

  static digest(data) {
    return super.digest(data, 512, 0x01);
  }

  static root(left, right) {
    return super.root(left, right, 512, 0x01);
  }

  static multi(one, two, three) {
    return super.multi(one, two, three, 512, 0x01);
  }

  static mac(data, key) {
    return super.mac(data, key, 512, 0x01);
  }
}

Keccak512.native = Keccak.native;
Keccak512.id = 'KECCAK512';
Keccak512.size = 32;
Keccak512.bits = 512;
Keccak512.blockSize = 72;
Keccak512.zero = Buffer.alloc(32, 0x00);
Keccak512.ctx = new Keccak512();

/*
 * Expose
 */

module.exports = Keccak512;
