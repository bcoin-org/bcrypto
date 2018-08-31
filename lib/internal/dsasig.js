/*!
 * dsasig.js - DSA signatures for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const bio = require('bufio');
const Signature = require('./signature');
const {leftPad, trimZeroes} = require('./util');

/**
 * DSA Signature
 */

class DSASignature extends Signature {
  constructor(size, r, s) {
    assert((size >>> 0) === size);
    assert(size >= 1 && size < 0x7d);

    super();

    this.size = size;
    this.r = leftPad(r, size);
    this.s = leftPad(s, size);
  }

  setR(r) {
    return super.setR(r, this.size);
  }

  setS(s) {
    return super.setS(s, this.size);
  }

  encode() {
    return super.encode(this.size);
  }

  decode(data) {
    return super.decode(data, this.size);
  }

  toDER() {
    return super.toDER(this.size);
  }

  fromDER(data) {
    return super.fromDER(data, this.size);
  }

  toDNS() {
    const r = trimZeroes(this.r);
    const s = trimZeroes(this.s);

    if (r.length > 20 || s.length > 20)
      throw new Error('Invalid R or S value.');

    const bw = bio.write(41);

    bw.writeU8(0);
    bw.writeBytes(leftPad(r, 20));
    bw.writeBytes(leftPad(s, 20));

    return bw.render();
  }

  fromDNS(data) {
    assert(Buffer.isBuffer(data));

    // Signatures are [T] [R] [S] (20 byte R and S) -- T is ignored.
    // See: https://github.com/NLnetLabs/ldns/blob/develop/dnssec.c#L1795
    // See: https://github.com/miekg/dns/blob/master/dnssec.go#L373
    const br = bio.read(data);

    // Compressed L value.
    const T = br.readU8();

    if (T > 8)
      throw new Error('Invalid L value.');

    this.r = br.readBytes(20);
    this.s = br.readBytes(20);

    return this;
  }

  static decode(data, size) {
    return new this(size).decode(data);
  }

  static fromDER(data, size) {
    return new this(size).fromDER(data);
  }

  static fromDNS(data) {
    return new this(20).fromDNS(data);
  }
}

/*
 * Expose
 */

module.exports = DSASignature;
