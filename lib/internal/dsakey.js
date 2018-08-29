/*!
 * dsakey.js - DSA keys for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const bio = require('bufio');
const BN = require('../../vendor/bn.js');
const base64 = require('./base64');
const pkcs1 = require('./pkcs1');
const {trimZeroes, countBits} = require('./util');

/*
 * Constants
 */

const ZERO = Buffer.from([0x00]);

/**
 * DSA Params
 */

class DSAParams extends bio.Struct {
  constructor(p, q, g) {
    super();
    this.p = trimZeroes(p);
    this.q = trimZeroes(q);
    this.g = trimZeroes(g);
  }

  toPKCS1() {
    return new pkcs1.DSAParameters(this.p, this.q, this.g);
  }

  fromPKCS1(key) {
    assert(key instanceof pkcs1.DSAParameters);

    this.p = trimZeroes(key.p.value);
    this.q = trimZeroes(key.q.value);
    this.g = trimZeroes(key.g.value);

    return this;
  }

  encode() {
    const key = this.toPKCS1();
    return key.encode();
  }

  decode(data) {
    const key = pkcs1.DSAParameters.decode(data);
    return this.fromPKCS1(key);
  }

  toPEM() {
    const key = this.toPKCS1();
    return key.toPEM();
  }

  fromPEM(str) {
    const key = pkcs1.DSAParameters.fromPEM(str);
    return this.fromPKCS1(key);
  }

  setP(p) {
    this.p = trimZeroes(p);
    return this;
  }

  setQ(q) {
    this.q = trimZeroes(q);
    return this;
  }

  setG(g) {
    this.g = trimZeroes(g);
    return this;
  }

  bits() {
    return this.L();
  }

  L() {
    return countBits(this.p);
  }

  N() {
    return countBits(this.q);
  }

  verify() {
    return true;
  }

  getJSON() {
    return {
      kty: 'DSA',
      p: base64.encodeURL(this.p),
      q: base64.encodeURL(this.q),
      g: base64.encodeURL(this.g),
      ext: true
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert(json.kty === 'DSA');

    this.p = base64.decodeURL(json.p);
    this.q = base64.decodeURL(json.q);
    this.g = base64.decodeURL(json.g);

    return this;
  }

  format() {
    return {
      type: 'DSAParams',
      p: this.p.toString('hex'),
      q: this.q.toString('hex'),
      g: this.g.toString('hex')
    };
  }

  static fromPEM(str) {
    return new this().fromPEM(str);
  }
}

/**
 * DSA Key
 */

class DSAKey extends DSAParams {
  constructor(p, q, g, y) {
    super(p, q, g);
    this.y = trimZeroes(y);
  }

  get type() {
    return 'dsa';
  }

  get curve() {
    return null;
  }

  toParams() {
    return new DSAParams(this.p, this.q, this.g);
  }

  fromParams(params) {
    assert(params instanceof DSAParams);
    this.p = params.p;
    this.q = params.q;
    this.g = params.g;
    return this;
  }

  setParams(params) {
    return this.fromParams(params);
  }

  setY(y) {
    this.y = trimZeroes(y);
    return this;
  }

  verify() {
    return true;
  }

  static fromParams(params) {
    return new this().fromParams(params);
  }
}

/**
 * DSA Public Key
 */

class DSAPublicKey extends DSAKey {
  constructor(p, q, g, y) {
    super(p, q, g, y);
  }

  toPKCS1() {
    return new pkcs1.DSAFullPublicKey(this.p, this.q, this.g, this.y);
  }

  fromPKCS1(key) {
    assert(key instanceof pkcs1.DSAFullPublicKey);

    this.p = trimZeroes(key.params.p.value);
    this.q = trimZeroes(key.params.q.value);
    this.g = trimZeroes(key.params.g.value);
    this.y = trimZeroes(key.y.value);

    return this;
  }

  encode() {
    const key = this.toPKCS1();
    return key.encode();
  }

  decode(data) {
    const key = pkcs1.DSAFullPublicKey.decode(data);
    return this.fromPKCS1(key);
  }

  toPEM() {
    const key = this.toPKCS1();
    return key.toPEM();
  }

  fromPEM(str) {
    const key = pkcs1.DSAFullPublicKey.fromPEM(str);
    return this.fromPKCS1(key);
  }

  toDNS() {
    const p = trimZeroes(this.p);
    const q = trimZeroes(this.q);
    const g = trimZeroes(this.g);
    const y = trimZeroes(this.y);

    if (q.length > 20)
      throw new Error('Invalid Q value.');

    if (y.length < 64)
      throw new Error('Invalid Y value.');

    const T = ((y.length - 64) + 7) >>> 3;
    const len = 64 + T * 8;

    if (p.length > len || g.length > len || y.length > len)
      throw new Error('Invalid P, G, or Y value.');

    const size = 21 + len * 3;
    const bw = bio.write(size);

    bw.writeU8(T);
    bw.writeBytes(leftPad(q, 20));
    bw.writeBytes(leftPad(p, len));
    bw.writeBytes(leftPad(g, len));
    bw.writeBytes(leftPad(y, len));

    return bw.render();
  }

  fromDNS(data) {
    assert(Buffer.isBuffer(data));

    // See: https://github.com/NLnetLabs/ldns/blob/develop/dnssec.c#L337
    const br = bio.read(data);

    // Compressed L value.
    const T = br.readU8();

    if (T > 8)
      throw new Error('Invalid L value.');

    // L = 512 + T (max=1024)
    // N = 160
    const len = 64 + T * 8;
    const q = br.readBytes(20);
    const p = br.readBytes(len);
    const g = br.readBytes(len);
    const y = br.readBytes(len);

    this.p = trimZeroes(p);
    this.q = trimZeroes(q);
    this.g = trimZeroes(g);
    this.y = trimZeroes(y);

    return this;
  }

  getJSON() {
    return {
      kty: 'DSA',
      p: base64.encodeURL(this.p),
      q: base64.encodeURL(this.q),
      g: base64.encodeURL(this.g),
      y: base64.encodeURL(this.y),
      ext: true
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert(json.kty === 'DSA');

    this.p = base64.decodeURL(json.p);
    this.q = base64.decodeURL(json.q);
    this.g = base64.decodeURL(json.g);
    this.y = base64.decodeURL(json.y);

    return this;
  }

  format() {
    return {
      type: 'DSAPublicKey',
      p: this.p.toString('hex'),
      q: this.q.toString('hex'),
      g: this.g.toString('hex'),
      y: this.y.toString('hex')
    };
  }

  static fromDNS(data) {
    return new this().fromDNS(data);
  }
}

/**
 * DSA Public Key
 */

class DSAPrivateKey extends DSAKey {
  constructor(p, q, g, y, x) {
    super(p, q, g, y);
    this.x = trimZeroes(x);
  }

  toPKCS1() {
    return new pkcs1.DSAPrivateKey(0, this.p, this.q, this.g, this.y, this.x);
  }

  fromPKCS1(key) {
    assert(key instanceof pkcs1.DSAPrivateKey);

    this.p = trimZeroes(key.p.value);
    this.q = trimZeroes(key.q.value);
    this.g = trimZeroes(key.g.value);
    this.y = trimZeroes(key.y.value);
    this.x = trimZeroes(key.x.value);

    return this;
  }

  setX(x) {
    this.x = trimZeroes(x);
    return this;
  }

  compute() {
    if (!this.y.equals(ZERO))
      return this;

    const g = new BN(this.g);
    const x = new BN(this.x);
    const p = new BN(this.p);
    const y = modPow(g, x, p);

    this.y = toBuffer(y);

    return this;
  }

  encode() {
    const key = this.toPKCS1();
    return key.encode();
  }

  decode(data) {
    const key = pkcs1.DSAPrivateKey.decode(data);
    return this.fromPKCS1(key);
  }

  toPEM() {
    const key = this.toPKCS1();
    return key.toPEM();
  }

  fromPEM(str) {
    const key = pkcs1.DSAPrivateKey.fromPEM(str);
    return this.fromPKCS1(key);
  }

  toPublic() {
    const pub = new DSAPublicKey();
    pub.p = this.p;
    pub.q = this.q;
    pub.g = this.g;
    pub.y = this.y;
    return pub;
  }

  getJSON() {
    return {
      kty: 'DSA',
      p: base64.encodeURL(this.p),
      q: base64.encodeURL(this.q),
      g: base64.encodeURL(this.g),
      y: base64.encodeURL(this.y),
      x: base64.encodeURL(this.x),
      ext: true
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert(json.kty === 'DSA');

    this.p = base64.decodeURL(json.p);
    this.q = base64.decodeURL(json.q);
    this.g = base64.decodeURL(json.g);
    this.y = base64.decodeURL(json.y);
    this.x = base64.decodeURL(json.x);

    return this;
  }

  format() {
    return {
      type: 'DSAPrivateKey',
      p: this.p.toString('hex'),
      q: this.q.toString('hex'),
      g: this.g.toString('hex'),
      y: this.y.toString('hex'),
      x: this.x.toString('hex')
    };
  }
}

/**
 * DSA Signature
 */

class DSASignature extends bio.Struct {
  constructor(r, s) {
    super();
    this.r = trimZeroes(r);
    this.s = trimZeroes(s);
  }

  toPKCS1() {
    return new pkcs1.DSASignature(this.r, this.s);
  }

  fromPKCS1(key) {
    assert(key instanceof pkcs1.DSASignature);

    this.r = trimZeroes(key.r.value);
    this.s = trimZeroes(key.s.value);

    return this;
  }

  encode() {
    const key = this.toPKCS1();
    return key.encode();
  }

  decode(data) {
    const key = pkcs1.DSASignature.decode(data);
    return this.fromPKCS1(key);
  }

  toPEM() {
    const key = this.toPKCS1();
    return key.toPEM();
  }

  fromPEM(str) {
    const key = pkcs1.DSASignature.fromPEM(str);
    return this.fromPKCS1(key);
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

  static fromPEM(str) {
    return new this().fromPEM(str);
  }

  static fromDNS(str) {
    return new this().fromDNS(str);
  }
}

/*
 * Helpers
 */

function leftPad(buf, size) {
  assert(Buffer.isBuffer(buf));
  assert((size >>> 0) === size);
  assert(buf.length <= size);

  if (buf.length === size)
    return buf;

  const p = size - buf.length;
  const b = Buffer.allocUnsafe(size);
  b.fill(0x00, 0, p);
  buf.copy(b, p);
  return b;
}

function modPow(x, y, m) {
  return x.toRed(BN.mont(m)).redPow(y).fromRed();
}

function toBuffer(n) {
  return n.toArrayLike(Buffer, 'be');
}

/*
 * Expose
 */

exports.DSAParams = DSAParams;
exports.DSAKey = DSAKey;
exports.DSAPublicKey = DSAPublicKey;
exports.DSAPrivateKey = DSAPrivateKey;
exports.DSASignature = DSASignature;
