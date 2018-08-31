/*!
 * dsakey.js - DSA keys for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const bio = require('bufio');
const base64 = require('./base64');
const openssl = require('../encoding/openssl');
const pkcs1 = require('../encoding/pkcs1');
const rfc2792 = require('../encoding/rfc2792');
const rfc3279 = require('../encoding/rfc3279');
const {trimZeroes, countBits} = require('./util');

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

  get dsa() {
    return this.constructor.dsa;
  }

  get type() {
    return 'dsa';
  }

  get curve() {
    return null;
  }

  toPKCS1() {
    return new rfc3279.DSAParameters(this.p, this.q, this.g);
  }

  fromPKCS1(key) {
    assert(key instanceof rfc3279.DSAParameters);

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
    const key = rfc3279.DSAParameters.decode(data);
    return this.fromPKCS1(key);
  }

  toPEM() {
    const key = this.toPKCS1();
    return key.toPEM();
  }

  fromPEM(str) {
    const key = rfc3279.DSAParameters.fromPEM(str);
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

  size() {
    return (this.N() + 7) >>> 3;
  }

  L() {
    return countBits(this.p);
  }

  N() {
    return countBits(this.q);
  }

  validate() {
    const L = this.L();
    const N = this.N();

    // if (L < 1024 || L > 3072)
    //   return false;

    // if (N < 160 || N > 256)
    //   return false;

    if (!(L === 1024 && N === 160)
        && !(L === 2048 && N === 224)
        && !(L === 2048 && N === 256)
        && !(L === 3072 && N === 256)) {
      return false;
    }

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
      type: this.type,
      p: this.p.toString('hex'),
      q: this.q.toString('hex'),
      g: this.g.toString('hex')
    };
  }

  static fromPEM(str) {
    return new this().fromPEM(str);
  }

  static generate(bits) {
    return this.dsa.paramsGenerate(bits);
  }

  static generateAsync(bits) {
    return this.dsa.paramsGenerateAsync(bits);
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
    return new rfc2792.DSAPublicKey(this.p, this.q, this.g, this.y);
  }

  fromPKCS1(key) {
    assert(key instanceof rfc2792.DSAPublicKey);

    this.p = trimZeroes(key.params.p.value);
    this.q = trimZeroes(key.params.q.value);
    this.g = trimZeroes(key.params.g.value);
    this.y = trimZeroes(key.y.value);

    return this;
  }

  verify(msg, sig) {
    return this.dsa.verify(msg, sig, this);
  }

  encode() {
    const key = this.toPKCS1();
    return key.encode();
  }

  decode(data) {
    const key = rfc2792.DSAPublicKey.decode(data);
    return this.fromPKCS1(key);
  }

  toPEM() {
    const key = this.toPKCS1();
    return key.toPEM();
  }

  fromPEM(str) {
    const key = rfc2792.DSAPublicKey.fromPEM(str);
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
      type: this.type,
      p: this.p.toString('hex'),
      q: this.q.toString('hex'),
      g: this.g.toString('hex'),
      y: this.y.toString('hex')
    };
  }

  static fromDNS(data) {
    return new this().fromDNS(data);
  }

  static generate(bits) {
    throw new Error('Unimplemented.');
  }

  static generateAsync(bits) {
    throw new Error('Unimplemented.');
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
    return new openssl.DSAPrivateKey(0, this.p, this.q, this.g, this.y, this.x);
  }

  fromPKCS1(key) {
    assert(key instanceof openssl.DSAPrivateKey);

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

  Y() {
    return this.dsa.computeY(this);
  }

  needsCompute() {
    return countBits(this.y) === 0;
  }

  compute() {
    if (!this.needsCompute())
      return this;

    this.y = this.Y();

    return this;
  }

  validate() {
    if (!this.toPublic().validate())
      return false;

    return this.y.equals(this.Y());
  }

  sign(msg) {
    return this.dsa.sign(msg, this);
  }

  verify(msg, sig) {
    return this.dsa.verify(msg, sig, this);
  }

  encode() {
    const key = this.toPKCS1();
    return key.encode();
  }

  decode(data) {
    const key = openssl.DSAPrivateKey.decode(data);
    return this.fromPKCS1(key);
  }

  toPEM() {
    const key = this.toPKCS1();
    return key.toPEM();
  }

  fromPEM(str) {
    const key = openssl.DSAPrivateKey.fromPEM(str);
    return this.fromPKCS1(key);
  }

  toPublic() {
    const dsa = this.dsa;
    const pub = new dsa.DSAPublicKey();

    this.compute();

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
      type: this.type,
      p: this.p.toString('hex'),
      q: this.q.toString('hex'),
      g: this.g.toString('hex'),
      y: this.y.toString('hex'),
      x: this.x.toString('hex')
    };
  }

  static generate(bits) {
    return this.dsa.privateKeyGenerate(bits);
  }

  static async generateAsync(bits) {
    return this.dsa.privateKeyGenerateAsync(bits);
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

/*
 * Expose
 */

module.exports = function create(backend) {
  assert(backend);

  return {
    DSAKey: DSAParams,
    DSAParams: class DSAParams_ extends DSAParams {
      constructor(p, q, g) {
        super(p, q, g);
      }

      static get dsa() {
        return backend;
      }
    },
    DSAPublicKey: class DSAPublicKey_ extends DSAPublicKey {
      constructor(p, q, g, y) {
        super(p, q, g, y);
      }

      static get dsa() {
        return backend;
      }
    },
    DSAPrivateKey: class DSAPrivateKey_ extends DSAPrivateKey {
      constructor(p, q, g, y, x) {
        super(p, q, g, y, x);
      }

      static get dsa() {
        return backend;
      }
    }
  };
};
