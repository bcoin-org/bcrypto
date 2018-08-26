/*!
 * pem.js - PEM for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 *
 * Parts of this software are based on crypto-browserify/EVP_BytesToKey:
 *   Copyright (c) 2017 crypto-browserify contributors
 *   https://github.com/crypto-browserify/EVP_BytesToKey
 *
 * Resources:
 *   https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem
 *   https://tools.ietf.org/html/rfc1421
 *   https://tools.ietf.org/html/rfc4880
 *   https://github.com/crypto-browserify/EVP_BytesToKey/blob/master/index.js
 *   https://github.com/openssl/openssl/blob/master/include/openssl/pem.h
 *   https://github.com/openssl/openssl/blob/master/crypto/pem/pem_lib.c
 *   https://github.com/openssl/openssl/blob/master/crypto/evp/evp_key.c
 *   https://github.com/openssl/openssl/blob/master/crypto/pem/pem_pkey.c
 */

/* eslint spaced-comment: "off" */

'use strict';

const assert = require('bsert');
const bio = require('bufio');
const base64 = require('./base64');
const {lines} = require('./util');

const MD5 = require('../md5');
// XXX
const crypto = require('crypto');

/*
 * Constants
 */

const EMPTY = Buffer.alloc(0);

/*
 * PEMBlock
 */

class PEMBlock {
  constructor() {
    this.type = 'PRIVACY-ENHANCED MESSAGE';
    this.headers = new Map();
    this.data = EMPTY;
  }

  toString(armor) {
    return encode(this.type, this.headers, this.data, armor);
  }

  fromString(str, armor) {
    const iter = decode(str, armor);
    const it = iter.next();

    if (it.done)
      throw new Error('No PEM data found.');

    const block = it.value;

    this.type = block.type;
    this.headers = block.headers;
    this.data = block.data;

    return this;
  }

  isEncrypted() {
    const type = this.getProcType();

    if (!type)
      return false;

    return type.version === 4 && type.state === 'ENCRYPTED';
  }

  getProcType() {
    const hdr = this.headers.get('Proc-Type');

    if (!hdr)
      return null;

    const parts = hdr.split(',', 3);

    if (parts.length < 2)
      return null;

    return { version: parts[0] >>> 0, state: parts[1] };
  }

  getDEKInfo() {
    if (!this.isEncrypted())
      return null;

    const hdr = this.headers.get('DEK-Info');

    if (!hdr)
      return null;

    const parts = hdr.split(',', 3);

    if (parts.length < 2)
      return null;

    return {
      cipher: parts[0],
      iv: Buffer.from(parts[1], 'hex')
    };
  }

  decrypt(passphrase) {
    assert(typeof passphrase === 'string');

    const info = this.getDEKInfo();

    if (!info)
      throw new Error('DEK-Info not found.');

    const [key] = evpBytesToKey(passphrase, info.iv, 16, 16);
    const cipher = crypto.createDecipheriv(info.cipher, key, info.iv);

    this.data = bio.concat(
      cipher.update(this.data),
      cipher.final()
    );
  }

  static fromString(str, armor) {
    return new this().fromString(str, armor);
  }
}

/*
 * PEM
 */

function encode(type, headers, data, armor = false) {
  assert(typeof type === 'string');
  assert(headers instanceof Map);
  assert(Buffer.isBuffer(data));
  assert(typeof armor === 'boolean');

  let str = '';

  str += `-----BEGIN ${type}-----\n`;

  if (headers.size > 0) {
    for (const [key, value] of headers)
      str += `${key}: ${value}\n`;

    str += '\n';
  }

  const s = base64.encode(data);

  for (let i = 0; i < s.length; i += 64)
    str += s.substring(i, i + 64) + '\n';

  if (armor) {
    const crc = crc24(data);

    str += `=${base64.encode(crc)}\n`;
  }

  str += `-----END ${type}-----\n`;

  return str;
}

function *decode(str, armor = false) {
  assert(typeof str === 'string');
  assert(typeof armor === 'boolean');

  let chunk = '';
  let block = null;
  let crc = null;

  for (const line of lines(str)) {
    const index = line.indexOf(':');

    if (index !== -1) {
      if (!block)
        throw new Error('PEM parse error (misplaced header).');

      const key = line.substring(0, index).trim();
      const value = line.substring(index + 1).trim();

      block.headers.set(key, value);

      continue;
    }

    if (line.length >= 15 && line.substring(0, 5) === '-----') {
      if (line.slice(-5) !== '-----')
        throw new Error('PEM parse error (invalid preamble).');

      const preamble = line.slice(5, -5);

      if (preamble.substring(0, 6) === 'BEGIN ') {
        const type = preamble.substring(6).trim();

        if (block)
          throw new Error('PEM parse error (un-ended block).');

        block = new PEMBlock();
        block.type = type;

        continue;
      }

      if (preamble.substring(0, 4) === 'END ') {
        const type = preamble.substring(4).trim();

        if (!block)
          throw new Error('PEM parse error (unexpected end).');

        if (block.type !== type)
          throw new Error('PEM parse error (type mismatch).');

        block.data = base64.decode(chunk);

        if (crc && !crc24(block.data).equals(crc))
          throw new Error('PEM parse error (invalid armor checksum).');

        yield block;

        chunk = '';
        block = null;
        crc = null;

        continue;
      }

      throw new Error('PEM parse error (unknown preamble).');
    }

    if (!block)
      throw new Error('PEM parse error (unexpected data).');

    if (line.length === 5 && line.charCodeAt(0) === 0x3d /*'='*/) {
      if (!armor)
        continue;

      if (crc)
        throw new Error('PEM parse error (unexpected armor checksum).');

      crc = base64.decode(line.substring(1));

      continue;
    }

    if (line.length > 96)
      throw new Error('PEM parse error (line too long).');

    chunk += line.replace(/[\t\v ]/g, '');
  }

  if (block || crc)
    throw new Error('PEM parse error (un-ended block).');

  if (chunk.length !== 0)
    throw new Error('PEM parse error (trailing data).');
}

function toPEM(data, type, armor) {
  assert(Buffer.isBuffer(data));
  assert(typeof type === 'string');

  const block = new PEMBlock();
  block.type = type;
  block.data = data;

  return block.toString(armor);
}

function fromPEM(str, type, armor) {
  assert(typeof str === 'string');
  assert(typeof type === 'string');

  const block = PEMBlock.fromString(str, armor);

  if (block.type !== type)
    throw new Error('PEM type mismatch.');

  return block.data;
}

function readPublicKey(str) {
  assert(typeof str === 'string');

  const block = PEMBlock.fromString(str, false);

  if (block.type.slice(-10) !== 'PUBLIC KEY')
    throw new Error('PEM type mismatch.');

  if (block.isEncrypted())
    throw new Error('Cannot decrypt public key.');

  return [block.type, block.data];
}

function readPrivateKey(str, passphrase) {
  assert(typeof str === 'string');
  assert(!passphrase || typeof passphrase === 'string');

  const block = PEMBlock.fromString(str, false);

  if (block.type.slice(-11) !== 'PRIVATE KEY')
    throw new Error('PEM type mismatch.');

  if (block.isEncrypted()) {
    if (passphrase == null)
      throw new Error('PEM block requires a passphrase.');

    block.decrypt(passphrase);
  }

  return [block.type, block.data];
}

/*
 * Helpers
 */

function crc24(data) {
  assert(Buffer.isBuffer(data));

  let crc = 0xb704ce;

  for (let i = 0; i < data.length; i++) {
    const ch = data[i];

    crc ^= ch << 16;

    for (let j = 0; j < 8; j++) {
      crc <<= 1;

      if (crc & 0x1000000)
        crc ^= 0x1864cfb;
    }
  }

  crc &= 0xffffff;

  const buf = Buffer.allocUnsafe(3);

  buf[2] = crc;
  crc >>>= 8;
  buf[1] = crc;
  crc >>>= 8;
  buf[0] = crc;

  return buf;
}

function evpBytesToKey(passwd, salt, keyLen, ivLen) {
  if (typeof passwd === 'string')
    passwd = Buffer.from(passwd, 'binary');

  if (typeof salt === 'string')
    salt = Buffer.from(salt, 'binary');

  if (ivLen == null)
    ivLen = 0;

  assert(Buffer.isBuffer(passwd));
  assert(salt === null || Buffer.isBuffer(salt));
  assert((keyLen >>> 0) === keyLen);
  assert((ivLen >>> 0) === ivLen);

  if (salt && salt.length > 8)
    salt = salt.slice(0, 8);

  if (salt && salt.length !== 8)
    throw new RangeError('Salt must be at least 8 bytes.');

  const key = Buffer.alloc(keyLen);
  const iv = Buffer.alloc(ivLen);

  let tmp = Buffer.alloc(0);

  while (keyLen > 0 || ivLen > 0) {
    const hash = new MD5();

    hash.init();
    hash.update(tmp);
    hash.update(passwd);

    if (salt)
      hash.update(salt);

    tmp = hash.final();

    let used = 0;

    if (keyLen > 0) {
      const keyStart = key.length - keyLen;
      used = Math.min(keyLen, tmp.length);
      tmp.copy(key, keyStart, 0, used);
      keyLen -= used;
    }

    if (used < tmp.length && ivLen > 0) {
      const ivStart = iv.length - ivLen;
      const length = Math.min(ivLen, tmp.length - used);
      tmp.copy(iv, ivStart, used, used + length);
      ivLen -= length;
    }
  }

  tmp.fill(0x00);

  return [key, iv];
}

/*
 * Expose
 */

exports.PEMBlock = PEMBlock;
exports.encode = encode;
exports.decode = decode;
exports.toPEM = toPEM;
exports.fromPEM = fromPEM;
exports.readPublicKey = readPublicKey;
exports.readPrivateKey = readPrivateKey;
