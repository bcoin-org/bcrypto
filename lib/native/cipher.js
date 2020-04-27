/*!
 * cipher.js - ciphers for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');
const ciphers = require('../internal/ciphers');

/**
 * CipherBase
 * @param {String} name
 * @param {Boolean} encrypt
 */

class CipherBase {
  constructor(name, encrypt) {
    const [type, mode] = parseName(name);

    this._handle = binding.cipher_create(type, mode, encrypt);
  }

  init(key, iv) {
    if (iv == null)
      iv = Buffer.alloc(0);

    assert(this instanceof CipherBase);
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(iv));

    binding.cipher_init(this._handle, key, iv);

    return this;
  }

  update(data) {
    assert(this instanceof CipherBase);
    assert(Buffer.isBuffer(data));

    return binding.cipher_update(this._handle, data);
  }

  final() {
    assert(this instanceof CipherBase);
    return binding.cipher_final(this._handle);
  }

  destroy() {
    assert(this instanceof CipherBase);

    binding.cipher_destroy(this._handle);

    return this;
  }

  setAAD(data) {
    assert(this instanceof CipherBase);
    assert(Buffer.isBuffer(data));

    binding.cipher_set_aad(this._handle, data);

    return this;
  }

  getAuthTag() {
    assert(this instanceof CipherBase);
    return binding.cipher_get_tag(this._handle);
  }

  setAuthTag(tag) {
    assert(this instanceof CipherBase);
    assert(Buffer.isBuffer(tag));

    binding.cipher_set_tag(this._handle, tag);

    return this;
  }
}

/**
 * Cipher
 * @param {String} name
 */

class Cipher extends CipherBase {
  constructor(name) {
    super(name, true);
  }
}

/**
 * Decipher
 * @param {String} name
 */

class Decipher extends CipherBase {
  constructor(name) {
    super(name, false);
  }
}

/*
 * API
 */

function encrypt(name, key, iv, data) {
  if (iv == null)
    iv = Buffer.alloc(0);

  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(iv));
  assert(Buffer.isBuffer(data));

  const [type, mode] = parseName(name);

  return binding.cipher_encrypt(type, mode, key, iv, data);
}

function decrypt(name, key, iv, data) {
  if (iv == null)
    iv = Buffer.alloc(0);

  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(iv));
  assert(Buffer.isBuffer(data));

  const [type, mode] = parseName(name);

  return binding.cipher_decrypt(type, mode, key, iv, data);
}

/*
 * Helpers
 */

function parseName(name) {
  const info = ciphers.get(name);
  const type = binding.algorithms[info.algorithm];
  const mode = binding.modes[info.mode];

  return [type, mode];
}

/*
 * Expose
 */

exports.native = 2;
exports.Cipher = Cipher;
exports.Decipher = Decipher;
exports.info = ciphers.info;
exports.get = ciphers.get;
exports.has = ciphers.has;
exports.encrypt = encrypt;
exports.decrypt = decrypt;
