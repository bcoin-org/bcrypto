/*!
 * bcrypto.js - crypto for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const digest = require('./digest');
const random = require('./random');
const aes = require('./aes');

exports.AEAD = require('./aead');
exports.aes = require('./aes');
exports.Blake160 = require('./blake160');
exports.Blake256 = require('./blake256');
exports.Blake2b = require('./blake2b');
exports.ccmp = require('./ccmp');
exports.ChaCha20 = require('./chacha20');
exports.cleanse = require('./cleanse');
exports.digest = require('./digest');
exports.DRBG = require('./drbg');
exports.ed25519 = require('./ed25519');
exports.Hash160 = require('./hash160');
exports.Hash256 = require('./hash256');
exports.hkdf = require('./hkdf');
exports.HMAC = require('./hmac');
exports.Keccak = require('./keccak');
exports.MD5 = require('./md5');
exports.merkle = require('./merkle');
exports.p192 = require('./p192');
exports.p224 = require('./p224');
exports.p256 = require('./p256');
exports.p384 = require('./p384');
exports.p521 = require('./p521');
exports.pbkdf2 = require('./pbkdf2');
exports.Poly1305 = require('./poly1305');
exports.random = require('./random');
exports.rfc6962 = require('./rfc6962');
exports.RIPEMD160 = require('./ripemd160');
exports.rsa = require('./rsa');
exports.scrypt = require('./scrypt');
exports.secp256k1 = require('./secp256k1');
exports.SHA1 = require('./sha1');
exports.SHA224 = require('./sha224');
exports.SHA256 = require('./sha256');
exports.SHA3 = require('./sha3');
exports.SHA384 = require('./sha384');
exports.SHA512 = require('./sha512');

exports.get = digest.get;
exports.hash = digest.hash;
exports.hmac = digest.hmac;
exports.blake160 = digest.blake160;
exports.blake256 = digest.blake256;
exports.blake2b = digest.blake2b;
exports.hash160 = digest.hash160;
exports.hash256 = digest.hash256;
exports.keccak = digest.keccak;
exports.md5 = digest.md5;
exports.ripemd160 = digest.ripemd160;
exports.sha1 = digest.sha1;
exports.sha224 = digest.sha224;
exports.sha256 = digest.sha256;
exports.sha3 = digest.sha3;
exports.sha384 = digest.sha384;
exports.sha512 = digest.sha512;

exports.encipher = aes.encipher;
exports.decipher = aes.decipher;

exports.randomBytes = random.randomBytes;
exports.randomInt = random.randomInt;
exports.randomRange = random.randomRange;
