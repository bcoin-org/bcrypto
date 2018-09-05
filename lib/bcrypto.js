/*!
 * bcrypto.js - crypto for bcoin
 * Copyright (c) 2014-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const aes = require('./aes');
const cipher = require('./cipher');
const random = require('./random');

exports.AEAD = require('./aead');
exports.aes = aes;
exports.Blake2b = require('./blake2b');
exports.Blake2b160 = require('./blake2b160');
exports.Blake2b256 = require('./blake2b256');
exports.Blake2b512 = require('./blake2b512');
exports.BN = require('./bn');
exports.bcrypt = require('./bcrypt');
exports.ChaCha20 = require('./chacha20');
exports.cipher = cipher;
exports.cleanse = require('./cleanse');
exports.DRBG = require('./drbg');
exports.dsa = require('./dsa');
exports.eb2k = require('./eb2k');
exports.ed25519 = require('./ed25519');
exports.encoding = require('./encoding');
exports.Hash160 = require('./hash160');
exports.Hash256 = require('./hash256');
exports.hkdf = require('./hkdf');
exports.Keccak = require('./keccak');
exports.Keccak256 = require('./keccak256');
exports.Keccak384 = require('./keccak384');
exports.Keccak512 = require('./keccak512');
exports.MD5 = require('./md5');
exports.merkle = require('./merkle');
exports.mrkl = require('./mrkl');
exports.p192 = require('./p192');
exports.p224 = require('./p224');
exports.p256 = require('./p256');
exports.p384 = require('./p384');
exports.p521 = require('./p521');
exports.pbkdf2 = require('./pbkdf2');
exports.pgp = require('./pgp');
exports.Poly1305 = require('./poly1305');
exports.random = random;
exports.RIPEMD160 = require('./ripemd160');
exports.rsa = require('./rsa');
exports.safeEqual = require('./safe-equal');
exports.scrypt = require('./scrypt');
exports.secp256k1 = require('./secp256k1');
exports.ssh = require('./ssh');
exports.SHA1 = require('./sha1');
exports.SHA224 = require('./sha224');
exports.SHA256 = require('./sha256');
exports.SHA384 = require('./sha384');
exports.SHA512 = require('./sha512');
exports.SHA3 = require('./sha3');
exports.SHA3_256 = require('./sha3-256');
exports.SHA3_384 = require('./sha3-384');
exports.SHA3_512 = require('./sha3-512');

exports.encipher = aes.encipher;
exports.decipher = aes.decipher;

exports.Cipher = cipher.Cipher;
exports.Decipher = cipher.Decipher;

exports.randomBytes = random.randomBytes;
exports.randomBytesAsync = random.randomBytesAsync;
exports.randomFill = random.randomFill;
exports.randomFillAsync = random.randomFillAsync;
exports.randomInt = random.randomInt;
exports.randomRange = random.randomRange;

exports.native = random.native;
