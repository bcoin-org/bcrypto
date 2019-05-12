'use strict';

const assert = require('bsert');
const fs = require('fs');
const MD4 = require('../lib/md4');
const MD5 = require('../lib/md5');
const RIPEMD160 = require('../lib/ripemd160');
const SHA1 = require('../lib/sha1');
const SHA224 = require('../lib/sha224');
const SHA256 = require('../lib/sha256');
const SHA384 = require('../lib/sha384');
const SHA512 = require('../lib/sha512');
const Hash160 = require('../lib/hash160');
const Hash256 = require('../lib/hash256');
const MD5SHA1 = require('../lib/md5sha1');
const BLAKE2s256 = require('../lib/blake2s256');
const BLAKE2b512 = require('../lib/blake2b512');
const Whirlpool = require('../lib/whirlpool');
const SHA3_224 = require('../lib/sha3-224');
const SHA3_256 = require('../lib/sha3-256');
const SHA3_384 = require('../lib/sha3-384');
const SHA3_512 = require('../lib/sha3-512');
const SHAKE128 = require('../lib/shake128');
const SHAKE256 = require('../lib/shake256');

const hashes = [
  ['md4', MD4],
  ['md5', MD5],
  ['ripemd160', RIPEMD160],
  ['sha1', SHA1],
  ['sha224', SHA224],
  ['sha256', SHA256],
  ['sha384', SHA384],
  ['sha512', SHA512],
  ['hash160', Hash160],
  ['hash256', Hash256],
  ['whirlpool', Whirlpool],
  ['md5-sha1', MD5SHA1],
  ['blake2s256', BLAKE2s256],
  ['blake2b512', BLAKE2b512],
  ['sha3-224', SHA3_224],
  ['sha3-256', SHA3_256],
  ['sha3-384', SHA3_384],
  ['sha3-512', SHA3_512],
  ['shake128', SHAKE128],
  ['shake256', SHAKE256]
];

describe('Hash', function() {
  for (const [name, hash] of hashes) {
    const file = `${__dirname}/data/hashes/${name}.json`;
    const text = fs.readFileSync(file, 'utf8');
    const vectors = JSON.parse(text);

    for (const [msg_, key_, expect_] of vectors) {
      const msg = Buffer.from(msg_, 'hex');
      const expect = Buffer.from(expect_, 'hex');

      if (key_ != null) {
        const key = Buffer.from(key_, 'hex');

        it(`should get ${hash.id} hmac of ${expect_}`, () => {
          const ch = Buffer.allocUnsafe(1);
          const ctx = hash.hmac();

          assert.bufferEqual(ctx.init(key).update(msg).final(), expect);

          ctx.init(key);

          for (let i = 0; i < msg.length; i++) {
            ch[0] = msg[i];
            ctx.update(ch);
          }

          assert.bufferEqual(ctx.final(), expect);

          assert.bufferEqual(hash.mac(msg, key), expect);
        });
      } else {
        it(`should get ${hash.id} hash of ${expect_}`, () => {
          const ch = Buffer.allocUnsafe(1);
          const size = msg.length >>> 1;
          const left = msg.slice(0, size);
          const right = msg.slice(size);
          const ctx = hash.hash();

          assert.bufferEqual(ctx.init().update(msg).final(), expect);

          ctx.init();

          for (let i = 0; i < msg.length; i++) {
            ch[0] = msg[i];
            ctx.update(ch);
          }

          assert.bufferEqual(ctx.final(), expect);

          assert.bufferEqual(hash.digest(msg), expect);

          assert.bufferEqual(hash.multi(left, right), expect);

          assert.bufferEqual(hash.root(expect, expect),
                             hash.multi(expect, expect));
        });
      }
    }
  }
});
