'use strict';

const bench = require('./bench');
const rsa = require('../lib/rsa');
const SHA256 = require('../lib/sha256');
const random = require('../lib/random');
const mul = rsa.native ? 10 : 1;

{
  const rounds = 1000 * mul;
  const key = rsa.privateKeyGenerate(2048);
  const pub = rsa.publicKeyCreate(key);
  const msg = random.randomBytes(32);
  const sig = rsa.sign(SHA256, msg, key);

  bench('rsa verify (pkcs1v1.5)', rounds, () => {
    rsa.verify(SHA256, msg, sig, pub);
  });
}
