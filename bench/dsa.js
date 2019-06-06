'use strict';

const bench = require('./bench');
const dsa = require('../lib/dsa');
const random = require('../lib/random');
const mul = dsa.native ? 10 : 1;

{
  const rounds = 100 * mul;
  const key = dsa.privateKeyGenerate(1024);
  const pub = dsa.publicKeyCreate(key);
  const msg = random.randomBytes(32);
  const sig = dsa.sign(msg, key);

  bench('dsa verify', rounds, () => {
    dsa.verify(msg, sig, pub);
  });
}
