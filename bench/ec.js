'use strict';

const bench = require('./bench');
const secp256k1 = require('../lib/secp256k1');
const p256 = require('../lib/p256');
const p521 = require('../lib/p521');
const ed25519 = require('../lib/ed25519');
const ed448 = require('../lib/ed448');
const x25519 = require('../lib/x25519');
const x448 = require('../lib/x448');
const random = require('../lib/random');
const mul = secp256k1.native ? 10 : 1;

{
  const rounds = 1000 * mul;
  const key = secp256k1.privateKeyGenerate();
  const pub = secp256k1.publicKeyCreate(key);
  const msg = random.randomBytes(32);
  const sig = secp256k1.sign(msg, key);
  const ssig = secp256k1.schnorrSign(msg, key);

  bench('secp256k1 pubkey', rounds, () => {
    secp256k1.publicKeyCreate(key);
  });

  bench('secp256k1 verify (ecdsa)', rounds, () => {
    secp256k1.verify(msg, sig, pub);
  });

  bench('secp256k1 verify (schnorr)', rounds, () => {
    secp256k1.schnorrVerify(msg, ssig, pub);
  });
}

{
  const rounds = 1000 * mul;
  const key = p256.privateKeyGenerate();
  const pub = p256.publicKeyCreate(key);
  const msg = random.randomBytes(32);
  const sig = p256.sign(msg, key);

  bench('p256 pubkey', rounds, () => {
    p256.publicKeyCreate(key);
  });

  bench('p256 verify', rounds, () => {
    p256.verify(msg, sig, pub);
  });
}

{
  const rounds = 100 * mul;
  const key = p521.privateKeyGenerate();
  const pub = p521.publicKeyCreate(key);
  const msg = random.randomBytes(64);
  const sig = p521.sign(msg, key);

  bench('p521 pubkey', rounds, () => {
    p521.publicKeyCreate(key);
  });

  bench('p521 verify', rounds, () => {
    p521.verify(msg, sig, pub);
  });
}

{
  const rounds = 1000 * mul;
  const key = ed25519.privateKeyGenerate();
  const pub = ed25519.publicKeyCreate(key);
  const msg = random.randomBytes(32);
  const sig = ed25519.sign(msg, key);

  bench('ed25519 pubkey', rounds, () => {
    ed25519.publicKeyCreate(key);
  });

  bench('ed25519 verify', rounds, () => {
    ed25519.verify(msg, sig, pub);
  });
}

{
  const rounds = 100 * mul;
  const key = ed448.privateKeyGenerate();
  const pub = ed448.publicKeyCreate(key);
  const msg = random.randomBytes(32);
  const sig = ed448.sign(msg, key);

  bench('ed448 pubkey', rounds, () => {
    ed448.publicKeyCreate(key);
  });

  bench('ed448 verify', rounds, () => {
    ed448.verify(msg, sig, pub);
  });
}

{
  const rounds = 1000 * mul;
  const key = x25519.privateKeyGenerate();
  const pub = x25519.publicKeyCreate(x25519.privateKeyGenerate());

  bench('x25519 pubkey', rounds, () => {
    x25519.publicKeyCreate(key);
  });

  bench('x25519 derive', rounds, () => {
    x25519.derive(pub, key);
  });
}

{
  const rounds = 100 * mul;
  const key = x448.privateKeyGenerate();
  const pub = x448.publicKeyCreate(x448.privateKeyGenerate());

  bench('x448 pubkey', rounds, () => {
    x448.publicKeyCreate(key);
  });

  bench('x448 derive', rounds, () => {
    x448.derive(pub, key);
  });
}
