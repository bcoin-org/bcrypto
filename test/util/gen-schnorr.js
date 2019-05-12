'use strict';

const fs = require('fs');
const secp256k1 = require('../../lib/secp256k1');
const random = require('../../lib/random');
const vectors = [];

for (let i = 0; i < 256; i++) {
  const key = secp256k1.privateKeyGenerate();
  const pub = secp256k1.publicKeyCreate(key);
  const msg = random.randomBytes(32);
  const sig = secp256k1.schnorrSign(msg, key);

  let priv = key;
  let result = true;
  let comment = null;

  if (Math.random() > 0.5) {
    if (Math.random() > 0.5) {
      sig[Math.random() * sig.length | 0] ^= 1;
      comment = 'mutated signature';
    } else if (Math.random() > 0.5) {
      pub[Math.random() * pub.length | 0] ^= 1;
      comment = 'mutated key';
    } else {
      msg[Math.random() * msg.length | 0] ^= 1;
      comment = 'mutated message';
    }
    priv = Buffer.alloc(0);
    result = false;
  }

  vectors.push([
    priv.toString('hex'),
    pub.toString('hex'),
    msg.toString('hex'),
    sig.toString('hex'),
    result,
    comment
  ]);
}

fs.writeFileSync(`${__dirname}/../data/schnorr-custom.json`,
  JSON.stringify(vectors, null, 2) + '\n');
