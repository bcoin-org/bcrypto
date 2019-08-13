'use strict';

const assert = require('bsert');
const SHA1 = require('../lib/sha1');
const SHA224 = require('../lib/sha224');
const SHA256 = require('../lib/sha256');
const SHA384 = require('../lib/sha384');
const SHA512 = require('../lib/sha512');
const dsa = require('../lib/dsa');
const vectors = require('./data/wycheproof/dsa_test.json');

const hashes = {
  'SHA-1': SHA1,
  'SHA-224': SHA224,
  'SHA-256': SHA256,
  'SHA-384': SHA384,
  'SHA-512': SHA512
};

describe('DSA-Wycheproof', function() {
  this.timeout(30000);

  for (const group of vectors.testGroups) {
    const pub = dsa.publicKeyImportSPKI(Buffer.from(group.keyDer, 'hex'));
    const hash = hashes[group.sha];

    for (const test of group.tests) {
      const text = test.sig.slice(0, 32) + '...';

      it(`should verify signature ${text} (${hash.id})`, () => {
        const msg = hash.digest(Buffer.from(test.msg, 'hex'));
        const sig = Buffer.from(test.sig, 'hex');
        const res = test.result !== 'invalid';

        assert.strictEqual(dsa.verifyDER(msg, sig, pub), res);
      });
    }
  }
});
