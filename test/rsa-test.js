/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const SHA1 = require('../lib/sha1');
const SHA256 = require('../lib/sha256');
const rsa = require('../lib/rsa');
const vectors = require('./data/rsa.json');
const {RSAPrivateKey, RSAPublicKey} = rsa;

const msg = Buffer.from('foobar', 'ascii');

describe('RSA', function() {
  this.timeout(15000);

  it('should generate keypair', () => {
    const privRaw = rsa.privateKeyGenerate(1024);
    const pubRaw = rsa.publicKeyCreate(privRaw);

    const priv = RSAPrivateKey.decode(privRaw);
    assert.bufferEqual(priv.encode(), privRaw);
    assert(rsa.privateVerify(priv));

    const pub = RSAPublicKey.decode(pubRaw);
    assert.bufferEqual(pub.encode(), pubRaw);
    assert(rsa.publicVerify(pub));

    const privPem = priv.toPEM();
    assert(typeof privPem === 'string');
    assert.deepStrictEqual(RSAPrivateKey.fromPEM(privPem), priv);

    const pubPem = pub.toPEM();
    assert(typeof pubPem === 'string');
    assert.deepStrictEqual(RSAPublicKey.fromPEM(pubPem), pub);

    const privJSON = priv.toJSON();
    assert(privJSON && typeof privJSON === 'object');
    assert.deepStrictEqual(RSAPrivateKey.fromJSON(privJSON), priv);

    const pubJSON = pub.toJSON();
    assert(pubJSON && typeof pubJSON === 'object');
    assert.deepStrictEqual(RSAPublicKey.fromJSON(pubJSON), pub);
  });

  it('should sign and verify', () => {
    const priv = rsa.privateKeyGenerate(2048);
    const pub = rsa.publicKeyCreate(priv);

    assert(rsa.privateKeyVerify(priv));
    assert(rsa.publicKeyVerify(pub));

    const sig = rsa.sign(SHA256, msg, priv);
    const valid = rsa.verify(SHA256, msg, sig, pub);

    assert(valid);
  });

  it('should sign and verify (async)', async () => {
    const bits = rsa.native < 2 ? 1024 : 4096;
    const priv = await rsa.privateKeyGenerateAsync(bits);
    const pub = rsa.publicKeyCreate(priv);

    assert(rsa.privateKeyVerify(priv));
    assert(rsa.publicKeyVerify(pub));

    const sig = rsa.sign(SHA256, msg, priv);
    const valid = rsa.verify(SHA256, msg, sig, pub);

    assert(valid);
  });

  for (const [i, vector] of vectors.entries()) {
    const hash = vector.hash === 'sha1' ? SHA1 : SHA256;
    const msg = Buffer.from(vector.msg, 'hex');
    const sig = Buffer.from(vector.sig, 'hex');
    const key = RSAPublicKey.fromJSON(vector.key);

    it(`should verify vector #${i}`, () => {
      assert(rsa.verifyKey(hash, msg, sig, key));

      msg[0] ^= 1;
      assert(!rsa.verifyKey(hash, msg, sig, key));
      msg[0] ^= 1;
      assert(rsa.verifyKey(hash, msg, sig, key));

      sig[0] ^= 1;
      assert(!rsa.verifyKey(hash, msg, sig, key));
      sig[0] ^= 1;
      assert(rsa.verifyKey(hash, msg, sig, key));

      key.n[0] ^= 1;
      assert(!rsa.verifyKey(hash, msg, sig, key));
      key.n[0] ^= 1;
      assert(rsa.verifyKey(hash, msg, sig, key));

      key.e[0] ^= 1;
      assert(!rsa.verifyKey(hash, msg, sig, key));
      key.e[0] ^= 1;
      assert(rsa.verifyKey(hash, msg, sig, key));
    });
  }
});
