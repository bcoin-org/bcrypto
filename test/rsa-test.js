/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const SHA1 = require('../lib/sha1');
const SHA256 = require('../lib/sha256');
const rsa = require('../lib/rsa');
const vectors = require('./data/rsa.json');
const {RSAPrivateKey, RSAPublicKey} = rsa;

const msg = SHA256.digest(Buffer.from('foobar'));

describe('RSA', function() {
  this.timeout(20000);

  it('should generate keypair', () => {
    const priv = RSAPrivateKey.generate(1024);
    const {d, dp, dq, qi} = priv;

    priv.setD(null);
    priv.setDP(null);
    priv.setDQ(null);
    priv.setQI(null);
    priv.compute();

    assert.bufferEqual(priv.d, d);
    assert.bufferEqual(priv.dp, dp);
    assert.bufferEqual(priv.dq, dq);
    assert.bufferEqual(priv.qi, qi);
  });

  it('should generate keypair with custom exponent', () => {
    const priv = RSAPrivateKey.generate(1024, 0x0100000001);
    assert.strictEqual(priv.n.length, 128);
    assert.bufferEqual(priv.e, Buffer.from('0100000001', 'hex'));
  });

  it('should generate keypair with custom exponent (async)', async () => {
    const priv = await RSAPrivateKey.generateAsync(1024, 0x0100000001);
    assert.strictEqual(priv.n.length, 128);
    assert.bufferEqual(priv.e, Buffer.from('0100000001', 'hex'));
  });

  it('should sign and verify', () => {
    const priv = RSAPrivateKey.generate(2048);
    const pub = priv.toPublic();

    assert(priv.validate());
    assert(pub.validate());

    const sig = priv.sign(SHA256, msg);
    const valid = pub.verify(SHA256, msg, sig);

    assert(valid);
  });

  it('should sign and verify (async)', async () => {
    const bits = rsa.native < 2 ? 1024 : 4096;
    const priv = await RSAPrivateKey.generateAsync(bits);
    const pub = priv.toPublic();

    assert(priv.validate());
    assert(pub.validate());

    const sig = priv.sign(SHA256, msg);
    const valid = pub.verify(SHA256, msg, sig);

    assert(valid);
  });

  it('should encrypt and decrypt', () => {
    const priv = RSAPrivateKey.generate(1024);
    const pub = priv.toPublic();
    const msg = Buffer.from('hello world');

    const ct = rsa.encrypt(msg, pub);

    assert.notBufferEqual(ct, msg);

    const pt = rsa.decrypt(ct, priv);

    assert.bufferEqual(pt, msg);
  });

  it('should encrypt and decrypt (OAEP)', () => {
    const priv = RSAPrivateKey.generate(1024);
    const pub = priv.toPublic();
    const label = Buffer.alloc(0);
    const msg = Buffer.from('hello world');

    const ct = rsa.encryptOAEP(SHA1, msg, label, pub);

    assert.notBufferEqual(ct, msg);

    const pt = rsa.decryptOAEP(SHA1, ct, label, priv);

    assert.bufferEqual(pt, msg);
  });

  for (const [i, vector] of vectors.entries()) {
    const hash = vector.hash === 'sha1' ? SHA1 : SHA256;
    const msg = Buffer.from(vector.msg, 'hex');
    const sig = Buffer.from(vector.sig, 'hex');
    const key = RSAPublicKey.fromJSON(vector.key);

    it(`should verify RSA vector #${i}`, () => {
      assert(key.validate());

      const m = hash.digest(msg);

      assert(key.verify(hash, m, sig, key));

      m[0] ^= 1;
      assert(!key.verify(hash, m, sig));
      m[0] ^= 1;
      assert(key.verify(hash, m, sig));

      sig[0] ^= 1;
      assert(!key.verify(hash, m, sig));
      sig[0] ^= 1;
      assert(key.verify(hash, m, sig));

      sig[40] ^= 1;
      assert(!key.verify(hash, m, sig));
      sig[40] ^= 1;
      assert(key.verify(hash, m, sig));

      key.n[0] ^= 1;
      assert(!key.verify(hash, m, sig));
      key.n[0] ^= 1;
      assert(key.verify(hash, m, sig));

      key.e[0] ^= 1;
      assert(!key.verify(hash, m, sig));
      key.e[0] ^= 1;
      assert(key.verify(hash, m, sig));
    });
  }
});
