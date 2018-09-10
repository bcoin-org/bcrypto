/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const MD5 = require('../lib/md5');
const SHA1 = require('../lib/sha1');
const SHA256 = require('../lib/sha256');
const random = require('../lib/random');
const rsa = require('../lib/rsa');
const base64 = require('../lib/internal/base64');
const vectors = require('./data/rsa.json');
const {RSAPublicKey} = rsa;

const msg = SHA256.digest(Buffer.from('foobar'));

function fromJSON(json) {
  assert(json && typeof json === 'object');
  assert(json.kty === 'RSA');

  const key = new RSAPublicKey();
  key.n = base64.decodeURL(json.n);
  key.e = base64.decodeURL(json.e);

  return key;
}

describe('RSA', function() {
  this.timeout(20000);

  it('should generate keypair', () => {
    const priv = rsa.privateKeyGenerate(1024);
    const {d, dp, dq, qi} = priv;

    priv.setD(null);
    priv.setDP(null);
    priv.setDQ(null);
    priv.setQI(null);
    rsa.privateKeyCompute(priv);

    assert.bufferEqual(priv.d, d);
    assert.bufferEqual(priv.dp, dp);
    assert.bufferEqual(priv.dq, dq);
    assert.bufferEqual(priv.qi, qi);

    assert.deepStrictEqual(
      rsa.privateKeyImport(rsa.privateKeyExport(priv)),
      priv);

    const pub = rsa.publicKeyCreate(priv);

    assert.deepStrictEqual(
      rsa.publicKeyImport(rsa.publicKeyExport(pub)),
      pub);
  });

  it('should generate keypair with custom exponent', () => {
    const priv = rsa.privateKeyGenerate(1024, 0x0100000001);
    assert.strictEqual(priv.n.length, 128);
    assert.bufferEqual(priv.e, Buffer.from('0100000001', 'hex'));
  });

  it('should generate keypair with custom exponent (async)', async () => {
    const priv = await rsa.privateKeyGenerateAsync(1024, 0x0100000001);
    assert.strictEqual(priv.n.length, 128);
    assert.bufferEqual(priv.e, Buffer.from('0100000001', 'hex'));
  });

  it('should sign and verify', () => {
    const bits = rsa.native < 2 ? 1024 : 4096;
    const priv = rsa.privateKeyGenerate(bits);
    const pub = rsa.publicKeyCreate(priv);

    assert(rsa.privateKeyVerify(priv));
    assert(rsa.publicKeyVerify(pub));

    const sig = rsa.sign(SHA256, msg, priv);
    assert(rsa.verify(SHA256, msg, sig, pub));
    sig[(Math.random() * sig.length) | 0] ^= 1;
    assert(!rsa.verify(SHA256, msg, sig, pub));
  });

  it('should sign and verify (PSS)', () => {
    const priv = rsa.privateKeyGenerate(1024);
    const pub = rsa.publicKeyCreate(priv);

    assert(rsa.privateKeyVerify(priv));
    assert(rsa.publicKeyVerify(pub));

    const sig1 = rsa.signPSS(SHA256, msg, priv, -1);
    assert(rsa.verifyPSS(SHA256, msg, sig1, pub));
    sig1[(Math.random() * sig1.length) | 0] ^= 1;
    assert(!rsa.verifyPSS(SHA256, msg, sig1, pub));

    const sig2 = rsa.signPSS(SHA256, msg, priv, 0);
    assert(rsa.verifyPSS(SHA256, msg, sig2, pub, 0));
    sig2[(Math.random() * sig1.length) | 0] ^= 1;
    assert(!rsa.verifyPSS(SHA256, msg, sig2, pub, 0));
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

  it('should test signature padding (PKCS1v1.5)', () => {
    const priv = rsa.privateKeyGenerate(512);
    const pub = rsa.publicKeyCreate(priv);

    let msg, sig;

    do {
      msg = random.randomBytes(32);
      sig = rsa.sign(SHA256, msg, priv);
    } while (sig[0] !== 0x00);

    sig = sig.slice(1);

    assert(!rsa.verify(SHA256, msg, sig, pub));
    assert(rsa.verify(SHA256, msg, rsa.signatureImport(sig, pub), pub));
  });

  it('should test signature padding (PSS)', () => {
    const priv = rsa.privateKeyGenerate(512);
    const pub = rsa.publicKeyCreate(priv);

    let msg, sig;

    do {
      msg = random.randomBytes(16);
      sig = rsa.signPSS(MD5, msg, priv);
    } while (sig[0] !== 0x00);

    sig = sig.slice(1);

    assert(!rsa.verifyPSS(MD5, msg, sig, pub));
    assert(rsa.verifyPSS(MD5, msg, rsa.signatureImport(sig, pub), pub));
  });

  it('should encrypt and decrypt', () => {
    const priv = rsa.privateKeyGenerate(1024);
    const pub = rsa.publicKeyCreate(priv);
    const msg = Buffer.from('hello world');

    const ct = rsa.encrypt(msg, pub);

    assert.notBufferEqual(ct, msg);

    const pt = rsa.decrypt(ct, priv);

    assert.bufferEqual(pt, msg);
  });

  it('should encrypt and decrypt (OAEP)', () => {
    const priv = rsa.privateKeyGenerate(1024);
    const pub = rsa.publicKeyCreate(priv);
    const msg = Buffer.from('hello world');

    const ct = rsa.encryptOAEP(SHA1, msg, pub);

    assert.notBufferEqual(ct, msg);

    const pt = rsa.decryptOAEP(SHA1, ct, priv);

    assert.bufferEqual(pt, msg);
  });

  for (const [i, vector] of vectors.entries()) {
    const hash = vector.hash === 'sha1' ? SHA1 : SHA256;
    const msg = Buffer.from(vector.msg, 'hex');
    const sig = Buffer.from(vector.sig, 'hex');
    const key = fromJSON(vector.key);

    it(`should verify RSA vector #${i}`, () => {
      assert(rsa.publicKeyVerify(key));

      const m = hash.digest(msg);

      assert(rsa.verify(hash, m, sig, key));

      m[0] ^= 1;
      assert(!rsa.verify(hash, m, sig, key));
      m[0] ^= 1;
      assert(rsa.verify(hash, m, sig, key));

      sig[0] ^= 1;
      assert(!rsa.verify(hash, m, sig, key));
      sig[0] ^= 1;
      assert(rsa.verify(hash, m, sig, key));

      sig[40] ^= 1;
      assert(!rsa.verify(hash, m, sig, key));
      sig[40] ^= 1;
      assert(rsa.verify(hash, m, sig, key));

      key.n[0] ^= 1;
      assert(!rsa.verify(hash, m, sig, key));
      key.n[0] ^= 1;
      assert(rsa.verify(hash, m, sig, key));

      key.e[0] ^= 1;
      assert(!rsa.verify(hash, m, sig, key));
      key.e[0] ^= 1;
      assert(rsa.verify(hash, m, sig, key));
    });
  }
});
