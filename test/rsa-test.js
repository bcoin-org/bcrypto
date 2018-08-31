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
    const priv_ = rsa.privateKeyGenerate(1024);
    const pub_ = rsa.publicKeyCreate(priv_);
    const privRaw = priv_.encode();
    const pubRaw = pub_.encode();

    const priv = RSAPrivateKey.decode(privRaw);
    assert.strictEqual(priv.n.length, 128);
    assert.bufferEqual(priv.e, Buffer.from('010001', 'hex'));
    assert.bufferEqual(priv.encode(), privRaw);
    assert(rsa.privateKeyVerify(priv));

    const pub = RSAPublicKey.decode(pubRaw);
    assert.bufferEqual(pub.encode(), pubRaw);
    assert(rsa.publicKeyVerify(pub));

    const privPEM = priv.toPEM();
    assert(typeof privPEM === 'string');
    assert.deepStrictEqual(RSAPrivateKey.fromPEM(privPEM), priv);

    const pubPEM = pub.toPEM();
    assert(typeof pubPEM === 'string');
    assert.deepStrictEqual(RSAPublicKey.fromPEM(pubPEM), pub);

    const privJSON = priv.toJSON();
    assert(privJSON && typeof privJSON === 'object');
    assert.deepStrictEqual(RSAPrivateKey.fromJSON(privJSON), priv);

    const pubJSON = pub.toJSON();
    assert(pubJSON && typeof pubJSON === 'object');
    assert.deepStrictEqual(RSAPublicKey.fromJSON(pubJSON), pub);

    const pubDNS = pub.toDNS();
    assert(Buffer.isBuffer(pubDNS));
    assert.deepStrictEqual(RSAPublicKey.fromDNS(pubDNS), pub);
  });

  it('should generate keypair', () => {
    const priv = rsa.privateKeyGenerate(1024);
    const {d, dp, dq, qi} = priv;

    priv.d = Buffer.alloc(1);
    priv.dp = Buffer.alloc(1);
    priv.dq = Buffer.alloc(1);
    priv.qi = Buffer.alloc(1);
    priv.compute();

    assert.bufferEqual(priv.d, d);
    assert.bufferEqual(priv.dp, dp);
    assert.bufferEqual(priv.dq, dq);
    assert.bufferEqual(priv.qi, qi);
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

    it(`should verify RSA vector #${i}`, () => {
      assert(key.validate());

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

  it('should generate keypair', () => {
    const priv_ = RSAPrivateKey.generate(1024);
    const pub_ = priv_.toPublic();
    const privRaw = priv_.encode();
    const pubRaw = pub_.encode();

    const priv = RSAPrivateKey.decode(privRaw);
    assert.strictEqual(priv.n.length, 128);
    assert.bufferEqual(priv.e, Buffer.from('010001', 'hex'));
    assert.bufferEqual(priv.encode(), privRaw);
    assert(priv.validate());

    const pub = RSAPublicKey.decode(pubRaw);
    assert.bufferEqual(pub.encode(), pubRaw);
    assert(pub.validate());

    const privPEM = priv.toPEM();
    assert(typeof privPEM === 'string');
    assert.deepStrictEqual(RSAPrivateKey.fromPEM(privPEM), priv);

    const pubPEM = pub.toPEM();
    assert(typeof pubPEM === 'string');
    assert.deepStrictEqual(RSAPublicKey.fromPEM(pubPEM), pub);

    const privJSON = priv.toJSON();
    assert(privJSON && typeof privJSON === 'object');
    assert.deepStrictEqual(RSAPrivateKey.fromJSON(privJSON), priv);

    const pubJSON = pub.toJSON();
    assert(pubJSON && typeof pubJSON === 'object');
    assert.deepStrictEqual(RSAPublicKey.fromJSON(pubJSON), pub);

    const pubDNS = pub.toDNS();
    assert(Buffer.isBuffer(pubDNS));
    assert.deepStrictEqual(RSAPublicKey.fromDNS(pubDNS), pub);
  });

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

    const sig = rsa.sign(SHA256, msg, priv);
    const valid = rsa.verify(SHA256, msg, sig, pub);

    assert(valid);
  });

  it('should sign and verify (async)', async () => {
    const bits = rsa.native < 2 ? 1024 : 4096;
    const priv = await RSAPrivateKey.generateAsync(bits);
    const pub = priv.toPublic();

    assert(priv.validate());
    assert(pub.validate());

    const sig = rsa.sign(SHA256, msg, priv);
    const valid = rsa.verify(SHA256, msg, sig, pub);

    assert(valid);
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
