'use strict';

const assert = require('bsert');
const fs = require('fs');
const Path = require('path');
const bio = require('bufio');
const dsa = require('../lib/dsa');
const asn1 = require('../lib/encoding/asn1');
const x509 = require('../lib/encoding/x509');
const params = require('./data/dsa-params.json');
const vectors = require('./data/dsa.json');
const custom = require('./data/sign/dsa.json');
const {DSAPublicKey} = dsa;

const PEM_PATH = Path.resolve(__dirname, 'data', 'testdsapub.pem');
const PEM_TXT = fs.readFileSync(PEM_PATH, 'utf8');

const {
  P1024_160,
  P2048_256,
  P3072_256
} = params;

function createParams(json) {
  const p = Buffer.from(json.p, 'hex');
  const q = Buffer.from(json.q, 'hex');
  const g = Buffer.from(json.g, 'hex');
  return new dsa.DSAParams(p, q, g);
}

describe('DSA', function() {
  this.timeout(30000);

  it('should sign and verify', () => {
    const params = createParams(P2048_256);
    const priv = dsa.privateKeyCreate(params);
    const pub = dsa.publicKeyCreate(priv);

    assert(dsa.privateKeyVerify(priv));
    assert(dsa.publicKeyVerify(pub));

    const msg = Buffer.alloc(priv.size(), 0xaa);
    const sig = dsa.sign(msg, priv);
    assert(sig);

    const result = dsa.verify(msg, sig, pub);
    assert(result);

    const zero = Buffer.alloc(0);
    assert(!dsa.verify(zero, sig, pub));
    assert(!dsa.verify(msg, zero, pub));

    sig[0] ^= 1;

    const result2 = dsa.verify(msg, sig, pub);
    assert(!result2);

    assert.deepStrictEqual(
      dsa.privateKeyImport(dsa.privateKeyExport(priv)),
      priv);

    assert.deepStrictEqual(
      dsa.privateKeyImportPKCS8(dsa.privateKeyExportPKCS8(priv)),
      priv);

    assert.deepStrictEqual(
      dsa.privateKeyImportJWK(dsa.privateKeyExportJWK(priv)),
      priv);

    assert.deepStrictEqual(
      dsa.publicKeyImport(dsa.publicKeyExport(pub)),
      pub);

    assert.deepStrictEqual(
      dsa.publicKeyImportSPKI(dsa.publicKeyExportSPKI(pub)),
      pub);

    assert.deepStrictEqual(
      dsa.publicKeyImportJWK(dsa.publicKeyExportJWK(pub)),
      pub);
  });

  it('should sign and verify (DER)', () => {
    const params = createParams(P3072_256);
    const priv = dsa.privateKeyCreate(params);
    const pub = dsa.publicKeyCreate(priv);

    const msg = Buffer.alloc(priv.size(), 0xaa);
    const sig = dsa.signDER(msg, priv);
    assert(sig);

    assert(dsa.verifyDER(msg, sig, pub));
    assert(!dsa.verify(msg, sig, pub));

    const sig2 = dsa.signatureImport(sig, priv.size());

    assert(dsa.verify(msg, sig2, pub));

    const sig3 = dsa.signatureExport(sig2);

    assert.bufferEqual(sig3, sig);

    sig[5] ^= 1;

    assert(!dsa.verifyDER(msg, sig, pub));
  });

  it('should sign and verify (async)', async () => {
    const size = dsa.native < 2 ? 1024 : 2048;
    const params = await dsa.paramsGenerateAsync(size);
    const priv = dsa.privateKeyCreate(params);
    const pub = dsa.publicKeyCreate(priv);

    assert(dsa.privateKeyVerify(priv));
    assert(dsa.publicKeyVerify(pub));

    const msg = Buffer.alloc(priv.size(), 0xaa);
    const sig = dsa.sign(msg, priv);
    assert(sig);

    const result = dsa.verify(msg, sig, pub);
    assert(result);

    sig[0] ^= 1;

    const result2 = dsa.verify(msg, sig, pub);
    assert(!result2);
  });

  it('should do diffie hellman', () => {
    const params = createParams(P1024_160);
    const alice = dsa.privateKeyCreate(params);
    const alicePub = dsa.publicKeyCreate(alice);
    const bob = dsa.privateKeyCreate(params);
    const bobPub = dsa.publicKeyCreate(bob);

    const aliceSecret = dsa.derive(bobPub, alice);
    const bobSecret = dsa.derive(alicePub, bob);
    const x = dsa.exchange(alicePub.y, bob);

    assert.bufferEqual(aliceSecret, bobSecret);
    assert.bufferEqual(x, bobSecret);
  });

  it('should parse SPKI', () => {
    const info = x509.SubjectPublicKeyInfo.fromPEM(PEM_TXT);
    assert(info.algorithm.algorithm.getKeyAlgorithmName() === 'DSA');
    assert(info.algorithm.parameters.node.type === 16); // SEQ
    assert(info.publicKey.type === 3); // BITSTRING

    const br = bio.read(info.algorithm.parameters.node.value);
    const p = asn1.Unsigned.read(br);
    const q = asn1.Unsigned.read(br);
    const g = asn1.Unsigned.read(br);
    const y = asn1.Unsigned.decode(info.publicKey.rightAlign());
    const key = new DSAPublicKey();

    key.setP(p.value);
    key.setQ(q.value);
    key.setG(g.value);
    key.setY(y.value);

    assert(dsa.publicKeyVerify(key));
  });

  for (const [i, vector] of vectors.entries()) {
    const text = vector.sig.slice(0, 32) + '...';

    it(`should verify signature: ${text} (${i})`, () => {
      const msg = Buffer.from(vector.msg, 'hex');
      const sig = Buffer.from(vector.sig, 'hex');
      const pubRaw = Buffer.from(vector.pub, 'hex');
      const privRaw = Buffer.from(vector.priv, 'hex');
      const priv = dsa.privateKeyImport(privRaw);
      const pub = dsa.publicKeyCreate(priv);

      assert(dsa.privateKeyVerify(priv));
      assert(dsa.publicKeyVerify(pub));

      assert.bufferEqual(dsa.publicKeyExport(pub), pubRaw);
      assert.strictEqual(dsa.verify(msg, sig, pub), true);

      const sig2 = dsa.signatureExport(sig);
      const sig3 = dsa.signatureExport(sig, sig.length >>> 1);
      const sig4 = dsa.signatureImport(sig2, sig.length >>> 1);

      assert.bufferEqual(sig2, sig3);
      assert.bufferEqual(sig4, sig);

      assert.strictEqual(dsa.verifyDER(msg, sig2, pub), true);

      sig[i % sig.length] ^= 1;

      assert.strictEqual(dsa.verify(msg, sig, pub), false);
    });
  }

  it('should sign zero-length message', () => {
    const msg = Buffer.alloc(0);
    const params = createParams(P2048_256);
    const key = dsa.privateKeyCreate(params);
    const pub = dsa.publicKeyCreate(key);
    const sig = dsa.sign(msg, key);

    assert(dsa.verify(msg, sig, pub));
  });

  for (const [i, json] of custom.entries()) {
    const vector = json.map(s => Buffer.from(s, 'hex'));

    const [
      paramsRaw,
      privRaw,
      pubRaw,
      msg,
      sig,
      der,
      pkcs8,
      spki
    ] = vector;

    const params = dsa.paramsImport(paramsRaw);
    const priv = dsa.privateKeyImport(privRaw);
    const pub = dsa.publicKeyImport(pubRaw);

    it(`should parse and serialize key (${i})`, () => {
      assert(dsa.privateKeyVerify(priv));
      assert(dsa.publicKeyVerify(priv));

      dsa.privateKeyCompute(priv);

      assert(dsa.publicKeyVerify(priv));
      assert.deepStrictEqual(dsa.publicKeyCreate(priv), pub);
      assert.bufferEqual(dsa.paramsExport(params), paramsRaw);
      assert.deepStrictEqual(dsa.paramsImport(paramsRaw), params);
      assert.bufferEqual(dsa.privateKeyExport(priv), privRaw);
      assert.bufferEqual(dsa.publicKeyExport(pub), pubRaw);
      assert.deepStrictEqual(dsa.privateKeyImport(privRaw), priv);
      assert.deepStrictEqual(dsa.publicKeyImport(pubRaw), pub);
      assert.bufferEqual(dsa.privateKeyExportPKCS8(priv), pkcs8);
      assert.bufferEqual(dsa.publicKeyExportSPKI(pub), spki);
      assert.deepStrictEqual(dsa.privateKeyImportPKCS8(pkcs8), priv);
      assert.deepStrictEqual(dsa.publicKeyImportSPKI(spki), pub);
    });

    it(`should recompute key (${i})`, () => {
      const empty = Buffer.alloc(0);

      assert(dsa.privateKeyVerify(priv));

      priv.y = empty;

      assert(!dsa.privateKeyVerify(priv));
      dsa.privateKeyCompute(priv);
      assert(dsa.privateKeyVerify(priv));

      assert.bufferEqual(dsa.privateKeyExport(priv), privRaw);
    });

    it(`should check signature (${i})`, () => {
      assert(dsa.signatureExport(sig), der);
      assert(dsa.signatureImport(der, sig.length >>> 1), sig);
    });

    it(`should sign and verify signature (${i})`, () => {
      const sig_ = dsa.sign(msg, priv);

      assert(dsa.verify(msg, sig_, pub));

      assert(dsa.verify(msg, sig, pub));

      msg[0] ^= 1;

      assert(!dsa.verify(msg, sig, pub));

      msg[0] ^= 1;
      sig[0] ^= 1;

      assert(!dsa.verify(msg, sig, pub));

      sig[0] ^= 1;
      pub.y[3] ^= 1;

      assert(!dsa.verify(msg, sig, pub));

      pub.y[3] ^= 1;

      assert(dsa.verify(msg, sig, pub));
    });

    it(`should sign and verify DER signature (${i})`, () => {
      const der_ = dsa.signDER(msg, priv);

      assert(dsa.verifyDER(msg, der_, pub));

      assert(dsa.verifyDER(msg, der, pub));

      msg[0] ^= 1;

      assert(!dsa.verifyDER(msg, der, pub));

      msg[0] ^= 1;
      der[3] ^= 1;

      assert(!dsa.verifyDER(msg, der, pub));

      der[3] ^= 1;
      pub.y[3] ^= 1;

      assert(!dsa.verifyDER(msg, der, pub));

      pub.y[3] ^= 1;

      assert(dsa.verifyDER(msg, der, pub));
    });
  }
});
