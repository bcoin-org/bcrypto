'use strict';

const assert = require('bsert');
const MD5 = require('../lib/md5');
const SHA1 = require('../lib/sha1');
const SHA256 = require('../lib/sha256');
const BLAKE2b256 = require('../lib/blake2b256');
const random = require('../lib/random');
const rsa = require('../lib/rsa');
const base64 = require('../lib/internal/base64');
const vectors = require('./data/rsa.json');
const {RSAPublicKey} = rsa;

const msg = SHA256.digest(Buffer.from('foobar'));
const zero = Buffer.alloc(0);

function fromJSON(json) {
  assert(json && typeof json === 'object');
  assert(json.kty === 'RSA');

  const key = new RSAPublicKey();
  key.n = base64.decodeURL(json.n);
  key.e = base64.decodeURL(json.e);

  return key;
}

describe('RSA', function() {
  this.timeout(30000);

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

    assert.deepStrictEqual(
      rsa.privateKeyImportPKCS8(rsa.privateKeyExportPKCS8(priv)),
      priv);

    assert.deepStrictEqual(
      rsa.privateKeyImportJWK(rsa.privateKeyExportJWK(priv)),
      priv);

    const pub = rsa.publicKeyCreate(priv);

    assert.deepStrictEqual(
      rsa.publicKeyImport(rsa.publicKeyExport(pub)),
      pub);

    assert.deepStrictEqual(
      rsa.publicKeyImportSPKI(rsa.publicKeyExportSPKI(pub)),
      pub);

    assert.deepStrictEqual(
      rsa.publicKeyImportJWK(rsa.publicKeyExportJWK(pub)),
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

    // Should veil/unveil.
    const sig2 = rsa.veil(sig, 4096, pub);
    assert(sig2.length === 512);
    const sig3 = rsa.unveil(sig2, 4096, pub);
    assert(rsa.verify(SHA256, msg, sig3, pub));

    assert(!rsa.verify(SHA256, zero, sig, pub));
    assert(!rsa.verify(SHA256, msg, zero, pub));

    sig[0] ^= 1;
    assert(!rsa.verify(SHA256, msg, sig, pub));
  });

  it('should sign and verify (PSS)', () => {
    const priv = rsa.privateKeyGenerate(1024);
    const pub = rsa.publicKeyCreate(priv);

    assert(rsa.privateKeyVerify(priv));
    assert(rsa.publicKeyVerify(pub));

    const sig1 = rsa.signPSS(SHA256, msg, priv, -1);
    assert(rsa.verifyPSS(SHA256, msg, sig1, pub));

    // Should veil/unveil.
    const sig2 = rsa.veil(sig1, 4096, pub);
    assert(sig2.length === 512);
    const sig3 = rsa.unveil(sig2, 4096, pub);
    assert(rsa.verifyPSS(SHA256, msg, sig3, pub));

    assert(!rsa.verifyPSS(SHA256, zero, sig1, pub));
    assert(!rsa.verifyPSS(SHA256, msg, zero, pub));

    sig1[0] ^= 1;
    assert(!rsa.verifyPSS(SHA256, msg, sig1, pub));

    const sig4 = rsa.signPSS(SHA256, msg, priv, 0);
    assert(rsa.verifyPSS(SHA256, msg, sig4, pub, 0));
    sig4[0] ^= 1;
    assert(!rsa.verifyPSS(SHA256, msg, sig4, pub, 0));
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

  it('should sign and verify (blake2b)', () => {
    const bits = rsa.native < 2 ? 1024 : 4096;
    const priv = rsa.privateKeyGenerate(bits);
    const pub = rsa.publicKeyCreate(priv);

    assert(rsa.privateKeyVerify(priv));
    assert(rsa.publicKeyVerify(pub));

    const sig = rsa.sign(BLAKE2b256, msg, priv);
    assert(rsa.verify(BLAKE2b256, msg, sig, pub));

    assert(!rsa.verify(BLAKE2b256, zero, sig, pub));
    assert(!rsa.verify(BLAKE2b256, msg, zero, pub));

    sig[0] ^= 1;
    assert(!rsa.verify(BLAKE2b256, msg, sig, pub));
  });

  it('should sign and verify (PSS) (blake2b)', () => {
    const priv = rsa.privateKeyGenerate(1024);
    const pub = rsa.publicKeyCreate(priv);

    assert(rsa.privateKeyVerify(priv));
    assert(rsa.publicKeyVerify(pub));

    const sig1 = rsa.signPSS(BLAKE2b256, msg, priv, -1);
    assert(rsa.verifyPSS(BLAKE2b256, msg, sig1, pub));

    assert(!rsa.verifyPSS(BLAKE2b256, zero, sig1, pub));
    assert(!rsa.verifyPSS(BLAKE2b256, msg, zero, pub));

    sig1[0] ^= 1;
    assert(!rsa.verifyPSS(BLAKE2b256, msg, sig1, pub));

    const sig2 = rsa.signPSS(BLAKE2b256, msg, priv, 0);
    assert(rsa.verifyPSS(BLAKE2b256, msg, sig2, pub, 0));
    sig2[0] ^= 1;
    assert(!rsa.verifyPSS(BLAKE2b256, msg, sig2, pub, 0));
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
    assert(rsa.verifyLax(SHA256, msg, sig, pub));
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
    assert(rsa.verifyPSSLax(MD5, msg, sig, pub));
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

  it('should encrypt and decrypt (OAEP, blake2b)', () => {
    const priv = rsa.privateKeyGenerate(1024);
    const pub = rsa.publicKeyCreate(priv);
    const msg = Buffer.from('hello world');

    const ct = rsa.encryptOAEP(BLAKE2b256, msg, pub);

    assert.notBufferEqual(ct, msg);

    const pt = rsa.decryptOAEP(BLAKE2b256, ct, priv);

    assert.bufferEqual(pt, msg);
  });

  for (const [i, vector] of vectors.entries()) {
    const hash = vector.hash === 'SHA1' ? SHA1 : SHA256;
    const msg = Buffer.from(vector.msg, 'hex');
    const sig = Buffer.from(vector.sig, 'hex');
    const key = fromJSON(vector.key);

    it(`should verify RSA vector #${i}`, () => {
      assert(rsa.publicKeyVerify(key));

      const m = hash.digest(msg);

      assert(rsa.verify(hash, m, sig, key));

      m[i % m.length] ^= 1;
      assert(!rsa.verify(hash, m, sig, key));
      m[i % m.length] ^= 1;
      assert(rsa.verify(hash, m, sig, key));

      sig[i % sig.length] ^= 1;
      assert(!rsa.verify(hash, m, sig, key));
      sig[i % sig.length] ^= 1;
      assert(rsa.verify(hash, m, sig, key));

      key.n[i % key.n.length] ^= 1;
      assert(!rsa.verify(hash, m, sig, key));
      key.n[i % key.n.length] ^= 1;
      assert(rsa.verify(hash, m, sig, key));

      key.e[i % key.e.length] ^= 1;
      assert(!rsa.verify(hash, m, sig, key));
      key.e[i % key.e.length] ^= 1;
      assert(rsa.verify(hash, m, sig, key));
    });
  }

  {
    const vector = require('./data/rsa-other.json');
    const priv = rsa.privateKeyImport(Buffer.from(vector.priv, 'hex'));
    const pub = rsa.publicKeyCreate(priv);
    const msg = Buffer.from('hello world');

    it('should verify PKCS1v1.5 signature', () => {
      const sig = Buffer.from(vector.sigPKCS1, 'hex');
      const result = rsa.verify(SHA1, SHA1.digest(msg), sig, pub);
      assert.strictEqual(result, true);
    });

    it('should decrypt PKCS1v1.5 type 2 ciphertext', () => {
      const ct = Buffer.from(vector.ctPKCS1, 'hex');

      const pt = rsa.decrypt(ct, priv);
      assert.bufferEqual(pt, msg);
    });

    it('should decrypt OAEP ciphertext', () => {
      const ct = Buffer.from(vector.ctOAEP, 'hex');

      const pt = rsa.decryptOAEP(SHA1, ct, priv);
      assert.bufferEqual(pt, msg);
    });

    it('should decrypt OAEP ciphertext (label=foo)', () => {
      const ct = Buffer.from(vector.ctOAEPLabelFoo, 'hex');

      const pt = rsa.decryptOAEP(SHA1, ct, priv, Buffer.from('foo'));
      assert.bufferEqual(pt, msg);
    });

    it('should verify PSS signature (auto)', () => {
      const sig = Buffer.from(vector.sigPSSAuto, 'hex');

      const result = rsa.verifyPSS(SHA1, SHA1.digest(msg), sig, pub, 0);
      assert.strictEqual(result, true);
    });

    it('should verify PSS signature (equals)', () => {
      const sig = Buffer.from(vector.sigPSSEquals, 'hex');

      const result = rsa.verifyPSS(SHA1, SHA1.digest(msg), sig, pub, -1);
      assert.strictEqual(result, true);
    });
  }

  it('should import standard JWK', () => {
    // https://tools.ietf.org/html/rfc7517#appendix-A.2
    const json = {
      'kty': 'RSA',
      'n': ''
        + '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAA'
        + 'tVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMst'
        + 'n64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0'
        + '_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajr'
        + 'n1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XP'
        + 'ksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
      'e': 'AQAB',
      'd': ''
        + 'X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5o'
        + 'o7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij'
        + 'wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwF'
        + 's9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg'
        + '1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBi'
        + 'i3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q',
      'p': ''
        + '83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD2'
        + '0R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQy'
        + 'qVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs',
      'q': ''
        + '3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZ'
        + 'QO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzF'
        + 'gxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk',
      'dp': ''
        + 'G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi'
        + '2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmt'
        + 'uYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0',
      'dq': ''
        + 's9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBc'
        + 'Mpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d'
        + '9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk',
      'qi': ''
        + 'GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEV'
        + 'FEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11r'
        + 'xyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU',
      'ext': true
    };

    const priv = rsa.privateKeyImportJWK(json);
    const pub = rsa.publicKeyImportJWK(json);

    assert(rsa.privateKeyVerify(priv));
    assert(rsa.publicKeyVerify(pub));

    assert.deepStrictEqual(rsa.publicKeyCreate(priv), pub);
    assert.deepStrictEqual(rsa.privateKeyExportJWK(priv), json);
  });
});
