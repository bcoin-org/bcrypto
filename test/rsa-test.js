'use strict';

const assert = require('bsert');
const MD5 = require('../lib/md5');
const SHA1 = require('../lib/sha1');
const SHA256 = require('../lib/sha256');
const BLAKE2b256 = require('../lib/blake2b256');
const BLAKE2s256 = require('../lib/blake2s256');
const BN = require('../lib/bn');
const random = require('../lib/random');
const rsa = require('../lib/rsa');
const base64 = require('../lib/encoding/base64');
const vectors = require('./data/rsa.json');
const custom = require('./data/sign/rsa.json');
const {RSAPublicKey} = rsa;

const hashes = {
  SHA1,
  SHA256,
  BLAKE2B256: BLAKE2b256,
  BLAKE2S256: BLAKE2s256
};

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

function parseVector(json) {
  return json.map((item) => {
    if (typeof item !== 'string')
      return item;

    if (hashes[item])
      return hashes[item];

    return Buffer.from(item, 'hex');
  });
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
    const bits = rsa.native < 2 ? 1024 : 2048;
    const priv = rsa.privateKeyGenerate(bits);
    const pub = rsa.publicKeyCreate(priv);

    assert(rsa.privateKeyVerify(priv));
    assert(rsa.publicKeyVerify(pub));

    const sig = rsa.sign(SHA256, msg, priv);
    assert(rsa.verify(SHA256, msg, sig, pub));

    assert(!rsa.verify(SHA256, zero, sig, pub));
    assert(!rsa.verify(SHA256, msg, zero, pub));

    sig[0] ^= 1;
    assert(!rsa.verify(SHA256, msg, sig, pub));
  });

  it('should veil/unveil', () => {
    const bits = rsa.native < 2 ? 1024 : 2048;
    const priv = rsa.privateKeyGenerate(bits);
    const pub = rsa.publicKeyCreate(priv);

    assert(rsa.privateKeyVerify(priv));
    assert(rsa.publicKeyVerify(pub));

    const s1 = rsa.sign(SHA256, msg, priv);
    const v1 = rsa.veil(s1, bits, pub);
    const s2 = rsa.unveil(v1, bits, pub);
    const v2 = rsa.veil(s1, bits + 8, pub);
    const s3 = rsa.unveil(v2, bits + 8, pub);
    const v3 = rsa.veil(s1, bits + 1024, pub);
    const s4 = rsa.unveil(v3, bits + 1024, pub);

    assert(v1.length === bits / 8);
    assert(v2.length === (bits + 8) / 8);
    assert(v3.length === (bits + 1024) / 8);

    assert(s1.length === bits / 8);
    assert(s2.length === bits / 8);
    assert(s3.length === bits / 8);
    assert(s4.length === bits / 8);

    assert(s2.equals(s1));
    assert(s3.equals(s1));
    assert(s4.equals(s1));

    assert(!v2.slice(0, (bits / 8)).equals(s1));
    assert(!v3.slice(0, (bits / 8)).equals(s1));
    assert(!v3.slice(-(bits / 8)).equals(s1));

    assert(rsa.verify(SHA256, msg, s1, pub));
    assert(rsa.verify(SHA256, msg, s2, pub));
    assert(rsa.verify(SHA256, msg, s3, pub));
    assert(rsa.verify(SHA256, msg, s4, pub));
  });

  it('should fail to verify non-canonical signature', () => {
    const bits = 1020;
    const priv = rsa.privateKeyGenerate(bits);
    const pub = rsa.publicKeyCreate(priv);

    assert(rsa.privateKeyVerify(priv));
    assert(rsa.publicKeyVerify(pub));

    const sig1 = rsa.sign(SHA256, msg, priv);
    const n = BN.decode(priv.n);
    const s = BN.decode(sig1);
    const sig2 = s.add(n).encode('be', priv.size());

    assert(!rsa.verify(SHA256, msg, sig2, pub));
  });

  it('should sign and verify (PSS)', () => {
    const priv = rsa.privateKeyGenerate(1024);
    const pub = rsa.publicKeyCreate(priv);

    assert(rsa.privateKeyVerify(priv));
    assert(rsa.publicKeyVerify(pub));

    const sig1 = rsa.signPSS(SHA256, msg, priv, -1);
    assert(rsa.verifyPSS(SHA256, msg, sig1, pub));

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
    const bits = rsa.native < 2 ? 1024 : 2048;
    const priv = await rsa.privateKeyGenerateAsync(bits);
    const pub = rsa.publicKeyCreate(priv);

    assert(rsa.privateKeyVerify(priv));
    assert(rsa.publicKeyVerify(pub));

    const sig = rsa.sign(SHA256, msg, priv);
    const valid = rsa.verify(SHA256, msg, sig, pub);

    assert(valid);
  });

  it('should validate lambda key', () => {
    const json = {
      kty: 'RSA',
      n: 'vAapTcBGyRClrxqI9ert54KizqnARN2d1OfMob4NTYaOYEfS4TOrZtVJlKXTFJkAn0'
       + 'Y5BiCfkNC0E65NxhPrWwP1MlqJWfWt-WUuiUlExBN_GMWZI-KvQgzXFszN7SV-V4kU'
       + 'avlQ-WvJOoP12hBuAkjM1dup9DtEqLXXFefOkVk',
      e: 'AQAB',
      d: 'DJfYH0lfXFBZfne1IF5gmnq_B38qTdp3e5beV19kofJ_Bu8MjlGA-3lRzStJjsW8G0'
       + '7PWywUb9UwmGhaVGfJYaDT1nyv4dsxjifjAG-1ebtNYfvDaZCyz3N0GPHr3ix3NjXh'
       + 'GrjXoKYrptBZLG5I0MYCCJI9qmAnYbpHHrQ4qaE',
      p: '6_uMVgyIYUnEmCGRsAOx7E-gw5ytMqquuyAVkeaKcJA22nVZZscZ0dJRHT6Bolkel8'
       + 'cqpv70vgdc-u6jKH6-OQ',
      q: 'y_m3t42TnV0bYgqQfIrux1ym9M3WXeCvCUZ6J1rUaMC-C8Bmw1duoK0KKfsuJgYwUN'
       + '3b459C1VBB8civcPhsIQ',
      dp: 'CbNPc4IUYRttL2vB12Bvge1MCH56SCjoAd0xxcuaSUJEXvqP8D-i-hMRLoiRP6E2N'
        + 'rsDL9YvLViUI-SHZHTBUQ',
      dq: 'Te8LksY1MFryq3L94Zfzw5hS8hXzYcsHFbQn2AGMRrnd4v-QQ_KUAjAbQg8GguC6d'
        + 'StPaJjhID-Z8peK8M76AQ',
      qi: 'MmI7iG6EyGUMeg0rkC7TZXhtSCqrriN_U3PjWGtNGx34IfqpR3QgsyigByqJF2eu_'
        + 'A8OutZUhmH3N4z0MjRmAA',
      ext: true
    };

    const priv = rsa.privateKeyImportJWK(json);

    assert(rsa.privateKeyVerify(priv));
  });

  it('should sign and verify (blake2b)', () => {
    const bits = rsa.native < 2 ? 1024 : 2048;
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

  it('should test PSS edge case', () => {
    const priv = rsa.privateKeyGenerate(513);
    const pub = rsa.publicKeyCreate(priv);
    const msg = random.randomBytes(16);
    const sig = rsa.signPSS(MD5, msg, priv);

    assert(rsa.verifyPSS(MD5, msg, sig, pub));
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

  for (const [i, json] of custom.entries()) {
    const vector = parseVector(json);

    const [
      privRaw,
      pubRaw,
      hash,
      saltLen,
      msg,
      sig1,
      sig2,
      ct1,
      ct2,
      ct3,
      pkcs8,
      spki
    ] = vector;

    const label = Buffer.from('bcrypto');
    const priv = rsa.privateKeyImport(privRaw);
    const pub = rsa.publicKeyImport(pubRaw);

    it(`should parse and serialize key (${i})`, () => {
      assert(rsa.privateKeyVerify(priv));
      assert(rsa.publicKeyVerify(priv));

      rsa.privateKeyCompute(priv);

      assert(rsa.publicKeyVerify(priv));
      assert.deepStrictEqual(rsa.publicKeyCreate(priv), pub);
      assert.bufferEqual(rsa.privateKeyExport(priv), privRaw);
      assert.bufferEqual(rsa.publicKeyExport(pub), pubRaw);
      assert.deepStrictEqual(rsa.privateKeyImport(privRaw), priv);
      assert.deepStrictEqual(rsa.publicKeyImport(pubRaw), pub);

      assert.deepStrictEqual(rsa.privateKeyImportPKCS8(pkcs8), priv);
      assert.deepStrictEqual(rsa.publicKeyImportSPKI(spki), pub);
    });

    it(`should recompute key (${i})`, () => {
      const empty = Buffer.alloc(0);

      priv.n = empty;

      assert(!rsa.privateKeyVerify(priv));
      rsa.privateKeyCompute(priv);
      assert(rsa.privateKeyVerify(priv));

      priv.d = empty;

      assert(!rsa.privateKeyVerify(priv));
      rsa.privateKeyCompute(priv);
      assert(rsa.privateKeyVerify(priv));

      priv.dp = empty;

      assert(!rsa.privateKeyVerify(priv));
      rsa.privateKeyCompute(priv);
      assert(rsa.privateKeyVerify(priv));

      priv.dq = empty;

      assert(!rsa.privateKeyVerify(priv));
      rsa.privateKeyCompute(priv);
      assert(rsa.privateKeyVerify(priv));

      priv.dq = empty;

      assert(!rsa.privateKeyVerify(priv));
      rsa.privateKeyCompute(priv);
      assert(rsa.privateKeyVerify(priv));

      priv.qi = empty;

      assert(!rsa.privateKeyVerify(priv));
      rsa.privateKeyCompute(priv);
      assert(rsa.privateKeyVerify(priv));

      priv.n = empty;
      priv.d = empty;
      priv.dp = empty;
      priv.dq = empty;
      priv.qi = empty;

      assert(!rsa.privateKeyVerify(priv));
      rsa.privateKeyCompute(priv);
      assert(rsa.privateKeyVerify(priv));

      priv.n = empty;
      priv.dp = empty;
      priv.dq = empty;
      priv.qi = empty;

      assert(!rsa.privateKeyVerify(priv));
      rsa.privateKeyCompute(priv);
      assert(rsa.privateKeyVerify(priv));

      assert.bufferEqual(rsa.privateKeyExport(priv), privRaw);
    });

    it(`should sign and verify PKCS1v1.5 signature (${i})`, () => {
      const sig = rsa.sign(hash, msg, priv);

      assert.bufferEqual(sig, sig1);

      assert(rsa.verify(hash, msg, sig, pub));

      msg[0] ^= 1;

      assert(!rsa.verify(hash, msg, sig, pub));

      msg[0] ^= 1;
      sig[0] ^= 1;

      assert(!rsa.verify(hash, msg, sig, pub));

      sig[0] ^= 1;
      pub.n[0] ^= 1;

      assert(!rsa.verify(hash, msg, sig, pub));

      pub.n[0] ^= 1;

      assert(rsa.verify(hash, msg, sig, pub));
    });

    it(`should sign and verify PSS signature (${i})`, () => {
      const sig = sig2;
      const sig_ = rsa.signPSS(hash, msg, priv, saltLen);

      assert(rsa.verifyPSS(hash, msg, sig_, pub, saltLen));

      assert(rsa.verifyPSS(hash, msg, sig, pub, saltLen));

      msg[0] ^= 1;

      assert(!rsa.verifyPSS(hash, msg, sig, pub, saltLen));

      msg[0] ^= 1;
      sig[0] ^= 1;

      assert(!rsa.verifyPSS(hash, msg, sig, pub, saltLen));

      sig[0] ^= 1;
      pub.n[0] ^= 1;

      assert(!rsa.verifyPSS(hash, msg, sig, pub, saltLen));

      pub.n[0] ^= 1;

      assert(rsa.verifyPSS(hash, msg, sig, pub, saltLen));
    });

    it(`should encrypt and decrypt PKCS1v1.5 type 2 ciphertext (${i})`, () => {
      assert.bufferEqual(rsa.decrypt(ct1, priv), msg);
      assert.bufferEqual(rsa.decrypt(rsa.encrypt(msg, pub), priv), msg);
    });

    it(`should encrypt and decrypt OAEP ciphertext (${i})`, () => {
      assert.bufferEqual(rsa.decryptOAEP(hash, ct2, priv, label), msg);
      assert.bufferEqual(rsa.decryptOAEP(hash,
        rsa.encryptOAEP(hash, msg, pub, label), priv, label), msg);
    });

    it(`should encrypt and decrypt raw ciphertext (${i})`, () => {
      const pad = Buffer.alloc(priv.size(), 0x00);
      msg.copy(pad, pad.length - hash.size);

      assert.bufferEqual(rsa.decryptRaw(ct3, priv).slice(-msg.length), msg);

      const ct4 = rsa.encryptRaw(pad, pub);

      assert.bufferEqual(rsa.decryptRaw(ct4, priv).slice(-msg.length), msg);
    });
  }
});
