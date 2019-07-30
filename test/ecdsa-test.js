'use strict';

const assert = require('bsert');
const fs = require('fs');
const random = require('../lib/random');
const p192 = require('../lib/p192');
const p224 = require('../lib/p224');
const p256 = require('../lib/p256');
const p384 = require('../lib/p384');
const p521 = require('../lib/p521');
const secp256k1 = require('../lib/secp256k1');
const SHA224 = require('../lib/sha224');
const SHA256 = require('../lib/sha256');
const SHA384 = require('../lib/sha384');
const SHA512 = require('../lib/sha512');
const {isStrictDER} = require('./util/bip66');
const Signature = require('../lib/internal/signature');

const curves = [
  p192,
  p224,
  p256,
  p384,
  p521,
  secp256k1
];

describe('ECDSA', function() {
  this.timeout(15000);

  for (const ec of curves) {
    describe(ec.id, () => {
      it(`should generate keypair and sign DER (${ec.id})`, () => {
        const msg = random.randomBytes(ec.size);
        const priv = ec.privateKeyGenerate();
        const pub = ec.publicKeyCreate(priv);
        const pubu = ec.publicKeyConvert(pub, false);

        const sig = ec.signDER(msg, priv);

        if (ec.size <= 32)
          assert(isStrictDER(sig));

        assert(ec.isLowDER(sig));
        assert(ec.verifyDER(msg, sig, pub));
        assert(ec.verifyDER(msg, sig, pubu));

        msg[0] ^= 1;

        assert(!ec.verifyDER(msg, sig, pub));
        assert(!ec.verifyDER(msg, sig, pubu));

        msg[0] ^= 1;

        assert(ec.verifyDER(msg, sig, pub));
        assert(ec.verifyDER(msg, sig, pubu));

        pub[2] ^= 1;

        assert(!ec.verifyDER(msg, sig, pub));
        assert(ec.verifyDER(msg, sig, pubu));

        pub[2] ^= 1;

        for (const c of [false, true]) {
          assert.bufferEqual(
            ec.privateKeyImport(ec.privateKeyExport(priv, c)),
            priv);

          assert.bufferEqual(
            ec.privateKeyImportPKCS8(ec.privateKeyExportPKCS8(priv, c)),
            priv);

          assert.bufferEqual(
            ec.privateKeyImportJWK(ec.privateKeyExportJWK(priv)),
            priv);

          for (const p of [pub, pubu]) {
            assert.bufferEqual(
              ec.publicKeyImport(ec.publicKeyExport(p, c), c),
              c ? pub : pubu);

            assert.bufferEqual(
              ec.publicKeyImportSPKI(ec.publicKeyExportSPKI(p, c), c),
              c ? pub : pubu);

            assert.bufferEqual(
              ec.publicKeyImportJWK(ec.publicKeyExportJWK(p), c),
              c ? pub : pubu);
          }
        }
      });

      it(`should generate keypair and sign RS (${ec.id})`, () => {
        const msg = random.randomBytes(ec.size);
        const priv = ec.privateKeyGenerate();
        const pub = ec.publicKeyCreate(priv);
        const pubu = ec.publicKeyConvert(pub, false);

        const sig = ec.sign(msg, priv);

        assert(ec.isLowS(sig));
        assert(ec.verify(msg, sig, pub));
        assert(ec.verify(msg, sig, pubu));

        sig[0] ^= 1;

        assert(!ec.verify(msg, sig, pub));
        assert(!ec.verify(msg, sig, pubu));

        sig[0] ^= 1;

        assert(ec.verify(msg, sig, pub));
        assert(ec.verify(msg, sig, pubu));

        pub[2] ^= 1;

        assert(!ec.verify(msg, sig, pub));
        assert(ec.verify(msg, sig, pubu));
      });

      it(`should fail with padded key (${ec.id})`, () => {
        const msg = random.randomBytes(ec.size);
        const priv = ec.privateKeyGenerate();
        const pub = ec.publicKeyCreate(priv);
        const pubu = ec.publicKeyConvert(pub, false);

        const sig = ec.sign(msg, priv);

        assert(ec.isLowS(sig));
        assert(ec.verify(msg, sig, pub));
        assert(ec.verify(msg, sig, pubu));

        const pad = (a, b) => Buffer.concat([a, Buffer.from([b])]);

        assert(!ec.verify(msg, sig, pad(pub, 0x00)));
        assert(!ec.verify(msg, sig, pad(pubu, 0x00)));
        assert(!ec.verify(msg, sig, pad(pub, 0x01)));
        assert(!ec.verify(msg, sig, pad(pubu, 0x01)));
        assert(!ec.verify(msg, sig, pad(pub, 0xff)));
        assert(!ec.verify(msg, sig, pad(pubu, 0xff)));

        pubu[0] = 0x06 | (pub[0] & 1);

        assert(ec.verify(msg, sig, pubu));

        pubu[0] = 0x06 | (pub[0] ^ 1);

        assert(!ec.verify(msg, sig, pubu));

        const zero = Buffer.alloc(0);

        assert(!ec.verify(zero, sig, pub));
        assert(!ec.verify(msg, zero, pub));
        assert(!ec.verify(msg, sig, zero));
      });

      it(`should do additive tweak (${ec.id})`, () => {
        const priv = ec.privateKeyGenerate();
        const pub = ec.publicKeyCreate(priv);
        const tweak = random.randomBytes(ec.size);

        tweak[0] = 0x00;

        const tpriv = ec.privateKeyTweakAdd(priv, tweak);
        const tpub = ec.publicKeyTweakAdd(pub, tweak);
        const zpub = ec.publicKeyCreate(tpriv);

        assert.bufferEqual(tpub, zpub);

        const msg = random.randomBytes(ec.size);

        const sig = ec.sign(msg, tpriv);

        assert(ec.isLowS(sig));
        assert(ec.verify(msg, sig, tpub));

        const der = ec.signDER(msg, tpriv);

        if (ec.size <= 32)
          assert(isStrictDER(der));

        assert(ec.isLowDER(der));
        assert(ec.verifyDER(msg, der, tpub));

        const parent = ec.privateKeyTweakAdd(tpriv, ec.privateKeyNegate(tweak));

        assert.bufferEqual(parent, priv);

        const tweakPub = ec.publicKeyCreate(tweak);
        const parentPub = ec.publicKeyAdd(tpub, ec.publicKeyNegate(tweakPub));

        assert.bufferEqual(parentPub, pub);
      });

      it(`should do multiplicative tweak (${ec.id})`, () => {
        const priv = ec.privateKeyGenerate();
        const pub = ec.publicKeyCreate(priv);
        const tweak = random.randomBytes(ec.size);

        tweak[0] = 0x00;

        const tpriv = ec.privateKeyTweakMul(priv, tweak);
        const tpub = ec.publicKeyTweakMul(pub, tweak);
        const zpub = ec.publicKeyCreate(tpriv);

        assert.bufferEqual(tpub, zpub);

        const msg = random.randomBytes(ec.size);

        const sig = ec.sign(msg, tpriv);

        assert(ec.isLowS(sig));
        assert(ec.verify(msg, sig, tpub));

        const der = ec.signDER(msg, tpriv);

        if (ec.size <= 32)
          assert(isStrictDER(der));

        assert(ec.isLowDER(der));
        assert(ec.verifyDER(msg, der, tpub));

        const parent = ec.privateKeyTweakMul(tpriv, ec.privateKeyInvert(tweak));

        assert.bufferEqual(parent, priv);
      });

      it(`should modulo key (${ec.id})`, () => {
        const key0 = Buffer.alloc(0);
        const mod0 = ec.privateKeyReduce(key0);
        const exp0 = Buffer.alloc(ec.size, 0x00);

        assert.bufferEqual(mod0, exp0);

        const key1 = Buffer.alloc(1, 0x0a);
        const mod1 = ec.privateKeyReduce(key1);
        const exp1 = Buffer.alloc(ec.size, 0x00);

        exp1[ec.size - 1] = 0x0a;
        assert.bufferEqual(mod1, exp1);

        const key2 = Buffer.alloc(ec.size, 0xff);
        const mod2 = ec.privateKeyReduce(key2);

        assert(ec.privateKeyVerify(mod2));

        const key3 = Buffer.alloc(ec.size + 1, 0xff);

        key3[ec.size] = 0x0a;

        const mod3 = ec.privateKeyReduce(key3);

        assert.bufferEqual(mod3, mod2);
      });

      it(`should do ECDH (${ec.id})`, () => {
        const alicePriv = ec.privateKeyGenerate();
        const alicePub = ec.publicKeyCreate(alicePriv);
        const bobPriv = ec.privateKeyGenerate();
        const bobPub = ec.publicKeyCreate(bobPriv);

        const aliceSecret = ec.derive(bobPub, alicePriv);
        const bobSecret = ec.derive(alicePub, bobPriv);

        assert.bufferEqual(aliceSecret, bobSecret);
      });

      it(`should generate keypair, sign DER and recover (${ec.id})`, () => {
        const msg = random.randomBytes(ec.size);
        const priv = ec.privateKeyGenerate();
        const pub = ec.publicKeyCreate(priv);
        const pubu = ec.publicKeyConvert(pub, false);

        const [
          signature,
          recovery
        ] = ec.signRecoverableDER(msg, priv);

        if (ec.size <= 32)
          assert(isStrictDER(signature));

        assert(ec.verifyDER(msg, signature, pub));
        assert(ec.verifyDER(msg, signature, pubu));

        const rpub = ec.recoverDER(msg, signature, recovery, true);
        const rpubu = ec.recoverDER(msg, signature, recovery, false);

        assert.bufferEqual(rpub, pub);
        assert.bufferEqual(rpubu, pubu);
      });

      it(`should test serialization formats (${ec.id})`, () => {
        const priv = ec.privateKeyGenerate();
        const pub = ec.publicKeyCreate(priv);
        const rawPriv = ec.privateKeyExport(priv);
        const rawPub = ec.publicKeyExport(pub);

        assert.bufferEqual(ec.privateKeyImport(rawPriv), priv);
        assert.bufferEqual(ec.publicKeyImport(rawPub), pub);

        const jsonPriv = ec.privateKeyExportJWK(priv);
        const jsonPub = ec.publicKeyExportJWK(pub);

        assert.bufferEqual(ec.privateKeyImportJWK(jsonPriv), priv);
        assert.bufferEqual(ec.publicKeyImportJWK(jsonPub), pub);

        const asnPriv = ec.privateKeyExportPKCS8(priv);
        const asnPub = ec.publicKeyExportSPKI(pub);

        assert.bufferEqual(ec.privateKeyImportPKCS8(asnPriv), priv);
        assert.bufferEqual(ec.publicKeyImportSPKI(asnPub), pub);
      });
    });
  }

  describe('RFC6979 vector', () => {
    const test = (opt) => {
      const curve = opt.curve;
      const key = Buffer.from(opt.key, 'hex');
      const pub = Buffer.concat([
        Buffer.from([0x04]),
        Buffer.from(opt.pub.x, 'hex'),
        Buffer.from(opt.pub.y, 'hex')
      ]);

      for (const c of opt.cases) {
        const hash = c.hash;
        const preimage = Buffer.from(c.message, 'binary');
        const r = Buffer.from(c.r, 'hex');
        const s = Buffer.from(c.s, 'hex');
        const sig = Buffer.concat([r, s]);

        const desc = `should not fail on "${opt.name}" `
                   + `and hash ${hash.id} on "${c.message}"`;

        it(desc, () => {
          const msg = hash.digest(preimage);
          const sig2 = curve.sign(msg, key);

          if (!c.custom) {
            if (curve.native === 0 || curve === secp256k1)
              assert.bufferEqual(sig2, curve.signatureNormalize(sig));
          }

          assert(curve.isLowS(sig2));
          assert(curve.publicKeyVerify(pub), 'Invalid public key');
          assert(curve.verify(msg, sig2, pub), 'Invalid signature (1)');
          assert(curve.verify(msg, sig, pub), 'Invalid signature (2)');
        });
      }
    };

    test({
      name: 'ECDSA, 192 Bits (Prime Field)',
      curve: p192,
      key: '6fab034934e4c0fc9ae67f5b5659a9d7d1fefd187ee09fd4',
      pub: {
        x: 'ac2c77f529f91689fea0ea5efec7f210d8eea0b9e047ed56',
        y: '3bc723e57670bd4887ebc732c523063d0a7c957bc97c1c43'
      },
      cases: [
        {
          message: 'sample',
          hash: SHA224,
          custom: true,
          r: 'a1f00dad97aeec91c95585f36200c65f3c01812aa60378f5',
          s: 'e07ec1304c7c6c9debbe980b9692668f81d4de7922a0f97a'
        },
        {
          message: 'sample',
          hash: SHA256,
          custom: false,
          r: '4b0b8ce98a92866a2820e20aa6b75b56382e0f9bfd5ecb55',
          s: 'ccdb006926ea9565cbadc840829d8c384e06de1f1e381b85'
        },
        {
          message: 'test',
          hash: SHA224,
          custom: true,
          r: '6945a1c1d1b2206b8145548f633bb61cef04891baf26ed34',
          s: 'b7fb7fdfc339c0b9bd61a9f5a8eaf9be58fc5cba2cb15293'
        },
        {
          message: 'test',
          hash: SHA256,
          custom: false,
          r: '3a718bd8b4926c3b52ee6bbe67ef79b18cb6eb62b1ad97ae',
          s: '5662e6848a4a19b1f1ae2f72acd4b8bbe50f1eac65d9124f'
        }
      ]
    });

    test({
      name: 'ECDSA, 224 Bits (Prime Field)',
      curve: p224,
      key: 'f220266e1105bfe3083e03ec7a3a654651f45e37167e88600bf257c1',
      pub: {
        x: '00cf08da5ad719e42707fa431292dea11244d64fc51610d94b130d6c',
        y: 'eeab6f3debe455e3dbf85416f7030cbd94f34f2d6f232c69f3c1385a'
      },
      cases: [
        {
          message: 'sample',
          hash: SHA224,
          custom: true,
          r: '1cdfe6662dde1e4a1ec4cdedf6a1f5a2fb7fbd9145c12113e6abfd3e',
          s: 'a6694fd7718a21053f225d3f46197ca699d45006c06f871808f43ebc'
        },
        {
          message: 'sample',
          hash: SHA256,
          custom: false,
          r: '61aa3da010e8e8406c656bc477a7a7189895e7e840cdfe8ff42307ba',
          s: 'bc814050dab5d23770879494f9e0a680dc1af7161991bde692b10101'
        },
        {
          message: 'test',
          hash: SHA224,
          custom: true,
          r: 'c441ce8e261ded634e4cf84910e4c5d1d22c5cf3b732bb204dbef019',
          s: '902f42847a63bdc5f6046ada114953120f99442d76510150f372a3f4'
        },
        {
          message: 'test',
          hash: SHA256,
          custom: false,
          r: 'ad04dde87b84747a243a631ea47a1ba6d1faa059149ad2440de6fba6',
          s: '178d49b1ae90e3d8b629be3db5683915f4e8c99fdf6e666cf37adcfd'
        }
      ]
    });

    test({
      name: 'ECDSA, 256 Bits (Prime Field)',
      curve: p256,
      key: 'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721',
      pub: {
        x: '60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6',
        y: '7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299'
      },
      cases: [
        {
          message: 'sample',
          hash: SHA224,
          custom: true,
          r: '53b2fff5d1752b2c689df257c04c40a587fababb3f6fc2702f1343af7ca9aa3f',
          s: 'b9afb64fdc03dc1a131c7d2386d11e349f070aa432a4acc918bea988bf75c74c'
        },
        {
          message: 'sample',
          hash: SHA256,
          custom: false,
          r: 'efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716',
          s: 'f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8'
        },
        {
          message: 'test',
          hash: SHA224,
          custom: true,
          r: 'c37edb6f0ae79d47c3c27e962fa269bb4f441770357e114ee511f662ec34a692',
          s: 'c820053a05791e521fcaad6042d40aea1d6b1a540138558f47d0719800e18f2d'
        },
        {
          message: 'test',
          hash: SHA256,
          custom: false,
          r: 'f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367',
          s: '019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083'
        }
      ]
    });

    test({
      name: 'ECDSA, 384 Bits (Prime Field)',
      curve: p384,
      key: '6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba'
         + '9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5',
      pub: {
        x: 'ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e'
         + '06aae5286b300c64def8f0ea9055866064a254515480bc13',
        y: '8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9'
         + 'f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720'
      },
      cases: [
        {
          message: 'sample',
          hash: SHA224,
          custom: true,
          r: '42356e76b55a6d9b4631c865445dbe54e056d3b3431766d0'
           + '509244793c3f9366450f76ee3de43f5a125333a6be060122',
          s: '9da0c81787064021e78df658f2fbb0b042bf304665db721f'
           + '077a4298b095e4834c082c03d83028efbf93a3c23940ca8d'
        },
        {
          message: 'sample',
          hash: SHA384,
          custom: false,
          r: '94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa7'
           + '3d64c4ea95ad133c81a648152e44acf96e36dd1e80fabe46',
          s: '99ef4aeb15f178cea1fe40db2603138f130e740a19624526'
           + '203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8'
        },
        {
          message: 'test',
          hash: SHA384,
          custom: false,
          r: '8203b63d3c853e8d77227fb377bcf7b7b772e97892a80f36'
           + 'ab775d509d7a5feb0542a7f0812998da8f1dd3ca3cf023db',
          s: 'ddd0760448d42d8a43af45af836fce4de8be06b485e9b61b'
           + '827c2f13173923e06a739f040649a667bf3b828246baa5a5'
        }
      ]
    });

    test({
      name: 'ECDSA, 521 Bits (Prime Field)',
      curve: p521,
      key: '00fad06daa62ba3b25d2fb40133da757205de67f5bb0018fee8c86e1b68c7e75ca'
        +  'a896eb32f1f47c70855836a6d16fcc1466f6d8fbec67db89ec0c08b0e996b83538',
      pub: {
        x: '01894550d0785932e00eaa23b694f213f8c3121f86dc97a04e5a7167db4e5bcd37'
         + '1123d46e45db6b5d5370a7f20fb633155d38ffa16d2bd761dcac474b9a2f5023a4',
        y: '00493101c962cd4d2fddf782285e64584139c2f91b47f87ff82354d6630f746a28'
         + 'a0db25741b5b34a828008b22acc23f924faafbd4d33f81ea66956dfeaa2bfdfcf5'
      },
      cases: [
        {
          message: 'sample',
          hash: SHA384,
          custom: true,
          r: '01ea842a0e17d2de4f92c15315c63ddf72685c18195c2bb95e572b9c5136ca4b4b'
           + '576ad712a52be9730627d16054ba40cc0b8d3ff035b12ae75168397f5d50c67451',
          s: '01f21a3cee066e1961025fb048bd5fe2b7924d0cd797babe0a83b66f1e35eeaf5f'
           + 'de143fa85dc394a7dee766523393784484bdf3e00114a1c857cde1aa203db65d61'
        },
        {
          message: 'sample',
          hash: SHA512,
          custom: false,
          r: '00c328fafcbd79dd77850370c46325d987cb525569fb63c5d3bc53950e6d4c5f17'
           + '4e25a1ee9017b5d450606add152b534931d7d4e8455cc91f9b15bf05ec36e377fa',
          s: '00617cce7cf5064806c467f678d3b4080d6f1cc50af26ca209417308281b68af28'
           + '2623eaa63e5b5c0723d8b8c37ff0777b1a20f8ccb1dccc43997f1ee0e44da4a67a'
        },
        {
          message: 'test',
          hash: SHA512,
          custom: false,
          r: '013e99020abf5cee7525d16b69b229652ab6bdf2affcaef38773b4b7d08725f10c'
           + 'db93482fdcc54edcee91eca4166b2a7c6265ef0ce2bd7051b7cef945babd47ee6d',
          s: '01fbd0013c674aa79cb39849527916ce301c66ea7ce8b80682786ad60f98f7e78a'
           + '19ca69eff5c57400e3b3a0ad66ce0978214d13baf4e9ac60752f7b155e2de4dce3'
        }
      ]
    });
  });

  describe('Custom Vectors', () => {
    const getVectors = (curve) => {
      const id = curve.id.toLowerCase();
      const file = `${__dirname}/data/sign/${id}.json`;
      const text = fs.readFileSync(file, 'utf8');
      const vectors = JSON.parse(text);

      return vectors.map((vector) => {
        return vector.map((item) => {
          if (typeof item !== 'string')
            return item;
          return Buffer.from(item, 'hex');
        });
      });
    };

    for (const curve of curves) {
      for (const [i, vector] of getVectors(curve).entries()) {
        const [
          priv,
          pub,
          tweak,
          privAdd,
          privMul,
          privNeg,
          privInv,
          pubAdd,
          pubMul,
          pubNeg,
          pubDbl,
          pubConv,
          pubHybrid,
          sec1,
          xy,
          pkcs8,
          spki,
          msg,
          sig,
          der,
          param,
          other,
          secret
        ] = vector;

        it(`should create and tweak key (${i}) (${curve.id})`, () => {
          assert(curve.privateKeyVerify(priv));
          assert(curve.publicKeyVerify(pub));
          assert(curve.publicKeyVerify(pubConv));
          assert(curve.publicKeyVerify(pubHybrid));

          const tweakNeg = curve.privateKeyNegate(tweak);
          const tweakInv = curve.privateKeyInvert(tweak);

          assert.bufferEqual(curve.publicKeyCreate(priv), pub);
          assert.bufferEqual(curve.privateKeyReduce(priv), priv);
          assert.bufferEqual(curve.privateKeyTweakAdd(priv, tweak), privAdd);
          assert.bufferEqual(curve.privateKeyTweakAdd(privAdd, tweakNeg), priv);
          assert.bufferEqual(curve.privateKeyTweakMul(priv, tweak), privMul);
          assert.bufferEqual(curve.privateKeyTweakMul(privMul, tweakInv), priv);
          assert.bufferEqual(curve.privateKeyNegate(priv), privNeg);
          assert.bufferEqual(curve.privateKeyInvert(priv), privInv);
          assert.bufferEqual(curve.publicKeyTweakAdd(pub, tweak), pubAdd);
          assert.bufferEqual(curve.publicKeyTweakAdd(pubAdd, tweakNeg), pub);
          assert.bufferEqual(curve.publicKeyTweakMul(pub, tweak), pubMul);
          assert.bufferEqual(curve.publicKeyTweakMul(pubMul, tweakInv), pub);
          assert.bufferEqual(curve.publicKeyNegate(pub), pubNeg);
          assert.bufferEqual(curve.publicKeyAdd(pub, pub), pubDbl);
          assert.bufferEqual(curve.publicKeyAdd(pubDbl, pubNeg), pub);
          assert.bufferEqual(curve.publicKeyCombine([pub, pub]), pubDbl);
          assert.bufferEqual(curve.publicKeyCombine([pubDbl, pubNeg]), pub);
          assert.bufferEqual(curve.publicKeyCombine([pub, pubNeg, pub]), pub);
          assert.bufferEqual(curve.publicKeyCreate(priv, false), pubConv);
          assert.bufferEqual(curve.publicKeyConvert(pub, false), pubConv);
          assert.bufferEqual(curve.publicKeyConvert(pubConv, true), pub);

          assert.throws(() => curve.publicKeyAdd(pub, pubNeg));
          assert.throws(() => curve.publicKeyCombine([pub, pubNeg]));
        });

        it(`should reserialize key (${i}) (${curve.id})`, () => {
          assert.bufferEqual(curve.privateKeyExport(priv), sec1);
          assert.bufferEqual(curve.privateKeyExportPKCS8(priv), pkcs8);
          assert.bufferEqual(curve.publicKeyExport(pub), xy);
          assert.bufferEqual(curve.publicKeyExportSPKI(pub), spki);
          assert.bufferEqual(curve.privateKeyImport(sec1), priv);
          assert.bufferEqual(curve.privateKeyImportPKCS8(pkcs8), priv);
          assert.bufferEqual(curve.publicKeyImport(xy), pub);
          assert.bufferEqual(curve.publicKeyImportSPKI(spki), pub);
          assert.bufferEqual(curve.publicKeyImport(xy, false), pubConv);
          assert.bufferEqual(curve.publicKeyImportSPKI(spki, false), pubConv);
        });

        it(`should check signature (${i}) (${curve.id})`, () => {
          if (curve.size <= 32)
            assert(isStrictDER(der));

          assert(curve.isLowS(sig));
          assert(curve.isLowDER(der));
          assert(curve.signatureExport(sig), der);
          assert(curve.signatureImport(der), sig);
        });

        it(`should recover public key (${i}) (${curve.id})`, () => {
          assert.bufferEqual(curve.recover(msg, sig, param), pub);
          assert.bufferEqual(curve.recoverDER(msg, der, param), pub);
          assert.bufferEqual(curve.recover(msg, sig, param, false), pubConv);
          assert.bufferEqual(curve.recoverDER(msg, der, param, false), pubConv);
        });

        it(`should derive shared secret (${i}) (${curve.id})`, () => {
          assert.bufferEqual(curve.derive(pub, other), secret);
          assert.bufferEqual(curve.derive(pubConv, other), secret);
          assert.bufferEqual(curve.derive(pubHybrid, other), secret);
        });

        it(`should sign and verify (${i}) (${curve.id})`, () => {
          const sig2 = curve.sign(msg, priv);
          const [sig3, param2] = curve.signRecoverable(msg, priv);
          const der2 = curve.signDER(msg, priv);
          const [der3, param3] = curve.signRecoverableDER(msg, priv);

          if (curve.size <= 32) {
            assert(isStrictDER(der2));
            assert(isStrictDER(der3));
          }

          if (curve.native === 0 || curve === secp256k1) {
            assert.bufferEqual(sig2, sig);
            assert.bufferEqual(sig3, sig);
            assert.strictEqual(param2, param);
            assert.bufferEqual(der2, der);
            assert.bufferEqual(der3, der);
            assert.strictEqual(param3, param);
          } else {
            assert(curve.isLowS(sig2));
            assert(curve.isLowS(sig3));
            assert(curve.isLowDER(der2));
            assert(curve.isLowDER(der3));
            assert(curve.verify(msg, sig2, pub));
            assert(curve.verify(msg, sig3, pub));
            assert(curve.verifyDER(msg, der2, pub));
            assert(curve.verifyDER(msg, der3, pub));
          }

          assert(curve.verify(msg, sig, pub));
          assert(curve.verifyDER(msg, der, pub));
          assert(curve.verify(msg, sig, pubConv));
          assert(curve.verifyDER(msg, der, pubConv));
          assert(curve.verify(msg, sig, pubHybrid));
          assert(curve.verifyDER(msg, der, pubHybrid));

          msg[0] ^= 1;

          assert(!curve.verify(msg, sig, pub));
          assert(!curve.verifyDER(msg, der, pub));

          msg[0] ^= 1;
          sig[0] ^= 1;
          der[0] ^= 1;

          assert(!curve.verify(msg, sig, pub));
          assert(!curve.verifyDER(msg, der, pub));

          sig[0] ^= 1;
          der[0] ^= 1;
          pub[2] ^= 1;

          assert(!curve.verify(msg, sig, pub));
          assert(!curve.verifyDER(msg, der, pub));

          pub[2] ^= 1;

          assert(curve.verify(msg, sig, pub));
          assert(curve.verifyDER(msg, der, pub));
        });

        it(`should sign and verify schnorr (${i}) (${curve.id})`, () => {
          if (curve.id === 'P224')
            this.skip();

          const pubu = curve.publicKeyConvert(pub, false);
          const msg = Buffer.alloc(32, 0xaa);
          const sig = curve.schnorrSign(msg, priv);

          assert(curve.schnorrVerify(msg, sig, pub));
          assert(curve.schnorrVerify(msg, sig, pubu));
          assert(curve.schnorrVerifyBatch([]));
          assert(curve.schnorrVerifyBatch([[msg, sig, pub]]));

          msg[0] ^= 1;

          assert(!curve.schnorrVerify(msg, sig, pub));
          assert(!curve.schnorrVerifyBatch([[msg, sig, pub]]));

          msg[0] ^= 1;
          sig[0] ^= 1;

          assert(!curve.schnorrVerify(msg, sig, pub));
          assert(!curve.schnorrVerifyBatch([[msg, sig, pub]]));

          sig[0] ^= 1;
          pub[2] ^= 1;

          assert(!curve.schnorrVerify(msg, sig, pub));
          assert(!curve.schnorrVerifyBatch([[msg, sig, pub]]));

          pub[2] ^= 1;

          assert(curve.schnorrVerify(msg, sig, pub));
          assert(curve.schnorrVerifyBatch([[msg, sig, pub]]));
        });
      }
    }
  });

  describe('Maxwell\'s trick', () => {
    const msg =
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

    const vectors = [
      {
        curve: p256,
        pub: '041548fc88953e06cd34d4b300804c5322cb48c24aaaa4d0'
           + '7a541b0f0ccfeedeb0ae4991b90519ea405588bdf699f5e6'
           + 'd0c6b2d5217a5c16e8371062737aa1dae1',
        message: msg,
        sig: '3006020106020104',
        result: true
      },
      {
        curve: p256,
        pub: '04ad8f60e4ec1ebdb6a260b559cb55b1e9d2c5ddd43a41a2'
           + 'd11b0741ef2567d84e166737664104ebbc337af3d861d352'
           + '4cfbc761c12edae974a0759750c8324f9a',
        message: msg,
        sig: '3006020106020104',
        result: true
      },
      {
        curve: p256,
        pub: '0445bd879143a64af5746e2e82aa65fd2ea07bba4e355940'
           + '95a981b59984dacb219d59697387ac721b1f1eccf4b11f43'
           + 'ddc39e8367147abab3084142ed3ea170e4',
        message: msg,
        sig: '301502104319055358e8617b0c46353d039cdaae020104',
        result: true
      },
      {
        curve: p256,
        pub: '040feb5df4cc78b35ec9c180cc0de5842f75f088b4845697'
           + '8ffa98e716d94883e1e6500b2a1f6c1d9d493428d7ae7d9a'
           + '8a560fff30a3d14aa160be0c5e7edcd887',
        message: msg,
        sig: '301502104319055358e8617b0c46353d039cdaae020104',
        result: false
      },
      {
        curve: p384,
        pub: '0425e299eea9927b39fa92417705391bf17e8110b4615e9e'
           + 'b5da471b57be0c30e7d89dbdc3e5da4eae029b300344d385'
           + '1548b59ed8be668813905105e673319d59d32f574e180568'
           + '463c6186864888f6c0b67b304441f82aab031279e48f047c31',
        message: msg,
        sig: '3006020103020104',
        result: true
      },
      {
        curve: p384,
        pub: '04a328f65c22307188b4af65779c1d2ec821c6748c6bd8dc'
           + '0e6a008135f048f832df501f7f3f79966b03d5bef2f187ec'
           + '34d85f6a934af465656fb4eea8dd9176ab80fbb4a27a649f'
           + '526a7dfe616091b78d293552bc093dfde9b31cae69d51d3afb',
        message: msg,
        sig: '3006020103020104',
        result: true
      },
      {
        curve: p384,
        pub: '04242e8585eaa7a28cc6062cab4c9c5fd536f46b17be1728'
           + '288a2cda5951df4941aed1d712defda023d10aca1c5ee014'
           + '43e8beacd821f7efa27847418ab95ce2c514b2b6b395ee73'
           + '417c83dbcad631421f360d84d64658c98a62d685b220f5aad4',
        message: msg,
        sig: '301d0218389cb27e0bc8d21fa7e5f24cb74f58851313e696333ad68e020104',
        result: true
      },
      {
        curve: p384,
        pub: '04cdf865dd743fe1c23757ec5e65fd5e4038b472ded2af26'
           + '1e3d8343c595c8b69147df46379c7ca40e60e80170d34a11'
           + '88dbb2b6f7d3934c23d2f78cfb0db3f3219959fad63c9b61'
           + '2ef2f20d679777b84192ce86e781c14b1bbb77eacd6e0520e2',
        message: msg,
        sig: '301d0218389cb27e0bc8d21fa7e5f24cb74f58851313e696333ad68e020104',
        result: false
      }
    ];

    for (const [i, vector] of vectors.entries()) {
      it(`should pass on vector #${i}`, () => {
        const curve = vector.curve;
        const key = Buffer.from(vector.pub, 'hex');
        const msg = Buffer.from(vector.message, 'hex');
        const sig = Buffer.from(vector.sig, 'hex');

        const actual = curve.verifyDER(msg, sig, key);

        if (curve.size <= 32)
          assert(isStrictDER(sig));

        assert.strictEqual(actual, vector.result);
      });
    }
  });

  describe('Specific Cases', () => {
    it('should verify lax signature', () => {
      // https://github.com/indutny/elliptic/issues/78
      const lax = {
        msg: 'de17556d2111ef6a964c9c136054870495b005b3942ad7b626'
           + '28af00293b9aa8',
        sig: '3045022100a9379b66c22432585cb2f5e1e85736c69cf5fdc9'
           + 'e1033ad583fc27f0b7c561d802202c7b5d9d92ceca742829ff'
           + 'be28ba6565faa8f94556cb091cbc39d2f11d45946700',
        pub: '04650a9a1deb523f636379ec70c29b3e1e832e314dea0f7911'
           + '60f3dba628f4f509360e525318bf7892af9ffe2f585bf7b264'
           + 'aa31792744ec1885ce17f3b1ef50f3'
      };

      const msg = Buffer.from(lax.msg, 'hex');
      const sig = Buffer.from(lax.sig, 'hex');
      const pub = Buffer.from(lax.pub, 'hex');

      assert(!isStrictDER(sig));
      assert(secp256k1.isLowDER(sig));

      assert.strictEqual(secp256k1.verifyDER(msg, sig, pub), true);
    });

    it('should recover the public key from a signature', () => {
      const priv = secp256k1.privateKeyGenerate();
      const pub = secp256k1.publicKeyCreate(priv, true);
      const msg = Buffer.alloc(32, 0x01);
      const sig = secp256k1.sign(msg, priv);

      let found = false;

      for (let i = 0; i < 4; i++) {
        const r = secp256k1.recover(msg, sig, i, true);

        if (!r)
          continue;

        if (r.equals(pub)) {
          found = true;
          break;
        }
      }

      assert(found, 'the keys should match');
    });

    it('should fail to recover key when no quadratic residue available', () => {
      const msg = Buffer.from(
        'f75c6b18a72fabc0f0b888c3da58e004f0af1fe14f7ca5d8c897fe164925d5e9',
        'hex');

      const r = Buffer.from(
        'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140',
        'hex');

      const s = Buffer.from(
        '8887321be575c8095f789dd4c743dfe42c1820f9231f98a962b210e3ac2452a3',
        'hex');

      const sig = Buffer.concat([r, s]);

      assert.strictEqual(secp256k1.recover(msg, sig, 0), null);
      assert.strictEqual(secp256k1.recover(msg, sig, 1), null);
      assert.strictEqual(secp256k1.recover(msg, sig, 2), null);
      assert.strictEqual(secp256k1.recover(msg, sig, 3), null);
    });

    it('should normalize high S signature', () => {
      const der = Buffer.from(''
        + '304502203e4516da7253cf068effec6b95c41221c0cf3a8e6ccb8cbf1725b562'
        + 'e9afde2c022100ab1e3da73d67e32045a20e0b999e049978ea8d6ee5480d485f'
        + 'cf2ce0d03b2ef0',
        'hex');

      const hi = Buffer.from(''
        + '3e4516da7253cf068effec6b95c41221c0cf3a8e6ccb8cbf1725b562e9afde2c'
        + 'ab1e3da73d67e32045a20e0b999e049978ea8d6ee5480d485fcf2ce0d03b2ef0',
        'hex');

      const lo = Buffer.from(''
        + '3e4516da7253cf068effec6b95c41221c0cf3a8e6ccb8cbf1725b562e9afde2c'
        + '54e1c258c2981cdfba5df1f46661fb6541c44f77ca0092f3600331abfffb1251',
        'hex');

      assert(isStrictDER(der));
      assert(!secp256k1.isLowDER(der));
      assert(!secp256k1.isLowS(hi));
      assert.bufferEqual(secp256k1.signatureExport(hi), der);
      assert.bufferEqual(secp256k1.signatureImport(der), hi);
      assert.bufferEqual(secp256k1.signatureNormalize(hi), lo);
      assert.bufferEqual(secp256k1.signatureNormalizeDER(der),
                         secp256k1.signatureExport(lo));
    });

    it('should generate keypair, sign RS and recover', () => {
      const msg = random.randomBytes(secp256k1.size);
      const priv = secp256k1.privateKeyGenerate();
      const pub = secp256k1.publicKeyCreate(priv);
      const pubu = secp256k1.publicKeyConvert(pub, false);

      const [
        signature,
        recovery
      ] = secp256k1.signRecoverable(msg, priv);

      assert(secp256k1.isLowS(signature));
      assert(secp256k1.verify(msg, signature, pub));
      assert(secp256k1.verify(msg, signature, pubu));

      const rpub = secp256k1.recover(msg, signature, recovery, true);
      const rpubu = secp256k1.recover(msg, signature, recovery, false);

      assert.bufferEqual(rpub, pub);
      assert.bufferEqual(rpubu, pubu);
    });

    it('should sign zero-length message', () => {
      const msg = Buffer.alloc(0);
      const key = p256.privateKeyGenerate();
      const pub = p256.publicKeyCreate(key);
      const sig = p256.sign(msg, key);

      assert(p256.isLowS(sig));
      assert(p256.verify(msg, sig, pub));
    });

    it('should import standard JWK (1)', () => {
      // https://tools.ietf.org/html/rfc7518#appendix-C
      const json = {
        'kty': 'EC',
        'crv': 'P-256',
        'x': 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
        'y': 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
        'd': '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
        'ext': true
      };

      const priv = p256.privateKeyImportJWK(json);
      const pub = p256.publicKeyImportJWK(json);

      assert.bufferEqual(p256.publicKeyCreate(priv), pub);
      assert.deepStrictEqual(p256.privateKeyExportJWK(priv), json);
    });

    it('should import standard JWK (2)', () => {
      // https://tools.ietf.org/html/rfc7517#appendix-A.2
      const json = {
        'kty': 'EC',
        'crv': 'P-256',
        'x': 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
        'y': '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
        'd': '870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE',
        'ext': true
      };

      const priv = p256.privateKeyImportJWK(json);
      const pub = p256.publicKeyImportJWK(json);

      assert.bufferEqual(p256.publicKeyCreate(priv), pub);
      assert.deepStrictEqual(p256.privateKeyExportJWK(priv), json);
    });
  });

  describe('Canonical', () => {
    it('should reject non-canonical R value', () => {
      const json = [
        ['2987f61715244cfb7e613770ec59bbd4eeb48d9f3b4a',
         '66cdb056acb82e75b1157b8538092ac43632541d8045',
         'd5a334d9063ff2c27e26cac1673bab85e9d1a4990d2f'].join(''),
        ['0372fb58279be153963a356a3c154e4aad826db0fb4f',
         'd156cc1ebe1cb937fd499fca2a8bffd82f19b14ab6a9',
         'b76d75ddf62cc06f7ef5d98158c96bad9c1b482656ca'].join(''),
        ['006eb96e4a6f3674ed254b915ac3241472ee8085e822',
         'e925e0d42711e5eed113ff44d27239388466595c5b71',
         '9c3fa5f4ebdfd6a099f3db3bd244623c68b3feacb49a'].join(''),
        ['02',
         '01c0c2cbc731e95d2086a9208c93febcbb72d95c2a37',
         'cde565df74d78b2dbfb90abe5540dbd5790c9a0683a8',
         'a01a7f2b342df7d660513d6f6532f861bb8c2d205061'].join('')
      ];

      const [m, r, s, p] = json;
      const msg = Buffer.from(m, 'hex');
      const sig = Buffer.from(r + s, 'hex');
      const der = Signature.toDER(sig, 66);
      const pub = Buffer.from(p, 'hex');

      assert(!p521.verify(msg, sig, pub));
      assert(!p521.verifyDER(msg, der, pub));
    });

    it('should reject non-canonical S value', () => {
      const json = [
        ['2987f61715244cfb7e613770ec59bbd4eeb48d9f3b4a',
         '66cdb056acb82e75b1157b8538092ac43632541d8045',
         'd5a334d9063ff2c27e26cac1673bab85e9d1a4990d2f'].join(''),
        ['0172fb58279be153963a356a3c154e4aad826db0fb4f',
         'd156cc1ebe1cb937fd499fcfd90578546fea1adf36dd',
         'b6247ed4505c84b9b53d4fe5111ab03de4fcb6edf2c1'].join(''),
        ['026eb96e4a6f3674ed254b915ac3241472ee8085e822',
         'e925e0d42711e5eed113ff3f23f8c0bc4395efc7db3d',
         '9d889cfe91b0125663ac64d819f31dac1fd28fe518a3'].join(''),
        ['02',
         '01c0c2cbc731e95d2086a9208c93febcbb72d95c2a37',
         'cde565df74d78b2dbfb90abe5540dbd5790c9a0683a8',
         'a01a7f2b342df7d660513d6f6532f861bb8c2d205061'].join('')
      ];

      const [m, r, s, p] = json;
      const msg = Buffer.from(m, 'hex');
      const sig = Buffer.from(r + s, 'hex');
      const der = Signature.toDER(sig, 66);
      const pub = Buffer.from(p, 'hex');

      assert(!p521.verify(msg, sig, pub));
      assert(!p521.verifyDER(msg, der, pub));
    });

    it('should reject non-canonical X coordinate (compressed)', () => {
      const json = [
        ['2987f61715244cfb7e613770ec59bbd4eeb48d9f3b4a',
         '66cdb056acb82e75b1157b8538092ac43632541d8045',
         'd5a334d9063ff2c27e26cac1673bab85e9d1a4990d2f'].join(''),
        ['0172fb58279be153963a356a3c154e4aad826db0fb4f',
         'd156cc1ebe1cb937fd499fcfd90578546fea1adf36dd',
         'b6247ed4505c84b9b53d4fe5111ab03de4fcb6edf2c1'].join(''),
        ['006eb96e4a6f3674ed254b915ac3241472ee8085e822',
         'e925e0d42711e5eed113ff44d27239388466595c5b71',
         '9c3fa5f4ebdfd6a099f3db3bd244623c68b3feacb49a'].join(''),
        ['02',
         '03c0c2cbc731e95d2086a9208c93febcbb72d95c2a37',
         'cde565df74d78b2dbfb90abe5540dbd5790c9a0683a8',
         'a01a7f2b342df7d660513d6f6532f861bb8c2d205060'].join('')
      ];

      const [m, r, s, p] = json;
      const msg = Buffer.from(m, 'hex');
      const sig = Buffer.from(r + s, 'hex');
      const der = Signature.toDER(sig, 66);
      const pub = Buffer.from(p, 'hex');

      assert(!p521.publicKeyVerify(pub));
      assert(!p521.verify(msg, sig, pub));
      assert(!p521.verifyDER(msg, der, pub));
    });

    it('should reject non-canonical X coordinate', () => {
      const json = [
        ['2987f61715244cfb7e613770ec59bbd4eeb48d9f3b4a',
         '66cdb056acb82e75b1157b8538092ac43632541d8045',
         'd5a334d9063ff2c27e26cac1673bab85e9d1a4990d2f'].join(''),
        ['0172fb58279be153963a356a3c154e4aad826db0fb4f',
         'd156cc1ebe1cb937fd499fcfd90578546fea1adf36dd',
         'b6247ed4505c84b9b53d4fe5111ab03de4fcb6edf2c1'].join(''),
        ['006eb96e4a6f3674ed254b915ac3241472ee8085e822',
         'e925e0d42711e5eed113ff44d27239388466595c5b71',
         '9c3fa5f4ebdfd6a099f3db3bd244623c68b3feacb49a'].join(''),
        ['04',
         '03c0c2cbc731e95d2086a9208c93febcbb72d95c2a37',
         'cde565df74d78b2dbfb90abe5540dbd5790c9a0683a8',
         'a01a7f2b342df7d660513d6f6532f861bb8c2d205060',
         '010ca5c0e1e861801cdc800cb07584027b332ecfe4a6',
         '152a9c0b7e09a18c14da428791ce6448743401b29724',
         '39969786a068a30f6690dec00c9e1a9149cdd87dfda8'].join('')
      ];

      const [m, r, s, p] = json;
      const msg = Buffer.from(m, 'hex');
      const sig = Buffer.from(r + s, 'hex');
      const der = Signature.toDER(sig, 66);
      const pub = Buffer.from(p, 'hex');

      assert(!p521.publicKeyVerify(pub));
      assert(!p521.verify(msg, sig, pub));
      assert(!p521.verifyDER(msg, der, pub));
    });

    it('should reject non-canonical Y coordinate', () => {
      const json = [
        ['2987f61715244cfb7e613770ec59bbd4eeb48d9f3b4a',
         '66cdb056acb82e75b1157b8538092ac43632541d8045',
         'd5a334d9063ff2c27e26cac1673bab85e9d1a4990d2f'].join(''),
        ['0172fb58279be153963a356a3c154e4aad826db0fb4f',
         'd156cc1ebe1cb937fd499fcfd90578546fea1adf36dd',
         'b6247ed4505c84b9b53d4fe5111ab03de4fcb6edf2c1'].join(''),
        ['006eb96e4a6f3674ed254b915ac3241472ee8085e822',
         'e925e0d42711e5eed113ff44d27239388466595c5b71',
         '9c3fa5f4ebdfd6a099f3db3bd244623c68b3feacb49a'].join(''),
        ['04',
         '01c0c2cbc731e95d2086a9208c93febcbb72d95c2a37',
         'cde565df74d78b2dbfb90abe5540dbd5790c9a0683a8',
         'a01a7f2b342df7d660513d6f6532f861bb8c2d205061',
         '030ca5c0e1e861801cdc800cb07584027b332ecfe4a6',
         '152a9c0b7e09a18c14da428791ce6448743401b29724',
         '39969786a068a30f6690dec00c9e1a9149cdd87dfda7'].join('')
      ];

      const [m, r, s, p] = json;
      const msg = Buffer.from(m, 'hex');
      const sig = Buffer.from(r + s, 'hex');
      const der = Signature.toDER(sig, 66);
      const pub = Buffer.from(p, 'hex');

      assert(!p521.publicKeyVerify(pub));
      assert(!p521.verify(msg, sig, pub));
      assert(!p521.verifyDER(msg, der, pub));
    });

    it('should reject non-canonical X coordinate (compressed)', () => {
      const json = [
        '02fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30',
        '03fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30'
      ];

      for (const str of json) {
        const pub = Buffer.from(str, 'hex');

        assert(!secp256k1.publicKeyVerify(pub));
      }
    });

    it('should reject non-canonical X coordinate (compressed)', () => {
      const json = [
        '02ffffffff00000001000000000000000000000001000000000000000000000004',
        '03ffffffff00000001000000000000000000000001000000000000000000000004'
      ];

      for (const str of json) {
        const pub = Buffer.from(str, 'hex');

        assert(!p256.publicKeyVerify(pub));
      }
    });
  });
});
