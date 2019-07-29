'use strict';

const assert = require('bsert');
const random = require('../lib/random');
const ed448 = require('../lib/ed448');
const SHAKE256 = require('../lib/shake256');
const rfc8032 = require('./data/rfc8032-vectors.json');

describe('Ed448', function() {
  this.timeout(15000);

  it('should generate keypair and sign', () => {
    const msg = random.randomBytes(ed448.size);
    const secret = ed448.privateKeyGenerate();
    const pub = ed448.publicKeyCreate(secret);

    assert(ed448.publicKeyVerify(pub));

    const sig = ed448.sign(msg, secret);

    assert(ed448.verify(msg, sig, pub));

    sig[0] ^= 1;

    assert(!ed448.verify(msg, sig, pub));

    assert.bufferEqual(
      ed448.privateKeyImport(ed448.privateKeyExport(secret)),
      secret);

    assert.bufferEqual(
      ed448.privateKeyImportPKCS8(ed448.privateKeyExportPKCS8(secret)),
      secret);

    assert.bufferEqual(
      ed448.publicKeyImport(ed448.publicKeyExport(pub)),
      pub);

    assert.bufferEqual(
      ed448.publicKeyImportSPKI(ed448.publicKeyExportSPKI(pub)),
      pub);
  });

  it('should disallow points at infinity', () => {
    // Fun fact about edwards curves: points
    // at infinity can actually be serialized.
    const msg = Buffer.from(''
      + 'bd0f6a3747cd561bdddf4640a332461a'
      + '4a30a12a434cd0bf40d766d9c6d458e5'
      + '512204a30c17d1f50b5079631f64eb31'
      + '12182da3005835461113718d1a5ef944',
      'hex');

    const sig = Buffer.from(''
      + '01000000000000000000000000000000'
      + '00000000000000000000000000000000'
      + '00000000000000000000000000000000'
      + '00000000000000000000000000000000'
      + '00000000000000000000000000000000'
      + '00000000000000000000000000000000'
      + '00000000000000000000000000000000'
      + '0000',
      'hex');

    const pub = Buffer.from(''
      + 'df9705f58edbab802c7f8363cfe5560a'
      + 'b1c6132c20a9f1dd163483a26f8ac53a'
      + '39d6808bf4a1dfbd261b099bb03b3fb5'
      + '0906cb28bd8a081f00',
      'hex');

    assert(!ed448.verify(msg, sig, pub));

    const inf = Buffer.from(''
      + '01000000000000000000000000000000'
      + '00000000000000000000000000000000'
      + '00000000000000000000000000000000'
      + '000000000000000000',
      'hex');

    assert(!ed448.publicKeyVerify(inf));
    assert(!ed448.verify(msg, sig, inf));
  });

  it('should validate small order points', () => {
    const small = [
      // 0, c (order 1)
      ['01000000000000000000000000000000000000000000000000000000',
       '0000000000000000000000000000000000000000000000000000000000'].join(''),
      // 0, -c (order 2) (native backend doesn't like this guy,
      //                  probably because it's the one small
      //                  order point that is not 4-isogenous
      //                  to curve448)
      ['feffffffffffffffffffffffffffffffffffffffffffffffffffffff',
       'feffffffffffffffffffffffffffffffffffffffffffffffffffffff00'].join(''),
      // c, 0 (order 4)
      ['00000000000000000000000000000000000000000000000000000000',
       '0000000000000000000000000000000000000000000000000000000080'].join(''),
      // -c, 0 (order 4)
      ['00000000000000000000000000000000000000000000000000000000',
       '0000000000000000000000000000000000000000000000000000000000'].join('')
    ];

    const key = ed448.scalarGenerate();

    for (let i = 0; i < small.length; i++) {
      const str = small[i];
      const pub = Buffer.from(str, 'hex');

      if (ed448.native === 2 && i === 1)
        continue;

      if (i > 0)
        assert(ed448.publicKeyVerify(pub));

      assert.throws(() => ed448.deriveWithScalar(pub, key));
    }
  });

  it('should validate signatures with torsion components', () => {
    const json = [
      // (0, 0)
      [
        '2a596cd0f0326747960ff7f36014472dd2faaff3e137f1d7bd7625ca1a632c86ea9c2a12c2111a4b682f8a69051f553777db77a93f287e991b',
        '848aa10e0baf75c788c9ae5aa59239cdc9eeadec4465e404f6d79064020cf5056ea5f9c9af78d0894db751c3ad2e6607a58f9f88d31536c300',
        '8e7a1f893fdf95fbde0980ae999167ac6090255c0453c7631c1a28e9810c6a4e2e0ab3215d8767181052fc86ab8808d5c19d1de6b049963400',
        '4b84907faf16cda003cf134b162d400a864fb300f9ad09b33d5f6b5679b5e7b653017d0893d47137668ebe4015176f3d54b9f00af047f14080',
        true,
        true
      ],

      // (0, 0)
      [
        '6998833d4e3dd4a7f7049e8e334ea7204ed7fef0b094e898b5d126239c953f9fc306982d1946561d0a799cdd0ea84465dd7c133b518ac1e3ba',
        'c7e1d289b350b1924ffdf2e81e6ef8bc29984a9066983b091b1d26772ede920f6720f5fee5c564e2571a170bb7d92f776393a7d50100729000',
        '2ed4a2ecca6c445af18026482e515596ffeb632c48e5e4d03d0a244f4141463b4ab4987459730447fa00fde0333c249d9158295670179a2000',
        '8b7ab2c01bed9b08a4c14fae468c0f701d82cfe4e470b9f5af682c58b15679961e841abe551eec528be5cb50201ae740a71e6e9457eb656680',
        false,
        true
      ],

      // (0, 1)
      [
        'c63f7c1e3cd8a7fcef1c4667a40c42f29d547cc4648799e324f7d23a7b0ea79c3940f00001b56ff59bea114c56e219082efc21714ce8b50afc',
        '521f59fa4c4cd55f47ecca8c95a9ea835a939db0636eefefa057521bce1ac53809f03f64f2ba901e0bc2218a6044486ca0eeb5212ee4adc500',
        'f4b99f1dc93be7d9ef2eb98c68169b368ccff3a65a7b370d5320c5b48edde50ae060f65862db08dfbeb24d8d8164024740c67240ebd32f2100',
        '05cad01e0be214e8a720a789e6e195aa8613f12010754769fe5440ddb3b67563406fde3890d22aa2867ece11ce9121dffaeeebd44b44346000',
        false,
        true
      ],

      // (1, 1)
      [
        '9f3c41e784fc34a6040e3fbc56fb7a133a47f96067c22d6f5dcd95c3eeddeae330980748470eceba52e46983a662fbf753bcde3b0d39eeff1f',
        'caf7da877bef663ad35841d31aab19d87ea4c0b551120631d8641b3f4fcf43460c222e4f83f5b18697be269ba5af1dde9b0ff96baa8d3d1d00',
        'faff63d451d3a7f1de112b37bc7a991a022bf876b5f9f1a10c4c493e9e33e78689064166a166739bf7ae5bd7b52541af9b775cff76304b3200',
        '8818a84042578578f2f96c01146b4067ed21ddd4f725caa988422c513123e728bbb54dae863e264b46774944fe3ab0eeff67f07d619d629500',
        true,
        true
      ],

      // (1, 1)
      [
        '8079b84b8476da19ae62721e5b8eca9e14d8f5cc2c09b34624530e7f2f61ab2a9824127183d674893686ab79d22552f6397616a759bb512d58',
        'b9cf91018948f955c3df0752f075c0c3553be8f0a380b4a5692d0c513f632e7b700f8b2183d987d81efb4449f0b32766b2034a54837cbc1180',
        'fa8eb259a60bcb2107f4aa5d7c33fb2f61b9b0110a018fbd7acf4d14ce2ad54065c5defb9311ee8c7fa4b83d927aa625f4d2932b17cc9a1200',
        'bd38ceea0e894dd3c6c21324161f350bcc553765092d81e287cdc368908de825e4b74e8dc142b2fe435ec557780d2d4fecbb5c93ff10609780',
        false,
        true
      ],

      // (1, 2)
      [
        'eaaedfadb7591be2f32303d1483f0f322f7bcc14124a4e1577d9bcfe454f00352e6362c1c66dd2b0cadeb2535af6d19850a27a5e47217e8fef',
        '37ccae0439012245098ef808df88472df479fee60bbe8fe899248096c09ee5296f8a25d16bfb4365be77b34e6df8da1110f8fcf0e6151c2a80',
        '8800d4ce199f99a94b7abf0246780cde0b2f559f922af849073cd47c09d01384c330f2e5234cd749f0a8f95625f8119ab8a34c9d6fb11e2100',
        '470b5f5ea3f7b3ad61dffcb3f17fb5532fbe5428ce501d11ad0db9294947322c6eaaba06450732ba851fd2ffbf7a22d645e906d40f83980c80',
        true,
        true
      ],

      // (1, 2)
      [
        'f2a8a2825f0e8b6d3629787039674a626e809cf65b6755b37263645c4f1a5031e5ed789299c0b7ff4d27eae2818a261a5b9e779585f46e1e07',
        'af881c54bd8dc2b8dba024b3939ebce13f9394287282f13017c89b99786d586ca5ea71a215caae44041a646689f386c4047ed656bab0cda980',
        '18923a6ce396d90cdfe147ee8c01f3f94cd4b8a6ebf9a49f33339e4e76b1d8b325800c474e1b904e913a6277c33024778d2e33d5106b051900',
        'bca27341df8ecd9c6be51cef237d13aa0caf86c1ea1eccb382c10b480b89d7b12a2c3f3b575f002a2c0baf015c41bd1adf023d103dce8e1700',
        false,
        true
      ],

      // (2, 2)
      [
        '66fe3f2570c564837d4877ebbc4acbf19e83af3f68c904ab751b2a3dd6578fdc7e9f1b6626f6b0ef5bf653a2fd97d41b214c38cf022d74aa59',
        'b85a45f025d112bc923942842ffb548539cb99afa2f8bf727486cc053667452c016ceef72f6695fae2d2e98b1bd2c0ad1c106e112cab924c00',
        '1579a45a05056bb4f8e3f40b7710b55c5f23c35f98efefb8cdf8e2666a96c23ca7fa2c8b7c1003a5cf64695db0e0eb95617f165ebaa7633a00',
        '4e7d7ab89f6938959bb4ee9b7aded93c596e758feae5c910055cd5f1c577df04f7871837b0b6ba2210918284a6aa588c88be8f40e55d82dd80',
        false,
        true
      ]
    ];

    const vectors = [];

    for (const [m, r, s, p, r1, r2] of json) {
      const msg = Buffer.from(m, 'hex');
      const sig = Buffer.from(r + s, 'hex');
      const pub = Buffer.from(p, 'hex');

      vectors.push([msg, sig, pub, r1, r2]);
    }

    const batch = [];

    for (const [msg, sig, pub,, res2] of vectors) {
      assert.strictEqual(ed448.verify(msg, sig, pub), res2);
      assert.strictEqual(ed448.verifySingle(msg, sig, pub), res2);

      batch.push([msg, sig, pub]);
    }

    batch.sort(() => Math.random() > 0.5 ? 1 : -1);

    assert.strictEqual(ed448.verifyBatch(batch), true);
  });

  it('should reject non-canonical R value', () => {
    const json = [
      '3dea88afc3a2802ef17ba72a90c512924902de5777df89a9ff7a4dd580e84fbc25bf33fa7b03e21002391a07ea170f57bd8b1b888ed2c3b568',
      '7a49c363d75f51ad32fa5952631e30285bbc954b1ed44612e23dba86d7430a6e398912fc88f6d3fabfbe05971aa5f11098b87eac97a8664c01',
      '07fa7072b4eab22219df35fffb85c91d1e67079d44e2aa8dee7d03dba792ff8309815efcab7ee04931790975854105d94f16beac4f67cb1500',
      'a675030aaf9ffcf7cd49d415b70582b08963b7ae22af601ed61436815164b91d10f86e9a8276d6f5a8a99f3c557eee161dd85ed2a5ab8b4700'
    ];

    const [m, r, s, p] = json;
    const msg = Buffer.from(m, 'hex');
    const sig = Buffer.from(r + s, 'hex');
    const pub = Buffer.from(p, 'hex');

    assert.strictEqual(ed448.verify(msg, sig, pub), false);
    assert.strictEqual(ed448.verifySingle(msg, sig, pub), false);
  });

  it('should reject non-canonical S value', () => {
    const json = [
      'd5158e4e16d9ea0d584245abcde079bdbdaa6658a30fc4ed7ae23bebe364037ade875736879557b00cbe19f2d53979e336882bff5f3390547d',
      'bbad6011448fc0f16527340aa35ff00ffd621b6b4035a3315f404e5294ee9159526617153801c8e8dfd939475d945f689d3a4e2b642be45900',
      '0e2284ac9848c25e0efa26971fd79c514c6e076dc824fb63ebda9cf8a363916bf023eeea94f9f28b8c109937ce1a6dd32e0775b59e39d14100',
      '1eb228ad82bf5d96c4c5f197169d4131de8732df5ce5b22dd9e9e1b9b3ed7417071e840a7582fc6b366ede96c9b7d79e066e963098c4402380'
    ];

    const [m, r, s, p] = json;
    const msg = Buffer.from(m, 'hex');
    const sig = Buffer.from(r + s, 'hex');
    const pub = Buffer.from(p, 'hex');

    assert.strictEqual(ed448.verify(msg, sig, pub), false);
    assert.strictEqual(ed448.verifySingle(msg, sig, pub), false);
  });

  it('should reject non-canonical key', () => {
    const json = [
      '1e9b34e04e51dd6da9c0dbcb7509d4408f25da9b47afa2734d36e6a7a40a3283e52e98e4f5e77fe07d0ba997aadb95cd78bb8dc3a1b1cc298c',
      '0b45ed34130a4966033f99ccf1d20d53031a147d6a55dabc9d8c65398e381a951cba6a47a591fb42abad1c6b446dc60cb8c81d9acc43fe5880',
      'efea554ad7a2b66e696f9382dcbd08aa6c7d65ab04d1fa41ac91c50c7a18b7b353e2bfac2a2414feb2f2084a5c17a513f5f877480b6cb63000',
      'a6e5c2c10b05a26c7502d3d1d7e5e59e9c96d9fe5151be56d8ccd429e97501a48f4f6f18d15c6fe244569672f789c290b2cb6dffec255f6100'
    ];

    const [m, r, s, p] = json;
    const msg = Buffer.from(m, 'hex');
    const sig = Buffer.from(r + s, 'hex');
    const pub = Buffer.from(p, 'hex');

    assert.strictEqual(ed448.verify(msg, sig, pub), false);
    assert.strictEqual(ed448.verifySingle(msg, sig, pub), false);
  });

  it('should expand key', () => {
    const secret = Buffer.from(''
      + 'a18d4e50f52e78a24e68288b3496'
      + 'd8881066a65b970ded82aac98b59'
      + '8d062648daf289640c830e9098af'
      + '286e8d1a19c7a1623c05d817d78c'
      + '3d', 'hex');

    const [key, prefix] = ed448.privateKeyExpand(secret);

    assert.bufferEqual(key, ''
      + '041a89beaebf4c118b34b4aa66afa8a150c464ca9c3eb46b15c599e4'
      + '3a9439e9131cd01b2c146d8b47d0d590f3938887db82e1334d43b9f2',
      'hex');

    assert.bufferEqual(prefix, '26'
      + 'a3b2541854b72b95c11775490069c50c5ccf64d94ae3648221a7c254'
      + '539834d04102266838a5c75ca340d885a3c318acc0f7dd6b5e398dbb',
      'hex');

    assert.bufferEqual(ed448.privateKeyConvert(secret), key);
  });

  it('should do ECDH', () => {
    const alicePriv = ed448.privateKeyGenerate();
    const alicePub = ed448.publicKeyCreate(alicePriv);

    const bobPriv = ed448.privateKeyGenerate();
    const bobPub = ed448.publicKeyCreate(bobPriv);

    const aliceSecret = ed448.derive(bobPub, alicePriv);
    const bobSecret = ed448.derive(alicePub, bobPriv);

    assert.bufferEqual(aliceSecret, bobSecret);

    const secret = aliceSecret;
    const xsecret = ed448.publicKeyConvert(secret);
    const xalicePub = ed448.publicKeyConvert(alicePub);
    const xbobPub = ed448.publicKeyConvert(bobPub);

    assert.notBufferEqual(xsecret, secret);

    const xaliceSecret = ed448.exchange(xbobPub, alicePriv);
    const xbobSecret = ed448.exchange(xalicePub, bobPriv);

    assert.bufferEqual(xaliceSecret, xsecret);
    assert.bufferEqual(xbobSecret, xsecret);
  });

  it('should do ECDH (with scalar)', () => {
    const aliceSeed = ed448.privateKeyGenerate();
    const alicePriv = ed448.privateKeyConvert(aliceSeed);
    const alicePub = ed448.publicKeyFromScalar(alicePriv);

    assert.bufferEqual(alicePub, ed448.publicKeyCreate(aliceSeed));

    const bobSeed = ed448.privateKeyGenerate();
    const bobPriv = ed448.privateKeyConvert(bobSeed);
    const bobPub = ed448.publicKeyFromScalar(bobPriv);

    assert.bufferEqual(bobPub, ed448.publicKeyCreate(bobSeed));

    const aliceSecret = ed448.deriveWithScalar(bobPub, alicePriv);
    const bobSecret = ed448.deriveWithScalar(alicePub, bobPriv);

    assert.bufferEqual(aliceSecret, bobSecret);

    const xalicePub = ed448.publicKeyConvert(alicePub);
    const xbobPub = ed448.publicKeyConvert(bobPub);

    const xaliceSecret = ed448.exchangeWithScalar(xbobPub, alicePriv);
    const xbobSecret = ed448.exchangeWithScalar(xalicePub, bobPriv);

    assert.bufferEqual(xaliceSecret, xbobSecret);
  });

  it('should do ECDH (vector)', () => {
    const pub = Buffer.from(''
      + '93890d139f2e5fedfdaa552aae92'
      + 'e5cc5c716719c28a2e2273962d10'
      + 'a83fc02f0205b1e2478239e4a267'
      + 'f5edd9489a3556f48df899424b4b'
      + '00', 'hex');

    const priv = Buffer.from(''
      + 'a18d4e50f52e78a24e68288b3496'
      + 'd8881066a65b970ded82aac98b59'
      + '8d062648daf289640c830e9098af'
      + '286e8d1a19c7a1623c05d817d78c'
      + '3d', 'hex');

    const xsecret = Buffer.from(''
      + 'e198182f06c67c8fe5e080088d5c'
      + '5b23be7c46782ed24774feeba6fb'
      + '37536ada82b71564818fa3df6af8'
      + '22af3dd09dd0529518b42a3d9655', 'hex');

    const secret2 = ed448.derive(pub, priv);
    const xsecret2 = ed448.publicKeyConvert(secret2);

    assert.notBufferEqual(secret2, xsecret);
    assert.bufferEqual(xsecret2, xsecret);

    const xpub = ed448.publicKeyConvert(pub);
    const xsecret3 = ed448.exchange(xpub, priv);

    assert.bufferEqual(xsecret3, xsecret);
  });

  it('should generate keypair and sign with additive tweak', () => {
    const key = ed448.privateKeyGenerate();
    const pub = ed448.publicKeyCreate(key);
    const tweak = ed448.scalarGenerate();
    const msg = random.randomBytes(57);
    const child = ed448.publicKeyTweakAdd(pub, tweak);
    const sig = ed448.signTweakAdd(msg, key, tweak);

    assert(ed448.scalarVerify(tweak));
    assert.notBufferEqual(child, pub);

    const childPriv = ed448.scalarTweakAdd(ed448.privateKeyConvert(key), tweak);
    const childPub = ed448.publicKeyFromScalar(childPriv);

    assert.bufferEqual(childPub, child);

    assert(ed448.verify(msg, sig, child));

    const sig2 = ed448.signWithScalar(msg, childPriv, msg);

    assert(ed448.verify(msg, sig2, child));

    const real = ed448.scalarReduce(ed448.privateKeyConvert(key));
    const parent = ed448.scalarTweakAdd(childPriv, ed448.scalarNegate(tweak));

    assert.bufferEqual(parent, real);

    const tweakPub = ed448.publicKeyFromScalar(tweak);
    const parentPub = ed448.publicKeyAdd(childPub, ed448.publicKeyNegate(tweakPub));

    assert.bufferEqual(parentPub, pub);
  });

  it('should generate keypair and sign with multiplicative tweak', () => {
    const key = ed448.privateKeyGenerate();
    const pub = ed448.publicKeyCreate(key);
    const tweak = ed448.scalarGenerate();
    const msg = random.randomBytes(57);
    const child = ed448.publicKeyTweakMul(pub, tweak);

    assert(ed448.scalarVerify(tweak));
    assert.notBufferEqual(child, pub);

    const sig = ed448.signTweakMul(msg, key, tweak);

    const childPriv = ed448.scalarTweakMul(ed448.privateKeyConvert(key), tweak);
    const childPub = ed448.publicKeyFromScalar(childPriv);

    assert.bufferEqual(childPub, child);

    assert(ed448.verify(msg, sig, child));

    const sig2 = ed448.signWithScalar(msg, childPriv, msg);

    assert(ed448.verify(msg, sig2, child));

    const real = ed448.scalarReduce(ed448.privateKeyConvert(key));
    const parent = ed448.scalarTweakMul(childPriv, ed448.scalarInvert(tweak));

    assert.bufferEqual(parent, real);
  });

  it('should generate keypair and sign with multiplicative tweak * cofactor', () => {
    const cofactor = Buffer.alloc(56, 0x00);
    cofactor[0] = 4;

    const key = ed448.privateKeyGenerate();
    const pub = ed448.publicKeyCreate(key);
    const tweak_ = ed448.scalarGenerate();
    const msg = random.randomBytes(57);
    const tweak = ed448.scalarTweakMul(tweak_, cofactor);
    const child = ed448.publicKeyTweakMul(pub, tweak);
    const child_ = ed448.publicKeyTweakMul(
      ed448.publicKeyTweakMul(pub, tweak_),
      cofactor);

    assert.bufferEqual(child, child_);
    assert(ed448.scalarVerify(tweak_));
    assert.notBufferEqual(child, pub);

    const sig = ed448.signTweakMul(msg, key, tweak);

    const childPriv = ed448.scalarTweakMul(ed448.privateKeyConvert(key), tweak);
    const childPub = ed448.publicKeyFromScalar(childPriv);

    assert.bufferEqual(childPub, child);

    assert(ed448.verify(msg, sig, child));

    const sig2 = ed448.signWithScalar(msg, childPriv, msg);

    assert(ed448.verify(msg, sig2, child));
  });

  it('should modulo scalar', () => {
    const scalar0 = Buffer.alloc(0);
    const mod0 = ed448.scalarReduce(scalar0);

    assert.bufferEqual(mod0, ''
      + '00000000000000000000000000000000000000000000000000000000'
      + '00000000000000000000000000000000000000000000000000000000',
      'hex');

    const scalar1 = Buffer.alloc(1, 0x0a);
    const mod1 = ed448.scalarReduce(scalar1);

    assert.bufferEqual(mod1, ''
      + '0a000000000000000000000000000000000000000000000000000000'
      + '00000000000000000000000000000000000000000000000000000000',
      'hex');

    const scalar2 = Buffer.alloc(56, 0xff);
    const mod2 = ed448.scalarReduce(scalar2);

    assert.bufferEqual(mod2, ''
      + '33ec9e52b5f51c72abc2e9c835f64c7abf25a744d992c4ee5870d70c'
      + '02000000000000000000000000000000000000000000000000000000',
      'hex');

    const scalar3 = Buffer.alloc(57, 0xff);

    scalar3[56] = 0x0a;

    const mod3 = ed448.scalarReduce(scalar3);

    assert.bufferEqual(mod3, mod2);
  });

  it('should convert to montgomery (vector)', () => {
    const pub = Buffer.from(''
      + '3167a5f7ce692bcf3af9094f792c'
      + 'b3618ea034371703a3ffd222254e'
      + '6edba0156aa236c2b3ef406e700c'
      + '55a0beff8e141348cfd354682321'
      + '00', 'hex');

    const xpub = Buffer.from(''
      + '5c8ae0100ddb3f5320924bef698c'
      + 'd78fa7456b6d9b5af66a9a99b5d2'
      + 'a7f7e789a81e2f539b24c69bdf4f'
      + '4f1cfcb881a5e9205e21ca27ff25', 'hex');

    const xpub2 = ed448.publicKeyConvert(pub);

    assert.bufferEqual(xpub2, xpub);
  });

  it.skip('should convert to montgomery and back', () => {
    const secret = ed448.privateKeyGenerate();
    const pub = ed448.publicKeyCreate(secret);
    const sign = (pub[56] & 0x80) !== 0;
    const xpub = ed448.publicKeyConvert(pub);
    const pub2 = ed448.publicKeyDeconvert(xpub, sign);

    assert.bufferEqual(pub2, pub);
  });

  it('should sign and verify (vector)', () => {
    const priv = Buffer.from(''
      + 'd65df341ad13e008567688baedda8e9d'
      + 'cdc17dc024974ea5b4227b6530e339bf'
      + 'f21f99e68ca6968f3cca6dfe0fb9f4fa'
      + 'b4fa135d5542ea3f01',
      'hex');

    const pub = Buffer.from(''
      + 'df9705f58edbab802c7f8363cfe5560a'
      + 'b1c6132c20a9f1dd163483a26f8ac53a'
      + '39d6808bf4a1dfbd261b099bb03b3fb5'
      + '0906cb28bd8a081f00',
      'hex');

    const msg = Buffer.from(''
      + 'bd0f6a3747cd561bdddf4640a332461a'
      + '4a30a12a434cd0bf40d766d9c6d458e5'
      + '512204a30c17d1f50b5079631f64eb31'
      + '12182da3005835461113718d1a5ef944',
      'hex');

    const sig = Buffer.from(''
      + '554bc2480860b49eab8532d2a533b7d5'
      + '78ef473eeb58c98bb2d0e1ce488a98b1'
      + '8dfde9b9b90775e67f47d4a1c3482058'
      + 'efc9f40d2ca033a0801b63d45b3b722e'
      + 'f552bad3b4ccb667da350192b61c508c'
      + 'f7b6b5adadc2c8d9a446ef003fb05cba'
      + '5f30e88e36ec2703b349ca229c267083'
      + '3900',
      'hex');

    const pub2 = ed448.publicKeyCreate(priv);

    assert.bufferEqual(pub2, pub);

    const sig2 = ed448.sign(msg, priv);

    assert.bufferEqual(sig2, sig);

    const result = ed448.verify(msg, sig, pub);

    assert.strictEqual(result, true);
  });

  describe('RFC 8032 vectors', () => {
    const batch = [];

    for (const [i, vector] of rfc8032.entries()) {
      if (!vector.algorithm.startsWith('Ed448'))
        continue;

      const ph = vector.algorithm === 'Ed448ph';
      const ctx = vector.ctx != null
                ? Buffer.from(vector.ctx, 'hex')
                : null;

      let msg = Buffer.from(vector.msg, 'hex');

      if (ph)
        msg = SHAKE256.digest(msg, 64);

      const sig = Buffer.from(vector.sig, 'hex');
      const pub = Buffer.from(vector.pub, 'hex');
      const priv = Buffer.from(vector.priv, 'hex');

      if (ph === false && ctx === null)
        batch.push([msg, sig, pub]);

      it(`should pass RFC 8032 vector (${vector.algorithm} #${i})`, () => {
        assert(ed448.privateKeyVerify(priv));
        assert(ed448.publicKeyVerify(pub));

        const sig_ = ed448.sign(msg, priv, ph, ctx);

        assert.bufferEqual(sig_, sig);

        assert(ed448.verify(msg, sig, pub, ph, ctx));
        assert(!ed448.verify(msg, sig, pub, !ph, ctx));

        if (msg.length > 0) {
          const msg_ = Buffer.from(msg);
          msg_[i % msg_.length] ^= 1;
          assert(!ed448.verify(msg_, sig, pub, ph, ctx));
          assert(!ed448.verifyBatch([[msg_, sig, pub]], ph, ctx));
        }

        {
          const sig_ = Buffer.from(sig);
          sig_[i % sig_.length] ^= 1;
          assert(!ed448.verify(msg, sig_, pub, ph, ctx));
        }

        {
          const pub_ = Buffer.from(pub);
          pub_[i % pub_.length] ^= 1;
          assert(!ed448.verify(msg, sig, pub_, ph, ctx));
        }

        if (ctx && ctx.length > 0) {
          const ctx_ = Buffer.from(ctx);
          ctx_[i % ctx_.length] ^= 1;
          assert(!ed448.verify(msg, sig, pub, ph, ctx_));
          assert(!ed448.verify(msg, sig, pub, ph, null));
        } else {
          const ctx_ = Buffer.alloc(1);
          assert(!ed448.verify(msg, sig, pub, true, ctx_));
          assert(!ed448.verify(msg, sig, pub, false, ctx_));
        }
      });
    }

    it('should do batch verification', () => {
      const [msg] = batch[0];

      assert.strictEqual(ed448.verifyBatch([]), true);
      assert.strictEqual(ed448.verifyBatch(batch), true);

      if (msg.length > 0) {
        msg[0] ^= 1;
        assert.strictEqual(ed448.verifyBatch(batch), false);
        msg[0] ^= 1;
      }
    });
  });

  it('should test serialization formats', () => {
    const priv = ed448.privateKeyGenerate();
    const pub = ed448.publicKeyCreate(priv);
    const rawPriv = ed448.privateKeyExport(priv);
    const rawPub = ed448.publicKeyExport(pub);

    assert.bufferEqual(ed448.privateKeyImport(rawPriv), priv);
    assert.bufferEqual(ed448.publicKeyImport(rawPub), pub);

    const jsonPriv = ed448.privateKeyExportJWK(priv);
    const jsonPub = ed448.publicKeyExportJWK(pub);

    assert.bufferEqual(ed448.privateKeyImportJWK(jsonPriv), priv);
    assert.bufferEqual(ed448.publicKeyImportJWK(jsonPub), pub);

    const asnPriv = ed448.privateKeyExportPKCS8(priv);
    const asnPub = ed448.publicKeyExportSPKI(pub);

    assert.bufferEqual(ed448.privateKeyImportPKCS8(asnPriv), priv);
    assert.bufferEqual(ed448.publicKeyImportSPKI(asnPub), pub);
  });
});
