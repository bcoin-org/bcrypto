'use strict';

const assert = require('bsert');
const random = require('../lib/random');
const ed448 = require('../lib/ed448');
const x448 = require('../lib/x448');
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

  it('should allow points at infinity', () => {
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

    assert(ed448.publicKeyVerify(inf));
    assert(ed448.publicKeyIsInfinity(inf));
    assert(ed448.scalarIsZero(sig.slice(57, 57 + 56)));
    assert(ed448.verify(msg, sig, inf));
  });

  it('should fail to validate malleated keys', () => {
    // x = 0, y = 1, sign = 1
    const hex1 = '0100000000000000000000000000'
               + '0000000000000000000000000000'
               + '0000000000000000000000000000'
               + '000000000000000000000000000080';

    // x = 0, y = -1, sign = 1
    const hex2 = 'feffffffffffffffffffffffffff'
               + 'ffffffffffffffffffffffffffff'
               + 'feffffffffffffffffffffffffff'
               + 'ffffffffffffffffffffffffffff80';

    const key1 = Buffer.from(hex1, 'hex');
    const key2 = Buffer.from(hex2, 'hex');

    assert(!ed448.publicKeyVerify(key1));
    assert(!ed448.publicKeyVerify(key2));

    key1[56] &= ~0x80;
    key2[56] &= ~0x80;

    assert(ed448.publicKeyVerify(key1));
    assert(ed448.publicKeyVerify(key2));
  });

  it('should test scalar zero', () => {
    // n = 0
    const hex1 = 'f34458ab92c27823558fc58d72c2'
               + '6c219036d6ae49db4ec4e923ca7c'
               + 'ffffffffffffffffffffffffffff'
               + 'ffffffffffffffffffffffffff3f';

    // n - 1 = -1
    const hex2 = 'f24458ab92c27823558fc58d72c2'
               + '6c219036d6ae49db4ec4e923ca7c'
               + 'ffffffffffffffffffffffffffff'
               + 'ffffffffffffffffffffffffff3f';

    assert(ed448.scalarIsZero(Buffer.alloc(56, 0x00)));
    assert(!ed448.scalarIsZero(Buffer.alloc(56, 0x01)));

    assert(ed448.scalarIsZero(Buffer.from(hex1, 'hex')));
    assert(!ed448.scalarIsZero(Buffer.from(hex2, 'hex')));
  });

  it('should validate small order points', () => {
    const small = [
      // 0, c (order 1)
      ['01000000000000000000000000000000000000000000000000000000',
       '0000000000000000000000000000000000000000000000000000000000'].join(''),
      // 0, -c (order 2, rejected)
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

      assert(ed448.publicKeyVerify(pub));
      assert.throws(() => ed448.deriveWithScalar(pub, key));
    }
  });

  it('should test small order points', () => {
    const small = [
      // 0, c (order 1)
      ['01000000000000000000000000000000000000000000000000000000',
       '0000000000000000000000000000000000000000000000000000000000'].join(''),
      // 0, -c (order 2, rejected)
      ['feffffffffffffffffffffffffffffffffffffffffffffffffffffff',
       'feffffffffffffffffffffffffffffffffffffffffffffffffffffff00'].join(''),
      // c, 0 (order 4)
      ['00000000000000000000000000000000000000000000000000000000',
       '0000000000000000000000000000000000000000000000000000000080'].join(''),
      // -c, 0 (order 4)
      ['00000000000000000000000000000000000000000000000000000000',
       '0000000000000000000000000000000000000000000000000000000000'].join('')
    ];

    {
      const pub = Buffer.from(small[0], 'hex');

      assert(ed448.publicKeyIsInfinity(pub));
      assert(!ed448.publicKeyIsSmall(pub));
      assert(!ed448.publicKeyHasTorsion(pub));
    }

    for (let i = 1; i < small.length; i++) {
      const str = small[i];
      const pub = Buffer.from(str, 'hex');

      assert(!ed448.publicKeyIsInfinity(pub));
      assert(ed448.publicKeyIsSmall(pub));
      assert(ed448.publicKeyHasTorsion(pub));
    }

    {
      const priv = ed448.privateKeyGenerate();
      const pub = ed448.publicKeyCreate(priv);

      assert(!ed448.publicKeyIsInfinity(pub));
      assert(!ed448.publicKeyIsSmall(pub));
      assert(!ed448.publicKeyHasTorsion(pub));
    }
  });

  it('should validate signatures with small order points', () => {
    const json = [
      // (-1, -1)
      [
        '56d69147eb80b6d3c1a909aa74286ee8e69729152de2ffb1cf10670b6893e8e8e0f22d85144c3073ef0d3dac36577eaaae42d7d9f65b6d6e05',
        '010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        '010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        true,
        true
      ],

      // (-1, -1)
      [
        '56d69147eb80b6d3c1a909aa74286ee8e69729152de2ffb1cf10670b6893e8e8e0f22d85144c3073ef0d3dac36577eaaae42d7d9f65b6d6e05',
        '010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        'df9705f58edbab802c7f8363cfe5560ab1c6132c20a9f1dd163483a26f8ac53a39d6808bf4a1dfbd261b099bb03b3fb50906cb28bd8a081f00',
        false,
        false
      ],

      // (0, 0)
      [
        '56d69147eb80b6d3c1a909aa74286ee8e69729152de2ffb1cf10670b6893e8e8e0f22d85144c3073ef0d3dac36577eaaae42d7d9f65b6d6e05',
        'fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff00',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        'fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff00',
        true,
        true
      ],

      // (0, 1)
      [
        '8e1ea3e1a3fc6849154b8def1158c3112c89027eafe01e0f81ca0c62abbad6f110c72bc6be497a3eedda1b558f296326b385f56a7d1ce7e6bc',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        'fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff00',
        false,
        true
      ],

      // (1, 0)
      [
        '8e1ea3e1a3fc6849154b8def1158c3112c89027eafe01e0f81ca0c62abbad6f110c72bc6be497a3eedda1b558f296326b385f56a7d1ce7e6bc',
        'fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff00',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080',
        true,
        true
      ],

      // (1, 1)
      [
        'c9e836c4fb92425ab41261ef55a9ca7187fa31278ebf5a73101542298ec49e8102b3d554abc9bdcf35f5c7bea7ea48e960cc41ef694d08cd39',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080',
        false,
        true
      ],

      // (1, 2)
      [
        'd131c7443a0fe4389c1e81db609b1098ddb2716d80507c696b6c44b7989db3a218e635ce9214bb1fa3e438e2733a107d3f90f16fbecf6f564f',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080',
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

      if (res2)
        batch.push([msg, sig, pub]);
    }

    batch.sort(() => Math.random() > 0.5 ? 1 : -1);

    assert.strictEqual(ed448.verifyBatch(batch), true);
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
      assert(!ed448.publicKeyIsSmall(pub));
      assert(ed448.publicKeyHasTorsion(pub));

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

    const xaliceSecret = x448.derive(xbobPub,
      ed448.privateKeyConvert(alicePriv));

    const xbobSecret = x448.derive(xalicePub,
      ed448.privateKeyConvert(bobPriv));

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

    const xaliceSecret = x448.derive(xbobPub, alicePriv);
    const xbobSecret = x448.derive(xalicePub, bobPriv);

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
    const xsecret3 = x448.derive(xpub, ed448.privateKeyConvert(priv));

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

  it('should convert to montgomery and back', () => {
    const secret = ed448.privateKeyGenerate();
    const pub = ed448.publicKeyCreate(secret);
    const sign = (pub[56] & 0x80) !== 0;
    const xpub = ed448.publicKeyConvert(pub);
    const pub2 = x448.publicKeyConvert(xpub, sign);

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

  it('should do elligator2 (edwards)', () => {
    const u1 = Buffer.from(''
      + '72ad074f3dbfbb3927125fab1f4023a408adc0ab1cbbbd6556615e3d'
      + '67501a428120ac1556a467734b1ad6820734d2100f0ed88510bd3e14', 'hex');

    const p1 = ed448.publicKeyFromUniform(u1);

    assert.bufferEqual(p1, ''
      + '133bf6517c0375c17d1e6d6bd715f6d58050bfe3dc571248628a0b19'
      + '39ac87ac79524363b120b449aa107ab2159476946a584878247bb76c00', 'hex');

    const u2 = ed448.publicKeyToUniform(p1);
    const p2 = ed448.publicKeyFromUniform(u2);
    const u3 = ed448.publicKeyToUniform(p2);
    const p3 = ed448.publicKeyFromUniform(u3);

    assert.bufferEqual(p1, p2);
    assert.bufferEqual(p2, p3);
  });

  it('should do elligator2 (mont)', () => {
    const u1 = Buffer.from(''
      + '72ad074f3dbfbb3927125fab1f4023a408adc0ab1cbbbd6556615e3d'
      + '67501a428120ac1556a467734b1ad6820734d2100f0ed88510bd3e14', 'hex');

    const p1 = x448.publicKeyFromUniform(u1);

    assert.bufferEqual(p1, ''
      + '6bd0c1ee9599249bff3276e2a8279bea5e62e47f6507656826fe0182'
      + '3a0580129b6df46dabe81c7559a7028344b50da7682423586d6e80dd');

    const u2 = x448.publicKeyToUniform(p1);
    const p2 = x448.publicKeyFromUniform(u2);
    const u3 = x448.publicKeyToUniform(p2);
    const p3 = x448.publicKeyFromUniform(u3);

    assert.bufferEqual(p1, p2);
    assert.bufferEqual(p2, p3);
  });

  it('should test elligator2 exceptional case (r=1)', () => {
    const u1 = Buffer.alloc(56, 0x00);

    u1[0] = 1;

    const p1 = x448.publicKeyFromUniform(u1);

    assert.bufferEqual(p1, Buffer.alloc(56, 0x00));

    const u2 = x448.publicKeyToUniform(p1, 1);
    const p2 = x448.publicKeyFromUniform(u2);
    const u3 = x448.publicKeyToUniform(p2, 1);
    const p3 = x448.publicKeyFromUniform(u3);

    assert.bufferEqual(p1, p2);
    assert.bufferEqual(p2, p3);
  });

  it('should pass elligator2 test vectors', () => {
    const preimages = [
      'deb6f5f0d785cb257e6cf0b29e965b503c5cecb9cdf23e5607963fb1',
      '10bc30b36562432b96dfadcb9e17bae7141651018d0d650c9eda61c4',
      '0429c0b5709bc67651a06d74768924d38040b69b0d7d8d71c9987ad6',
      'fa415cd547400348dbf823e29a291d1c353d82b7ec30607e3104ab24',
      '51407d4284c76c2d3b395e22224db763a395f7d41574435da8644103',
      'eb95432d09d74e007b36d7f6260dc4bc4115b38d02f3e9e9be78ca09',
      'eb124097d35525aa1ab0a5dbb528a5fdc03c6bf7cfca613f8e336dd4',
      '1419cf77ac5e461239b1ee0dd1a1dba49cb5a6adeb9771c92b0191ee',
      'df7d05ae360d9de456b7459f1314ee02b1fa04881d7aadb0ad6590a4',
      '461e45384fc1bcd448da76f6f8dd0285e326cb388e3ab4d9cfa96af7',
      'b5a6620ec84e94ecc25459c39f5bead24cd5419371ff1dfe71f1bc57',
      '4f334819236b0c787589a85ba17e738b099d1e5cd4a195bda4f7fd67',
      '433fc294d604649fccbfec82940875f56efa26eb5bc3f722783aa919',
      '4286873a3e46dcc19c06d04b2c5f0b9c4b27d62f59749a04e0804c1e',
      'f0bdc9fc2e602f774ec57f7629ec2c77611f3365570256c5786679c1',
      '4b6f2388da909f22b17568266f6ff43545d5d4f06679de80544a4440',
      '2222c0366c871892da27582a84b1d7fbdcb0f2bd905dbf2345eeab41',
      'cd3b6080f0b68c7765520b734653a4cd95f98aa63709621b31a0d613',
      'bd9ff88f0062c59efd123fadf6b9fa7d357017d72620b9191fb50888',
      'cc6059cfe024033359481a803173928885d1da5d6268e23e818e4660',
      '091f0a3253605b73d90547c2ad02b7062d0401e3ff29078c3eb37d87',
      '187c4e6c5d8e6c495fba1399c2fc045faac018fe04948bd2f4c9d4dc',
      'c04b55ecf79b25dbf1a92c8f11e6b3a476866f84ae476d2a8b3ea50d',
      '5659a498512060f5e8fdcbd2b607776f423824109437eb4ecfcf5698',
      '1a3a0ff91e2b9faf6fb96ecf91b3caf495b2d1a7b90c0c184c47c07e',
      '3a8b52a50a887f397fe3649a89b098a7e5256158f04aa151cd994c36',
      'd90908072e287265b2a77cfbf6f75e91b52066f9a24fd034c045039a',
      '5dce7b970cea5b8b3f32a955bde2dd958791163966f6e150d0ee72ab',
      '513b5f6db4a3de086e1c21f453c6632113ab94a35b14ce5819e0196d',
      '152a8fe89dec8accf2db31e79c143deffe8491c2cee85a4d49431bbd',
      'bf34ff224c03983440f8e8f1d11023ebc3fc4594dfb9ff05bc3ffca8',
      'd0d2c48d818bbfb73b3fab274bfa095bd5992b2c452256b8fddd9a87'
    ];

    const keys = [
      '8142c17ef976faa69acffb5d4b12e3f0c1d665fa75a1fbcbb8075007',
      'abc2e7e9a52bca4ac6160070c1959c42346d89bb58dc6e2877006c9180',
      '0c09a848bc51bade99466e4ad34dea748ac354400cd933f38f095c6c',
      '88aa2a2006bd699f65c1df456ed2b4ed2d4739cd6f03e2fcfc46fa0780',
      'b659693f2165507597572408f1644d5737004ead65c855d5f7ad6660',
      '5b2b42482676eb5470fa1ffbd38d5f0eb03dc39baf35654fd7cdd75400',
      '2e20a2bb173cb3b436f64da59ef30d96857953a605e95e4c395e62f0',
      '23eecc2353edd5844de1ce1bf751a6140297bed68f2263324572f4a080',
      '900d0d275ff1f7c81993093c394161f019530489fb9005003425863d',
      'dae75156dd1c4364aa6c752a8aa9cb71d1a82c52bd2aa40c019672e600',
      '030e6c3c85ae39580da625ab17e8edea903357dbc9ea5d93f14025e6',
      'e0fa619185961e127adbf9d6a68dc7f6d5e9f1ca0968ee2c8e6a4efc00',
      '515915972ee730a1275339b77df637a2f71c913ac2cadc6480df3888',
      '7a610eba8812f6cd46d3fb3f9f1b1d00c9f1bd8ecc0f588a6c1b193480',
      'f76649315c07df3803504ec9f6d140d5363f1c130f7db4a295c666a1',
      '5acd4e42e70ec1e43e9ffd0bf143b5f628a52d95db65a42fa988bc3f00',
      '46427899cddfe26dd8833b6cea5be4d563509f0b284aa80bc6e2f682',
      '226dc4b90eeb15f92e14bb8a5c1698e9be738c0466f4b9cdb19c8ec580',
      '64c59e41155bb18193955a49dd23e0e5b8c47657c4dde9aeeb46bf1f',
      '149c663fb38b22762307b9d80de3defaac407c558ddef4b65f16fcb300',
      'e42f29a0a2e9548a6ab382b263497c9a1a326f9cd3e9f4b78850bdcc',
      '427f432ec904fc4c7b06faca9b24188bb4e763e47483d9792191c43f80',
      '1c958b27f4d20f458e2de793af7f8d4c4a05c1e1993fb4561a979f7a',
      '16c7e2bdc2293ff8827f6a3e0200392ff601c74eb721d6ea79a1ab4980',
      '4578bb7d6b671d2a82a276abbf37b082a9361adac641cc701fad5680',
      'bf810144f675575b6b416518094f54e2b8e335b4d32b3adc859d9d7f80',
      'c2651320d1f3f7b428007c0bb41e035ae0f199ea502a9855811b3a46',
      '152c6b849cb92f03d6521bf430d9ee7e0853e91a4ca8d86510b83e3e00',
      'bd24627bb398d910ef77224f015255a618595ddd7e1a476fd96f441d',
      'c4271dc45a48d6ebf69c2f47bad175b2a2ec25b40b7eab25b798df8e80',
      'b3517475f3deb74d0ffc0f1547f001f55a77d5c8b2dc26869f42d7ba',
      '7eb84ac0ee29790280410c5dcdaca333808249ae9a8ca8c04cc192e480'
    ];

    const points = [
      'c126fb8a2dc5f667c4bf96682a6691784e0fd6c862aba17f6f583fb7',
      'bb4ab0c44e2da431b56cf0dfdb1f4811c71605546a115e5e068843d1',
      'a353a22cc2603d9ed38e6b9c56ddcf04e5fef4c290a369f5a9869b86',
      '7fb763347136b5c4be1e3e2aa3ee25d143766be9af68196c328750ea',
      '01dc8771974fbfca7d79e6b399044187321c80a9d272e3a5e5776de3',
      '11d30e63057fb034804ff6d0c43a02142d7df7c286fbf35125414ad3',
      'b013d7699dc01aa9c0e11ad1890d050c84bd8d0f821e161fd15f39b3',
      'bf873e664a03411e4bba8e2ce8ab8346ae6bfbd513dc1681e8c0b4b4',
      '3b8231c490b09f918b536e2ac494e25fd60302ca943b7db2619e09b6',
      '1a7e5a227282099edaf9814bdb982b600e1fa4606ae3051160118154',
      '5a0b09e0c74cc26c3e1bf6b015344aced002392c19542cca170861dd',
      '6b8f5c29012bf087e5fd4d2fa558885d2476c337e77b7a229bc6d089',
      '455eb788fca84e2e927e2d73efe1fb9e75162c3b8ca70fbd3574e37f',
      'a567564e69c0284bb56f3b88b4e1056044f15f87369ded430647a21e',
      'ac28b03b8f4520d23e75b310ec9836f487b76e1fec2304842f70b123',
      '61aab6ba7ae8bbd09224e0e0d98ff3465220fa9c213480b898ecef57',
      '9f6454284204a841addf6ec48ec3302cec969f93f1d8c6d5b53ae22c',
      '4a95469112488ef3462a0d84152eee36c80bd224489390ee8dffed2c',
      '4a3912a90da5c2f06d8e1ded8483c7c0e9e7673e321f6abc89b579ba',
      '553eafcfcecf92138ea4193008daaadba2ded7b2fa2754f74625d513',
      '99ae842f7c39ee3bb6515479fc600d6116db23cfc85597afe7eeabb3',
      '104e78c99d8f6f695efcf5d84805618bb7aa718d6b4a7cefc168c38f',
      '44b57feb542452e1b28d13f1e63ed3955b1afb189f37c57d2dda366e',
      '83713aeb3050553a8c0ccbbcc112500eb68497d0484ad57e9554b8c3',
      '2a0400ce8fcc1de09f8da6fe46cb030d09e9ca8a8a333ab9b6f117f7',
      'db2636283cdac4a12450a203c4f8ebe7be4c1d700f09cd42983a3542',
      '7b8143bc7d7f82ecbcf005953bbc529470a8d0db373935ab00097d94',
      '03468e9c77bd40d5d7ab85a6ae2f425f46eacfe5307e53a5c2be7d4e',
      '1111ebdec50303fc82b089d4c48818578f5daf1fe959602d3467c5aa',
      'bb8790c52092e94292861f0cb9abf4d74b8649a71b45fe8eb4a3cdf7',
      '489b4b716370c99117af5abf865eac47be0ddca2d0a47039ba03e965',
      'edc6a016f56dde9ca4157d25397fb56311245b53c45611c0c432780d'
    ];

    const raws1 = [
      'deb6f5f0d785cb257e6cf0b29e965b503c5cecb9cdf23e5607963fb1',
      '10bc30b36562432b96dfadcb9e17bae7141651018d0d650c9eda61c4',
      'c4b9ea3e527dfd9ce475e28b0772a511b14bc65dccf582a14d5759db',
      'cee24a106ed8d2122a8218ceeaa65b513e1e59d51b739e020a1c8e92',
      '51407d4284c76c2d3b395e22224db763a395f7d41574435da8644103',
      'eb95432d09d74e007b36d7f6260dc4bc4115b38d02f3e9e9be78ca09',
      '03221198d1c7828cd440ecc4ab431fda2abe2300b4eaa0cf6fcae35e',
      'ebc39e38447ea5155040a7618315c65e0f784b81e82e931111f397b3',
      'd8891b0f20d321e4b0d5e19d568c5d254451ba391113db40f79bcd50',
      'a382b2ca86e537db1f81f5a6cda9b5e93a8d6318f124c67f3bddab09',
      'b5a6620ec84e94ecc25459c39f5bead24cd5419371ff1dfe71f1bc57',
      '4f334819236b0c787589a85ba17e738b099d1e5cd4a195bda4f7fd67',
      '433fc294d604649fccbfec82940875f56efa26eb5bc3f722783aa919',
      '4286873a3e46dcc19c06d04b2c5f0b9c4b27d62f59749a04e0804c1e',
      'f0bdc9fc2e602f774ec57f7629ec2c77611f3365570256c5786679c1',
      '4b6f2388da909f22b17568266f6ff43545d5d4f06679de80544a4440',
      '140bed6b453d4383b44355497e7172c70dc8adca5b4102800b7a232c',
      '3237784b150d24361cbe7996163c96ccf74e9cd06090a431d1a913b0',
      'fb3ecf5d53ae62d284820a923ce795183d4da8c46ab988395b150e3b',
      'e01ca59980e36b2af45c43c3ce48125da6a26a63b44411ae8336d6c8',
      '7189258d9314f1b70ba7390b872ad10f49de00081cd87d9515770e7f',
      'e0261e42e45353b453e6d59e553a9532663da36854b6a062c5f5bb2b',
      'c67ac39853f8e675a70af5faf82d17b4e9d6c13eedc3d4ae57cd1258',
      '2ff9e058ca70c6ae07b95d2fe35810f5f0f02556108457df6c98e749',
      '1a3a0ff91e2b9faf6fb96ecf91b3caf495b2d1a7b90c0c184c47c07e',
      '3a8b52a50a887f397fe3649a89b098a7e5256158f04aa151cd994c36',
      '083dd5ed27f2773a1f52efc2977cb5c497e924ddc54cbd4f2a32e689',
      '4682e9f58623e6ed795e192879dcadf6d7e721aeddc839e5246663c7',
      'df81fe53af987e45663a7607319346de63708e91c87642e55b28e82c',
      '2c9097f9e55a82a1cbe1785e7fdc8a7ca3911660fff5b71c982e64ca',
      'bf34ff224c03983440f8e8f1d11023ebc3fc4594dfb9ff05bc3ffca8',
      'd0d2c48d818bbfb73b3fab274bfa095bd5992b2c452256b8fddd9a87'
    ];

    const raws2 = [
      '21490a0f287a34da81930f4d6169a4afc3a31346320dc1a9f869c04e',
      'ee43cf4c9a9dbcd46920523461e84518ebe9aefe72f29af361259e3b',
      '0429c0b5709bc67651a06d74768924d38040b69b0d7d8d71c9987ad6',
      'fa415cd547400348dbf823e29a291d1c353d82b7ec30607e3104ab24',
      '51407d4284c76c2d3b395e22224db763a395f7d41574435da8644103',
      'eb95432d09d74e007b36d7f6260dc4bc4115b38d02f3e9e9be78ca09',
      '14edbf682caada55e54f5a244ad75a023fc3940830359ec071cc922b',
      'eae6308853a1b9edc64e11f22e5e245b634a595214688e36d4fe6e11',
      '2082fa51c9f2621ba948ba60eceb11fd4e05fb77e285524f529a6f5b',
      'b8e1bac7b03e432bb72589090722fd7a1cd934c771c54b2630569508',
      '4a599df137b16b133daba63c60a4152db32abe6c8e00e2018e0e43a8',
      'afccb7e6dc94f3878a7657a45e818c74f662e1a32b5e6a425b080298',
      '433fc294d604649fccbfec82940875f56efa26eb5bc3f722783aa919',
      '4286873a3e46dcc19c06d04b2c5f0b9c4b27d62f59749a04e0804c1e',
      '0f423603d19fd088b13a8089d613d3889ee0cc9aa8fda93a8799863e',
      'b390dc77256f60dd4e8a97d990900bcaba2a2b0f9986217fabb5bbbf',
      'a1261e132e406f27ea90edc8e31bcdc96baae3993bd823e218a114b0',
      'a33327999ac9ecd94efa67b7c2e6afb2bf289509ee0be39f5278c679',
      'bd9ff88f0062c59efd123fadf6b9fa7d357017d72620b9191fb50888',
      'cc6059cfe024033359481a803173928885d1da5d6268e23e818e4660',
      'f6e0f5cdac9fa48c26fab83d52fd48f9d2fbfe1c00d6f873c14c8278',
      'e683b193a27193b6a045ec663d03fba0553fe701fb6b742d0b362b23',
      'c04b55ecf79b25dbf1a92c8f11e6b3a476866f84ae476d2a8b3ea50d',
      '5659a498512060f5e8fdcbd2b607776f423824109437eb4ecfcf5698',
      '1a3a0ff91e2b9faf6fb96ecf91b3caf495b2d1a7b90c0c184c47c07e',
      '3a8b52a50a887f397fe3649a89b098a7e5256158f04aa151cd994c36',
      '083dd5ed27f2773a1f52efc2977cb5c497e924ddc54cbd4f2a32e689',
      '4682e9f58623e6ed795e192879dcadf6d7e721aeddc839e5246663c7',
      '207e01ac506781ba99c589f8ce6cb9219c8f716e3789bd1aa4d717d3',
      'd26f68061aa57d5e341e87a1802375835c6ee99f000a48e367d19b35',
      'bf34ff224c03983440f8e8f1d11023ebc3fc4594dfb9ff05bc3ffca8',
      'd0d2c48d818bbfb73b3fab274bfa095bd5992b2c452256b8fddd9a87'
    ];

    for (let i = 0; i < 32; i += 2) {
      const preimage = Buffer.from(preimages[i] + preimages[i + 1], 'hex');
      const key = Buffer.from(keys[i] + keys[i + 1], 'hex');
      const point = Buffer.from(points[i] + points[i + 1], 'hex');
      const raw1 = Buffer.from(raws1[i] + raws1[i + 1], 'hex');
      const raw2 = Buffer.from(raws2[i] + raws2[i + 1], 'hex');

      assert.strictEqual(ed448.publicKeyVerify(key), true);
      assert.bufferEqual(ed448.publicKeyFromUniform(preimage), key);
      assert.bufferEqual(x448.publicKeyFromUniform(preimage), point);
      assert.bufferEqual(ed448.publicKeyToUniform(key, i / 2), raw1);
      assert.bufferEqual(x448.publicKeyToUniform(point, i / 2), raw2);
      assert.bufferEqual(ed448.publicKeyFromUniform(raw1), key);
      assert.bufferEqual(x448.publicKeyFromUniform(raw2), point);
    }
  });

  it('should test random oracle encoding', () => {
    const bytes = SHAKE256.digest(Buffer.from('turn me into a point'), 112);
    const pub = ed448.publicKeyFromHash(bytes, true);
    const point = x448.publicKeyFromHash(bytes, true);

    assert.bufferEqual(pub, ''
      + 'a5f7d148e75933ec9c99348179d0f105a1bbffb84d2a03313e2724cf'
      + '3647e1db13c2d6c41be53ffe9e8bf53c4c2e3242ef0066260ec04bf3'
      + '00');

    assert.bufferEqual(point, ''
      + '9f3d68330e24951bdbc200ed6d25ef4e90bc678d68282af081e6204f'
      + 'c2f36dcc5d6611b41042d708caebbe80724e48d09adb9782a9a2d9ea');

    assert.strictEqual(ed448.publicKeyVerify(pub), true);
    assert.bufferEqual(ed448.publicKeyConvert(pub), point);
    assert.bufferEqual(x448.publicKeyConvert(point, false), pub);
  });

  it('should test random oracle encoding (doubling)', () => {
    const bytes0 = SHAKE256.digest(Buffer.from('turn me into a point'), 56);
    const bytes = Buffer.concat([bytes0, bytes0]);
    const pub = ed448.publicKeyFromHash(bytes, true);
    const point = x448.publicKeyFromHash(bytes, true);

    assert.bufferEqual(pub, ''
      + 'e54d0e650d175799577247b7bc9ed88628bc0123a602f9f3f4a8da17'
      + '5e49cbf33912aca9396ded8b88b46807be5325f865587092ef71bc5e'
      + '80');

    assert.bufferEqual(point, ''
      + '6fee3c18014c2c61dc1bc145c224d2b5c2e48ccbb41e007927d08435'
      + '6dd0a932c189fa810622612d982a0326760c6e74b39866bbd905f9df');

    assert.strictEqual(ed448.publicKeyVerify(pub), true);
    assert.bufferEqual(ed448.publicKeyConvert(pub), point);
    assert.bufferEqual(x448.publicKeyConvert(point, true), pub);
  });

  if (ed448.native === 2) {
    const native = ed448;
    const curve = require('../lib/js/ed448');

    it('should invert elligator (native vs. js)', () => {
      const priv = native.privateKeyGenerate();
      const pub = native.publicKeyCreate(priv);

      for (let i = 0; i < 2; i++) {
        let bytes1 = null;
        let bytes2 = null;

        try {
          bytes1 = native.publicKeyToUniform(pub, i);
        } catch (e) {
          ;
        }

        try {
          bytes2 = curve.publicKeyToUniform(pub, i);
        } catch (e) {
          ;
        }

        if (!bytes1) {
          assert(!bytes2);
          continue;
        }

        assert(bytes2);
        assert.bufferEqual(bytes1, bytes2);
        assert.bufferEqual(native.publicKeyFromUniform(bytes1), pub);
      }

      const bytes = native.publicKeyToHash(pub);

      assert.bufferEqual(native.publicKeyFromHash(bytes), pub);
    });
  }

  it('should invert elligator squared', () => {
    const priv = ed448.privateKeyGenerate();
    const pub = ed448.publicKeyCreate(priv);
    const bytes = ed448.publicKeyToHash(pub);
    const out = ed448.publicKeyFromHash(bytes);

    assert.bufferEqual(out, pub);
  });

  it('should test equivalence edge cases', () => {
    const inf = ed448.publicKeyCombine([]);
    const x = Buffer.alloc(56, 0x00);
    const e = Buffer.from('feffffffffffffffffffffffffff'
                        + 'ffffffffffffffffffffffffffff'
                        + 'feffffffffffffffffffffffffff'
                        + 'ffffffffffffffffffffffffffff00', 'hex');

    assert.bufferEqual(ed448.publicKeyConvert(e), x);
    assert.bufferEqual(x448.publicKeyConvert(x, false), inf);
    assert.throws(() => ed448.publicKeyConvert(inf));
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
