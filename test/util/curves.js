'use strict';

const elliptic = require('../../lib/js/elliptic');

const {
  ShortCurve,
  MontCurve,
  EdwardsCurve
} = elliptic;

/**
 * SECP192K1
 * https://www.secg.org/SEC2-Ver-1.0.pdf (page 12, section 2.5.1)
 * https://www.secg.org/sec2-v2.pdf (page 6, section 2.2.1)
 */

class SECP192K1 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'SECP192K1',
      ossl: 'secp192k1',
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prime: null,
      // 2^192 − 2^32 − 4553 (= 3 mod 4)
      p: ['ffffffff ffffffff ffffffff ffffffff',
          'fffffffe ffffee37'],
      a: '0',
      b: '3',
      n: ['ffffffff ffffffff fffffffe 26f2fc17',
          '0f69466a 74defd8d'],
      h: '1',
      // SVDW
      z: '1',
      g: [
        ['db4ff10e c057e9ae 26b07d02 80b7f434',
         '1da5d1b1 eae06c7d'],
        ['9b2f2f6d 9c5628a7 844163d0 15be8634',
         '4082aa88 d95e2f9d']
      ]
    });
  }
}

/**
 * SECP224K1
 * https://www.secg.org/SEC2-Ver-1.0.pdf (page 13, section 2.6.1)
 * https://www.secg.org/sec2-v2.pdf (page 7, section 2.3.1)
 */

class SECP224K1 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'SECP224K1',
      ossl: 'secp224k1',
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prime: null,
      // 2^224 − 2^32 − 6803 (= 5 mod 8)
      p: ['ffffffff ffffffff ffffffff ffffffff',
          'ffffffff fffffffe ffffe56d'],
      a: '0',
      b: '5',
      n: ['01',
          '00000000 00000000 00000000 0001dce8',
          'd2ec6184 caf0a971 769fb1f7'],
      h: '1',
      // SVDW
      z: '-1',
      g: [
        ['a1455b33 4df099df 30fc28a1 69a467e9',
         'e47075a9 0f7e650e b6b7a45c'],
        ['7e089fed 7fba3442 82cafbd6 f7e319f7',
         'c0b0bd59 e2ca4bdb 556d61a5']
      ]
    });
  }
}

/**
 * WEI25519
 * https://tools.ietf.org/id/draft-ietf-lwig-curve-representations-02.html#rfc.appendix.E.3
 */

class WEI25519 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'WEI25519',
      ossl: null,
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prime: 'p25519',
      // 2^255 - 19 (= 5 mod 8)
      p: ['7fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffed'],
      a: ['2aaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa',
          'aaaaaaaa aaaaaaaa aaaaaa98 4914a144'],
      b: ['7b425ed0 97b425ed 097b425e d097b425',
          'ed097b42 5ed097b4 260b5e9c 7710c864'],
      n: ['10000000 00000000 00000000 00000000',
          '14def9de a2f79cd6 5812631a 5cf5d3ed'],
      h: '8',
      // SSWU
      z: '2',
      g: [
        ['2aaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa',
         'aaaaaaaa aaaaaaaa aaaaaaaa aaad245a'],
        ['20ae19a1 b8a086b4 e01edd2c 7748d14c',
         '923d4d7e 6d7c61b2 29e9c5a2 7eced3d9'],
        pre
      ]
    });
  }
}

/**
 * ISO448
 * https://tools.ietf.org/html/rfc7748#section-4.2
 * https://git.zx2c4.com/goldilocks/tree/_aux/ristretto/ristretto.sage#n658
 */

class ISO448 extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'ISO448',
      ossl: null,
      type: 'edwards',
      endian: 'le',
      hash: 'SHAKE256',
      prefix: 'SigEd448',
      context: true,
      prime: 'p448',
      // 2^448 - 2^224 - 1 (= 3 mod 4)
      p: ['ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff fffffffe ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff'],
      a: '1',
      c: '1',
      // 39082 / 39081 mod p
      d: ['d78b4bdc 7f0daf19 f24f38c2 9373a2cc',
          'ad461572 42a50f37 809b1da3 412a12e7',
          '9ccc9c81 264cfe9a d0809970 58fb61c4',
          '243cc32d baa156b9'],
      n: ['3fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff 7cca23e9',
          'c44edb49 aed63690 216cc272 8dc58f55',
          '2378c292 ab5844f3'],
      h: '4',
      // Elligator 2
      z: '-1',
      g: [
        ['79a70b2b 70400553 ae7c9df4 16c792c6',
         '1128751a c9296924 0c25a07d 728bdc93',
         'e21f7787 ed697224 9de732f3 8496cd11',
         '69871309 3e9c04fc'],
        // Note: the RFC has this wrong.
        ['7fffffff ffffffff ffffffff ffffffff',
         'ffffffff ffffffff ffffffff 80000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000001'],
        pre
      ]
    });
  }
}

/**
 * TWIST448
 * https://git.zx2c4.com/goldilocks/tree/_aux/ristretto/ristretto.sage#n675
 */

class TWIST448 extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'TWIST448',
      ossl: null,
      type: 'edwards',
      endian: 'le',
      hash: 'SHAKE256',
      prefix: 'SigEd448',
      context: true,
      prime: 'p448',
      // 2^448 - 2^224 - 1 (= 3 mod 4)
      p: ['ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff fffffffe ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff'],
      a: '-1',
      c: '1',
      // -39082 mod p
      d: ['ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff fffffffe ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffff6755'],
      n: ['3fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff 7cca23e9',
          'c44edb49 aed63690 216cc272 8dc58f55',
          '2378c292 ab5844f3'],
      h: '4',
      // Elligator 2
      z: '-1',
      g: [
        ['7fffffff ffffffff ffffffff ffffffff',
         'ffffffff ffffffff fffffffe 80000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000000'],
        ['8508de14 f04286d4 8d06c130 78ca2408',
         '05264370 504c74c3 93d5242c 50452714',
         '14181844 d73f48e5 199b0c1e 3ab470a1',
         'c86079b4 dfdd4a64'],
        pre
      ]
    });
  }
}

/**
 * MONT448
 * Isomorphic to Ed448-Goldilocks.
 */

class MONT448 extends MontCurve {
  constructor() {
    super({
      id: 'MONT448',
      ossl: null,
      type: 'mont',
      endian: 'le',
      hash: 'SHAKE256',
      prime: 'p448',
      // 2^448 - 2^224 - 1 (= 3 mod 4)
      p: ['ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff fffffffe ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff'],
      // -78160 / -39082 mod p
      a: ['b2cf97d2 d43459a9 31ed36b1 fc4e3cb5',
          '5d93f8d2 22746997 60ccffc6 49961ed6',
          'c5b05fca c24864ed 6fb59697 931b78da',
          '84ddecd8 ca2b5cfb'],
      b: '1',
      n: ['3fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff 7cca23e9',
          'c44edb49 aed63690 216cc272 8dc58f55',
          '2378c292 ab5844f3'],
      h: '4',
      // Elligator 2
      z: '-1',
      g: [
        ['ac0d24cc c6c75cb0 eb71f81e 7a6edf51',
         '48e88aee 009a2a24 e795687e c28e125a',
         '3e6730a6 0d46367b aa7fe99d 152128dc',
         '41321bc7 7817f059'],
        ['5a4437f6 80c0d0db 9b061276 d5d0ffcc',
         'e786ff33 b6a53d30 98746425 82e66f09',
         '4433dae7 7244a6e2 6b11e905 7228f483',
         '556c41a5 913f55fe']
      ]
    });
  }
}

/**
 * ED1174
 * http://elligator.cr.yp.to/elligator-20130828.pdf
 */

class ED1174 extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'ED1174',
      ossl: null,
      type: 'edwards',
      endian: 'le',
      hash: 'SHA512',
      prefix: 'SigEd1174',
      context: false,
      prime: null,
      // 2^251 - 9 (= 3 mod 4)
      p: ['07ffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff fffffff7'],
      a: '1',
      c: '1',
      // -1174 mod p
      d: ['07ffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff fffffb61'],
      n: ['01ffffff ffffffff ffffffff ffffffff',
          'f77965c4 dfd30734 8944d45f d166c971'],
      h: '4',
      // Elligator 1
      s: ['03fe707f 0d7004fd 334ee813 a5f1a74a',
          'b2449139 c82c39d8 4a09ae74 cc78c615'],
      // Elligator 2
      z: '-1',
      g: [
        ['037fbb0c ea308c47 9343aee 7c029a190',
         'c021d96a 492ecd65 16123f2 7bce29eda'],
        ['06b72f82 d47fb7cc 66568411 69840e0c',
         '4fe2dee2 af3f976b a4ccb1bf 9b46360e'],
        pre
      ]
    });
  }
}

/**
 * ED41417 (also known as Curve3617)
 * https://cr.yp.to/ecdh/curve41417-20140706.pdf
 * https://tools.ietf.org/html/draft-ladd-safecurves-02
 */

class ED41417 extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'ED41417',
      ossl: null,
      type: 'edwards',
      endian: 'le',
      hash: 'SHAKE256',
      prefix: 'SigEd41417',
      context: false,
      prime: null,
      // 2^414 - 17 (= 3 mod 4)
      p: ['3fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffef'],
      a: '1',
      c: '1',
      // 3617
      d: ['00000000 00000000 00000000 00000000',
          '00000000 00000000 00000000 00000000',
          '00000000 00000000 00000000 00000000',
          '00000e21'],
      n: ['07ffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffeb3c c92414cf',
          '706022b3 6f1c0338 ad63cf18 1b0e71a5',
          'e106af79'],
      h: '8',
      // Elligator 1
      s: ['09d97112 36cb615f 21a3ee8b 56f69ebb',
          '592d05eb 9401dbd3 de60e7d4 b0bdbb03',
          'f1ecba9b 5ce72822 e95ef209 e638bb96',
          'dda55cef'],
      // Elligator 2
      z: '-1',
      g: [
        ['1a334905 14144330 0218c063 1c326e5f',
         'cd46369f 44c03ec7 f57ff354 98a4ab4d',
         '6d6ba111 301a73fa a8537c64 c4fd3812',
         'f3cbc595'],
        ['00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000022'],
        pre
      ]
    });
  }
}

/**
 * M221
 * http://eprint.iacr.org/2013/647.pdf
 */

class M221 extends MontCurve {
  constructor() {
    super({
      id: 'M221',
      ossl: null,
      type: 'mont',
      endian: 'le',
      hash: 'SHA256',
      prime: null,
      // 2^221 - 3 (= 5 mod 8)
      p: ['1fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff fffffffd'],
      // 117050
      a: '1c93a',
      b: '1',
      n: ['04000000 00000000 00000000 000015a0',
          '8ed730e8 a2f77f00 5042605b'],
      h: '8',
      // Elligator 2
      z: '2',
      g: [
        ['00000000 00000000 00000000 00000000',
         '00000000 00000000 00000004'],
        ['0f7acdd2 a4939571 d1cef14e ca37c228',
         'e61dbff1 0707dc6c 08c5056d']
      ]
    });
  }
}

/**
 * E222
 * http://eprint.iacr.org/2013/647.pdf
 */

class E222 extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'E222',
      ossl: null,
      type: 'edwards',
      endian: 'le',
      hash: 'SHA512',
      prefix: 'SigE222',
      context: false,
      prime: null,
      // 2^222 - 117 (= 3 mod 4)
      p: ['3fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffff8b'],
      a: '1',
      c: '1',
      // 160102
      d: ['00000000 00000000 00000000 00000000',
          '00000000 00000000 00027166'],
      n: ['0fffffff ffffffff ffffffff fffff70c',
          'bc95e932 f802f314 23598cbf'],
      h: '4',
      // Elligator 1
      s: ['108bd829 b2739d6a 89a0d065 61849d96',
          '8cd2cf7d 01ea0846 5368b19b'],
      // Elligator 2
      z: '-1',
      g: [
        ['19b12bb1 56a389e5 5c9768c3 03316d07',
         'c23adab3 736eb2bc 3eb54e51'],
        ['00000000 00000000 00000000 00000000',
         '00000000 00000000 0000001c'],
        pre
      ]
    });
  }
}

/**
 * M383
 * http://eprint.iacr.org/2013/647.pdf
 * http://tools.ietf.org/html/draft-ladd-safecurves-02
 */

class M383 extends MontCurve {
  constructor() {
    super({
      id: 'M383',
      ossl: null,
      type: 'mont',
      endian: 'le',
      hash: 'SHAKE256',
      prime: null,
      // 2^383 - 187 (= 5 mod 8)
      p: ['7fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffff45'],
      // 2065150
      a: '1f82fe',
      b: '1',
      n: ['10000000 00000000 00000000 00000000',
          '00000000 00000000 06c79673 ac36ba6e',
          '7a32576f 7b1b249e 46bbc225 be9071d7'],
      h: '8',
      // Elligator 2
      z: '2',
      g: [
        ['00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 0000000c'],
        ['1ec7ed04 aaf834af 310e304b 2da0f328',
         'e7c165f0 e8988abd 39928612 90f617aa',
         '1f1b2e7d 0b6e332e 969991b6 2555e77e']
      ]
    });
  }
}

/**
 * E382
 * http://eprint.iacr.org/2013/647.pdf
 * http://tools.ietf.org/html/draft-ladd-safecurves-02
 */

class E382 extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'E382',
      ossl: null,
      type: 'edwards',
      endian: 'le',
      hash: 'SHAKE256',
      prefix: 'SigE382',
      context: false,
      prime: null,
      // 2^382 - 105 (= 3 mod 4)
      p: ['3fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffff97'],
      a: '1',
      c: '1',
      // -67254 mod p
      d: ['3fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff fffef8e1'],
      n: ['0fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff d5fb21f2 1e95eee1',
          '7c5e6928 1b102d27 73e27e13 fd3c9719'],
      h: '4',
      // Elligator 1
      s: ['11e24c2d 89fc3662 81997e95 e0d98705',
          '3c450018 7834351f 34055452 39ac8ad5',
          '19dae89c e8c7a39a 131cc679 c00ffffc'],
      // Elligator 2
      z: '-1',
      g: [
        ['196f8dd0 eab20391 e5f05be9 6e8d20ae',
         '68f84003 2b0b6435 2923bab8 53648411',
         '93517dbc e8105398 ebc0cc94 70f79603'],
        ['00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000011'],
        pre
      ]
    });
  }
}

/**
 * M511
 * http://eprint.iacr.org/2013/647.pdf
 * http://tools.ietf.org/html/draft-ladd-safecurves-02
 */

class M511 extends MontCurve {
  constructor() {
    super({
      id: 'M511',
      ossl: null,
      type: 'mont',
      endian: 'le',
      hash: 'SHAKE256',
      prime: null,
      // 2^511 - 187 (= 5 mod 8)
      p: ['7fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffff45'],
      // 530438
      a: '81806',
      b: '1',
      n: ['10000000 00000000 00000000 00000000',
          '00000000 00000000 00000000 00000000',
          '17b5feff 30c7f567 7ab2aeeb d13779a2',
          'ac125042 a6aa10bf a54c15ba b76baf1b'],
      h: '8',
      // Elligator 2
      z: '2',
      g: [
        ['00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000005'],
        ['2fbdc0ad 8530803d 28fdbad3 54bb488d',
         '32399ac1 cf8f6e01 ee3f9638 9b90c809',
         '422b9429 e8a43dbf 49308ac4 455940ab',
         'e9f1dbca 542093a8 95e30a64 af056fa5']
      ]
    });
  }
}

/**
 * E521
 * http://eprint.iacr.org/2013/647.pdf
 * http://tools.ietf.org/html/draft-ladd-safecurves-02
 */

class E521 extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'E521',
      ossl: null,
      type: 'edwards',
      endian: 'le',
      hash: 'SHAKE256',
      prefix: 'SigE521',
      context: false,
      prime: 'p521',
      // 2^521 - 1 (= 3 mod 4)
      p: ['000001ff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff'],
      a: '1',
      c: '1',
      // -376014 mod p
      d: ['000001ff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'fffa4331'],
      n: ['0000007f ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'fffffffd 15b6c647 46fc85f7 36b8af5e',
          '7ec53f04 fbd8c456 9a8f1f45 40ea2435',
          'f5180d6b'],
      h: '4',
      // Elligator 1
      s: ['000000cd c45eed49 413d0fb4 56e2e7c4',
          '003c943e 8030aae7 5e6c0702 c871f054',
          '2fc3b693 70d50b2e 0dc92250 9eb0e675',
          '812bf1b2 f7ea84ad 2db62f78 aa8c789c',
          '85796224'],
      // Elligator 2
      z: '-1',
      g: [
        ['00000075 2cb45c48 648b189d f90cb229',
         '6b2878a3 bfd9f42f c6c818ec 8bf3c9c0',
         'c6203913 f6ecc5cc c72434b1 ae949d56',
         '8fc99c60 59d0fb13 364838aa 302a940a',
         '2f19ba6c'],
        ['00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '0000000c'],
        pre
      ]
    });
  }
}

/**
 * MDC
 * https://cryptoexperts.github.io/million-dollar-curve/
 */

class MDC extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'MDC',
      ossl: null,
      type: 'edwards',
      endian: 'le',
      hash: 'SHA512',
      prefix: 'SigMDC',
      context: false,
      prime: null,
      // (= 3 mod 4)
      p: ['f13b68b9 d456afb4 532f92fd d7a5fd4f',
          '086a9037 ef07af9e c1371040 5779ec13'],
      a: '1',
      c: '1',
      d: ['57130452 1965b68a 7cdfbfcc fb0cb962',
          '5f1270f6 3f21f041 ee930925 0300cf89'],
      n: ['3c4eda2e 7515abed 14cbe4bf 75e97f53',
          '4fb38975 faf974bb 588552f4 21b0f7fb'],
      h: '4',
      // Elligator 1
      s: ['2bfcf45c fbcc3086 fb60bbeb fc611e28',
          'f70e33ab 41de2ecb 42225097 817038e2'],
      // Elligator 2
      z: '-1',
      g: [
        ['b681886a 7f903b83 d85b421 e03cbcf63',
         '50d72abb 8d2713e2 232c25b fee68363b'],
        ['ca6734e1 b59c0b03 59814dcf 6563da42',
         '1da8bc3d 81a93a3a 7e73c355 bd2864b5'],
        pre
      ]
    });
  }
}

/*
 * Register
 */

elliptic.register('SECP192K1', SECP192K1);
elliptic.register('SECP224K1', SECP224K1);
elliptic.register('WEI25519', WEI25519);
elliptic.register('ISO448', ISO448);
elliptic.register('TWIST448', TWIST448);
elliptic.register('MONT448', MONT448);
elliptic.register('ED1174', ED1174);
elliptic.register('ED41417', ED41417);
elliptic.register('M221', M221);
elliptic.register('E222', E222);
elliptic.register('M383', M383);
elliptic.register('E382', E382);
elliptic.register('M511', M511);
elliptic.register('E521', E521);
elliptic.register('MDC', MDC);

/*
 * Expose
 */

module.exports = {
  SECP192K1,
  SECP224K1,
  WEI25519,
  ISO448,
  TWIST448,
  MONT448,
  ED1174,
  ED41417,
  M221,
  E222,
  M383,
  E382,
  M511,
  E521,
  MDC
};
