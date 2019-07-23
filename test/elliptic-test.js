'use strict';

const assert = require('bsert');
const BN = require('../lib/bn.js');
const EDDSA = require('../lib/js/eddsa');
const SHAKE256 = require('../lib/shake256');
const elliptic = require('../lib/js/elliptic');
const rng = require('../lib/random');

const {
  ShortCurve,
  EdwardsCurve,
  curves
} = elliptic;

describe('Elliptic', function() {
  describe('Vectors', () => {
    const test = (curve, vector) => {
      it(`should test curve ${curve.id}`, () => {
        // Quick sanity test.
        if (curve.type === 'mont') {
          const g = curve.g;
          const p1 = g.mul(new BN(2));
          const p2 = g.mul(new BN(3));

          assert(g.dbl().eq(p1));
          assert(g.diffTrpl(g).eq(p2));
        } else {
          const p = curve.g;
          const j = curve.g.toJ();
          const tp = p.trpl();
          const tj = j.trpl();

          assert(p.add(p).eq(p.dbl()));
          assert(j.add(j).eq(j.dbl()));
          assert(j.add(p).eq(j.dbl()));

          assert(p.trpl().eq(p.dbl().add(p)));
          assert(j.trpl().eq(j.dbl().add(j)));
          assert(j.trpl().add(p).eq(j.dblp(2)));

          assert(p.dbl().validate());
          assert(j.dbl().validate());
          assert(p.trpl().validate());
          assert(j.trpl().validate());

          assert(p.dbl().eq(p.uadd(p)));
          assert(j.dbl().eq(j.uadd(j)));
          assert(p.dbl().eq(p.udbl()));
          assert(j.dbl().eq(j.udbl()));
          assert(p.uadd(p).uadd(p).eq(tp));
          assert(j.uadd(j).uadd(j).eq(tj));
        }

        for (let i = 0; i < 2; i++) {
          const ak = new BN(vector.a.k, 16);
          const ap = curve.g.mul(ak);

          assert.equal(ap.getX().toString(16), vector.a.x);
          assert.equal(ap.getY().toString(16), vector.a.y);
          assert(curve.g.mulSimple(ak).eq(ap));
          assert(curve.g.mulConst(ak).eq(ap));
          assert(curve.g.mulConst(ak, rng).eq(ap));

          const bk = new BN(vector.b.k, 16);
          const bp = curve.g.mul(bk);

          assert.equal(bp.getX().toString(16), vector.b.x);
          assert.equal(bp.getY().toString(16), vector.b.y);
          assert(curve.g.mulSimple(bk).eq(bp));
          assert(curve.g.mulConst(bk).eq(bp));
          assert(curve.g.mulConst(bk, rng).eq(bp));

          const p1 = bp.mul(ak);
          const p2 = ap.mul(bk);

          assert(p1.eq(p2));
          assert.equal(p1.getX().toString(16), vector.s.x);
          assert.equal(p1.getY().toString(16), vector.s.y);
          assert(bp.mulSimple(ak).eq(p1));
          assert(ap.mulSimple(bk).eq(p1));
          assert(ap.mulConst(bk).eq(p1));
          assert(ap.mulConst(bk, rng).eq(p1));

          const p3 = bp.mulBlind(ak);
          const p4 = ap.mulBlind(bk);

          assert(p3.eq(p4));
          assert.equal(p3.getX().toString(16), vector.s.x);
          assert.equal(p3.getY().toString(16), vector.s.y);
          assert(bp.mulSimple(ak).eq(p3));
          assert(ap.mulSimple(bk).eq(p3));
          assert(bp.mulConst(ak).eq(p3));
          assert(bp.mulConst(ak, rng).eq(p3));
          assert(ap.mulConst(bk).eq(p3));
          assert(ap.mulConst(bk, rng).eq(p3));

          assert(curve.decodePoint(ap.encode()).eq(ap));
          assert(curve.decodePoint(bp.encode()).eq(bp));
          assert(curve.decodePoint(p1.encode()).eq(p1));
          assert(curve.decodePoint(p2.encode()).eq(p2));
          assert(curve.decodePoint(p3.encode()).eq(p3));
          assert(curve.decodePoint(p4.encode()).eq(p4));

          curve.precompute(rng);
        }
      });
    };

    test(new curves.P192(), {
      a: {
        k: 'e8c74e99092a9c2ef5c9d0826697ba7b0dfab11ab17c059d',
        x: 'c6e75a4b307136b15e6fcd818f7293172daed8a6ee60322c',
        y: 'c9f41596800c4ccf49fb1c269f884a3d579d12a27f9b2d96'
      },
      b: {
        k: '5d41ac4d405c63962e4e54012641c786a9159ce76459815a',
        x: '90fe10587acc6225b838c713b5b57229350e101ee617cc12',
        y: '802b7be71b58520f10a34645fcaa5d5f60b3f810d24b997c'
      },
      s: {
        x: '9f2dece64a07592fb7decd76a9d05b5a20625518791a199f',
        y: 'e8741f00bef890a7e4ae24553206cae441031968df5ec32c'
      }
    });

    test(new curves.P224(), {
      a: {
        k: 'abb9950e547809ad079ba8fde54779758933b032ec672b295a9deaf6',
        x: '534394a69b2691518977f518e7beed689f6fd9c27d0dc1f6d32d2c3b',
        y: '29cf860ff12256838a40a67d73adf4122be7c2df1bbca7f75c14ceb0'
      },
      b: {
        k: '4745aa8211b380bdc4b255c2c6da9b99d906b5b18e2290a99f195d67',
        x: '9ea0592b17e215614e1f183250dfa34c749ff0d8a5226c3258042e2e',
        y: '71a37e1e2dd0c89e3a0188bbb715a2aa945c38fb0f3335d8727ac7ac'
      },
      s: {
        x: 'ca2597e841478ae363e20a8b081676c201aef595036df5d3633b8f5f',
        y: 'f1c70b6d66af764eb5b0ccc586e7a8639396204ff0cafe998d3d07b6'
      }
    });

    test(new curves.P256(), {
      a: {
        k: '7d31b3980a670adb31fd5943b87453e7c19e30b90be2f6fe1698e0f5796df55e',
        x: '647293c0e08ae35140ba371f67883bfc848ead975e27dd7f8a6db2a259bc2e1b',
        y: 'aba8d40f11322dcd93d1d88b9907cd9e0c15be4a50f7850cca86c0e9492c1bf3'
      },
      b: {
        k: '05a0d3d015d0c82732b29c4c5e671c623b3360c58490baa84e3e43ca8d596097',
        x: '7040bad247e0508acde9df1b495304808c6b87428a0cd4a5e4940c63ab0abd34',
        y: 'd4be56bb2eadc8be86880bbbc8c13dd2e36096b1f3377679129f4a40526bb8f6'
      },
      s: {
        x: 'ee80975a3db44157e862133724380f84169059a3ab8bac331f4c4892a9119182',
        y: 'e37df17f1e7064d1b12a192ae65ca6ca20ffc470d88d91b66f94da700e107cd4'
      }
    });

    test(new curves.P384(), {
      a: {
        k: 'f1ac3d7aa847c2235e393fdbe353d4408bf603207da7918eda6c9c9d66db6e04f9d13bad8b554a04b690bcbfc125c540',
        x: 'eb4aec872170c5b79205de6ba8b0196cc3d8c75e4291eff800ba3dcf88a581a5281b3b860586147b6d926bf6829f4ac5',
        y: 'e12abdd483df66b6b7c210ee927d549e6eb58a2ce66b2abe41cab3eb05743c05802d580752f09c4872e86f5965ce2f22'
      },
      b: {
        k: '79fba6a1a13caa899d9829ba5c5a0431a954980a559b747c11071816babb13868744800879dbcdfb40120087917da3e0',
        x: '63b9eb16e3c999692b5ec009863cb57e8fb849659eac50b507ee651f3d1b93869a956386e31c11574cc948ceae95a704',
        y: '8a116cb2bc9fe827fb7c6cb9af4649fd278e2c0af7dcecb062f17c716049cc57a975028bbaf57987f35fc4f1ac9803ff'
      },
      s: {
        x: 'e79e3a3c14c5405b74dcd86fdd1d03b81e7a8c394fe451d104ca3f99e3f57a674e548f61dfde54fd9ed6558ea62c9ade',
        y: '1213c4a9e0b996824455694d9af2a7573ff00dc35cdb1decce45931c089d2f9d1b07c85500af3d6ec6e70f8834759c87'
      }
    });

    test(new curves.P521(), {
      a: {
        k: '007783085a324b70832c4d6e5607d25fb291459bf9d7c620f658d8f01903861dcfba056756cad95a6628cf0084eb778baddbe71a47f177e3e09c0f278b8585dd7ea4',
        x: '3654feaa311aae18d74d021f3fb12c9ba193b1673a298aadce1214f17d41640f222650b66dec1fe98559a4e9b0a3f4523099f98371c808cf6360fae7258b166192',
        y: '12c4c3fc89547a2697b567b9fb226b204336faa06e963751baad4000e16105a5230d890f2e867ee9fe3538e6babc442688850d5bb469035621ad38d45724d7ca3fd'
      },
      b: {
        k: '01891acf4771cf31fae03c1c1e37e4fa7cfba3cc53ce3941d9cbc5cf57c2a2a0524ecf805418485e2157f900f7a4d490dd97f3191b1bf1b27fe50a190196d2517b79',
        x: '121936da291d82d91a2a2c7b5395b0fa1b5ec78c7997f2947ff2c818f737df8c62583d4b9833b3889616c483cde977e79b593c0f03b497e40e0412ca04ed6e518e',
        y: '10afd2ae9c4a86a7bb732270da25504d1ffbba1805386bb83acbd25b085419ccda4c56bf3af4fa62b4060a333718e199d73e6830f81c0e7beb2ffd959acf3bb7512'
      },
      s: {
        x: '1b0d33c6c257eaf624fa379ce1db07e47910dde06f9e60568a17372439ab058873d9c29a220631b9873ed451e911ff6069f95f68c6ac6dfb69f5133437b31e0194d',
        y: '12b6bc4b6cc2da4584489f2179ccd70c016a746f1acd67c4bd040fb9a048ddc100d08240b3ffea8a8054fac4307ef10f66e8fad2986f2fddf41092847b40de38e41'
      }
    });

    test(new curves.SECP256K1(), {
      a: {
        k: 'f40749b74e7454a808fe318349129d7956bfe4df271d7ad31b3daf9866d538b6',
        x: 'eef57567a6beda8b2307bdb2e2d64649ca3da5e99b0e6e600b258ed7fc5c6432',
        y: '76cdd5f153bd292bc5c0aa451f70d4adc43f0fb6944cc75dea850bf87701061a'
      },
      b: {
        k: 'b13d3ceda8e56c900005788a822a432a42cadd11f690a260c71418eb8e44d683',
        x: 'f96e09c5f26fa15c38fd52282087c96a53411a75d4a65a9faed9c1113955b28f',
        y: 'cf867faf174f422673a146bec0fc41e0d1082e4a6e2711012c30ed49cfa7c360'
      },
      s: {
        x: '42fb130736618fcf3b70c6b44d8317fd754ec46b8ad4cd83b75571374b33a268',
        y: 'd920e5c9a283600917e38540bcebea9e56543c30055958b60fca0a4ff26ad8db'
      }
    });

    test(new curves.X25519(), {
      a: {
        k: '4041c0f90e24de439869dc636e15f78dab1437652918cd23f24bf267838e5920',
        x: '4e855a3acc67d76456afc5a2c854bb4ee83f0df16d3010e9cfeb02854b518370',
        y: '6069949d58d70d9b62ce29e09bb28f17d85698f6f77f34abf6db24eb58e01d14'
      },
      b: {
        k: '660dd8004c28dc548c341e3b9e39faad2fef0ce77fbc56beed9c016689cb9468',
        x: '2820cf502c9d9e227c785b4c58c0911cd3b6421c507f6a54dab413b0488ab82d',
        y: '243f45f6f3822a93121cd88e36c7ffbfdec7c706c5278e09cd5b189f60e191c4'
      },
      s: {
        x: '1af9818fd4ea2348a3695c730e647d4f0cbe9ad193e4d1d37b653afbc1ca27ed',
        y: '6895d8b2bc9f023da982e5b3dae1d7c980317060bae54207322b376748efc2a8'
      }
    });

    test(new curves.ED25519(), {
      a: {
        k: '0041c0f90e24de439869dc636e15f78dab1437652918cd23f24bf267838e5923',
        x: '7143fec2823a20e85bbfedff1a30468136983c8b32c09bba6991f4055b213613',
        y: '3b1dd63ace37221fd9bc0d11b2196938c32d92bf04aff3913bfb90b5489e19bf'
      },
      b: {
        k: '660dd8004c28dc548c341e3b9e39faad2fef0ce77fbc56beed9c016689cb9468',
        x: 'dc96522329ccd49233ade48a29fdbfe8dd46f23974d9b5ee5ec41ddf9f9ab44',
        y: '7cb80d4fc3336a3e7e7e63b18616cef9d269c580059f1842bd814b06280740d'
      },
      s: {
        x: '41ba2e23566ad6a2b41e08bb389c96aa71a470b03f0ed0a0137e91017e2cdd3b',
        y: '45b57e51719ec114cc1cb17d74aead651946293166152e90223a82b4b5b449eb'
      }
    });

    test(new curves.X448(), {
      a: {
        k: 'c17d6835ec83facd2a3fe89cc909f901a45a535c34763669a55177b956ecbf54abe19011df330c1c2498b30b8e13277453636fe4e6312fbc',
        x: 'a31700b63788e5b28616a3528c361f15abb59af9541bc66b74dd5dffaf9a0e31ccd32e032e843bd199870a255b22cdedce637b680ec68786',
        y: '2cdb7c77ee22cc2b25cf9a143d1efdc8326e3dbdfc2e1b95448dd0b7449dea313c82135b621db02d9edee8b1f7ecc55b5af77d3dfe200ad6'
      },
      b: {
        k: 'a6e3d9e47b915f758efe24b373f7d94b6802f516e7608a6389bef1c3299cd0b176f0b41a0ead25f6cd03c8dffc02d0f94eeb57eb854c63c8',
        x: 'a9989ad97dc0c1a53cd6b25c3277f51aef5b285c4aa2d9def8db83021deea334878cd056eaecbf6bf1d1b8bb9748bd95f3199c707bd24874',
        y: 'a6d629678478133e2685ab426064dd49681afd10000036059275365fe14c88dfc2b9e7467f059b12baa9d6fcdecaacd94052f93a15b6c9d2'
      },
      s: {
        x: 'd46033d9447dd8beb58504e511b007e09050e6009f605e55ee923ce61dca73a204d20cd0bb02209f9c67ba95dac759108d62299981d46e91',
        y: '6c7c3b108999e690258bc1415b634302bbef170ed4099dbe0c911e41f0ef45e3cb25bdfa8aa0fc7e933325691d047b7fe31483cc3cd213ac'
      }
    });

    test(new curves.ED448(), {
      a: {
        k: 'c17d6835ec83facd2a3fe89cc909f901a45a535c34763669a55177b956ecbf54abe19011df330c1c2498b30b8e13277453636fe4e6312fbc',
        x: '5a261d8379f0a2eba1f937c1be72cd54459c42f0510488f12828f2e455cd774d3ac17a7fa5a774403b9f3109c6035b9212e0923add16bcf4',
        y: '7765689f859de84d0feb418644db17e1ac2c3040a294d904a21930e23114d14db8c60f07e65ff133e56fd2295e5b215d4d4034a52ec6e1c6'
      },
      b: {
        k: 'a6e3d9e47b915f758efe24b373f7d94b6802f516e7608a6389bef1c3299cd0b176f0b41a0ead25f6cd03c8dffc02d0f94eeb57eb854c63c8',
        x: 'f9034affb5ae198a8a50934f86dfdabe74ea4a0b9379c1d71d1539c99c60d353a3b85185f45e6a53106346a7b1e2f01099e39587a50e968',
        y: 'd17800e9860f2eeaa7d2f9955969b981304351841eff8390a398d0af9b0219b6accd974ef729c31cf88bb723cb9b218096a9632106a8c64d'
      },
      s: {
        x: 'f99f4dbebd341334940a4215151a69d5ebb0412343a07efe4ba205c534713ca5110ea9683d734d05e3b706d92466311d0e99c3284dc6dab2',
        y: '9ff6d9d30735cf9f8cd25042ba28f40c9ab34da9aec2ff743601be24a32cb36d8d19184a75f20b9dad183be6791ec2a17dac7433232581d4'
      }
    });

    // https://github.com/indutny/elliptic/pull/144
    // https://tools.ietf.org/html/rfc7027
    test(new curves.BRAINPOOLP256(), {
      a: {
        k: '81db1ee100150ff2ea338d708271be38300cb54241d79950f77b063039804f1d',
        x: '44106e913f92bc02a1705d9953a8414db95e1aaa49e81d9e85f929a8e3100be5',
        y: '8ab4846f11caccb73ce49cbdd120f5a900a69fd32c272223f789ef10eb089bdc'
      },
      b: {
        k: '55e40bc41e37e3e2ad25c3c6654511ffa8474a91a0032087593852d3e7d76bd3',
        x: '8d2d688c6cf93e1160ad04cc4429117dc2c41825e1e9fca0addd34e6f1b39f7b',
        y: '990c57520812be512641e47034832106bc7d3e8dd0e4c7f1136d7006547cec6a'
      },
      s: {
        x: '89afc39d41d3b327814b80940b042590f96556ec91e6ae7939bce31f3a18bf2b',
        y: '49c27868f4eca2179bfd7d59b1e3bf34c1dbde61ae12931648f43e59632504de'
      }
    });

    test(new curves.BRAINPOOLP384(), {
      a: {
        k: '1e20f5e048a5886f1f157c74e91bde2b98c8b52d58e5003d57053fc4b0bd65d6f15eb5d1ee1610df870795143627d042',
        x: '68b665dd91c195800650cdd363c625f4e742e8134667b767b1b476793588f885ab698c852d4a6e77a252d6380fcaf068',
        y: '55bc91a39c9ec01dee36017b7d673a931236d2f1f5c83942d049e3fa20607493e0d038ff2fd30c2ab67d15c85f7faa59'
      },
      b: {
        k: '032640bc6003c59260f7250c3db58ce647f98e1260acce4acda3dd869f74e01f8ba5e0324309db6a9831497abac96670',
        x: '4d44326f269a597a5b58bba565da5556ed7fd9a8a9eb76c25f46db69d19dc8ce6ad18e404b15738b2086df37e71d1eb4',
        y: '62d692136de56cbe93bf5fa3188ef58bc8a3a0ec6c1e151a21038a42e9185329b5b275903d192f8d4e1f32fe9cc78c48'
      },
      s: {
        x: 'bd9d3a7ea0b3d519d09d8e48d0785fb744a6b355e6304bc51c229fbbce239bbadf6403715c35d4fb2a5444f575d4f42',
        y: 'df213417ebe4d8e40a5f76f66c56470c489a3478d146decf6df0d94bae9e598157290f8756066975f1db34b2324b7bd'
      }
    });

    test(new curves.BRAINPOOLP512(), {
      a: {
        k: '16302ff0dbbb5a8d733dab7141c1b45acbc8715939677f6a56850a38bd87bd59b09e80279609ff333eb9d4c061231fb26f92eeb04982a5f1d1764cad57665422',
        x: 'a420517e406aac0acdce90fcd71487718d3b953efd7fbec5f7f27e28c6149999397e91e029e06457db2d3e640668b392c2a7e737a7f0bf04436d11640fd09fd',
        y: '72e6882e8db28aad36237cd25d580db23783961c8dc52dfa2ec138ad472a0fcef3887cf62b623b2a87de5c588301ea3e5fc269b373b60724f5e82a6ad147fde7'
      },
      b: {
        k: '230e18e1bcc88a362fa54e4ea3902009292f7f8033624fd471b5d8ace49d12cfabbc19963dab8e2f1eba00bffb29e4d72d13f2224562f405cb80503666b25429',
        x: '9d45f66de5d67e2e6db6e93a59ce0bb48106097ff78a081de781cdb31fce8ccbaaea8dd4320c4119f1e9cd437a2eab3731fa9668ab268d871deda55a5473199f',
        y: '2fdc313095bcdd5fb3a91636f07a959c8e86b5636a1e930e8396049cb481961d365cc11453a06c719835475b12cb52fc3c383bce35e27ef194512b71876285fa'
      },
      s: {
        x: 'a7927098655f1f9976fa50a9d566865dc530331846381c87256baf3226244b76d36403c024d7bbf0aa0803eaff405d3d24f11a9b5c0bef679fe1454b21c4cd1f',
        y: '7db71c3def63212841c463e881bdcf055523bd368240e6c3143bd8def8b3b3223b95e0f53082ff5e412f4222537a43df1c6d25729ddb51620a832be6a26680a2'
      }
    });
  });

  describe('Precomputation', () => {
    it('should have precomputed curves', () => {
      const p256 = new curves.P256();
      p256.precompute(rng);

      const secp256k1 = new curves.SECP256K1();
      secp256k1.precompute(rng);

      const ed25519 = new curves.ED25519();
      ed25519.precompute(rng);

      const x25519 = new curves.X25519();
      x25519.precompute(rng);

      const ed448 = new curves.ED448();
      ed448.precompute(rng);

      const x448 = new curves.X448();
      x448.precompute(rng);

      assert(p256.g.pre);
      assert(secp256k1.g.pre);
      assert(ed25519.g.pre);
      assert(!x25519.g.pre);
      assert(ed448.g.pre);
      assert(!x448.g.pre);
    });
  });

  describe('Curve', () => {
    it('should work with example curve', () => {
      const curve = new ShortCurve({
        p: '1d',
        a: '4',
        b: '14',
        n: '24',
        h: '1',
        g: [
          '18',
          '16'
        ]
      });

      const p = curve.pointFromJSON(['18', '16']);

      assert(p.validate());
      assert(p.dbl().validate());
      assert(p.dbl().add(p).validate());
      assert(p.dbl().add(p.dbl()).validate());
      assert(p.dbl().add(p.dbl()).eq(p.add(p).add(p).add(p)));

      const q = curve.randomPoint(rng);

      assert(q.validate());
    });

    it('should dbl points on edwards curve using proj coordinates', () => {
      const curve = new EdwardsCurve({
        p: '3fffffffffffffffffffffffffffffffffffffffffffffff'
         + 'ffffffffffffffffffffffffffffffffffffffffffffff97',
        a: '1',
        c: '1',
        // -67254 mod p
        d: '3fffffffffffffffffffffffffffffffffffffffffffffff'
         + 'fffffffffffffffffffffffffffffffffffffffffffef8e1',
        n: '0fffffffffffffffffffffffffffffffffffffffffffffff'
         + 'd5fb21f21e95eee17c5e69281b102d2773e27e13fd3c9719',
        h: '8',
        g: [
          ['196f8dd0eab20391e5f05be96e8d20ae68f840032b0b6435',
           '2923bab85364841193517dbce8105398ebc0cc9470f79603'].join(''),
          '11'
        ]
      });

      const point = [
        ['21fd21b36cbdbe0d77ad8692c25d918774f5d3bc179c4cb0',
         'ae3c364bf1bea981d02e9f97cc62f20acacf0c553887e5fb'].join(''),
        ['29f994329799dba72aa12ceb06312300167b6e18fbed607c',
         '63709826c57292cf29f5bab4f5c99c739cf107a3833bb553'].join('')
      ];

      const double = [
        ['0561c8722cf82b2f0d7c36bc72e34539dcbf181e8d98f524',
         '4480e79f5b51a4a541457016c9c0509d49078eb5909a1121'].join(''),
        ['05b7812fae9d164ee9249c56a16e29a1ad2cdc6353227074',
         'dd96d59df363a0bcb5bc67d50b44843ea833156bdc0ac6a2'].join('')
      ];

      const p = curve.pointFromJSON(point);
      const d = curve.pointFromJSON(double);

      assert(p.dbl().eq(d));
    });

    it('should be able to find a point given y coordinate (edwards)', () => {
      const curve = new EdwardsCurve({
        p: '07fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7',
        a: '1',
        // -1174 mod p
        d: '07fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb61',
        c: '1',
        n: '01fffffffffffffffffffffffffffffff77965c4dfd307348944d45fd166c971',
        h: '4'
      });

      const target = curve.point(
        new BN('05d040ddaa645bf27d2d2f302c569723'
             + '1425185fd9a410f220ac5c5c7fbeb8a1', 16),
        new BN('02f8ca771306cd23e929775177f2c213'
             + '843a017a6487b2ec5f9b2a3808108ef2', 16)
      );

      const point = curve.pointFromY(
        new BN('02f8ca771306cd23e929775177f2c213'
             + '843a017a6487b2ec5f9b2a3808108ef2', 16),
        true
      );

      assert(point.eq(target));
      assert(point.randomize(rng).eq(target));
    });

    it('should find an odd point given a y coordinate', () => {
      const curve = new EdwardsCurve({
        id: 'ED25519',
        // 2^255 - 19
        p: '7fffffffffffffff ffffffffffffffff'
         + 'ffffffffffffffff ffffffffffffffed',
        a: '-1',
        c: '1',
        // (-121665 * 121666^-1) mod p
        d: '52036cee2b6ffe73 8cc740797779e898'
         + '00700a4d4141d8ab 75eb4dca135978a3',
        n: '1000000000000000 0000000000000000'
         + '14def9dea2f79cd6 5812631a5cf5d3ed',
        h: '8',
        g: [
          '216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a',
          // 4/5
          '6666666666666666666666666666666666666666666666666666666666666658'
        ]
      });

      const y = new BN(
        '4627191eb12f51005d2a7f3ef570376a3403801aae928c8ffd13feabadf84505',
        16);

      const point = curve.pointFromY(y, true);

      const target =
        '2cd591ae3789fd62dc420a152002f79973a387eacecadc6a9a00c1a89488c15d';

      assert.deepStrictEqual(point.getX().toString(16), target);
    });

    it('should work with secp112r1', () => {
      const curve = new ShortCurve({
        id: 'SECP112R1',
        s: '00f50b02 8e4d696e 67687561 51752904 72783fb1',
        // (2^128 - 3) / 76439
        p: 'db7c 2abf62e3 5e668076 bead208b',
        a: 'db7c 2abf62e3 5e668076 bead2088',
        b: '659e f8ba0439 16eede89 11702b22',
        n: 'db7c 2abf62e3 5e7628df ac6561c5',
        h: '1',
        g: [
          '0948 7239995a 5ee76b55 f9c2f098',
          'a89c e5af8724 c0a23e0e 0ff77500'
        ]
      });

      const p = curve.pointFromJSON(['0948 7239995a 5ee76b55 f9c2f098',
                                     'a89c e5af8724 c0a23e0e 0ff77500']);

      assert(p.validate());
      assert(p.dbl().validate());

      const raw = Buffer.from('0209487239995a5ee76b55f9c2f098', 'hex');
      const p2 = curve.decodePoint(raw);

      assert(p2.eq(curve.g));
      assert(p2.randomize(rng).eq(curve.g.toJ()));
    });

    it('should work with secp192k1', () => {
      const curve = new ShortCurve({
        id: 'SECP192K1',
        // 2^192 − 2^32 − 2^12 − 2^8 − 2^7 − 2^6 − 2^3 − 1
        p: 'ffffffff ffffffff ffffffff ffffffff fffffffe ffffee37',
        a: '0',
        b: '3',
        n: 'ffffffff ffffffff fffffffe 26f2fc17 0f69466a 74defd8d',
        h: '1',
        g: [
          'db4ff10e c057e9ae 26b07d02 80b7f434 1da5d1b1 eae06c7d',
          '9b2f2f6d 9c5628a7 844163d0 15be8634 4082aa88 d95e2f9d'
        ]
      });

      assert(curve.endo);

      assert.deepStrictEqual(curve.endo.toJSON(), {
        beta: '447a96e6c647963e2f7809feaab46947f34b0aa3ca0bba74',
        lambda: 'c27b0d93eddc7284b0c2ae9813318686dbb7a0ea73692cdb',
        basis: [
          {
            a: 'b3fb3400dec5c4adceb8655c',
            b: '-71169be7330b3038edb025f1'
          },
          {
            a: '71169be7330b3038edb025f1',
            b: '012511cfe811d0f4e6bc688b4d'
          }
        ]
      });

      const p = curve.pointFromJSON([
        'f091cf6331b1747684f5d2549cd1d4b3a8bed93b94f93cb6',
        'fd7af42e1e7565a02e6268661c5e42e603da2d98a18f2ed5'
      ]);

      assert(p.validate());
      assert(p.dbl().validate());
    });

    it('should work with secp224k1', () => {
      const curve = new ShortCurve({
        id: 'SECP224K1',
        // 2^224 − 2^32 − 2^12 − 2^11 − 2^9 − 2^7 − 2^4 − 2 − 1
        p: 'ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe ffffe56d',
        a: '0',
        b: '5',
        n: '01 00000000 00000000 00000000 0001dce8 d2ec6184 caf0a971 769fb1f7',
        h: '1',
        g: [
          'a1455b33 4df099df 30fc28a1 69a467e9 e47075a9 0f7e650e b6b7a45c',
          '7e089fed 7fba3442 82cafbd6 f7e319f7 c0b0bd59 e2ca4bdb 556d61a5'
        ]
      });

      assert(curve.endo);

      assert.deepStrictEqual(curve.endo.toJSON(), {
        beta: '01f178ffa4b17c89e6f73aece2aad57af4c0a748b63c830947b27e04',
        lambda: '9f232defb3b343f41911103d422bcc75342913534b55766d0a016a6e',
        basis: [
          {
            a: 'b8adf1378a6eb73409fa6c9c637d',
            b: '-6b8cf07d4ca75c88957d9d670591'
          },
          {
            a: '6b8cf07d4ca75c88957d9d670591',
            b: '01243ae1b4d71613bc9f780a03690e'
          }
        ]
      });

      const p = curve.pointFromJSON([
        '86c0deb56aeb9712390999a0232b9bf596b9639fa1ce8cf426749e60',
        '8f598c954e1085555b474a79906b855c539ed633dbf4a9fa9f06b69a'
      ]);

      assert(p.validate());
      assert(p.dbl().validate());
    });

    it('should get correct endomorphism', () => {
      // See: Guide to Elliptic Curve Cryptography,
      // Example 3.73, page 125, section 3.5.
      const curve = new ShortCurve({
        id: 'P160', // NID_wap_wsg_idm_ecid_wtls9
        p: 'fffffffffffffffffffffffffffffffffffc808f',
        a: '0', // Above document incorrectly says a=3.
        b: '3',
        n: '100000000000000000001cdc98ae0e2de574abf33',
        h: '1',
        g: [
          '1',
          '2'
        ]
      });

      assert(curve.endo);

      // Our code picks different beta/lambda values.
      assert.deepStrictEqual(curve.endo.toJSON(), {
        beta: '78ddf260453f1c29e9ad657a99290ffb7aa67330',
        lambda: '61ad83913c4f1cba4aa27087d04e9fa19257885c',
        basis: [
          { a: '7faab9faa7718443dc49', b: '-a70f68731db66985312e' },
          { a: '0126ba226dc527edc90d77', b: '7faab9faa7718443dc49' }
        ]
      });

      const beta = new BN('771473166210819779552257112796337671037538143582', 10);
      const lambda = new BN('903860042511079968555273866340564498116022318806', 10);
      const a1e = new BN('788919430192407951782190', 10);
      const b1e = new BN('-602889891024722752429129', 10);
      const a2e = new BN('602889891024722752429129', 10);
      const b2e = new BN('1391809321217130704211319', 10);

      // We pick index 0 when the example assumes 1.
      // Note that secp256k1 picks 1 (if we ever
      // want to switch to always choosing 1).
      curve.endo.beta = beta.toRed(curve.red);
      curve.endo.lambda = lambda.clone();
      curve.endo.basis[0].a = a1e.clone();
      curve.endo.basis[0].b = b1e.clone();
      curve.endo.basis[1].a = a2e.clone();
      curve.endo.basis[1].b = b2e.clone();

      assert(curve.endo.beta.fromRed().eq(beta));
      assert(curve.endo.lambda.eq(lambda));

      assert(curve._getEndoRoots(curve.p)[1].eq(beta));
      assert(curve._getEndoRoots(curve.n)[0].eq(lambda));

      // Should be cube roots.
      assert(beta.powmn(3, curve.p).cmpn(1) === 0);
      assert(lambda.powmn(3, curve.n).cmpn(1) === 0);

      // Example 3.75, page 127, section 3.5.
      const rle = new BN('2180728751409538655993509', 10);
      const tle = new BN('-186029539167685199353061', 10);
      const rl1e = new BN('788919430192407951782190', 10);
      const tl1e = new BN('602889891024722752429129', 10);
      const rl2e = new BN('602889891024722752429129', 10);
      const tl2e = new BN('-1391809321217130704211319', 10);

      const [rl, tl, rl1, tl1, rl2, tl2] = curve._egcdSqrt(lambda);

      assert(rl.eq(rle));
      assert(tl.eq(tle));
      assert(rl1.eq(rl1e));
      assert(tl1.eq(tl1e));
      assert(rl2.eq(rl2e));
      assert(tl2.eq(tl2e));

      const [v1, v2] = curve._getEndoBasis(lambda);

      assert(v1.a.eq(a1e));
      assert(v1.b.eq(b1e));
      assert(v2.a.eq(a2e));
      assert(v2.b.eq(b2e));

      const k = new BN('965486288327218559097909069724275579360008398257', 10);
      const c1e = new BN('919446671339517233512759', 10);
      const c2e = new BN('398276613783683332374156', 10);
      const k1e = new BN('-98093723971803846754077', 10);
      const k2e = new BN('381880690058693066485147', 10);

      const c1 = v2.b.mul(k).divRound(curve.n);
      const c2 = v1.b.neg().mul(k).divRound(curve.n);

      assert(c1.eq(c1e));
      assert(c2.eq(c2e));

      assert(curve.endo.basis[0].a.eq(v1.a));
      assert(curve.endo.basis[0].b.eq(v1.b));
      assert(curve.endo.basis[1].a.eq(v2.a));
      assert(curve.endo.basis[1].b.eq(v2.b));

      const [k1, k2] = curve._endoSplit(k);

      assert(k1.eq(k1e));
      assert(k2.eq(k2e));
    });

    it('should work with secp256k1', () => {
      const curve = new ShortCurve({
        id: 'SECP256K1',
        p: 'ffffffff ffffffff ffffffff ffffffff'
         + 'ffffffff ffffffff fffffffe fffffc2f',
        a: '0',
        b: '7',
        n: 'ffffffff ffffffff ffffffff fffffffe'
         + 'baaedce6 af48a03b bfd25e8c d0364141',
        g: [
          '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
          '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
        ]
      });

      const p = curve.pointFromJSON([
        ['79be667e f9dcbbac 55a06295 ce870b07',
         '029bfcdb 2dce28d9 59f2815b 16f81798'].join(''),
        ['483ada77 26a3c465 5da4fbfc 0e1108a8',
         'fd17b448 a6855419 9c47d08f fb10d4b8'].join('')
      ]);

      const s = new BN('79be667e f9dcbbac 55a06295 ce870b07', 16);

      assert(p.validate());
      assert(p.dbl().validate());
      assert(p.toJ().dbl().toP().validate());
      assert(p.mul(s).validate());

      const j = p.toJ();

      assert(j.trpl().eq(j.dbl().add(j)));

      // Endomorphism test
      assert(curve.endo);

      assert.strictEqual(
        curve.endo.beta.fromRed().toString(16),
        '7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee');

      assert.strictEqual(
        curve.endo.lambda.toString(16),
        '5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72');

      assert.strictEqual(curve.endo.basis[0].a.toString(16),
                         '3086d221a7d46bcde86c90e49284eb15');
      assert.strictEqual(curve.endo.basis[0].b.toString(16),
                         '-e4437ed6010e88286f547fa90abfe4c3');
      assert.strictEqual(curve.endo.basis[1].a.toString(16),
                         '114ca50f7a8e2f3f657c1108d9d44cfd8');
      assert.strictEqual(curve.endo.basis[1].b.toString(16),
                         '3086d221a7d46bcde86c90e49284eb15');

      const scalars = [
        '1234567890123456789012345678901234',
        '-1234567890123456789012345678901234',
        '1234567890123456789012345678901233',
        '-1234567890123456789012345678901233'
      ];

      for (const hex of scalars) {
        const k = new BN(hex, 16);

        assert(k.abs().cmp(curve.n) < 0);

        const [k1, k2] = curve._endoSplit(k);

        const testK = k1.add(k2.mul(curve.endo.lambda)).mod(curve.n);

        const km = k.sign() < 0 ? k.mod(curve.n) : k;

        assert.strictEqual(testK.toString(16), km.toString(16));
      }
    });

    it('should compute this problematic secp256k1 multiplication', () => {
      const curve = new curves.SECP256K1();

      curve.precompute(rng);

      const g1 = curve.g; // precomputed g

      assert(g1.pre);

      const g2 = curve.point(g1.getX(), g1.getY()); // not precomputed g

      assert(!g2.pre);

      const a = new BN(
        '6d1229a6b24c2e775c062870ad26bc261051e0198c67203167273c7c62538846',
        16);

      const p1 = g1.mul(a);
      const p2 = g2.mul(a);

      assert(p1.eq(p2));
    });

    it('should not use fixed NAF when k is too large', () => {
      const curve = new curves.SECP256K1();

      curve.precompute(rng);

      const g1 = curve.g; // precomputed g

      assert(g1.pre);

      const g2 = curve.point(g1.getX(), g1.getY()); // not precomputed g
      assert(!g2.pre);

      const a = new BN('6d1229a6b24c2e775c062870ad26bc26105'
                     + '1e0198c67203167273c7c6253884612345678', 16);

      const p1 = g1.mul(a);
      const p2 = g2.mul(a);

      assert(p1.eq(p2));
    });

    it('should not fail on secp256k1 regression', () => {
      const curve = new curves.SECP256K1();

      curve.precompute(rng);

      const k1 = new BN(
        '32efeba414cd0c830aed727749e816a01c471831536fd2fce28c56b54f5a3bb1',
        16);

      const k2 = new BN(
        '5f2e49b5d64e53f9811545434706cde4de528af97bfd49fde1f6cf792ee37a8c',
        16);

      const p1 = curve.g.mul(k1);
      const p2 = curve.g.mul(k2);

      // 2 + 2 + 1 = 2 + 1 + 2
      const two = p2.dbl();
      const five = two.dbl().add(p2);
      const three = two.add(p2);
      const maybeFive = three.add(two);

      assert(maybeFive.eq(five));

      const p3 = p1.mul(k2);
      const p4 = p2.mul(k1);

      assert(p3.validate());
      assert(p4.validate());
      assert(p3.eq(p4));
    });

    it('should correctly double the affine point on secp256k1', () => {
      const bad = {
        x: new BN(
          '026a2073b1ef6fab47ace18e60e728a05180a82755bbcec9a0abc08ad9f7a3d4',
          16),
        y: new BN(
          '9cd8cb48c3281596139f147c1364a3ede88d3f310fdb0eb98c924e599ca1b3c9',
          16),
        z: new BN(
          'd78587ad45e4102f48b54b5d85598296e069ce6085002e169c6bad78ddc6d9bd',
          16)
      };

      const good = {
        x: new BN(
          'e7789226739ac2eb3c7ccb2a9a910066beeed86cdb4e0f8a7fee8eeb29dc7016',
          16),
        y: new BN(
          '4b76b191fd6d47d07828ea965e275b76d0e3e0196cd5056d38384fbb819f9fcb',
          16),
        z: new BN(
          'cbf8d99056618ba132d6145b904eee1ce566e0feedb9595139c45f84e90cfa7d',
          16)
      };

      const curve = new curves.SECP256K1();
      const pbad = curve.jpoint(bad.x, bad.y, bad.z);
      const pgood = curve.jpoint(good.x, good.y, good.z);

      // They are the same points
      assert(pbad.add(pgood.neg()).isInfinity());

      // But doubling borks them out
      assert(pbad.dbl().add(pgood.dbl().neg()).isInfinity());
    });

    it('should multiply with blinding', () => {
      const curve = new curves.SECP256K1();

      curve.precompute(rng);

      const {blind} = curve.g.pre.blinding;
      const neg = blind.neg().imod(curve.n);
      const point1 = curve.g.mulBlind(neg);
      const point2 = curve.g.mul(neg);
      const point3 = curve.g.mulBlind(blind);
      const point4 = curve.g.mul(blind);

      assert(point1.eq(point2));
      assert(point3.eq(point4));
      assert(point3.neg().eq(point1));
    });

    it('should match multiplications', () => {
      const p256 = new curves.P256();
      const secp256k1 = new curves.SECP256K1();
      const ed25519 = new curves.ED25519();

      for (const curve of [p256, secp256k1, ed25519]) {
        const N = curve.n;
        const s = curve.randomScalar(rng);

        curve.precompute(rng);

        const p1 = curve.g.mul(s);
        const p2 = curve.g.mulSimple(s);

        assert(p1.eq(p2));

        const j1 = curve.g.jmul(s);
        const j2 = curve.g.jmulSimple(s);

        assert(j1.eq(j2));

        const j3 = curve.g.toJ().mul(s);
        const j4 = curve.g.toJ().mulSimple(s);

        assert(j3.eq(j4));

        const p3 = curve.g.mul(s.divn(3).mul(s));
        const p4 = curve.g.mulSimple(s.divn(3).mul(s).imod(N));
        const p4_ = curve.g.mulSimple(s.divn(3).mul(s));

        assert(p3.eq(p4));
        assert(p4_.eq(p4));

        const p5 = curve.g.mul(s.divn(3).mul(s).ineg());
        const p6 = curve.g.mulSimple(s.divn(3).mul(s).ineg().imod(N));
        const p6_ = curve.g.mulSimple(s.divn(3).mul(s).ineg());

        assert(p5.eq(p6));
        assert(p6_.eq(p6));
      }
    });

    it('should match multiplications (ladder)', () => {
      const curve = new curves.SECP256K1();
      const N = curve.n;

      const s = curve.randomScalar(rng);

      const p1 = curve.g.mulConst(s);
      const p2 = curve.g.mulSimple(s);

      assert(p1.eq(p2));

      const p3 = curve.g.mulConst(s.neg());
      const p4 = curve.g.mulSimple(s.neg().imod(N));

      assert(p3.eq(p4));

      const j1 = curve.g.jmulConst(s);
      const j2 = curve.g.jmulSimple(s);

      assert(j1.eq(j2));

      const j3 = curve.g.jmulConst(s.neg());
      const j4 = curve.g.jmulSimple(s.neg().imod(N));

      assert(j3.eq(j4));

      const j5 = curve.g.jmulConst(s.muln(17));
      const j6 = curve.g.jmulSimple(s.muln(17));

      assert(j5.eq(j6));

      const j7 = curve.g.jmulConst(s.muln(17).neg());
      const j8 = curve.g.jmulSimple(s.muln(17).neg().imod(N));

      assert(j7.eq(j8));

      assert(curve.g.mulConst(new BN(0)).isInfinity());
      assert(curve.g.mulConst(new BN(-1)).eq(curve.g.neg()));
      assert(curve.g.mulConst(new BN(-2)).eq(curve.g.dbl().neg()));
      assert(curve.g.mulConst(new BN(1)).eq(curve.g));
      assert(curve.g.mulConst(new BN(2)).eq(curve.g.dbl()));
      assert(curve.g.mulConst(new BN(3)).eq(curve.g.trpl()));
      assert(curve.g.mulConst(curve.n).isInfinity());
      assert(curve.g.mulConst(curve.n.subn(1)).eq(curve.g.neg()));
      assert(curve.g.mulConst(curve.n.subn(2)).eq(curve.g.dbl().neg()));
      assert(curve.g.mulConst(curve.n.muln(2)).isInfinity());
      assert(curve.g.mulConst(curve.n.neg()).isInfinity());
      assert(curve.g.mulConst(curve.n.muln(2).neg()).isInfinity());
    });

    it('should match multiplications (ladder+rng)', () => {
      const curve = new curves.SECP256K1();
      const N = curve.n;

      const s = curve.randomScalar(rng);

      const p1 = curve.g.mulConst(s, rng);
      const p2 = curve.g.mulSimple(s);

      assert(p1.eq(p2));

      const p3 = curve.g.mulConst(s.neg(), rng);
      const p4 = curve.g.mulSimple(s.neg().imod(N));

      assert(p3.eq(p4));

      const j1 = curve.g.jmulConst(s, rng);
      const j2 = curve.g.jmulSimple(s);

      assert(j1.eq(j2));

      const j3 = curve.g.jmulConst(s.neg(), rng);
      const j4 = curve.g.jmulSimple(s.neg().imod(N));

      assert(j3.eq(j4));

      const j5 = curve.g.jmulConst(s.muln(17), rng);
      const j6 = curve.g.jmulSimple(s.muln(17));

      assert(j5.eq(j6));

      const j7 = curve.g.jmulConst(s.muln(17).neg(), rng);
      const j8 = curve.g.jmulSimple(s.muln(17).neg().imod(N));

      assert(j7.eq(j8));

      assert(curve.g.mulConst(new BN(0), rng).isInfinity());
      assert(curve.g.mulConst(new BN(-1), rng).eq(curve.g.neg()));
      assert(curve.g.mulConst(new BN(-2)).eq(curve.g.dbl().neg()));
      assert(curve.g.mulConst(new BN(1), rng).eq(curve.g));
      assert(curve.g.mulConst(new BN(2), rng).eq(curve.g.dbl()));
      assert(curve.g.mulConst(new BN(3), rng).eq(curve.g.trpl()));
      assert(curve.g.mulConst(curve.n, rng).isInfinity());
      assert(curve.g.mulConst(curve.n.subn(1), rng).eq(curve.g.neg()));
      assert(curve.g.mulConst(curve.n.subn(2), rng).eq(curve.g.dbl().neg()));
      assert(curve.g.mulConst(curve.n.muln(2), rng).isInfinity());
      assert(curve.g.mulConst(curve.n.neg(), rng).isInfinity());
      assert(curve.g.mulConst(curve.n.muln(2).neg(), rng).isInfinity());
    });

    it('should match multiplications (fixed)', () => {
      const curve = new curves.SECP256K1();

      curve.precompute(rng);

      const N = curve.n;

      const mul = (p, k) => curve._fixedNafMul(p, k).toP();
      const jmul = (p, k) => curve._fixedNafMul(p, k);

      const s = curve.randomScalar(rng);
      const s2 = BN.mask(256);

      assert(curve.g._hasDoubles(s));
      assert(curve.g._hasDoubles(s.neg()));

      assert(s2.bitLength() === 256);
      assert(curve.g._hasDoubles(s2));
      assert(curve.g._hasDoubles(s2.neg()));

      const p1 = mul(curve.g, s);
      const p2 = curve.g.mulSimple(s);

      assert(p1.eq(p2));

      const p3 = mul(curve.g, s.neg());
      const p4 = curve.g.mulSimple(s.neg().imod(N));

      assert(p3.eq(p4));

      const j1 = jmul(curve.g, s);
      const j2 = curve.g.jmulSimple(s);

      assert(j1.eq(j2));

      const j3 = jmul(curve.g, s.neg());
      const j4 = curve.g.jmulSimple(s.neg().imod(N));

      assert(j3.eq(j4));
    });

    it('should match multiplications (ladder)', () => {
      const curve = new curves.SECP256K1();
      const N = curve.n;

      const mul = (p, k) => curve._ladderMul(p, k).toP();
      const jmul = (p, k) => curve._ladderMul(p, k);

      const s = curve.randomScalar(rng);

      const p1 = mul(curve.g, s);
      const p2 = curve.g.mulSimple(s);

      assert(p1.eq(p2));

      const j1 = jmul(curve.g, s);
      const j2 = curve.g.jmulSimple(s);

      assert(j1.eq(j2));

      const p3 = mul(curve.g, s.divn(3).mul(s));
      const p4 = curve.g.mulSimple(s.divn(3).mul(s).imod(N));

      assert(p3.eq(p4));

      const p5 = mul(curve.g, s.divn(3).mul(s).ineg());
      const p6 = curve.g.mulSimple(s.divn(3).mul(s).ineg().imod(N));

      assert(p5.eq(p6));
    });

    it('should match multiplications (co-z)', () => {
      const curve = new curves.SECP256K1();
      const N = curve.n;

      const mul = (p, k) => curve._coZLadderMul(p, k).toP();
      const jmul = (p, k) => curve._coZLadderMul(p, k);

      const s = curve.randomScalar(rng);

      const p1 = mul(curve.g, s);
      const p2 = curve.g.mulSimple(s);

      assert(p1.eq(p2));

      const j1 = jmul(curve.g, s);
      const j2 = curve.g.jmulSimple(s);

      assert(j1.eq(j2));

      const p3 = mul(curve.g, s.divn(3).mul(s));
      const p4 = curve.g.mulSimple(s.divn(3).mul(s).imod(N));

      assert(p3.eq(p4));

      const p5 = mul(curve.g, s.divn(3).mul(s).ineg());
      const p6 = curve.g.mulSimple(s.divn(3).mul(s).ineg().imod(N));

      assert(p5.eq(p6));
    });

    it('should match multiplications (wnaf)', () => {
      const curve = new curves.SECP256K1();

      curve.precompute(rng);

      const N = curve.n;

      const mul = (p, k) => curve._wnafMul(4, p, k).toP();
      const jmul = (p, k) => curve._wnafMul(4, p, k);
      const pre = curve.g.pre;

      let g = curve.g;

      for (let i = 0; i < 3; i++) {
        const s = curve.randomScalar(rng);

        const p1 = mul(g, s);
        const p2 = g.mulSimple(s);

        assert(p1.eq(p2));

        const j1 = jmul(g, s);
        const j2 = g.jmulSimple(s);

        assert(j1.eq(j2));

        const p3 = mul(g, s.divn(3).mul(s));
        const p4 = g.mulSimple(s.divn(3).mul(s).imod(N));

        assert(p3.eq(p4));

        const p5 = mul(g, s.divn(3).mul(s).ineg());
        const p6 = g.mulSimple(s.divn(3).mul(s).ineg().imod(N));

        assert(p5.eq(p6));

        if (i === 0) {
          g.pre = null;
          continue;
        }

        if (i === 1) {
          assert(g === curve.g);
          g.pre = pre;
        }

        if (i === 2)
          assert(g !== curve.g);

        g = p6;
      }

      assert(curve.g.pre === pre);
    });

    it('should match multiplications (muladd)', () => {
      const curve = new curves.SECP256K1();

      curve.precompute(rng);

      const N = curve.n;

      const mul = (p, k) => curve._wnafMulAdd(1, [p], [k]).toP();
      const jmul = (p, k) => curve._wnafMulAdd(1, [p], [k]);
      const pre = curve.g.pre;

      let g = curve.g;

      for (let i = 0; i < 3; i++) {
        const s = curve.randomScalar(rng);

        const p1 = mul(g, s);
        const p2 = g.mulSimple(s);

        assert(p1.eq(p2));

        const j1 = jmul(g, s);
        const j2 = g.jmulSimple(s);

        assert(j1.eq(j2));

        const p3 = mul(g, s.divn(3).mul(s));
        const p4 = g.mulSimple(s.divn(3).mul(s).imod(N));

        assert(p3.eq(p4));

        const p5 = mul(g, s.divn(3).mul(s).ineg());
        const p6 = g.mulSimple(s.divn(3).mul(s).ineg().imod(N));

        assert(p5.eq(p6));

        if (i === 0) {
          g.pre = null;
          continue;
        }

        if (i === 1) {
          assert(g === curve.g);
          g.pre = pre;
        }

        if (i === 2)
          assert(g !== curve.g);

        g = p6;
      }

      assert(curve.g.pre === pre);
    });

    it('should match multiplications (endo)', () => {
      const curve = new curves.SECP256K1();

      curve.precompute(rng);

      const N = curve.n;

      const mul = (p, k) => curve._endoWnafMulAdd([p], [k]).toP();
      const jmul = (p, k) => curve._endoWnafMulAdd([p], [k]);
      const pre = curve.g.pre;

      let g = curve.g;

      for (let i = 0; i < 3; i++) {
        const s = curve.randomScalar(rng);

        const p1 = mul(g, s);
        const p2 = g.mulSimple(s);

        assert(p1.eq(p2));

        const j1 = jmul(g, s);
        const j2 = g.jmulSimple(s);

        assert(j1.eq(j2));

        const p3 = mul(g, s.divn(3).mul(s));
        const p4 = g.mulSimple(s.divn(3).mul(s).imod(N));

        assert(p3.eq(p4));

        const p5 = mul(g, s.divn(3).mul(s).ineg());
        const p6 = g.mulSimple(s.divn(3).mul(s).ineg().imod(N));

        assert(p5.eq(p6));

        if (i === 0) {
          g.pre = null;
          continue;
        }

        if (i === 1) {
          assert(g === curve.g);
          g.pre = pre;
        }

        if (i === 2)
          assert(g !== curve.g);

        g = p6;
      }

      assert(curve.g.pre === pre);
    });

    it('should match multiplications (blind)', () => {
      const curve = new curves.SECP256K1();

      curve.precompute(rng);

      const N = curve.n;

      const mul = (p, k) => p.mulBlind(k, rng);
      const jmul = (p, k) => p.jmulBlind(k, rng);
      const pre = curve.g.pre;

      let g = curve.g;

      for (let i = 0; i < 3; i++) {
        const s = curve.randomScalar(rng);

        const p1 = mul(g, s);
        const p2 = g.mulSimple(s);

        assert(p1.eq(p2));

        const j1 = jmul(g, s);
        const j2 = g.jmulSimple(s);

        assert(j1.eq(j2));

        const p3 = mul(g, s.divn(3).mul(s));
        const p4 = g.mulSimple(s.divn(3).mul(s).imod(N));

        assert(p3.eq(p4));

        const p5 = mul(g, s.divn(3).mul(s).ineg());
        const p6 = g.mulSimple(s.divn(3).mul(s).ineg().imod(N));

        assert(p5.eq(p6));

        if (i === 0) {
          g.pre = null;
          continue;
        }

        if (i === 1) {
          assert(g === curve.g);
          g.pre = pre;
        }

        if (i === 2)
          assert(g !== curve.g);

        g = p6;
      }

      assert(curve.g.pre === pre);
    });

    it('should match multiply+add', () => {
      const p256 = new curves.P256();
      const secp256k1 = new curves.SECP256K1();
      const ed25519 = new curves.ED25519();

      for (const curve of [p256, secp256k1, ed25519]) {
        const N = curve.n;
        const s = curve.randomScalar(rng);
        const A = curve.randomPoint(rng);
        const J = A.toJ();
        const s0 = curve.randomScalar(rng);

        curve.precompute(rng);

        const p1 = curve.g.mulAdd(s, A, s0);
        const p2 = curve.g.mulAddSimple(s, A, s0);

        assert(p1.eq(p2));

        const j1 = curve.g.jmulAdd(s, A, s0);
        const j2 = curve.g.jmulAddSimple(s, A, s0);

        assert(j1.eq(j2));

        const j3 = curve.g.toJ().mulAdd(s, J, s0);
        const j4 = curve.g.toJ().mulAddSimple(s, J, s0);

        assert(j3.eq(j4));

        const p3 = curve.g.mulAdd(s.divn(3).mul(s), A, s0);
        const p4 = curve.g.mulAddSimple(s.divn(3).mul(s).imod(N), A, s0);
        const p4_ = curve.g.mulAddSimple(s.divn(3).mul(s), A, s0);

        assert(p3.eq(p4));
        assert(p4_.eq(p4));

        const p5 = curve.g.mulAdd(s.divn(3).mul(s).ineg(), A, s0);
        const p6 = curve.g.mulAddSimple(s.divn(3).mul(s).ineg().imod(N), A, s0);
        const p6_ = curve.g.mulAddSimple(s.divn(3).mul(s).ineg(), A, s0);

        assert(p5.eq(p6));
        assert(p6_.eq(p6));
      }
    });

    it('should multiply negative scalar', () => {
      const p256 = new curves.P256();
      const secp256k1 = new curves.SECP256K1();
      const ed25519 = new curves.ED25519();

      for (const curve of [p256, secp256k1, ed25519]) {
        const N = curve.n;
        const s1 = curve.randomScalar(rng);

        curve.precompute(rng);

        {
          const p1 = curve.g.mul(s1);
          const p2 = curve.g.mul(s1.neg());

          assert(!p2.isInfinity());
          assert(p2.eq(p1.neg()));

          const s2 = s1.sqr();

          const p3 = curve.g.mul(s2);
          const p4 = curve.g.mul(s2.neg());

          assert(!p4.isInfinity());
          assert(p4.eq(p3.neg()));

          const s3 = s2.divn(17);
          const p5 = p1.mul(s3);
          const p6 = p1.mul(s3.neg());

          assert(!p6.isInfinity());
          assert(p6.eq(p5.neg()));

          const s4 = s3.mod(N);
          const p7 = p2.mul(s4);
          const p8 = p2.mul(s4.neg());

          assert(!p8.isInfinity());
          assert(p8.eq(p7.neg()));
        }

        {
          const p1 = curve.g.jmul(s1);
          const p2 = curve.g.jmul(s1.neg());

          assert(!p2.isInfinity());
          assert(p2.eq(p1.neg()));

          const s2 = s1.sqr();

          const p3 = curve.g.jmul(s2);
          const p4 = curve.g.jmul(s2.neg());

          assert(!p4.isInfinity());
          assert(p4.eq(p3.neg()));

          const s3 = s2.divn(17);
          const p5 = p1.jmul(s3);
          const p6 = p1.jmul(s3.neg());

          assert(!p6.isInfinity());
          assert(p6.eq(p5.neg()));

          const s4 = s3.mod(N);
          const p7 = p2.jmul(s4);
          const p8 = p2.jmul(s4.neg());

          assert(!p8.isInfinity());
          assert(p8.eq(p7.neg()));
        }

        {
          const p1 = curve.g.mulBlind(s1, rng);
          const p2 = curve.g.mulBlind(s1.neg(), rng);

          assert(!p2.isInfinity());
          assert(p2.eq(p1.neg()));

          const s2 = s1.sqr();

          const p3 = curve.g.mulBlind(s2, rng);
          const p4 = curve.g.mulBlind(s2.neg(), rng);

          assert(!p4.isInfinity());
          assert(p4.eq(p3.neg()));

          const s3 = s2.divn(17);
          const p5 = p1.mulBlind(s3, rng);
          const p6 = p1.mulBlind(s3.neg(), rng);

          assert(!p6.isInfinity());
          assert(p6.eq(p5.neg()));

          const s4 = s3.mod(N);
          const p7 = p2.mulBlind(s4, rng);
          const p8 = p2.mulBlind(s4.neg(), rng);

          assert(!p8.isInfinity());
          assert(p8.eq(p7.neg()));
        }
      }
    });

    it('should multiply+add negative scalar', () => {
      const p256 = new curves.P256();
      const secp256k1 = new curves.SECP256K1();
      const ed25519 = new curves.ED25519();

      for (const curve of [p256, secp256k1, ed25519]) {
        const N = curve.n;
        const A = curve.randomPoint(rng);
        const J = A.toJ();
        const s0 = curve.randomScalar(rng);
        const as0 = A.mul(s0);
        const js0 = as0.toJ();
        const s1 = curve.randomScalar(rng);

        curve.precompute(rng);

        {
          const p1 = curve.g.mul(s1).neg().add(as0);
          const p2 = curve.g.mulAdd(s1.neg(), A, s0);

          assert(!p2.isInfinity());
          assert(p2.eq(p1));

          const s2 = s1.sqr();

          const p3 = curve.g.mul(s2).neg().add(as0);
          const p4 = curve.g.mulAdd(s2.neg(), A, s0);

          assert(!p4.isInfinity());
          assert(p4.eq(p3));

          const s3 = s2.divn(17);
          const p5 = p1.mul(s3).neg().add(as0);
          const p6 = p1.mulAdd(s3.neg(), A, s0);

          assert(!p6.isInfinity());
          assert(p6.eq(p5));

          const s4 = s3.mod(N);
          const p7 = p2.mul(s4).neg().add(as0);
          const p8 = p2.mulAdd(s4.neg(), A, s0);

          assert(!p8.isInfinity());
          assert(p8.eq(p7));
        }

        {
          const p1 = curve.g.jmul(s1).neg().add(js0);
          const p2 = curve.g.jmulAdd(s1.neg(), A, s0);

          assert(!p2.isInfinity());
          assert(p2.eq(p1));

          const s2 = s1.sqr();

          const p3 = curve.g.jmul(s2).neg().add(js0);
          const p4 = curve.g.jmulAdd(s2.neg(), A, s0);

          assert(!p4.isInfinity());
          assert(p4.eq(p3));

          const s3 = s2.divn(17);
          const p5 = p1.jmul(s3).neg().add(js0);
          const p6 = p1.jmulAdd(s3.neg(), J, s0);

          assert(!p6.isInfinity());
          assert(p6.eq(p5));

          const s4 = s3.mod(N);
          const p7 = p2.jmul(s4).neg().add(js0);
          const p8 = p2.jmulAdd(s4.neg(), J, s0);

          assert(!p8.isInfinity());
          assert(p8.eq(p7));
        }
      }
    });

    it('should correctly recover Y', () => {
      const ed25519 = new curves.ED25519();
      const x = ed25519.g.getX();
      const y = ed25519.g.y.redIsOdd();
      const g = ed25519.pointFromX(x, y);
      const r = ed25519.pointFromR(x);

      assert(ed25519.g.eq(g));
      assert(ed25519.g.eq(r));
    });

    it('should have basepoint for x25519', () => {
      // https://tools.ietf.org/html/rfc7748#section-4.1
      const x25519 = new curves.X25519();
      const v = x25519.g.getY(1);

      // Note: this is negated.
      const e = new BN('147816194475895447910205935684099868872'
                     + '64606134616475288964881837755586237401', 10);

      assert(v.cmp(e) === 0);
      assert(x25519.g.validate());
    });

    it('should have basepoint for x448', () => {
      // https://tools.ietf.org/html/rfc7748#section-4.2
      const x448 = new curves.X448();
      const v = x448.g.getY(0);

      // Note: this is negated.
      const e = new BN('355293926785568175264127502063783334808'
                     + '976399387714271831880898435169088786967'
                     + '410002932673765864550910142774147268105'
                     + '838985595290606362', 10);

      assert(v.cmp(e) === 0);
      assert(x448.g.validate());
    });

    it('should test birational equivalence', () => {
      const ed25519 = new curves.ED25519();
      const x25519 = new curves.X25519();
      const edwardsG = ed25519.pointFromMont(x25519.g, false);
      const montG = x25519.pointFromEdwards(ed25519.g);

      assert(edwardsG.eq(ed25519.g));
      assert(montG.eq(x25519.g));
    });

    it('should test 4-isogeny equivalence', () => {
      const ed448 = new curves.ED448();
      const x448 = new curves.X448();
      const montG = x448.pointFromEdwards(ed448.g);

      assert(montG.eq(x448.g));

      assert.throws(() => ed448.pointFromMont(x448.g, false));
    });

    it('should test unified addition', () => {
      const curve = new curves.SECP256K1();

      const vectors = [
        // G + R
        [
          [
            '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
            '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
          ],
          [
            '9474d13ad9314a46210de4b7e846bc2324fc0638cc77f88a84ebf6c283c704f4 ',
            '161e854a5015fd39b45c32c1897b1cd423ffdd4a4dbad2b09fb56351cf7e2c4e'
          ]
        ],
        // R + R
        [
          [
            'c7f5c3fe72dd8e0c7c71efc5ce1611115419e5a6cf5d645ee30f3603fca08a29',
            '58fb0e0348a4bee8b4e8cd253f6429135fc7c556a0c5af87d6ca6194166a6790'
          ],
          [
            'd63f7ed3c5ef0f3caeae2d2baf3d3636a12a993e0a72fe81d1beb0589dcc7687',
            '383d0b172413048a5deff4ffca1b183645fc6f2c82e881c790fdb2fb178834d6'
          ]
        ],
        // M = 0, R = 0
        [
          [
            '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
            '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
          ],
          [
            'bcace2e99da01887ab0102b696902325872844067f15e98da7bba04400b88fcb',
            'b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777'
          ]
        ],
        [
          [
            'f96e09c5f26fa15c38fd52282087c96a53411a75d4a65a9faed9c1113955b28f',
            'cf867faf174f422673a146bec0fc41e0d1082e4a6e2711012c30ed49cfa7c360'
          ],
          [
            '3ba398aa59edee676a580508b285c92cbad4d45f9bd24c9b0e635ac1b7ec5dbb',
            '30798050e8b0bdd98c5eb9413f03be1f2ef7d1b591d8eefed3cf12b5305838cf'
          ]
        ],
        [
          [
            'eef57567a6beda8b2307bdb2e2d64649ca3da5e99b0e6e600b258ed7fc5c6432',
            '76cdd5f153bd292bc5c0aa451f70d4adc43f0fb6944cc75dea850bf87701061a'
          ],
          [
            'ff429d7bb1932077e2f99ebfc8da744fcace96ed151e77f6935836a51584c204',
            '89322a0eac42d6d43a3f55bae08f2b523bc0f0496bb338a2157af40688fef615'
          ]
        ],
        // M = 0, R != 0
        [
          [
            '89cef607c2cfe639107741129288f9508df3537abe429af16fc42a86b684b0d2',
            'aa2ecd65992c94e9cc8e4013ac0f3d08b588d7a4b3b25e8612642c5498e9ab2b'
          ],
          [
            '89cef607c2cfe639107741129288f9508df3537abe429af16fc42a86b684b0d2',
            '55d1329a66d36b163371bfec53f0c2f74a77285b4c4da179ed9bd3aa67165104'
          ]
        ],
        [
          [
            '2a6603cea614a0034057d7bfc56949743a2e3c15d1a4cfb7920cb9652d0bfbe8',
            'cc36607d45f9aed4bbe93d212456ffdd481337da39c141c8d82a5db283679c40'
          ],
          [
            '2a6603cea614a0034057d7bfc56949743a2e3c15d1a4cfb7920cb9652d0bfbe8',
            '33c99f82ba06512b4416c2dedba90022b7ecc825c63ebe3727d5a24c7c985fef'
          ]
        ],
        // M != 0, R = 0
        [
          [
            'f96e09c5f26fa15c38fd52282087c96a53411a75d4a65a9faed9c1113955b28f',
            'cf867faf174f422673a146bec0fc41e0d1082e4a6e2711012c30ed49cfa7c360'
          ],
          [
            '3ba398aa59edee676a580508b285c92cbad4d45f9bd24c9b0e635ac1b7ec5dbb',
            'cf867faf174f422673a146bec0fc41e0d1082e4a6e2711012c30ed49cfa7c360'
          ]
        ],
        [
          [
            '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
            '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
          ],
          [
            'bcace2e99da01887ab0102b696902325872844067f15e98da7bba04400b88fcb',
            '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
          ]
        ],
        [
          [
            'eef57567a6beda8b2307bdb2e2d64649ca3da5e99b0e6e600b258ed7fc5c6432',
            '76cdd5f153bd292bc5c0aa451f70d4adc43f0fb6944cc75dea850bf87701061a'
          ],
          [
            'ff429d7bb1932077e2f99ebfc8da744fcace96ed151e77f6935836a51584c204',
            '76cdd5f153bd292bc5c0aa451f70d4adc43f0fb6944cc75dea850bf87701061a'
          ]
        ]
      ];

      for (const [json1, json2] of vectors) {
        const o = curve.point();
        const p = curve.pointFromJSON(json1);
        const q = curve.pointFromJSON(json2);
        const r = p.add(q);

        const oj = curve.jpoint();
        const pj = p.toJ().randomize(rng);
        const qj = q.toJ().scale(pj.z);
        const rj = pj.add(qj);

        // Sanity check for affine.
        assert(r.toJ().eq(rj));

        assert(p.add(o).eq(p));
        assert(o.add(p).eq(p));
        assert(o.add(o).eq(o));

        // Sanity check for jacobian.
        assert(rj.toP().eq(r));

        assert(pj.add(oj).eq(pj));
        assert(oj.add(pj).eq(pj));
        assert(oj.add(oj).eq(oj));

        // Sanity check for jacobian (mixed).
        assert(pj.add(o).eq(pj));
        assert(oj.add(p).eq(pj));
        assert(oj.add(o).eq(oj));

        // Affine unified.
        assert(p.uadd(q).eq(r));
        assert(p.uadd(p).eq(p.dbl()));
        assert(q.uadd(q).eq(q.dbl()));
        assert(p.udbl().eq(p.dbl()));
        assert(q.udbl().eq(q.dbl()));

        assert(p.uadd(o).eq(p));
        assert(o.uadd(p).eq(p));
        assert(o.uadd(o).eq(o));

        // Jacobian unified.
        assert(pj.uadd(qj).eq(rj));
        assert(pj.uadd(pj).eq(pj.dbl()));
        assert(qj.uadd(qj).eq(qj.dbl()));
        assert(pj.udbl().eq(pj.dbl()));
        assert(qj.udbl().eq(qj.dbl()));

        assert(pj.uadd(oj).eq(pj));
        assert(oj.uadd(pj).eq(pj));
        assert(oj.uadd(oj).eq(oj));

        // Jacobian unified (mixed).
        assert(pj.uadd(q).eq(rj));
        assert(pj.uadd(p).eq(pj.dbl()));
        assert(qj.uadd(q).eq(qj.dbl()));

        assert(pj.uadd(o).eq(pj));
        assert(oj.uadd(p).eq(pj));
        assert(oj.uadd(o).eq(oj));

        // Jacobian Co-Z.
        assert(pj.zaddu(qj)[0].eq(rj));
        assert(pj.zaddc(qj)[0].eq(rj));
        assert(pj.zdblu()[0].eq(pj.dbl()));
        assert(qj.zdblu()[0].eq(qj.dbl()));
        assert(pj.ztrplu()[0].eq(pj.trpl()));
        assert(qj.ztrplu()[0].eq(qj.trpl()));
        assert(pj.zaddu(pj.neg())[0].eq(oj));
        assert(pj.zaddc(pj.neg())[0].eq(oj));
        assert(oj.zdblu()[0].eq(oj));
        assert(oj.ztrplu()[0].eq(oj));
      }
    });

    it('should test adding when lambda=0', () => {
      const curve = new curves.SECP256K1();

      const p = curve.pointFromJSON([
        'f96e09c5f26fa15c38fd52282087c96a53411a75d4a65a9faed9c1113955b28f',
        'cf867faf174f422673a146bec0fc41e0d1082e4a6e2711012c30ed49cfa7c360'
      ]);

      const q = curve.pointFromJSON([
        '3ba398aa59edee676a580508b285c92cbad4d45f9bd24c9b0e635ac1b7ec5dbb',
        'cf867faf174f422673a146bec0fc41e0d1082e4a6e2711012c30ed49cfa7c360'
      ]);

      const r = p.toJ().add(q).toP();

      assert(p.add(q).eq(r));
      assert(p.uadd(q).eq(r));
    });

    it('should test doubling when lambda=0', () => {
      const curve = new curves.P521();
      const p = curve.pointFromX(new BN(1), false);
      const q = p.toJ().dbl().toP();

      assert(p.dbl().eq(q));
    });

    it('should test montgomery multiplication', () => {
      const curve = new curves.X25519();
      const k = curve.randomScalar(rng);
      const p = curve.g.mul(k);

      assert(curve.g.mul(k).eq(p));
      assert(curve.g.mulSimple(k).eq(p));
      assert(curve.g.mulConst(k).eq(p));
      assert(curve.g.mulBlind(k).eq(p));
      assert(curve.g.mulBlind(k, rng).eq(p));
      assert(curve.g.mulConst(k, rng).eq(p));

      {
        const m = curve.n.muln(17);
        const p1 = curve.g.mul(k.mul(m));
        const p2 = curve.g.mulSimple(k.mul(m));
        const p3 = curve.g.mulConst(k.mul(m));
        const p4 = curve.g.mul(k.mul(m).imod(curve.n));
        const p5 = curve.g.mulSimple(k.mul(m).imod(curve.n));
        const p6 = curve.g.mulBlind(k.mul(m).imod(curve.n));
        const p7 = curve.g.mulBlind(k.mul(m).imod(curve.n), rng);
        const p8 = curve.g.mulConst(k.mul(m).imod(curve.n));
        const p9 = curve.g.mulConst(k.mul(m).imod(curve.n), rng);

        assert(p1.eq(p2));
        assert(p2.eq(p3));
        assert(p3.eq(p4));
        assert(p4.eq(p5));
        assert(p5.eq(p6));
        assert(p6.eq(p7));
        assert(p8.eq(p9));
      }

      {
        const p1 = curve.g.mul(k.neg());
        const p2 = curve.g.mulSimple(k.neg());
        const p3 = curve.g.mulConst(k.neg());
        const p4 = curve.g.mul(k.neg().imod(curve.n));
        const p5 = curve.g.mulSimple(k.neg().imod(curve.n));
        const p6 = curve.g.mulBlind(k.neg().imod(curve.n));
        const p7 = curve.g.mulBlind(k.neg().imod(curve.n), rng);
        const p8 = curve.g.mulConst(k.neg().imod(curve.n));
        const p9 = curve.g.mulConst(k.neg().imod(curve.n), rng);

        assert(p1.eq(p2));
        assert(p2.eq(p3));
        assert(p3.eq(p4));
        assert(p4.eq(p5));
        assert(p5.eq(p6));
        assert(p6.eq(p7));
        assert(p8.eq(p9));
      }
    });

    it('should test montgomery multiplication and conversion', () => {
      const ed25519 = new curves.ED25519();
      const x25519 = new curves.X25519();
      const g = x25519.randomPoint(rng);
      const k = x25519.reduce(x25519.randomScalar(rng));

      const p = g.mul(k);

      const eg = ed25519.pointFromMont(g, false);
      const ep1 = ed25519.pointFromMont(p, false);
      const ep2 = ed25519.pointFromMont(p, true);

      const ep = eg.mul(k);

      assert(ep.eq(ep1) || ep.eq(ep2));
    });

    it('should test x equality', () => {
      const secp256k1 = new curves.SECP256K1();
      const ed25519 = new curves.ED25519();

      for (const curve of [secp256k1, ed25519]) {
        const p = curve.randomPoint(rng);
        const x = p.getX();
        const r = p.randomize(rng);

        assert(p.eqX(x));
        assert(p.eqXToP(x));
        assert(r.eqX(x));
        assert(r.eqXToP(x));

        x.iaddn(1);

        assert(!p.eqX(x));
        assert(!p.eqXToP(x));
        assert(!r.eqX(x));
        assert(!r.eqXToP(x));
      }
    });

    it('should test x equality (mont)', () => {
      const curve = new curves.X448();
      const p = curve.randomPoint(rng);
      const x = p.getX();
      const r = p.randomize(rng);

      assert(p.eqX(x));
      assert(r.eqX(x));

      x.iaddn(1);

      assert(!p.eqX(x));
      assert(!r.eqX(x));
    });

    it('should test fuzzy x equality', () => {
      const secp256k1 = new curves.SECP256K1();
      const ed25519 = new curves.ED25519();

      for (const curve of [secp256k1, ed25519]) {
        let p;

        for (;;) {
          const x = BN.random(rng, curve.n, curve.p);
          const s = BN.random(rng, 0, 2);

          try {
            p = curve.pointFromX(x, s.isOdd());
          } catch (e) {
            continue;
          }

          break;
        }

        const x = p.getX().imod(curve.n);

        assert(x.cmp(p.getX()) < 0);

        assert(p.eqXToP(x));
        assert(!p.eqXToP(x.subn(1)));
        assert(!p.eqXToP(x.addn(1)));

        const r = p.randomize(rng);

        assert(r.eqXToP(x));
        assert(!r.eqXToP(x.subn(1)));
        assert(!r.eqXToP(x.addn(1)));
      }
    });

    it('should test swapping (jacobi, edwards)', () => {
      const secp256k1 = new curves.SECP256K1();
      const ed25519 = new curves.ED25519();

      for (const curve of [secp256k1, ed25519]) {
        const p1 = curve.randomPoint(rng).toJ();
        const p2 = curve.randomPoint(rng).randomize(rng);
        const q1 = p1.clone();
        const q2 = p2.clone();

        q1.swap(q2, 0);

        assert(q1.clone().eq(p1.clone()));
        assert(q2.clone().eq(p2.clone()));
        assert(q1.zOne);
        assert(!q2.zOne);

        q1.swap(q2, 1);

        assert(q1.clone().eq(p2.clone()));
        assert(q2.clone().eq(p1.clone()));
        assert(!q1.zOne);
        assert(q2.zOne);
      }
    });

    it('should test mont swapping', () => {
      const curve = new curves.X25519();
      const p1 = curve.randomPoint(rng);
      const p2 = curve.randomPoint(rng).randomize(rng);
      const q1 = p1.clone();
      const q2 = p2.clone();

      q1.swap(q2, 0);

      assert(q1.clone().eq(p1.clone()));
      assert(q2.clone().eq(p2.clone()));

      q1.swap(q2, 1);

      assert(q1.clone().eq(p2.clone()));
      assert(q2.clone().eq(p1.clone()));
    });

    it('should test jacobian equality', () => {
      const curve = new curves.SECP256K1();
      const p1 = curve.randomPoint(rng).randomize(rng);
      const p2 = p1.clone();
      const p3 = curve.randomPoint(rng).scale(p1.z);
      const p4 = p1.clone().normalize().randomize(rng);

      assert(p1 !== p2);
      assert(p1.z.eq(p2.z));
      assert(p1.eq(p2));

      assert(p1 !== p3);
      assert(p1.z.eq(p3.z));
      assert(!p1.eq(p3));

      assert(p1 !== p4);
      assert(!p1.z.eq(p4.z));
      assert(p1.eq(p4));
    });

    it('should test quad y', () => {
      const secp256k1 = new curves.SECP256K1();
      const ed25519 = new curves.ED25519();

      for (const curve of [secp256k1, ed25519]) {
        for (let i = 0; i < 100; i++) {
          const p = curve.randomPoint(rng);
          const q = p.normalize().y.redJacobi() === 1;
          const r = p.randomize(rng);

          assert.strictEqual(p.hasQuadY(), q);
          assert.strictEqual(r.hasQuadY(), q);
        }
      }
    });

    it('should test validation', () => {
      const p256 = new curves.P256();
      const ed25519 = new curves.ED25519();
      const x25519 = new curves.X25519();
      const ed448 = new curves.ED448();

      for (const curve of [p256, ed25519, x25519, ed448]) {
        const p = curve.randomPoint(rng);

        assert(p.validate());
        assert(p.toJ().validate());
        assert(p.randomize(rng).validate());
      }
    });

    it('should test equality', () => {
      const p256 = new curves.P256();
      const ed25519 = new curves.ED25519();
      const x25519 = new curves.X25519();
      const ed448 = new curves.ED448();

      for (const curve of [p256, ed25519, x25519, ed448]) {
        const p = curve.randomPoint(rng).randomize(rng);
        const q = p.randomize(rng);
        const o = curve.jpoint();

        assert(p.eq(q));
        assert(!p.eq(o));

        q.x.inject(curve.one);

        assert(!p.eq(q));
      }
    });

    it('should test brier-joye y recovery (affine)', () => {
      const curve = new curves.P256();
      const k = curve.randomScalar(rng);
      const expect = curve.g.mul(k);

      const x1 = curve.g.mul(k.addn(0)).x;
      const x2 = curve.g.mul(k.addn(1)).x;

      const p = curve.g.recover(x1, x2);

      assert(p.eq(expect));
    });

    it('should test brier-joye y recovery (jacobian)', () => {
      const curve = new curves.P256();
      const k = curve.randomScalar(rng);
      const expect = curve.g.jmul(k);

      const x1 = curve.g.mul(k.addn(0)).x;
      const x2 = curve.g.mul(k.addn(1)).x;

      const p = curve.g.randomize(rng).recover(x1, x2);
      const q = curve.g.recover(x1, x2);

      assert(p.eq(expect));
      assert(q.toJ().eq(expect));
    });

    it('should test okeya-sakurai y recovery (mont)', () => {
      const ed25519 = new curves.ED25519();
      const x25519 = new curves.X25519();
      const am2 = new BN(-486664).toRed(ed25519.red);
      const k = x25519.randomScalar(rng);
      const p = ed25519.g.mul(k).normalize();

      // u = (1 + y) / (1 - y)
      const u = p.z.redAdd(p.y).redMul(p.z.redSub(p.y).redInvert());

      // v = sqrt(-a - 2) * u / x
      const v = am2.redSqrt().redMul(u.redMul(p.x.redInvert()));

      const p1 = x25519.g.mulSimple(k.addn(0));
      const p2 = x25519.g.mulSimple(k.addn(1));

      // Returns an affinized X and Y.
      const [x, y] = x25519.g.randomize(rng).recover(p1, p2, 1);

      assert(x.eq(u));
      assert(y.eq(v));
    });

    it('should mul by cofactor', () => {
      const curve = new curves.ED25519();
      const p1 = curve.randomPoint(rng);
      const p2 = p1.mul(curve.h);
      const p3 = p1.mulSimple(curve.h);
      const p4 = p1.mulH();

      assert(p2.eq(p3));
      assert(p3.eq(p4));
    });

    it('should check for small order points (ed25519)', () => {
      const curve = new curves.ED25519();

      const small = [
        // 0 (order 1)
        // [
        //   '0000000000000000000000000000000000000000000000000000000000000000',
        //   '0000000000000000000000000000000000000000000000000000000000000001'
        // ],
        // 0 (order 2)
        [
          '0000000000000000000000000000000000000000000000000000000000000000',
          '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec'
        ],
        // 1 (order 4)
        [
          '547cdb7fb03e20f4d4b2ff66c2042858d0bce7f952d01b873b11e4d8b5f15f3d',
          '0000000000000000000000000000000000000000000000000000000000000000'
        ],
        [
          '2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0',
          '0000000000000000000000000000000000000000000000000000000000000000'
        ],
        // 325606250916557431795983626356110631294008115727848805560023387167927233504 (order 8)
        [
          '602a465ff9c6b5d716cc66cdc721b544a3e6c38fec1a1dc7215eb9b93aba2ea3',
          '7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7'
        ],
        [
          '1fd5b9a006394a28e933993238de4abb5c193c7013e5e238dea14646c545d14a',
          '7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7'
        ],
        // 39382357235489614581723060781553021112529911719440698176882885853963445705823 (order 8)
        [
          '602a465ff9c6b5d716cc66cdc721b544a3e6c38fec1a1dc7215eb9b93aba2ea3',
          '05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826'
        ],
        [
          '1fd5b9a006394a28e933993238de4abb5c193c7013e5e238dea14646c545d14a',
          '05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826'
        ]
      ];

      assert(!curve.g.isSmall());
      assert(!curve.g.hasSmall());

      // This is why edwards curves suck.
      for (const json of small) {
        // P = point of small order
        const p = curve.pointFromJSON(json);

        // Q = G + P
        const q = curve.g.add(p);

        assert(p.validate());
        assert(!p.isInfinity());
        assert(q.validate());
        assert(!q.isInfinity());

        // P * H == O
        assert(p.isSmall());

        // P * N != O
        assert(p.hasSmall());

        // Q * H != O
        assert(!q.isSmall());

        // Q * N != O
        assert(q.hasSmall());

        // Q * H == G * H
        assert(q.mulH().eq(curve.g.mulH()));
      }
    });

    it('should check for small order points (x25519)', () => {
      const curve = new curves.X25519();

      // Full list from: https://cr.yp.to/ecdh.html
      //
      // See also:
      // https://github.com/jedisct1/libsodium/blob/cec56d8/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L17
      // https://eprint.iacr.org/2017/806.pdf
      const small = [
        // 0 (order 1 & 2)
        ['0000000000000000000000000000000000000000000000000000000000000000'],
        // 1 (order 4)
        ['0000000000000000000000000000000000000000000000000000000000000001'],
        // 325606250916557431795983626356110631294008115727848805560023387167927233504 (order 8)
        ['00b8495f16056286fdb1329ceb8d09da6ac49ff1fae35616aeb8413b7c7aebe0'],
        // 39382357235489614581723060781553021112529911719440698176882885853963445705823 (order 8)
        ['57119fd0dd4e22d8868e1c58c45c44045bef839c55b1d0b1248c50a3bc959c5f'],
        // p - 1 (invalid)
        ['7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec'],
        // p (order 1 & 2)
        ['7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed'],
        // p + 1 (order 4)
        ['7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffee'],
        // p + 325606250916557431795983626356110631294008115727848805560023387167927233504 (order 8)
        ['80b8495f16056286fdb1329ceb8d09da6ac49ff1fae35616aeb8413b7c7aebcd'],
        // p + 39382357235489614581723060781553021112529911719440698176882885853963445705823 (order 8)
        ['d7119fd0dd4e22d8868e1c58c45c44045bef839c55b1d0b1248c50a3bc959c4c'],
        // 2 * p - 1 (invalid)
        ['ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd9'],
        // 2 * p (order 1 & 2)
        ['ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffda'],
        // 2 * p + 1 (order 4)
        ['ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdb']
      ];

      assert(!curve.g.isSmall());
      assert(!curve.g.hasSmall());

      let total = 0;

      for (const json of small) {
        const p = curve.pointFromJSON(json);

        if (p.validate()) {
          total += 1;
        } else {
          // Note that `p - 1`, and `2 * p - 1`
          // do not satisfy the curve equation.
          // `a - 2` is not a quadratic residue.
          assert(p.x.cmp(curve.one.redNeg()) === 0);
        }

        assert(!p.isInfinity());
        assert(p.isSmall());

        if (!p.x.isZero())
          assert(p.hasSmall());
      }

      assert.strictEqual(total, small.length - 2);
    });

    it('should check for small order points (ed448)', () => {
      const curve = new curves.ED448();

      // https://hyperelliptic.org/EFD/g1p/auto-edwards.html
      // - The neutral element of the curve is the point (0, c).
      // - The point (0, -c) has order 2.
      // - The points (c, 0) and (-c, 0) have order 4.
      const small = [
        // 0, c (order 1)
        // [
        //   ['00000000000000000000000000000000000000000000000000000000',
        //    '00000000000000000000000000000000000000000000000000000000'].join(''),
        //   ['00000000000000000000000000000000000000000000000000000000',
        //    '00000000000000000000000000000000000000000000000000000001'].join('')
        // ],
        // 0, -c (order 2, not 4-isogenous)
        [
          ['00000000000000000000000000000000000000000000000000000000',
           '00000000000000000000000000000000000000000000000000000000'].join(''),
          ['fffffffffffffffffffffffffffffffffffffffffffffffffffffffe',
           'fffffffffffffffffffffffffffffffffffffffffffffffffffffffe'].join('')
        ],
        // c, 0 (order 4)
        [
          ['00000000000000000000000000000000000000000000000000000000',
           '00000000000000000000000000000000000000000000000000000001'].join(''),
          ['00000000000000000000000000000000000000000000000000000000',
           '00000000000000000000000000000000000000000000000000000000'].join('')
        ],
        // -c, 0 (order 4)
        [
          ['fffffffffffffffffffffffffffffffffffffffffffffffffffffffe',
           'fffffffffffffffffffffffffffffffffffffffffffffffffffffffe'].join(''),
          ['00000000000000000000000000000000000000000000000000000000',
           '00000000000000000000000000000000000000000000000000000000'].join('')
        ]
      ];

      assert(!curve.g.isSmall());
      assert(!curve.g.hasSmall());

      // This is why edwards curves suck.
      for (const json of small) {
        // P = point of small order
        const p = curve.pointFromJSON(json);

        // Q = G + P
        const q = curve.g.add(p);

        assert(p.validate());
        assert(!p.isInfinity());
        assert(q.validate());
        assert(!q.isInfinity());

        // P * H == O
        assert(p.isSmall());

        // P * N != O
        assert(p.hasSmall());

        // Q * H != O
        assert(!q.isSmall());

        // Q * N != O
        assert(q.hasSmall());

        // Q * H == G * H
        assert(q.mulH().eq(curve.g.mulH()));
      }
    });

    it('should check for small order points (x448)', () => {
      const curve = new curves.X448();

      const small = [
        // 0 (order 1)
        [
          ['00000000000000000000000000000000000000000000000000000000',
           '00000000000000000000000000000000000000000000000000000000'].join('')
        ],
        // 1 (order 2, invalid, not 4-isogenous)
        [
          ['00000000000000000000000000000000000000000000000000000000',
           '00000000000000000000000000000000000000000000000000000001'].join('')
        ],
        // p - 1 (order 4)
        [
          ['fffffffffffffffffffffffffffffffffffffffffffffffffffffffe',
           'fffffffffffffffffffffffffffffffffffffffffffffffffffffffe'].join('')
        ],
        // p (order 1)
        [
          ['fffffffffffffffffffffffffffffffffffffffffffffffffffffffe',
           'ffffffffffffffffffffffffffffffffffffffffffffffffffffffff'].join('')
        ],
        // p + 1 (order, invalid, not 4-isogenous)
        [
          ['ffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
           '00000000000000000000000000000000000000000000000000000000'].join('')
        ]
      ];

      assert(!curve.g.isSmall());
      assert(!curve.g.hasSmall());

      let total = 0;

      for (const json of small) {
        const p = curve.pointFromJSON(json);

        if (p.validate()) {
          total += 1;
        } else {
          // Note that `1`, and `p + 1`
          // do not satisfy the curve equation.
          // `a + 2` is not a quadratic residue.
          assert(p.x.cmp(curve.one) === 0);
        }

        assert(!p.isInfinity());
        assert(p.isSmall());

        if (!p.x.isZero())
          assert(p.hasSmall());
      }

      assert.strictEqual(total, small.length - 2);
    });
  });

  describe('Point codec', () => {
    const makeShortTest = (definition) => {
      return () => {
        const curve = new curves.SECP256K1();
        const p = curve.pointFromJSON(definition.coords);

        // Encodes as expected
        assert.bufferEqual(p.encode(false), definition.encoded);
        assert.bufferEqual(p.encode(true), definition.compact);

        // Decodes as expected
        assert(curve.decodePoint(Buffer.from(definition.encoded, 'hex')).eq(p));
        assert(curve.decodePoint(Buffer.from(definition.compact, 'hex')).eq(p));
        assert(curve.decodePoint(Buffer.from(definition.hybrid, 'hex')).eq(p));
      };
    };

    const makeMontTest = (definition) => {
      return () => {
        const curve = new curves.X25519();
        const p = curve.pointFromJSON(definition.coords);
        const scalar = new BN(definition.scalar, 16);
        const encoded = p.encode();
        const decoded = curve.decodePoint(encoded);

        assert(decoded.eq(p));

        assert.bufferEqual(encoded, definition.encoded);
        assert.bufferEqual(curve.g.mul(scalar).encode(), encoded);
        assert.bufferEqual(curve.g.mulSimple(scalar).encode(), encoded);
        assert.bufferEqual(curve.g.mulConst(scalar).encode(), encoded);
        assert.bufferEqual(curve.g.mulBlind(scalar).encode(), encoded);
        assert.bufferEqual(curve.g.mulBlind(scalar, rng).encode(), encoded);
        assert.bufferEqual(curve.g.mulConst(scalar, rng).encode(), encoded);
      };
    };

    const shortPointEvenY = {
      coords: [
        '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
        '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
      ],
      compact: '02'
        + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
      encoded: '04'
        + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
        + '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
      hybrid: '06'
        + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
        + '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
    };

    const shortPointOddY = {
      coords: [
        'fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556',
        'ae12777aacfbb620f3be96017f45c560de80f0f6518fe4a03c870c36b075f297'
      ],
      compact: '03'
        + 'fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556',
      encoded: '04'
        + 'fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556'
        + 'ae12777aacfbb620f3be96017f45c560de80f0f6518fe4a03c870c36b075f297',
      hybrid: '07'
        + 'fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556'
        + 'ae12777aacfbb620f3be96017f45c560de80f0f6518fe4a03c870c36b075f297'
    };

    it('should throw when trying to decode random bytes', () => {
      const secp256k1 = new curves.SECP256K1();

      assert.throws(() => {
        secp256k1.decodePoint(Buffer.from(
          '0579be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
          'hex'));
      });
    });

    it('should be able to encode/decode a short curve point with even Y',
        makeShortTest(shortPointEvenY));

    it('should be able to encode/decode a short curve point with odd Y',
        makeShortTest(shortPointOddY));

    it('should be able to encode/decode a mont curve point', makeMontTest({
      scalar: '6',
      coords: [
        '26954ccdc99ebf34f8f1dde5e6bb080685fec73640494c28f9fe0bfa8c794531'
      ],
      encoded:
        '3145798cfa0bfef9284c494036c7fe850608bbe6e5ddf1f834bf9ec9cd4c9526'
    }));
  });

  describe('E521', () => {
    it('should have E521', () => {
      const e521 = new curves.E521();
      const inf = e521.point();

      assert(e521.g.validate());
      assert(e521.g.dbl().validate());
      assert(e521.g.trpl().validate());
      assert(e521.g.dbl().dbl().validate());
      assert(e521.g.mul(e521.n).eq(inf));
      assert(!e521.g.mul(e521.n.subn(1)).eq(inf));
      assert(e521.g.mul(e521.n.addn(1)).eq(e521.g));
      assert(e521.g.mul(new BN(1)).eq(e521.g));
      assert(e521.g.mul(new BN(2)).eq(e521.g.dbl()));
      assert(e521.g.mul(new BN(3)).eq(e521.g.trpl()));
    });

    it('should clamp properly', () => {
      const e521 = new curves.E521();
      const scalar = rng.randomBytes(e521.p.byteLength());

      e521.clamp(scalar);

      assert(e521.isClamped(scalar));
    });

    it('should handle difference in scalar/field bytes', () => {
      const e521 = new EDDSA('E521', null, SHAKE256);

      const msg = rng.randomBytes(e521.size);
      const secret = e521.privateKeyGenerate();
      const pub = e521.publicKeyCreate(secret);

      assert(e521.publicKeyVerify(pub));

      const sig = e521.sign(msg, secret);

      assert(e521.verify(msg, sig, pub));

      sig[0] ^= 1;

      assert(!e521.verify(msg, sig, pub));
    });

    it('should do diffie hellman', () => {
      const e521 = new EDDSA('E521', null, SHAKE256);

      const alicePriv = e521.privateKeyGenerate();
      const alicePub = e521.publicKeyCreate(alicePriv);

      const bobPriv = e521.privateKeyGenerate();
      const bobPub = e521.publicKeyCreate(bobPriv);

      const aliceSecret = e521.derive(bobPub, alicePriv);
      const bobSecret = e521.derive(alicePub, bobPriv);

      assert.bufferEqual(aliceSecret, bobSecret);
    });
  });
});
