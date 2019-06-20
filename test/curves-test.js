'use strict';

const assert = require('bsert');
const BN = require('../lib/bn.js');
const curves = require('../lib/js/curves');
const rng = require('../lib/random');

const {
  ShortCurve,
  EdwardsCurve,
  SECP256K1,
  ED25519,
  X25519
} = curves;

let secp256k1 = null;
let ed25519 = null;
let x25519 = null;

describe('Curves', function() {
  describe('Precomputation', () => {
    it('should have precomputed curves', () => {
      secp256k1 = new SECP256K1();
      secp256k1.precompute(rng);

      ed25519 = new ED25519();
      ed25519.precompute(rng);

      x25519 = new X25519();
      x25519.precompute(rng);

      assert(secp256k1.g.precomputed);
      assert(ed25519.g.precomputed);
      assert(!x25519.g.precomputed);
    });
  });

  describe('Curve', () => {
    it('should work with example curve', () => {
      const curve = new ShortCurve({
        p: '1d',
        a: '4',
        b: '14'
      });

      const p = curve.point(new BN('18', 16), new BN('16', 16));

      assert(p.validate());
      assert(p.dbl().validate());
      assert(p.dbl().add(p).validate());
      assert(p.dbl().add(p.dbl()).validate());
      assert(p.dbl().add(p.dbl()).eq(p.add(p).add(p).add(p)));
    });

    it('should dbl points on edwards curve using proj coordinates', () => {
      const curve = new EdwardsCurve({
        p: '3fffffffffffffffffffffffffffffffffffffffffffffff'
         + 'ffffffffffffffffffffffffffffffffffffffffffffff97',
        n: '0fffffffffffffffffffffffffffffffffffffffffffffff'
         + 'd5fb21f21e95eee17c5e69281b102d2773e27e13fd3c9719',
        h: '8',
        a: '1',
        c: '1',
        // -67254 mod p
        d: '3fffffffffffffffffffffffffffffffffffffffffffffff'
         + 'fffffffffffffffffffffffffffffffffffffffffffef8e1',
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
        n: '01fffffffffffffffffffffffffffffff77965c4dfd307348944d45fd166c971',
        h: '4',
        a: '1',
        // -1174 mod p
        d: '07fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb61',
        c: '1'
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
    });

    it('should find an odd point given a y coordinate', () => {
      const curve = new EdwardsCurve({
        p: '7fffffffffffffff ffffffffffffffff'
         + 'ffffffffffffffff ffffffffffffffed',
        a: '-1',
        c: '1',
        // -121665 * (121666^(-1)) (mod P)
        d: '52036cee2b6ffe73 8cc740797779e898'
         + '00700a4d4141d8ab 75eb4dca135978a3',
        n: '1000000000000000 0000000000000000'
         + '14def9dea2f79cd6 5812631a5cf5d3ed',
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

    it('should work with secp112k1', () => {
      const curve = new ShortCurve({
        p: 'db7c 2abf62e3 5e668076 bead208b',
        n: 'db7c 2abf62e3 5e7628df ac6561c5',
        a: 'db7c 2abf62e3 5e668076 bead2088',
        b: '659e f8ba0439 16eede89 11702b22'
      });

      const p = curve.point(
        new BN('0948 7239995a 5ee76b55 f9c2f098', 16),
        new BN('a89c e5af8724 c0a23e0e 0ff77500', 16));

      assert(p.validate());
      assert(p.dbl().validate());
    });

    it('should work with secp256k1', () => {
      const curve = new ShortCurve({
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

      const p = curve.point(
        new BN('79be667e f9dcbbac 55a06295 ce870b07'
             + '029bfcdb 2dce28d9 59f2815b 16f81798', 16),
        new BN('483ada77 26a3c465 5da4fbfc 0e1108a8'
             + 'fd17b448 a6855419 9c47d08f fb10d4b8', 16)
      );

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

      const k = new BN('1234567890123456789012345678901234', 16);
      const [k1, k2] = curve._endoSplit(k);

      const testK = k1.add(k2.mul(curve.endo.lambda)).mod(curve.n);

      assert.strictEqual(testK.toString(16), k.toString(16));
    });

    it('should compute this problematic secp256k1 multiplication', () => {
      const curve = secp256k1;

      const g1 = curve.g; // precomputed g
      assert(g1.precomputed);

      const g2 = curve.point(g1.getX(), g1.getY()); // not precomputed g
      assert(!g2.precomputed);

      const a = new BN(
        '6d1229a6b24c2e775c062870ad26bc261051e0198c67203167273c7c62538846',
        16);

      const p1 = g1.mul(a);
      const p2 = g2.mul(a);

      assert(p1.eq(p2));
    });

    it('should not use fixed NAF when k is too large', () => {
      const curve = secp256k1;
      const g1 = curve.g; // precomputed g

      assert(g1.precomputed);

      const g2 = curve.point(g1.getX(), g1.getY()); // not precomputed g
      assert(!g2.precomputed);

      const a = new BN('6d1229a6b24c2e775c062870ad26bc26105'
                     + '1e0198c67203167273c7c6253884612345678', 16);

      const p1 = g1.mul(a);
      const p2 = g2.mul(a);

      assert(p1.eq(p2));
    });

    it('should not fail on secp256k1 regression', () => {
      const curve = secp256k1;

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

      const curve = secp256k1;
      const pbad = curve.jpoint(bad.x, bad.y, bad.z);
      const pgood = curve.jpoint(good.x, good.y, good.z);

      // They are the same points
      assert(pbad.add(pgood.neg()).isInfinity());

      // But doubling borks them out
      assert(pbad.dbl().add(pgood.dbl().neg()).isInfinity());
    });

    it('should store precomputed values correctly on negation', () => {
      const curve = secp256k1;
      const p = curve.g.mul(new BN(2));

      p.precompute(0);

      const neg = p.neg(true);
      const neg2 = neg.neg(true);

      assert(p.eq(neg2));
    });

    it('should multiply with blinding', () => {
      const curve = secp256k1;
      const {blind} = curve.g.precomputed.blinding;
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
      for (const curve of [secp256k1, ed25519]) {
        const s = new BN(
          '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
          16);

        const p1 = curve.g.mul(s);
        const p2 = curve.g.mulSlow(s);

        assert(p1.eq(p2));

        const j1 = curve.g.jmul(s);
        const j2 = curve.g.jmulSlow(s);

        assert(j1.eq(j2));

        const j3 = curve.g.toJ().mul(s);
        const j4 = curve.g.toJ().mulSlow(s);

        assert(j3.eq(j4));
      }
    });

    it('should multiply negative scalar', () => {
      for (const curve of [secp256k1, ed25519]) {
        const s1 = new BN(
          '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
          16);

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

          const s4 = s3.mod(curve.n);
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

          const s4 = s3.mod(curve.n);
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

          const s4 = s3.mod(curve.n);
          const p7 = p2.mulBlind(s4, rng);
          const p8 = p2.mulBlind(s4.neg(), rng);

          assert(!p8.isInfinity());
          assert(p8.eq(p7.neg()));
        }
      }
    });
  });

  describe('Point codec', () => {
    function makeShortTest(definition) {
      return () => {
        const curve = secp256k1;
        const co = definition.coordinates;
        const p = curve.point(new BN(co.x, 16), new BN(co.y, 16));

        // Encodes as expected
        assert.strictEqual(p.encode(false).toString('hex'), definition.encoded);
        assert.strictEqual(p.encode(true).toString('hex'), definition.compactEncoded);

        // Decodes as expected
        assert(curve.decodePoint(Buffer.from(definition.encoded, 'hex')).eq(p));
        assert(curve.decodePoint(
          Buffer.from(definition.compactEncoded, 'hex')).eq(p));
        assert(curve.decodePoint(Buffer.from(definition.hybrid, 'hex')).eq(p));
      };
    }

    function makeMontTest(definition) {
      return () => {
        const curve = x25519;
        const co = definition.coordinates;
        const p = curve.point(new BN(co.x, 16), new BN(co.z, 16));
        const scalar = new BN(definition.scalar, 16);
        const encoded = p.encode();
        const decoded = curve.decodePoint(encoded);

        assert(decoded.eq(p));
        assert.strictEqual(encoded.toString('hex'), definition.encoded);

        assert.bufferEqual(curve.g.mul(scalar).encode(), encoded);
      };
    }

    const shortPointEvenY = {
      coordinates: {
        x: '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
        y: '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
      },
      compactEncoded: '02'
        + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
      encoded: '04'
        + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
        + '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
      hybrid: '06'
        + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
        + '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
    };

    const shortPointOddY = {
      coordinates: {
        x: 'fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556',
        y: 'ae12777aacfbb620f3be96017f45c560de80f0f6518fe4a03c870c36b075f297'
      },
      compactEncoded: '03'
        + 'fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556',
      encoded: '04'
        + 'fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556'
        + 'ae12777aacfbb620f3be96017f45c560de80f0f6518fe4a03c870c36b075f297',
      hybrid: '07'
        + 'fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556'
        + 'ae12777aacfbb620f3be96017f45c560de80f0f6518fe4a03c870c36b075f297'
    };

    it('should throw when trying to decode random bytes', () => {
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
      coordinates: {
        x: '743bcb585f9990edc2cfc4af84f6ff300729bb5facda28154362cd47a37de52f',
        z: '1'
      },
      encoded:
        '2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74'
    }));
  });
});
