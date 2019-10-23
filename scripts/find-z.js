'use strict';

const assert = require('bsert');
const BN = require('../lib/bn');
const elliptic = require('../lib/js/elliptic');

require('../test/util/curves');

function printZ(curve) {
  assert(curve instanceof elliptic.Curve);

  const alg = getAlg(curve);
  const s = tryFindS(curve);
  const z = findZ(curve);

  if (s != null) {
    const size = (((curve.fieldBits + 7) >>> 3) + 3) & -4;

    let str = s.fromRed().toString(16);

    while (str.length < size * 2)
      str = '0' + str;

    console.log('%s S: %s (elligator1)', curve.id, str);
  }

  let sign = '';

  if (z.redIsNeg()) {
    sign = '-';
    z.redINeg();
  }

  const str = sign + z.fromRed().toString(16);

  console.log('%s Z: %s (%s)', curve.id, str, alg);
}

function getAlg(curve) {
  assert(curve instanceof elliptic.Curve);

  if (curve.type === 'short') {
    // p = 2 mod 3
    if (curve.p.modrn(3) === 2)
      return 'icart';

    // a != 0, b != 0
    if (!curve.a.isZero() && !curve.b.isZero())
      return 'sswu';

    // p = 1 mod 3, b != 0
    if (curve.p.modrn(3) === 1 && !curve.b.isZero())
      return 'svdw';
  }

  if (curve.type === 'mont' || curve.type === 'edwards')
    return 'elligator2';

  throw new Error('Not implemented.');
}

function findZ(curve) {
  assert(curve instanceof elliptic.Curve);

  if (curve.type === 'short') {
    // a != 0, b != 0
    if (!curve.a.isZero() && !curve.b.isZero())
      return findSSWUZ(curve);

    // p = 1 mod 3, b != 0
    if (curve.p.modrn(3) === 1 && !curve.b.isZero())
      return findSVDWZ(curve);

    throw new Error('Not implemented.');
  }

  if (curve.type === 'mont' || curve.type === 'edwards')
    return findElligator2Z(curve);

  throw new Error('Not implemented.');
}

function tryFindS(curve) {
  assert(curve instanceof elliptic.Curve);

  try {
    return findS(curve);
  } catch (e) {
    return null;
  }
}

function findS(curve) {
  assert(curve instanceof elliptic.Curve);

  if (curve.type === 'edwards') {
    if (curve.p.andln(3) === 3 && curve.d.redJacobi() === -1)
      return findElligator1S(curve);
  }

  throw new Error('Not implemented.');
}

function findElligator1S(curve) {
  assert(curve instanceof elliptic.Curve);

  // s = +-sqrt(2 * d / (d + 1) +- 4 * sqrt(-d) / (d + 1) - 2 / (d + 1))
  const {d, one} = curve;
  const di = d.redAdd(one).redInvert();
  const ds = d.redNeg().redSqrt();
  const t0 = d.redMuln(2).redMul(di);
  const t1 = ds.redMuln(4).redMul(di);
  const t2 = di.redMuln(2);
  const s1 = t0.redAdd(t1).redSub(t2).redSqrt();
  const s2 = s1.redNeg();
  const s3 = t0.redSub(t1).redSub(t2).redSqrt();
  const s4 = s3.redNeg();
  const S = [s1, s2, s3, s4].filter(s => isElligator1S(curve, s));

  if (S.length === 0)
    throw new Error('X is not a square mod P.');

  console.log('Found %d `s` values:', S.length);
  console.log('');

  for (const s of S)
    console.log('  %s', s.fromRed().toString(16));

  console.log('');

  // Use DJB's `s` value.
  if (curve.id === 'ED1174')
    return S[2];

  // Pick the smallest `s`.
  const s = S.map(s => s.fromRed()).sort(BN.cmp)[0];

  return s.toRed(curve.red);
}

function isElligator1S(curve, s) {
  assert(curve instanceof elliptic.Curve);
  assert(s instanceof BN);

  try {
    getElligator1SCR(curve, s);
    return true;
  } catch (e) {
    return false;
  }
}

function getElligator1SCR(curve, s) {
  assert(curve instanceof elliptic.Curve);
  assert(s instanceof BN);

  // Assumptions:
  //
  //   - Let q be a prime power congruent to 3 mod 4.
  //   - Let s be a nonzero element of F(q) with (s^2 - 2)(s^2 + 2) != 0.
  //   - Let c = 2 / s^2. Then c(c - 1)(c + 1) != 0.
  //   - Let r = c + 1 / c. Then r != 0.
  //   - Let d = -(c + 1)^2 / (c - 1)^2. Then d is not a square.
  const s2 = s.redSqr();
  const lhs = s2.redSub(curve.two);
  const rhs = s2.redAdd(curve.two);
  const k0 = lhs.redMul(rhs);

  if (k0.isZero())
    throw new Error('Invalid S (s^2 - 2)(s^2 + 2) = 0).');

  const c = curve.two.redMul(s2.redInvert());
  const cm1 = c.redSub(curve.one);
  const cp1 = c.redAdd(curve.one);
  const k1 = c.redMul(cm1).redMul(cp1);

  if (k1.isZero())
    throw new Error('Invalid C (c(c - 1)(c + 1) = 0).');

  const r = c.redAdd(c.redInvert());

  if (r.isZero())
    throw new Error('Invalid R (c + 1 / c = 0).');

  const dl = c.redAdd(curve.one).redSqr().redINeg();
  const dr = c.redSub(curve.one).redSqr();
  const d = dl.redMul(dr.redInvert());

  if (!d.eq(curve.d))
    throw new Error('Invalid D (D != d).');

  if (d.redJacobi() !== -1)
    throw new Error('Invalid D (square).');

  return [s, c, r];
}

function findElligator2Z(curve) {
  assert(curve instanceof elliptic.Curve);

  // Find non-square in F(q).
  const z = curve.one.clone();

  for (;;) {
    if (z.redJacobi() === -1)
      return z;

    if (z.redNeg().redJacobi() === -1)
      return z.redNeg();

    z.redIAdd(curve.one);
  }
}

function findSSWUZ(curve) {
  assert(curve instanceof elliptic.Curve);

  // Find non-square in F(q) where
  // g(B / (Z * A)) is square.
  const z = curve.one.clone();

  for (;;) {
    if (isSSWUZ(curve, z))
      return z;

    if (isSSWUZ(curve, z.redNeg()))
      return z.redNeg();

    z.redIAdd(curve.one);
  }
}

function isSSWUZ(curve, z) {
  assert(curve instanceof elliptic.Curve);
  assert(z instanceof BN);

  if (z.redJacobi() !== -1)
    return false;

  const zai = z.redMul(curve.a).redInvert();

  return curve.solveY2(curve.b.redMul(zai)).redJacobi() === 1;
}

function findSVDWZ(curve) {
  assert(curve instanceof elliptic.Curve);

  // Find element in F(q) where
  // g((sqrt(-3 * Z^2) - Z) / 2) is square.
  const z = curve.one.clone();

  for (;;) {
    if (isSVDWZ(curve, z))
      return z;

    if (isSVDWZ(curve, z.redNeg()))
      return z.redNeg();

    z.redIAdd(curve.one);
  }
}

function isSVDWZ(curve, z) {
  assert(curve instanceof elliptic.Curve);
  assert(z instanceof BN);

  const z2 = z.redSqr();

  let c;

  try {
    c = curve.three.redNeg().redMul(z2).redSqrt();
  } catch (e) {
    return false;
  }

  const d = c.redISub(z).redMul(curve.i2);

  return curve.solveY2(d).redJacobi() === 1;
}

function main(argv) {
  if (argv.length < 3) {
    console.error('Must enter a curve ID.');
    process.exit(1);
    return;
  }

  const curve = elliptic.curve(argv[2]);

  printZ(curve);
}

main(process.argv);
