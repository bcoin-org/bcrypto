'use strict';

const assert = require('bsert');
const BN = require('../lib/bn');
const elliptic = require('../lib/js/elliptic');
const extra = require('../test/util/curves');
const id = (process.argv[2] || '').toUpperCase();
const ell1 = process.argv.includes('--elligator1');
const Curve = elliptic.curves[id] || extra[id];

if (!Curve)
  throw new Error(`Curve not found (${id}).`);

function printZ(curve) {
  assert(curve instanceof elliptic.Curve);

  const z = findZ(curve);

  let sign = '';

  if (z.redNeg().bitLength() < z.bitLength()) {
    sign = '-';
    z.redINeg();
  }

  let alg;

  if (curve.type === 'short') {
    if (curve.p.modrn(3) === 2)
      alg = 'icart';
    else if (!curve.a.isZero() && !curve.b.isZero())
      alg = 'sswu';
    else if (curve.p.modrn(3) === 1 && !curve.b.isZero())
      alg = 'svdw';
  } else if (curve.type === 'mont' || curve.type === 'edwards') {
    alg = 'elligator2';

    if (ell1 && curve.type === 'edwards') {
      if (curve.p.andln(3) === 3 && curve.d.redJacobi() === -1)
        alg = 'elligator1';
    }
  } else {
    throw new Error('Not implemented.');
  }

  const str = sign + z.fromRed().toString(16);

  console.log('%s Z: %s (%s)', curve.id, str, alg);
}

function findZ(curve) {
  assert(curve instanceof elliptic.Curve);

  if (curve.type === 'short') {
    // p = 2 mod 3
    if (curve.p.modrn(3) === 2)
      return findSSWUZ(curve); // Icart.

    // a != 0, b != 0
    if (!curve.a.isZero() && !curve.b.isZero())
      return findSSWUZ(curve);

    // p = 1 mod 3, b != 0
    if (curve.p.modrn(3) === 1 && !curve.b.isZero())
      return findSVDWZ(curve);

    throw new Error('Not implemented.');
  }

  if (ell1 && curve.type === 'edwards') {
    if (curve.p.andln(3) === 3 && curve.d.redJacobi() === -1)
      return findElligator1S(curve);
  }

  if (curve.type === 'mont' || curve.type === 'edwards')
    return findElligator2Z(curve);

  throw new Error('Not implemented.');
}

function findElligator1S(curve) {
  assert(curve instanceof elliptic.Curve);

  const s = curve.one.clone();

  for (;;) {
    if (isElligator1S(curve, s))
      return s;

    if (isElligator1S(curve, s.redNeg()))
      return s.redNeg();

    s.redIAdd(curve.one);
  }
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
    throw new Error('Invalid D (not square).');

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

// Test ED1174 `s`.
{
  const ed1174 = new extra.ED1174();
  const s = new BN('03fe707f 0d7004fd 334ee813 a5f1a74a'
                 + 'b2449139 c82c39d8 4a09ae74 cc78c615', 16);

  assert(isElligator1S(ed1174, s.toRed(ed1174.red)));
}

printZ(new Curve());
