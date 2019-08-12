/*!
 * ristretto.js - ristretto encoding for bcrypto
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://ristretto.group
 *   https://datatracker.ietf.org/doc/draft-hdevalence-cfrg-ristretto
 *   https://git.zx2c4.com/goldilocks
 *   https://github.com/dalek-cryptography/curve25519-dalek
 */

'use strict';

const assert = require('bsert');
const BN = require('../bn.js');

/**
 * Ristretto
 */

class Ristretto {
  constructor(curve) {
    assert(curve != null);

    // Curve.
    this.curve = curve;

    // Track extended vs. non-extended coords.
    this.extended = curve.extended;

    // Need to recompute.
    this.fieldSize = this.curve.p.byteLength();

    // AD = a * d
    this.ad = this.curve._mulA(this.curve.d);

    // MA = -a
    this.ma = this.curve.a.redNeg();

    // ADM1S = sqrt(a * d - 1)
    this.adm1s = this.ad.redSub(this.curve.one).redSqrt();

    // AS = 0
    this.as = this.curve.zero;

    // MAS = 0
    this.mas = this.curve.zero;

    // IAMDS = 0
    this.iamds = this.curve.zero;

    // if H = 8
    // Note that we modify things slightly below.
    // This is necessary to perfectly replicate
    // the reference implementations' elligator
    // behavior. The changes are marked with diff
    // notation.
    if (this.curve.h.cmpn(8) === 0) {
      // - AS = sqrt(a)
      // + AS = 1 / sqrt(a)
      this.as = this.curve.a.redSqrt().redInvert();

      // MAS = sqrt(-a)
      this.mas = this.ma.redSqrt();

      // IAMDS = 1 / sqrt(a - d)
      this.iamds = this.invsqrt(this.curve.a.redSub(this.curve.d));
    } else {
      // - ADM1S = sqrt(a * d - 1)
      // + ADM1S = -sqrt(a * d - 1)
      this.adm1s = this.adm1s.redNeg();

      // AS = -1
      this.as = this.curve.a.redNeg();
    }
  }

  encodeField(x) {
    assert(x instanceof BN);
    assert(!x.red);

    return x.encode('le', this.fieldSize);
  }

  decodeField(bytes) {
    assert(Buffer.isBuffer(bytes));

    if (bytes.length !== this.fieldSize)
      throw new Error('Invalid field element size.');

    return BN.decode(bytes, 'le');
  }

  encode(p) {
    assert(p != null);

    if (this.curve.h.cmpn(4) === 0)
      return this._encode4(p);

    return this._encode8(p);
  }

  _encode4(p) {
    // https://git.zx2c4.com/goldilocks/tree/_aux/ristretto/ristretto.sage#n176
    // https://git.zx2c4.com/goldilocks/tree/src/per_curve/decaf.tmpl.c#n233

    // U = -((Z1 + Y1) * (Z1 - Y1))
    const u = p.z.redAdd(p.y).redMul(p.z.redSub(p.y)).redINeg();

    // Y1 = Z1 or Y1 = -Z1 or Y1 = 0
    if (u.sign() === 0 || p.y.sign() === 0)
      return this.encodeField(new BN(0));

    // I = 1 / sqrt(U * Y1^2)
    const i = this.invsqrt(u.redMul(p.y.redSqr()));

    // T = (X1 * Y1) / Z1 (if not extended)
    const t = this.extended ? p.t : p.x.redMul(p.y).redMul(p.z.redInvert());

    // N = I^2 * U * Y1 * T
    const n = i.redSqr().redMul(u).redMul(p.y).redMul(t);

    // Y = Y1
    const y = p.y.clone();

    // If N < 0: Y = -Y
    if (n.redIsOdd())
      y.redINeg();

    // S = I * Y * (Z1 - Y)
    const s = i.redMul(y).redMul(p.z.redSub(y));

    // S < 0
    if (s.redIsOdd()) {
      // S = -S
      s.redINeg();
    }

    // Return the byte encoding of S.
    return this.encodeField(s.fromRed());
  }

  _encode8(p) {
    // https://ristretto.group/formulas/encoding.html
    // https://github.com/dalek-cryptography/curve25519-dalek/blob/9a62386/src/ristretto.rs#L434
    // https://git.zx2c4.com/goldilocks/tree/_aux/ristretto/ristretto.sage#n176
    // https://git.zx2c4.com/goldilocks/tree/src/per_curve/decaf.tmpl.c#n233

    // U1 = (Z0 + Y0) * (Z0 - Y0)
    const u1 = p.z.redAdd(p.y).redMul(p.z.redSub(p.y));

    // U2 = X0 * Y0
    const u2 = p.x.redMul(p.y);

    // Y1 = Z1 or Y1 = -Z1 or X1 = 0 or Y1 = 0
    if (u1.sign() === 0 || u2.sign() === 0)
      return this.encodeField(new BN(0));

    // I = 1 / sqrt(U1 * U2^2)
    const i = this.invsqrt(u1.redMul(u2.redSqr()));

    // D1 = U1 * I
    const d1 = u1.redMul(i);

    // D2 = U2 * I
    const d2 = u2.redMul(i);

    // T0 = (X0 * Y0) / Z0 (if not extended)
    const t = this.extended ? p.t : p.x.redMul(p.y).redMul(p.z.redInvert());

    // Zinv = D1 * D2 * T0
    const zinv = d1.redMul(d2).redMul(t);

    let x, y, d;

    // T0 * Zinv < 0
    if (t.redMul(zinv).redIsOdd()) {
      // X = Y * sqrt(a)
      x = p.y.redMul(this.as);

      // Y = X * sqrt(a)
      y = p.x.redMul(this.as);

      // D = D1 / sqrt(a - d)
      d = d1.redMul(this.iamds);
    } else {
      // X = X0
      x = p.x;

      // Y = Y0
      y = p.y;

      // D = D2
      d = d2;
    }

    // X * Zinv < 0
    if (x.redMul(zinv).redIsOdd()) {
      // Y = -Y
      y = y.redNeg();
    }

    // S = sqrt(-a) * (Z - Y) * D
    const s = this.mas.redMul(d.redMul(p.z.redSub(y)));

    // S < 0
    if (s.redIsOdd()) {
      // S = -S
      s.redINeg();
    }

    // Return the byte encoding of S.
    return this.encodeField(s.fromRed());
  }

  decode(bytes) {
    // https://ristretto.group/formulas/decoding.html
    // https://github.com/dalek-cryptography/curve25519-dalek/blob/9a62386/src/ristretto.rs#L251
    // https://git.zx2c4.com/goldilocks/tree/_aux/ristretto/ristretto.sage#n248
    // https://git.zx2c4.com/goldilocks/tree/src/per_curve/decaf.tmpl.c#n239
    const e = this.decodeField(bytes);

    // Check for canonical encoding.
    if (e.cmp(this.curve.p) >= 0)
      throw new Error('Invalid point.');

    // Reduce.
    const s = e.toRed(this.curve.red);

    // S < 0
    if (s.redIsOdd())
      throw new Error('Invalid point.');

    // AS2 = a * S^2
    const as2 = this.curve._mulA(s.redSqr());

    // U1 = 1 + a * S^2
    const u1 = this.curve.one.redAdd(as2);

    // U2 = 1 - a * S^2
    const u2 = this.curve.one.redSub(as2);

    // U2U2 = U2^2
    const u2u2 = u2.redSqr();

    // V = a * d * U1^2 - U2^2
    const v = this.ad.redMul(u1.redSqr()).redISub(u2u2);

    // I = 1 / sqrt(v * U2^2)
    const i = this.invsqrt(v.redMul(u2u2));

    // DX = I * U2
    const dx = u2.redMul(i);

    // DY = I * DX * V
    const dy = dx.redMul(v).redMul(i);

    // X = 2 * S * DX
    const x = s.redIAdd(s).redMul(dx);

    // X < 0
    if (x.redIsOdd()) {
      // X = -X
      x.redINeg();
    }

    // Y = U1 * DY
    const y = u1.redMul(dy);

    // Z = 1
    const z = this.curve.one;

    // if H = 4
    if (!this.extended) {
      // P = (X : Y : 1)
      return this.curve.point(x, y, z);
    }

    // T = X * Y
    const t = x.redMul(y);

    // T < 0 or Y = 0
    if (t.redIsOdd() || y.isZero())
      throw new Error('Invalid point.');

    // P = (X : Y : 1 : T)
    return this.curve.point(x, y, z, t);
  }

  equal(p, q) {
    // https://ristretto.group/formulas/equality.html
    // https://github.com/dalek-cryptography/curve25519-dalek/blob/9a62386/src/ristretto.rs#L752
    assert(p != null);
    assert(q != null);

    // XY = X1 * Y2
    const xy = p.x.redMul(q.y);

    // YX = Y1 * X2
    const yx = p.y.redMul(q.x);

    // X1 * Y2 == Y1 * X2
    if (xy.cmp(yx) === 0)
      return true;

    // if H = 4
    if (this.curve.h.cmpn(4) === 0)
      return false;

    // YY = Y1 * Y2
    const yy = p.y.redMul(q.y);

    // XX = -a * X1 * X2
    const xx = this.ma.redMul(p.x).redMul(q.x);

    // Y1 * Y2 === -a * X1 * X2
    return yy.cmp(xx) === 0;
  }

  elligator(r0) {
    // https://ristretto.group/details/elligator.html
    // https://ristretto.group/details/elligator_in_extended.html
    // https://ristretto.group/formulas/elligator.html
    // https://github.com/dalek-cryptography/curve25519-dalek/blob/9a62386/src/ristretto.rs#L592
    // https://git.zx2c4.com/goldilocks/tree/_aux/ristretto/ristretto.sage#n298
    // https://git.zx2c4.com/goldilocks/tree/src/per_curve/elligator.tmpl.c#n28
    // Assumes I = as.
    assert(r0 instanceof BN);

    // R = I * R0^2
    const r = this.as.redMul(r0.redSqr());

    // AR1 = a * (R + 1)
    const ar1 = this.curve._mulA(r.redAdd(this.curve.one));

    // APD = a + d
    const apd = this.curve.a.redAdd(this.curve.d);

    // DMA = d - a (note: sage script is right, ristretto.group is wrong)
    const dma = this.curve.d.redSub(this.curve.a);

    // - NS = (R + 1) * (1 - d^2)
    // + NS = a * (R + 1) * (a + d) * (d - a)
    const ns = ar1.redMul(apd).redMul(dma);

    // C = -1
    const c = this.curve.one.redNeg();

    // DRA = d * R - a
    const dra = this.curve._mulD(r).redISub(this.curve.a);

    // ARD = a * R - d
    const ard = this.curve._mulA(r).redISub(this.curve.d);

    // - D = (C - d * R) * (R + d)
    // + D = (d * R - a) * (a * R - d)
    const d = dra.redMul(ard);

    // [SQR, S] = ISQRT(NS, D)
    const [sqr, s] = this.isqrt(ns, d);

    // S' = S * R0
    const sp = s.redMul(r0);

    // S' = -S' if not negative
    sp.cinject(sp.redNeg(), sp.redIsOdd() ^ 1);

    // S = S' if not square
    s.cinject(sp, sqr ^ 1);

    // C = R if not square
    c.cinject(r, sqr ^ 1);

    // - DS = (d - 1)^2
    // + DS = (d + a)^2
    const ds = this.curve.d.redAdd(this.curve.a).redSqr();

    // - NT = C * (R - 1) * (d - 1)^2 - D
    // + NT = C * (R - 1) * (d + a)^2 - D
    const nt = c.redMul(r.redSub(this.curve.one)).redMul(ds).redISub(d);

    // AS2 = A * S^2
    const as2 = this.curve._mulA(s.redSqr());

    // W0 = 2 * S * D
    const w0 = s.redAdd(s).redMul(d);

    // W1 = NT * sqrt(a * d - 1)
    const w1 = nt.redMul(this.adm1s);

    // - W2 = 1 - s^2
    // + W2 = 1 + a * s^2
    const w2 = this.curve.one.redAdd(as2);

    // - W3 = 1 + s^2
    // + W3 = 1 - a * s^2
    const w3 = this.curve.one.redSub(as2);

    // X = W0 * W3
    const x = w0.redMul(w3);

    // Y = W2 * W1
    const y = w2.redMul(w1);

    // Z = W1 * W3
    const z = w1.redMul(w3);

    // H = 4
    if (!this.extended) {
      // P = (X : Y : Z)
      return this.curve.point(x, y, z);
    }

    // T = W0 * W2
    const t = w0.redMul(w2);

    // P = (X : Y : Z : T)
    return this.curve.point(x, y, z, t);
  }

  invert(p, hint) {
    // Todo: invert elligator.
    // https://git.zx2c4.com/goldilocks/tree/src/per_curve/elligator.tmpl.c#n106
    throw new Error('Not implemented.');
  }

  isqrt(u, v) {
    // p mod 4 == 3 (p448)
    if (this.curve.p.andln(3) === 3)
      return this._isqrt3mod4(u, v);

    // p mod 8 == 5 (p25519)
    if (this.curve.p.andln(7) === 5)
      return this._isqrt5mod8(u, v);

    // Compute `r = sqrt(u / v)` slowly.
    return this._isqrt(u, v);
  }

  _isqrt3mod4(u, v) {
    // https://git.zx2c4.com/goldilocks/tree/_aux/ristretto/ristretto.sage#n48
    // https://git.zx2c4.com/goldilocks/tree/src/p448/f_arithmetic.c
    // Compute sqrt(u / v).
    assert(u instanceof BN);
    assert(v instanceof BN);

    // U2 = U^2
    const u2 = u.redSqr();

    // U3 = U2 * U
    const u3 = u2.redMul(u);

    // U5 = U3 * U2
    const u5 = u3.redMul(u2);

    // V3 = V^2 * V
    const v3 = v.redSqr().redMul(v);

    // E = (p - 3) / 4
    const e = this.curve.p.subn(3).iushrn(2);

    // P = U5 * V3 * E
    const p = u5.redMul(v3).redPow(e);

    // R = U3 * V * P
    const r = u3.redMul(v).redMul(p);

    // C = V * R^2
    const c = v.redMul(r.redSqr());

    // CSS = C = U
    const css = c.ceq(u);

    // R = -R if R < 0
    r.cinject(r.redNeg(), r.redIsOdd() | 0);

    // Return (css, R).
    return [css, r];
  }

  _isqrt5mod8(u, v) {
    // https://ristretto.group/formulas/invsqrt.html
    // https://github.com/dalek-cryptography/curve25519-dalek/blob/9a62386/src/field.rs#L210
    // https://git.zx2c4.com/goldilocks/tree/src/p25519/f_arithmetic.c
    // Compute sqrt(u / v).
    // Assumes I = as.
    assert(u instanceof BN);
    assert(v instanceof BN);

    // V3 = V^2 * V
    const v3 = v.redSqr().redMul(v);

    // V7 = V3^2 * V
    const v7 = v3.redSqr().redMul(v);

    // E = (p - 5) / 8
    const e = this.curve.p.subn(5).iushrn(3);

    // P = U * V7 * E
    const p = u.redMul(v7).redPow(e);

    // R = U * V3 * P
    const r = u.redMul(v3).redMul(p);

    // C = V * R^2
    const c = v.redMul(r.redSqr());

    // CSS = C = U
    const css = c.ceq(u);

    // FSS = C = -U
    const fss = c.ceq(u.redNeg());

    // FSSI = C = -U * I
    const fssi = c.ceq(u.redNeg().redMul(this.as));

    // R = I * R if fss or fssi
    r.cinject(this.as.redMul(r), fss | fssi);

    // R = -R if R < 0
    r.cinject(r.redNeg(), r.redIsOdd() | 0);

    // Return (css | fss, R).
    return [css | fss, r];
  }

  _isqrt(u, v) {
    // https://git.zx2c4.com/goldilocks/tree/_aux/ristretto/ristretto.sage#n48
    assert(u instanceof BN);
    assert(v instanceof BN);

    // V = 0
    if (v.isZero())
      return [0, u];

    // R2 = U / V
    const r2 = u.redMul(v.redInvert());

    // R = sqrt(R2)
    let r;
    try {
      r = r2.redSqrt();
    } catch (e) {
      return [0, r2];
    }

    // R = -R if R < 0
    if (r.redIsOdd())
      r.redINeg();

    return [1, r];
  }

  invsqrt(v) {
    // https://github.com/dalek-cryptography/curve25519-dalek/blob/9a62386/src/field.rs#L270
    const [sqrt, r] = this.isqrt(this.curve.one, v);

    if (!sqrt)
      throw new Error('Invalid root.');

    return r;
  }

  fromBytes(bytes) {
    // https://github.com/dalek-cryptography/curve25519-dalek/blob/9a62386/src/ristretto.rs#L713
    // https://git.zx2c4.com/goldilocks/tree/src/per_curve/elligator.tmpl.c#n87
    assert(Buffer.isBuffer(bytes));
    assert(bytes.length === this.fieldSize * 2);

    const s1 = bytes.slice(0, this.fieldSize);
    const s2 = bytes.slice(this.fieldSize);

    const r1 = this.decodeField(s1);
    const r2 = this.decodeField(s2);

    r1.iumaskn(this.curve.fieldBits);
    r2.iumaskn(this.curve.fieldBits);

    const p1 = this.elligator(r1.toRed(this.curve.red));
    const p2 = this.elligator(r2.toRed(this.curve.red));

    return p1.add(p2);
  }

  toMain(p) {
    assert(p != null);

    // Back into the main subgroup.
    return p.mulH().divH();
  }

  fromMain(p) {
    // Could maybe add a torsion point faster?
    return this.decode(this.encode(p));
  }
}

/*
 * Expose
 */

module.exports = Ristretto;
