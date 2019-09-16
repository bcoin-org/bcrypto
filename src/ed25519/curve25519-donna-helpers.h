/*
  Public domain by Andrew M. <liquidsun@gmail.com>
  See: https://github.com/floodyberry/curve25519-donna

  Curve25519 implementation agnostic helpers
*/

static const bignum25519 ALIGN(16) ge25519_sqrtneg1;

/*
 * In:  b =   2^5 - 2^0
 * Out: b = 2^250 - 2^0
 */
static void
curve25519_pow_two5mtwo0_two250mtwo0(bignum25519 b) {
  bignum25519 ALIGN(16) t0,c;

  /* 2^5  - 2^0 */ /* b */
  /* 2^10 - 2^5 */ curve25519_square_times(t0, b, 5);
  /* 2^10 - 2^0 */ curve25519_mul_noinline(b, t0, b);
  /* 2^20 - 2^10 */ curve25519_square_times(t0, b, 10);
  /* 2^20 - 2^0 */ curve25519_mul_noinline(c, t0, b);
  /* 2^40 - 2^20 */ curve25519_square_times(t0, c, 20);
  /* 2^40 - 2^0 */ curve25519_mul_noinline(t0, t0, c);
  /* 2^50 - 2^10 */ curve25519_square_times(t0, t0, 10);
  /* 2^50 - 2^0 */ curve25519_mul_noinline(b, t0, b);
  /* 2^100 - 2^50 */ curve25519_square_times(t0, b, 50);
  /* 2^100 - 2^0 */ curve25519_mul_noinline(c, t0, b);
  /* 2^200 - 2^100 */ curve25519_square_times(t0, c, 100);
  /* 2^200 - 2^0 */ curve25519_mul_noinline(t0, t0, c);
  /* 2^250 - 2^50 */ curve25519_square_times(t0, t0, 50);
  /* 2^250 - 2^0 */ curve25519_mul_noinline(b, t0, b);
}

/*
 * z^(p - 2) = z(2^255 - 21)
 */
static void
curve25519_recip(bignum25519 out, const bignum25519 z) {
  bignum25519 ALIGN(16) a,t0,b;

  /* 2 */ curve25519_square_times(a, z, 1); /* a = 2 */
  /* 8 */ curve25519_square_times(t0, a, 2);
  /* 9 */ curve25519_mul_noinline(b, t0, z); /* b = 9 */
  /* 11 */ curve25519_mul_noinline(a, b, a); /* a = 11 */
  /* 22 */ curve25519_square_times(t0, a, 1);
  /* 2^5 - 2^0 = 31 */ curve25519_mul_noinline(b, t0, b);
  /* 2^250 - 2^0 */ curve25519_pow_two5mtwo0_two250mtwo0(b);
  /* 2^255 - 2^5 */ curve25519_square_times(b, b, 5);
  /* 2^255 - 21 */ curve25519_mul_noinline(out, b, a);
}

/*
 * z^((p-5)/8) = z^(2^252 - 3)
 */
static void
curve25519_pow_two252m3(bignum25519 two252m3, const bignum25519 z) {
  bignum25519 ALIGN(16) b,c,t0;

  /* 2 */ curve25519_square_times(c, z, 1); /* c = 2 */
  /* 8 */ curve25519_square_times(t0, c, 2); /* t0 = 8 */
  /* 9 */ curve25519_mul_noinline(b, t0, z); /* b = 9 */
  /* 11 */ curve25519_mul_noinline(c, b, c); /* c = 11 */
  /* 22 */ curve25519_square_times(t0, c, 1);
  /* 2^5 - 2^0 = 31 */ curve25519_mul_noinline(b, t0, b);
  /* 2^250 - 2^0 */ curve25519_pow_two5mtwo0_two250mtwo0(b);
  /* 2^252 - 2^2 */ curve25519_square_times(b, b, 2);
  /* 2^252 - 3 */ curve25519_mul_noinline(two252m3, b, z);
}

/*
 * z^((p+3)/8) = z^(2^252 - 2)
 */
static void
curve25519_pow_two252m2(bignum25519 two252m2, const bignum25519 z) {
  bignum25519 ALIGN(16) b,c,t0;

  /* 2 */ curve25519_square_times(c, z, 1); /* c = 2 */
  /* 8 */ curve25519_square_times(t0, c, 2); /* t0 = 8 */
  /* 9 */ curve25519_mul_noinline(b, t0, z); /* b = 9 */
  /* 11 */ curve25519_mul_noinline(c, b, c); /* c = 11 */
  /* 22 */ curve25519_square_times(t0, c, 1);
  /* 2^5 - 2^0 = 31 */ curve25519_mul_noinline(b, t0, b);
  /* 2^250 - 2^0 */ curve25519_pow_two5mtwo0_two250mtwo0(b);
  /* 2^252 - 2^1 */ curve25519_square_times(b, b, 1);
  /* 2^252 - 2 */ curve25519_mul_noinline(b, b, z);
  /* 2^252 - 2 */ curve25519_square_times(two252m2, b, 1);
}

/*
 * z^((p - 1) / 2) = z^(2^254 - 10)
 * From: https://gist.github.com/Yawning/0181098c1119f49b3eb2
 */
static void
curve25519_pow_two254m10(bignum25519 out, const bignum25519 z) {
  bignum25519 ALIGN(16) t0, t1, t2, t3;
  curve25519_square(t0, z);   /* 2^1 */
  curve25519_mul(t1, t0, z);  /* 2^1 + 2^0 */
  curve25519_square(t0, t1);  /* 2^2 + 2^1 */
  curve25519_square(t2, t0);  /* 2^3 + 2^2 */
  curve25519_square(t2, t2);  /* 4,3 */
  curve25519_mul(t2, t2, t0); /* 4,3,2,1 */
  curve25519_mul(t1, t2, z);  /* 4..0 */
  curve25519_square(t2, t1);  /* 5..1 */
  curve25519_square_times(t2, t2, 5 - 1);   /* 9,8,7,6,5 */
  curve25519_mul(t1, t2, t1); /* 9,8,7,6,5,4,3,2,1,0 */
  curve25519_square(t2, t1); /* 10..1 */
  curve25519_square_times(t2, t2, 10 - 1);  /* 19..10 */
  curve25519_mul(t2, t2, t1); /* 19..0 */
  curve25519_square(t3, t2);  /* 20..1 */
  curve25519_square_times(t3, t3, 20 - 1);  /* 39..20 */
  curve25519_mul(t2, t3, t2); /* 39..0 */
  curve25519_square(t2, t2);  /* 40..1 */
  curve25519_square_times(t2, t2, 10 - 1);  /* 49..10 */
  curve25519_mul(t1, t2, t1); /* 49..0 */
  curve25519_square(t2, t1);  /* 50..1 */
  curve25519_square_times(t2, t2, 50 - 1);  /* 99..50 */
  curve25519_mul(t2, t2, t1); /* 99..0 */
  curve25519_square(t3, t2);  /* 100..1 */
  curve25519_square_times(t3, t3, 100 - 1); /* 199..100 */
  curve25519_mul(t2, t3, t2); /* 199..0 */
  curve25519_square(t2, t2);  /* 200..1 */
  curve25519_square_times(t2, t2, 50 - 1);  /* 249..50 */
  curve25519_mul(t1, t2, t1); /* 249..0 */
  curve25519_square(t1, t1);  /* 250..1 */
  curve25519_square_times(t1, t1, 4 - 1); /* 253..4 */
  curve25519_mul(out, t1, t0); /* 253..4,2,1 */
}

/* From: https://gist.github.com/Yawning/0181098c1119f49b3eb2 */
static unsigned int
curve25519_bytes_lte(const unsigned char a[32], const unsigned char b[32]) {
  int eq = ~0;
  int lt = 0;
  size_t shift = sizeof(int) * 8 - 1;

  for (int i = 31; i >= 0; i--) {
    int x = (int)a[i];
    int y = (int)b[i];

    lt = (~eq & lt) | (eq & ((x - y) >> shift));
    eq = eq & (((x ^ y) - 1) >> shift);
  }

  return (eq | lt) & 1;
}

static int
curve25519_is_neg(const bignum25519 a) {
  unsigned char out[32];

  static const unsigned char fq2[32] = {
    0xf6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f
  };

  curve25519_contract(out, a);

  return curve25519_bytes_lte(out, fq2) ^ 1;
}

static int
curve25519_is_zero(const bignum25519 a) {
  unsigned char out[32];
  unsigned int c = 0;
  int i;

  curve25519_contract(out, a);

  for (i = 0; i < 32; i++)
    c |= (unsigned int)out[i];

  return (c - 1) >> (sizeof(unsigned int) * 8 - 1);
}

static int
curve25519_is_equal(const bignum25519 a, const bignum25519 b) {
  unsigned char x[32];
  unsigned char y[32];
  unsigned int c = 0;
  int i;

  curve25519_contract(x, a);
  curve25519_contract(y, b);

  for (i = 0; i < 32; i++)
    c |= (unsigned int)x[i] ^ (unsigned int)y[i];

  return (c - 1) >> (sizeof(unsigned int) * 8 - 1);
}

static void
curve25519_neg_conditional(bignum25519 out, const bignum25519 x, int negate) {
  bignum25519 z;
  curve25519_copy(out, x);
  curve25519_neg(z, x);
  curve25519_swap_conditional(out, z, negate);
}

static int
curve25519_is_odd(const bignum25519 a) {
  unsigned char out[32];
  curve25519_contract(out, a);
  return out[0] & 1;
}

static int
curve25519_sqrt(bignum25519 out, const bignum25519 x) {
  bignum25519 ALIGN(16) a, b, c;
  int r;

  curve25519_pow_two252m2(a, x);
  curve25519_mul(b, a, ge25519_sqrtneg1);

  curve25519_square(c, a);
  r = curve25519_is_equal(c, x);

  curve25519_swap_conditional(a, b, r ^ 1);

  curve25519_square(c, a);
  r = curve25519_is_equal(c, x);

  curve25519_copy(out, a);

  return r;
}

static int
curve25519_isqrt(bignum25519 out, const bignum25519 u, const bignum25519 v) {
  bignum25519 ALIGN(16) v3, x, c;
  int css, fss;

  /* V3 = V^2 * V */
  curve25519_square(c, v);
  curve25519_mul(v3, c, v);

  /* V7 = V3^2 * V */
  curve25519_square(c, v3);
  curve25519_mul(c, c, v);

  /* P = (U * V7)^((p - 5) / 8) */
  curve25519_mul(x, u, c);
  curve25519_pow_two252m3(x, x);

  /* X = U * V3 * P */
  curve25519_mul(x, x, v3);
  curve25519_mul(x, x, u);

  /* C = V * X^2 */
  curve25519_square(c, x);
  curve25519_mul(c, c, v);

  /* C = U */
  css = curve25519_is_equal(c, u);

  /* C = -U */
  curve25519_neg(c, c);
  fss = curve25519_is_equal(c, u);

  /* X = X * I if C = -U */
  curve25519_mul(c, x, ge25519_sqrtneg1);
  curve25519_swap_conditional(x, c, fss);
  curve25519_copy(out, x);

  return css | fss;
}

static void
curve25519_solve_y2(bignum25519 out, const bignum25519 x) {
  /* y^2 = x^3 + a * x^2 + x */
  static const bignum25519 a = {486662};
  bignum25519 ALIGN(16) x2, x3, y2;

  curve25519_square(x2, x);
  curve25519_mul(x3, x2, x);
  curve25519_add_reduce(y2, x3, x);
  curve25519_mul(x3, x2, a);
  curve25519_add(out, y2, x3);
}

static int
curve25519_solve_y(bignum25519 out, const bignum25519 x) {
  curve25519_solve_y2(out, x);
  return curve25519_sqrt(out, out);
}

static int
curve25519_get_y(bignum25519 out, const bignum25519 x, int sign) {
  int ret = curve25519_solve_y(out, x);

  if (sign != -1)
    curve25519_neg_conditional(out, out, curve25519_is_odd(out) ^ sign);

  return ret;
}

static int
curve25519_valid_x(const bignum25519 x) {
  bignum25519 ALIGN(16) e;

  curve25519_solve_y2(e, x);
  curve25519_pow_two254m10(e, e);

  return curve25519_is_equal(e, curve25519_neg1) ^ 1;
}

static int
curve25519_unpack(bignum25519 x, bignum25519 y,
                  const unsigned char raw[32],
                  int sign) {
  curve25519_expand(x, raw);
  return curve25519_get_y(y, x, sign);
}

static void
curve25519_double(
  bignum25519 x0,
  bignum25519 z0,
  const bignum25519 x1,
  const bignum25519 z1
) {
  bignum25519 ALIGN(16) a, aa, b, bb, c;
  static const bignum25519 a24 = {121666};

  /* A = X1 + Z1 */
  curve25519_add(a, x1, z1);

  /* AA = A^2 */
  curve25519_square(aa, a);

  /* B = X1 - Z1 */
  curve25519_sub(b, x1, z1);

  /* BB = B^2 */
  curve25519_square(bb, b);

  /* C = AA - BB */
  curve25519_sub(c, aa, bb);

  /* X3 = AA * BB */
  curve25519_mul(x0, aa, bb);

  /* Z3 = C * (BB + a24 * C) */
  curve25519_mul(a, c, a24);
  curve25519_add(a, a, bb);
  curve25519_mul(z0, c, a);
}

static void
curve25519_ladder(
  bignum25519 x0,
  bignum25519 z0,
  const bignum25519 x1,
  const unsigned char k[32]
) {
  bignum25519 ALIGN(16) x2, z2, x3, z3, t1, t2;
  static const bignum25519 a24 = {121666};
  int swap = 0;
  int i, b;

  curve25519_set_word(x2, 1);
  curve25519_set_word(z2, 0);
  curve25519_copy(x3, x1);
  curve25519_set_word(z3, 1);

  for (i = 255 - 1; i >= 0; i--) {
    b = (k[i >> 3] >> (i & 7)) & 1;

    swap ^= b;

    curve25519_swap_conditional(x2, x3, swap);
    curve25519_swap_conditional(z2, z3, swap);

    swap = b;

    curve25519_sub(t1, x3, z3);
    curve25519_sub(t2, x2, z2);
    curve25519_add(x2, x2, z2);
    curve25519_add(z2, x3, z3);
    curve25519_mul(z3, t1, x2);
    curve25519_mul(z2, z2, t2);
    curve25519_square(t1, t2);
    curve25519_square(t2, x2);
    curve25519_add(x3, z3, z2);
    curve25519_sub(z2, z3, z2);
    curve25519_mul(x2, t2, t1);
    curve25519_sub(t2, t2, t1);
    curve25519_square(z2, z2);
    curve25519_mul(z3, t2, a24);
    curve25519_square(x3, x3);
    curve25519_add(t1, t1, z3);
    curve25519_mul(z3, x1, z2);
    curve25519_mul(z2, t2, t1);
  }

  curve25519_swap_conditional(x2, x3, swap);
  curve25519_swap_conditional(z2, z3, swap);

  curve25519_copy(x0, x2);
  curve25519_copy(z0, z2);
}

static void
curve25519_elligator2(bignum25519 x, bignum25519 y,
                      const unsigned char bytes[32],
                      int spec) {
  static const bignum25519 z = {2};
  static const bignum25519 a = {486662};
  bignum25519 ALIGN(16) u, x1, x2, y1, y2;
  bignum25519 one = {1};
  int quad1, quad2;

  curve25519_expand(u, bytes);

  /* x1 = -a / (1 + z * u^2) */
  curve25519_square(x1, u);
  curve25519_mul(x1, x1, z);
  curve25519_add(x1, x1, one);
  curve25519_swap_conditional(x1, one, curve25519_is_zero(x1));
  curve25519_recip(x1, x1);
  curve25519_mul(x1, a, x1);
  curve25519_neg(x1, x1);

  /* x2 = -x1 - a */
  curve25519_neg(x2, x1);
  curve25519_sub(x2, x2, a);

  /* compute y coordinate */
  quad1 = curve25519_solve_y(y1, x1);
  quad2 = curve25519_solve_y(y2, x2);

  /* mathematically impossible */
  assert((quad1 | quad2) != 0);

  /* x = cmov(x1, x2, f(g(x1)) != 1) */
  curve25519_swap_conditional(x1, x2, quad1 ^ 1);
  curve25519_swap_conditional(y1, y2, quad1 ^ 1);

  /* adjust sign */
  if (spec) {
    curve25519_neg_conditional(y1, y1,
      curve25519_is_neg(y1) ^ curve25519_is_neg(u));
  } else {
    curve25519_neg_conditional(y1, y1, curve25519_is_neg(y1));
    curve25519_neg_conditional(y1, y1, quad1);
  }

  curve25519_copy(x, x1);
  curve25519_copy(y, y1);
}

int
bcrypto_ed25519_randombytes(void *p, size_t len);

static int
curve25519_invert2(unsigned char out[32],
                   const bignum25519 x,
                   const bignum25519 y) {
  static const bignum25519 z = {2};
  static const bignum25519 a = {486662};
  bignum25519 ALIGN(16) n, d, u;
  unsigned char bit = 0;
  int ret = 1;

  /* u = sqrt(-n / (d * z)) */
  curve25519_copy(n, x);
  curve25519_add(d, x, a);
  curve25519_swap_conditional(n, d, curve25519_is_neg(y));
  curve25519_neg(n, n);
  curve25519_mul(d, d, z);
  ret &= curve25519_isqrt(u, n, d);

  /* output */
  curve25519_contract(out, u);

  /* randomize the top bit */
  ret &= bcrypto_ed25519_randombytes(&bit, sizeof(unsigned char));

  out[31] |= (bit & 1) << 7;

  return ret;
}
