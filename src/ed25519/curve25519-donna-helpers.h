/*
  Public domain by Andrew M. <liquidsun@gmail.com>
  See: https://github.com/floodyberry/curve25519-donna

  Curve25519 implementation agnostic helpers
*/

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
 * z^((2^255 - 19 - 1) / 2)
 * From: https://gist.github.com/Yawning/0181098c1119f49b3eb2
 */
static void
curve25519_pow_two255m20d2(bignum25519 out, const bignum25519 z) {
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
curve25519_bytes_le(const unsigned char a[32], const unsigned char b[32]) {
  int eq = ~0;
  int lt = 0;
  size_t shift = sizeof(int) * 8 - 1;

  for (int i = 31; i >= 0; i--) {
    int x = (int)a[i];
    int y = (int)b[i];

    lt = (~eq & lt) | (eq & ((x - y) >> shift));
    eq = eq & (((x ^ y) - 1) >> shift);
  }

  return (~eq & lt) & 1;
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

static int
curve25519_sqrt(bignum25519 out, const bignum25519 x) {
  static const bignum25519 one = {1};
  bignum25519 ALIGN(16) t, a, b;
  int r;

  curve25519_add_reduce(t, x, x);
  curve25519_pow_two252m3(a, t);
  curve25519_square(b, a);
  curve25519_mul(b, b, t);
  curve25519_sub(b, b, one);
  curve25519_mul(b, b, x);
  curve25519_mul(b, b, a);

  curve25519_square(t, b);
  r = curve25519_is_equal(t, x);

  curve25519_copy(out, b);

  return r;
}

static const bignum25519 ALIGN(16) ge25519_sqrtneg1;

static int
curve25519_isqrt(bignum25519 out, const bignum25519 u, const bignum25519 v) {
  bignum25519 ALIGN(16) t, v3, x, c;
  int nz, css, fss;

  nz = curve25519_is_zero(v) ^ 1;

  /* V3 = V^2 * V */
  curve25519_square(t, v);
  curve25519_mul(v3, t, v);

  /* V7 = V3^2 * V */
  curve25519_square(x, v3);
  curve25519_mul(x, x, v);

  /* P = (U * V7)^((p - 5) / 8) */
  curve25519_mul(x, x, u);
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
  curve25519_neg(t, u);
  fss = curve25519_is_equal(c, t);

  /* X = X * I if C = -U */
  curve25519_mul(t, x, ge25519_sqrtneg1);
  curve25519_swap_conditional(x, t, fss);
  curve25519_copy(out, x);

  return (css | fss) & nz;
}

static int
curve25519_solve_y(bignum25519 out, const bignum25519 x) {
  /* y^2 = x^3 + a * x^2 + x */
  static const bignum25519 a = {486662};
  bignum25519 ALIGN(16) x2, x3, y2;

  curve25519_square(x2, x);
  curve25519_mul(x3, x2, x);
  curve25519_add_reduce(y2, x3, x);
  curve25519_mul(x3, x2, a);
  curve25519_add(y2, y2, x3);

  return curve25519_sqrt(out, y2);
}

static int
curve25519_valid_x(const bignum25519 x) {
  bignum25519 ALIGN(16) y;
  return curve25519_solve_y(y, x);
}

static void
curve25519_cond_neg(bignum25519 out, const bignum25519 x, int negate) {
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
