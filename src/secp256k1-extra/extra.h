/**********************************************************************
 * Copyright (c) 2016 Andrew Poelstra & Pieter Wuille                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

static const unsigned char fq2[32] = {
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xfe, 0x17
};

/* From: https://gist.github.com/Yawning/0181098c1119f49b3eb2 */
static unsigned int secp256k1_bytes_lte(const unsigned char a[32], const unsigned char b[32]) {
    int eq = ~0;
    int lt = 0;
    size_t shift = sizeof(int) * 8 - 1;
    int i;

    for (i = 0; i < 32; i++) {
        int x = (int)a[i];
        int y = (int)b[i];

        lt = (~eq & lt) | (eq & ((x - y) >> shift));
        eq = eq & (((x ^ y) - 1) >> shift);
    }

    return (eq | lt) & 1;
}

static int secp256k1_fe_is_neg(const secp256k1_fe* fe) {
    unsigned char check[32];
    secp256k1_fe u;

    secp256k1_fe_cmov(&u, fe, 1);
    secp256k1_fe_normalize(&u);
    secp256k1_fe_get_b32(check, &u);
    secp256k1_fe_clear(&u);

    return secp256k1_bytes_lte(check, fq2) ^ 1;
}

static void shallue_van_de_woestijne(secp256k1_ge* ge, const secp256k1_fe* t) {
    /* Implements the algorithm from:
     *    Indifferentiable Hashing to Barreto-Naehrig Curves
     *    Pierre-Alain Fouque and Mehdi Tibouchi
     *    Latincrypt 2012
     */

    /* Basic algorithm:

       c = sqrt(-3)
       d = (c - 1)/2

       w = c * t / (1 + b + t^2)  [with b = 7]
       x1 = d - t*w
       x2 = -(x1 + 1)
       x3 = 1 + 1/w^2

       To avoid the 2 divisions, compute the above in numerator/denominator form:
       wn = c * t
       wd = 1 + 7 + t^2
       x1n = d*wd - t*wn
       x1d = wd
       x2n = -(x1n + wd)
       x2d = wd
       x3n = wd^2 + c^2 + t^2
       x3d = (c * t)^2

       The joint denominator j = wd * c^2 * t^2, and
       1 / x1d = 1/j * c^2 * t^2
       1 / x2d = x3d = 1/j * wd
    */

    static const secp256k1_fe c = SECP256K1_FE_CONST(0x0a2d2ba9, 0x3507f1df, 0x233770c2, 0xa797962c, 0xc61f6d15, 0xda14ecd4, 0x7d8d27ae, 0x1cd5f852);
    static const secp256k1_fe d = SECP256K1_FE_CONST(0x851695d4, 0x9a83f8ef, 0x919bb861, 0x53cbcb16, 0x630fb68a, 0xed0a766a, 0x3ec693d6, 0x8e6afa40);
    static const secp256k1_fe b = SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 7);
    static const secp256k1_fe b_plus_one = SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 8);

    secp256k1_fe wn, wd, x1n, x2n, x3n, x3d, jinv, tmp, x1, x2, x3, alphain, betain, gammain, y1, y2, y3;
    int alphaquad, betaquad;

    secp256k1_fe_mul(&wn, &c, t); /* mag 1 */
    secp256k1_fe_sqr(&wd, t); /* mag 1 */
    secp256k1_fe_add(&wd, &b_plus_one); /* mag 2 */
    secp256k1_fe_mul(&tmp, t, &wn); /* mag 1 */
    secp256k1_fe_negate(&tmp, &tmp, 1); /* mag 2 */
    secp256k1_fe_mul(&x1n, &d, &wd); /* mag 1 */
    secp256k1_fe_add(&x1n, &tmp); /* mag 3 */
    x2n = x1n; /* mag 3 */
    secp256k1_fe_add(&x2n, &wd); /* mag 5 */
    secp256k1_fe_negate(&x2n, &x2n, 5); /* mag 6 */
    secp256k1_fe_mul(&x3d, &c, t); /* mag 1 */
    secp256k1_fe_sqr(&x3d, &x3d); /* mag 1 */
    secp256k1_fe_sqr(&x3n, &wd); /* mag 1 */
    secp256k1_fe_add(&x3n, &x3d); /* mag 2 */
    secp256k1_fe_mul(&jinv, &x3d, &wd); /* mag 1 */
    secp256k1_fe_inv(&jinv, &jinv); /* mag 1 */
    secp256k1_fe_mul(&x1, &x1n, &x3d); /* mag 1 */
    secp256k1_fe_mul(&x1, &x1, &jinv); /* mag 1 */
    secp256k1_fe_mul(&x2, &x2n, &x3d); /* mag 1 */
    secp256k1_fe_mul(&x2, &x2, &jinv); /* mag 1 */
    secp256k1_fe_mul(&x3, &x3n, &wd); /* mag 1 */
    secp256k1_fe_mul(&x3, &x3, &jinv); /* mag 1 */

    secp256k1_fe_sqr(&alphain, &x1); /* mag 1 */
    secp256k1_fe_mul(&alphain, &alphain, &x1); /* mag 1 */
    secp256k1_fe_add(&alphain, &b); /* mag 2 */
    secp256k1_fe_sqr(&betain, &x2); /* mag 1 */
    secp256k1_fe_mul(&betain, &betain, &x2); /* mag 1 */
    secp256k1_fe_add(&betain, &b); /* mag 2 */
    secp256k1_fe_sqr(&gammain, &x3); /* mag 1 */
    secp256k1_fe_mul(&gammain, &gammain, &x3); /* mag 1 */
    secp256k1_fe_add(&gammain, &b); /* mag 2 */

    alphaquad = secp256k1_fe_sqrt(&y1, &alphain);
    betaquad = secp256k1_fe_sqrt(&y2, &betain);
    secp256k1_fe_sqrt(&y3, &gammain);

    secp256k1_fe_cmov(&x1, &x2, (!alphaquad) & betaquad);
    secp256k1_fe_cmov(&y1, &y2, (!alphaquad) & betaquad);
    secp256k1_fe_cmov(&x1, &x3, (!alphaquad) & !betaquad);
    secp256k1_fe_cmov(&y1, &y3, (!alphaquad) & !betaquad);

    secp256k1_ge_set_xy(ge, &x1, &y1);

    /* The linked algorithm from the paper uses the Jacobi symbol of t to
     * determine the Jacobi symbol of the produced y coordinate. Since the
     * rest of the algorithm only uses t^2, we can safely use another criterion
     * as long as negation of t results in negation of the y coordinate. Here
     * we choose to use t's oddness, as it is faster to determine. */
    secp256k1_fe_negate(&tmp, &ge->y, 1);
    secp256k1_fe_cmov(&ge->y, &tmp, secp256k1_fe_is_neg(&ge->y) ^ secp256k1_fe_is_neg(t));
}

static void secp256k1_pubkey_store(secp256k1_pubkey* pubkey, secp256k1_ge* ge) {
    if (sizeof(secp256k1_ge_storage) == 64) {
        secp256k1_ge_storage s;
        secp256k1_ge_to_storage(&s, ge);
        memcpy(&pubkey->data[0], &s, 64);
    } else {
        VERIFY_CHECK(!secp256k1_ge_is_infinity(ge));
        secp256k1_fe_normalize_var(&ge->x);
        secp256k1_fe_normalize_var(&ge->y);
        secp256k1_fe_get_b32(pubkey->data, &ge->x);
        secp256k1_fe_get_b32(pubkey->data + 32, &ge->y);
    }
}

static void secp256k1_pubkey_from_uniform(secp256k1_pubkey* pubkey, const unsigned char* bytes) {
    secp256k1_ge ge;
    secp256k1_fe t;

    secp256k1_fe_set_b32(&t, bytes);

    shallue_van_de_woestijne(&ge, &t);

    secp256k1_pubkey_store(pubkey, &ge);

    secp256k1_ge_clear(&ge);
    secp256k1_fe_clear(&t);
}

static int secp256k1_pubkey_from_hash(secp256k1_pubkey* pubkey, const unsigned char* bytes) {
    secp256k1_gej r, j;
    secp256k1_ge ge1, ge2;
    secp256k1_fe t1, t2;
    int ret;

    secp256k1_fe_set_b32(&t1, bytes);
    secp256k1_fe_set_b32(&t2, bytes + 32);

    shallue_van_de_woestijne(&ge1, &t1);
    shallue_van_de_woestijne(&ge2, &t2);

    secp256k1_gej_set_ge(&j, &ge1);
    secp256k1_gej_add_ge(&r, &j, &ge2);
    secp256k1_ge_set_gej(&ge1, &r);

    ret = !secp256k1_ge_is_infinity(&ge1);

    if (ret)
      secp256k1_pubkey_store(pubkey, &ge1);

    secp256k1_gej_clear(&r);
    secp256k1_gej_clear(&j);
    secp256k1_ge_clear(&ge1);
    secp256k1_ge_clear(&ge2);
    secp256k1_fe_clear(&t1);
    secp256k1_fe_clear(&t2);

    return ret;
}
