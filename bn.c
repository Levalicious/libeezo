/*
 * bn.c - the natural numbers as a list of limbs (see bn.h)
 */
#include "bn.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* The limb lists come from the resource policy (res.h): a failed allocation is never a typing
   judgement. BN_TEST builds this file as its own program, on plain calloc. */
#ifdef BN_TEST
static void *bn_bytes(size_t n) { void *p = calloc(1, n ? n : 1); if (!p) { fprintf(stderr, "out of memory\n"); exit(1); } return p; }
#else
#include "res.h"
static void *bn_bytes(size_t n) { return rcalloc(1, n); }
#endif

typedef unsigned __int128 u128;
typedef __int128 i128;

static Bn *bn_alloc(int n) {
    Bn *b = bn_bytes(sizeof *b);
    b->limb = n ? bn_bytes((size_t)n * sizeof(u64)) : NULL;
    b->n = n;
    return b;
}
static Bn *bn_norm(Bn *b) {
    while (b->n > 0 && b->limb[b->n - 1] == 0) b->n--;
    return b;
}

Bn *bn_from_u64(u64 x) { Bn *b = bn_alloc(1); b->limb[0] = x; return bn_norm(b); }
Bn *bn_from_limbs(const u64 *limb, int n) {
    Bn *b = bn_alloc(n);
    if (n) memcpy(b->limb, limb, (size_t)n * sizeof(u64));
    return bn_norm(b);
}
Bn *bn_copy(const Bn *a) { return bn_from_limbs(a->limb, a->n); }
void bn_free(Bn *a) { if (!a) return; free(a->limb); free(a); }
int bn_is_zero(const Bn *a) { return a->n == 0; }
int bn_to_u64(const Bn *a, u64 *out) { if (a->n > 1) return 0; *out = a->n ? a->limb[0] : 0; return 1; }

int bn_cmp(const Bn *a, const Bn *b) {
    if (a->n != b->n) return a->n < b->n ? -1 : 1;
    for (int i = a->n - 1; i >= 0; i--)
        if (a->limb[i] != b->limb[i]) return a->limb[i] < b->limb[i] ? -1 : 1;
    return 0;
}

int bn_bitlen(const Bn *a) {
    if (a->n == 0) return 0;
    return 64 * (a->n - 1) + (64 - __builtin_clzll(a->limb[a->n - 1]));
}
int bn_bit(const Bn *a, int i) {
    if (i < 0 || i >= 64 * a->n) return 0;
    return (int)((a->limb[i / 64] >> (i % 64)) & 1);
}

Bn *bn_add(const Bn *a, const Bn *b) {
    if (a->n < b->n) { const Bn *t = a; a = b; b = t; }
    Bn *r = bn_alloc(a->n + 1);
    u64 carry = 0;
    for (int i = 0; i < a->n; i++) {
        u128 s = (u128)a->limb[i] + (i < b->n ? b->limb[i] : 0) + carry;
        r->limb[i] = (u64)s; carry = (u64)(s >> 64);
    }
    r->limb[a->n] = carry;
    return bn_norm(r);
}

Bn *bn_monus(const Bn *a, const Bn *b) {
    if (bn_cmp(a, b) <= 0) return bn_alloc(0);
    Bn *r = bn_alloc(a->n);
    u64 borrow = 0;
    for (int i = 0; i < a->n; i++) {
        u64 bi = i < b->n ? b->limb[i] : 0;
        u128 d = (u128)a->limb[i] - bi - borrow;
        r->limb[i] = (u64)d;
        borrow = (u64)(d >> 64) & 1;    /* wrapped: the high word is all ones */
    }
    return bn_norm(r);
}

Bn *bn_mul(const Bn *a, const Bn *b) {
    if (a->n == 0 || b->n == 0) return bn_alloc(0);
    Bn *r = bn_alloc(a->n + b->n);
    for (int i = 0; i < a->n; i++) {
        u64 carry = 0;
        for (int j = 0; j < b->n; j++) {
            u128 t = (u128)a->limb[i] * b->limb[j] + r->limb[i + j] + carry;
            r->limb[i + j] = (u64)t; carry = (u64)(t >> 64);
        }
        r->limb[i + b->n] = carry;
    }
    return bn_norm(r);
}

/* r = r * m + c in place (r has room for one more limb) */
static void mul_small_add(Bn *r, u64 m, u64 c) {
    u64 carry = c;
    for (int i = 0; i < r->n; i++) {
        u128 t = (u128)r->limb[i] * m + carry;
        r->limb[i] = (u64)t; carry = (u64)(t >> 64);
    }
    if (carry) r->limb[r->n++] = carry;
}

/* Knuth's algorithm D on 64-bit digits (Hacker's Delight divmnu, with 128-bit intermediates) */
void bn_divmod(const Bn *a, const Bn *b, Bn **q, Bn **r) {
    if (b->n == 0 || bn_cmp(a, b) < 0) {   /* x / 0 = 0, x % 0 = x; and a small dividend */
        *q = bn_alloc(0); *r = bn_alloc(a->n);
        if (a->n) memcpy((*r)->limb, a->limb, (size_t)a->n * sizeof(u64));
        return;
    }
    if (b->n == 1) {
        u64 d = b->limb[0], rem = 0;
        Bn *qq = bn_alloc(a->n);
        for (int i = a->n - 1; i >= 0; i--) {
            u128 cur = ((u128)rem << 64) | a->limb[i];
            qq->limb[i] = (u64)(cur / d); rem = (u64)(cur % d);
        }
        *q = bn_norm(qq); *r = bn_from_u64(rem);
        return;
    }
    int m = a->n, n = b->n;
    int s = __builtin_clzll(b->limb[n - 1]);
    u64 *vn = bn_bytes((size_t)n * sizeof(u64)), *un = bn_bytes((size_t)(m + 1) * sizeof(u64));
    for (int i = n - 1; i > 0; i--) vn[i] = s ? (b->limb[i] << s) | (b->limb[i - 1] >> (64 - s)) : b->limb[i];
    vn[0] = b->limb[0] << s;
    un[m] = s ? a->limb[m - 1] >> (64 - s) : 0;
    for (int i = m - 1; i > 0; i--) un[i] = s ? (a->limb[i] << s) | (a->limb[i - 1] >> (64 - s)) : a->limb[i];
    un[0] = a->limb[0] << s;
    Bn *qq = bn_alloc(m - n + 1);
    const u128 B = (u128)1 << 64;
    for (int j = m - n; j >= 0; j--) {
        u128 num = ((u128)un[j + n] << 64) | un[j + n - 1];
        u128 qhat = num / vn[n - 1], rhat = num % vn[n - 1];
        while (qhat >= B || qhat * vn[n - 2] > ((rhat << 64) | un[j + n - 2])) {
            qhat--; rhat += vn[n - 1];
            if (rhat >= B) break;
        }
        i128 t; u64 k = 0;
        for (int i = 0; i < n; i++) {
            u128 p = qhat * vn[i];
            t = (i128)un[i + j] - k - (u64)p;
            un[i + j] = (u64)t;
            k = (u64)(p >> 64) - (u64)(t >> 64);
        }
        t = (i128)un[j + n] - k;
        un[j + n] = (u64)t;
        qq->limb[j] = (u64)qhat;
        if (t < 0) {   /* one too many: add back */
            qq->limb[j]--;
            u64 c = 0;
            for (int i = 0; i < n; i++) {
                u128 s2 = (u128)un[i + j] + vn[i] + c;
                un[i + j] = (u64)s2; c = (u64)(s2 >> 64);
            }
            un[j + n] += c;
        }
    }
    Bn *rr = bn_alloc(n);
    for (int i = 0; i < n; i++) rr->limb[i] = s ? (un[i] >> s) | (un[i + 1] << (64 - s)) : un[i];
    *q = bn_norm(qq); *r = bn_norm(rr);
    free(vn); free(un);
}

Bn *bn_pow(const Bn *a, const Bn *e) {
    Bn *result = bn_from_u64(1), *base = (Bn *)a;
    int bits = bn_bitlen(e);
    for (int i = 0; i < bits; i++) {
        if (bn_bit(e, i)) result = bn_mul(result, base);
        if (i + 1 < bits) base = bn_mul(base, base);
    }
    return result;
}

/*
 * a ^ e mod m (m != 0), by square and multiply with every product reduced: the cost is the size of the
 * exponent and of the modulus, and a ^ e is never built. That is the difference between a number the
 * machine can hold and a number it can only denote - 3 ^ (2 ^ 64) has no limbs to hold it in, but its
 * residue modulo a machine-sized prime does, and this is how you get it.
 */
Bn *bn_powmod(const Bn *a, const Bn *e, const Bn *m) {
    Bn *q, *r;
    Bn *acc = bn_from_u64(1);
    bn_divmod(acc, m, &q, &r); bn_free(q); bn_free(acc); acc = r;      /* 1 mod m */
    Bn *base = bn_copy(a);
    bn_divmod(base, m, &q, &r); bn_free(q); bn_free(base); base = r;   /* a mod m */
    for (int i = bn_bitlen(e) - 1; i >= 0; i--) {
        Bn *t = bn_mul(acc, acc); bn_free(acc); bn_divmod(t, m, &q, &r); bn_free(q); bn_free(t); acc = r;
        if (bn_bit(e, i)) {
            t = bn_mul(acc, base); bn_free(acc); bn_divmod(t, m, &q, &r); bn_free(q); bn_free(t); acc = r;
        }
    }
    bn_free(base);
    return acc;
}

/* minv x y = mod (pow x (y - 2)) y: the exponent is the modulus's own size, so the power is taken modulo
   y all the way. The value is the one the definition names; computing the power first and dividing it
   after is what made an inverse of a machine-sized modulus impossible. y <= 2 leaves the exponent 0, and
   that is 1 mod y (x % 0 = x, so y = 0 gives 1). */
Bn *bn_minv(const Bn *x, const Bn *y) {
    Bn *two = bn_from_u64(2), *e = bn_monus(y, two), *r;
    if (bn_is_zero(y)) r = bn_from_u64(1);
    else r = bn_powmod(x, e, y);
    bn_free(two); bn_free(e);
    return r;
}

Bn *bn_succ(const Bn *a) { Bn one = { (u64[]){1}, 1 }; return bn_add(a, &one); }
Bn *bn_pred(const Bn *a) { Bn one = { (u64[]){1}, 1 }; return bn_monus(a, &one); }

Bn *bn_from_dec(const char *s) {
    if (!*s) return NULL;
    for (const char *p = s; *p; p++) if (*p < '0' || *p > '9') return NULL;
    size_t len = strlen(s);
    Bn *r = bn_alloc((int)(len / 19 + 2));
    r->n = 0;
    size_t i = 0;
    while (i < len) {
        size_t take = len - i < 19 ? len - i : 19;
        u64 chunk = 0, scale = 1;
        for (size_t k = 0; k < take; k++) { chunk = chunk * 10 + (u64)(s[i + k] - '0'); scale *= 10; }
        mul_small_add(r, scale, chunk);
        i += take;
    }
    return bn_norm(r);
}

char *bn_to_dec(const Bn *a) {
    if (a->n == 0) { char *z = bn_bytes(2); z[0] = '0'; return z; }
    const u64 TEN19 = 10000000000000000000ULL;
    Bn ten19 = { (u64[]){TEN19}, 1 };
    char *chunks = bn_bytes((size_t)a->n * 20 + 21);
    /* the chunk array holds u64s, so it is sized in u64s: a limb is one chunk and a fraction (19 digits
       against 64 bits), so 2n + 2 of them always suffice. Sized in bytes until 2026-09-22, it was four
       times too small - the heap came back as "double free or corruption" on every literal of a few
       hundred limbs and was quietly overrun below that. */
    int nchunks = 0; u64 *vals = bn_bytes(((size_t)a->n * 2 + 2) * sizeof(u64));
    Bn *cur = bn_copy(a);   /* the working dividend, ours to free: the chunk loop allocated one per chunk and dropped it */
    while (cur->n > 0) {
        Bn *q, *r;
        bn_divmod(cur, &ten19, &q, &r);
        u64 v = 0; bn_to_u64(r, &v);
        vals[nchunks++] = v;
        bn_free(r); bn_free(cur);
        cur = q;
    }
    bn_free(cur);
    char *out = chunks; size_t pos = 0;
    pos += (size_t)sprintf(out + pos, "%llu", (unsigned long long)vals[nchunks - 1]);
    for (int i = nchunks - 2; i >= 0; i--) pos += (size_t)sprintf(out + pos, "%019llu", (unsigned long long)vals[i]);
    free(vals);
    return out;
}

#ifdef BN_TEST
static int fails = 0;
static void expect(const char *what, const Bn *got, const char *want) {
    char *g = bn_to_dec(got);
    if (strcmp(g, want)) { printf("FAIL %s: got %s want %s\n", what, g, want); fails++; } else printf("ok   %s = %s\n", what, want);
}
int main(void) {
    Bn *two = bn_from_u64(2), *n64 = bn_from_u64(64);
    Bn *p = bn_pow(two, n64);
    expect("2^64", p, "18446744073709551616");
    Bn *m = bn_pred(p);
    expect("2^64-1", m, "18446744073709551615");
    expect("(2^64-1)^2", bn_mul(m, m), "340282366920938463426481119284349108225");
    Bn *q, *r;
    bn_divmod(bn_mul(m, m), p, &q, &r); expect("(2^64-1)^2 / 2^64", q, "18446744073709551614"); expect("(2^64-1)^2 % 2^64", r, "1");
    Bn *big = bn_from_dec("123456789012345678901234567890123456789012345678901234567890");
    expect("roundtrip", big, "123456789012345678901234567890123456789012345678901234567890");
    Bn *d = bn_from_dec("98765432109876543210987654321");
    bn_divmod(big, d, &q, &r);
    expect("big / d", q, "1249999988609375000142382812499");
    expect("big % d", r, "46440971104644097110464409711");
    expect("q*d + r", bn_add(bn_mul(q, d), r), "123456789012345678901234567890123456789012345678901234567890");
    bn_divmod(big, bn_from_u64(0), &q, &r); expect("x / 0", q, "0"); expect("x % 0", r, "123456789012345678901234567890123456789012345678901234567890");
    expect("monus 3 5", bn_monus(bn_from_u64(3), bn_from_u64(5)), "0");
    expect("monus 5 3", bn_monus(bn_from_u64(5), bn_from_u64(3)), "2");
    expect("2^64 - 1 (monus)", bn_monus(p, bn_from_u64(1)), "18446744073709551615");
    expect("3^100", bn_pow(bn_from_u64(3), bn_from_u64(100)), "515377520732011331036461129765621272702107522001");
    Bn *k = bn_from_dec("340282366920938463463374607431768211456");   /* 2^128 */
    bn_divmod(k, bn_from_dec("18446744073709551617"), &q, &r);        /* 2^128 / (2^64+1) = 2^64 - 1 rem 1 */
    expect("2^128 / (2^64+1)", q, "18446744073709551615"); expect("2^128 % (2^64+1)", r, "1");
    printf("bitlen 2^64 = %d, bit 64 = %d, cmp = %d\n", bn_bitlen(p), bn_bit(p, 64), bn_cmp(p, m));
    return fails ? 1 : 0;
}
#endif
