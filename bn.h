/*
 * bn.h - the natural numbers as a list of limbs (M15, the runtime's since 2026-09-16).
 *
 * Immutable arbitrary-precision naturals: little-endian u64 limbs with no
 * leading zero limb, zero being the empty limb array. Plain C, our own, and
 * THE list: the checker's literals and native definitions (add sub mul div
 * mod pow eq lt le on a type shaped like the naturals) compute on these, and
 * so do the run-time limb primitives, which hand a chain of machine words to
 * exactly these functions rather than unfolding a fold (see term.h's TERM_BIG).
 * Conventions match the run-time words and the definitions they stand
 * for: sub is monus, x / 0 = 0, x % 0 = x.
 */
#ifndef EEZOTT_BN_H
#define EEZOTT_BN_H

#include "types.h"

typedef struct { u64 *limb; int n; } Bn;

Bn *bn_from_u64(u64 x);
Bn *bn_from_dec(const char *s);          /* decimal digits; NULL if not */
Bn *bn_from_limbs(const u64 *limb, int n);  /* little-endian, as the list reads; normalized */
Bn *bn_copy(const Bn *a);                /* freshly allocated, canonical */
void bn_free(Bn *a);                     /* and nothing else refers to it */
char *bn_to_dec(const Bn *a);            /* freshly allocated */
int bn_is_zero(const Bn *a);
int bn_cmp(const Bn *a, const Bn *b);
int bn_to_u64(const Bn *a, u64 *out);    /* 1 if it fits */
int bn_bitlen(const Bn *a);
int bn_bit(const Bn *a, int i);
Bn *bn_add(const Bn *a, const Bn *b);
Bn *bn_monus(const Bn *a, const Bn *b);  /* a - b, or 0 */
Bn *bn_mul(const Bn *a, const Bn *b);
void bn_divmod(const Bn *a, const Bn *b, Bn **q, Bn **r);
Bn *bn_pow(const Bn *a, const Bn *e);
/* a limb list lives in memory; past this it is not one, and a value that would need more is denoted
   rather than built (M17) */
#define BN_MAX_BYTES ((size_t)1 << 30)
Bn *bn_powmod(const Bn *a, const Bn *e, const Bn *m);  /* a ^ e mod m, m != 0: never builds a ^ e */
Bn *bn_minv(const Bn *x, const Bn *y);                 /* mod (pow x (sub y 2)) y, by the modular power */
Bn *bn_succ(const Bn *a);
Bn *bn_pred(const Bn *a);                /* 0 stays 0 */

#endif
