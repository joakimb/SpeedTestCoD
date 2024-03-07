//
//  dh_key_pair.h
//  OpenSSL-for-iOS
//
//  Created by Paul Stankovski Wagner on 2023-10-07.
//
#ifndef DH_KEY_PAIR_H
#define DH_KEY_PAIR_H

#include "P256.h"
#include "nizk_dl_eq.h"

typedef struct {
    BIGNUM *priv;
    EC_POINT *pub;
} key_pair;

void key_pair_free(key_pair *kp);
void key_pair_generate(const EC_GROUP *group, key_pair *kp, BN_CTX *ctx);
void prove_vrf(const EC_GROUP *group, BIGNUM *seed, BIGNUM *output, nizk_dl_eq_proof *pi, BN_CTX *ctx);
#endif /* DH_KEY_PAIR_H */
