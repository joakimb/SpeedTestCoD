//
//  dh_key_pair.h
//  OpenSSL-for-iOS
//
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
void prove_vrf(const EC_GROUP *group, BIGNUM *seed, BIGNUM **randval, EC_POINT *u, nizk_dl_eq_proof *pi,  key_pair *kp, BN_CTX *ctx);
int verify_vrf(const EC_GROUP *group, BIGNUM *seed, BIGNUM *randval, EC_POINT *u, nizk_dl_eq_proof *pi, EC_POINT *pub_key, BN_CTX *ctx);
#endif /* DH_KEY_PAIR_H */
