//
//  dh_key_pair.c
//  OpenSSL-for-iOS
//
//  Created by Paul Stankovski Wagner on 2023-10-07.
//

#include "key_pair.h"

void key_pair_free(key_pair *kp) {
    bn_free(kp->priv);
    point_free(kp->pub);
}

void key_pair_generate(const EC_GROUP *group, key_pair *kp, BN_CTX *ctx) {
    const BIGNUM *order = get0_order(group);
    kp->priv = bn_random(order, ctx);
    kp->pub = bn2point(group, kp->priv, ctx);
}
