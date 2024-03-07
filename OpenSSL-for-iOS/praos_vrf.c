//
//  dh_key_pair.c
//  OpenSSL-for-iOS
//
//  Created by Paul Stankovski Wagner on 2023-10-07.
//

#include "praos_vrf.h"
#include "openssl_hashing_tools.h"

void key_pair_free(key_pair *kp) {
    bn_free(kp->priv);
    point_free(kp->pub);
}

void key_pair_generate(const EC_GROUP *group, key_pair *kp, BN_CTX *ctx) {
    const BIGNUM *order = get0_order(group);
    kp->priv = bn_random(order, ctx);
    kp->pub = bn2point(group, kp->priv, ctx);
}

//output evaluation and proof on input a seed
void prove_vrf(const EC_GROUP *group, BIGNUM *seed, BIGNUM *output, nizk_dl_eq_proof *pi, BN_CTX *ctx) {
    //hash_seed = H'(seed)
    BIGNUM *hash_seed = openssl_hash_bn2bn(seed);
    //u = hash_seed^k
    EC_POINT *u = bn2point(group, hash_seed, ctx);
    point_mul(group, u, hash_seed, u, ctx);
    //y = H(m,u):
    //interpret m into a point first for easier hashing
    EC_POINT *seed_point = bn2point(group, seed, ctx);
    //then use hash of points interface
    output = openssl_hash_points2bn(group, ctx, 2, seed_point, u);
    //continue coding here, follwoing spec from praos paper.
    
    //WE ARE NOW USING ONLY ONE HASH FUNCTION, INVESTIGATE SECURITY NEED FoR TWO
    
    
    point_free(u);
    point_free(seed_point);
    bn_free(hash_seed);
}
