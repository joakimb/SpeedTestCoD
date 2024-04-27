//
//  dh_key_pair.c
//  OpenSSL-for-iOS
//

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

//output randval and proof on input a seed and keypair
void prove_vrf(const EC_GROUP *group, BIGNUM *seed, BIGNUM **randval, EC_POINT *u, nizk_dl_eq_proof *pi,  key_pair *kp, BN_CTX *ctx) {
    //hash_seed = H'(seed)
    BIGNUM *hash_seed = openssl_hash_bn2bn(seed);
    //u = hash_seed^k
    EC_POINT *hash_seed_point = bn2point(group, hash_seed, ctx);
    
    point_mul(group, u, kp->priv, hash_seed_point, ctx);
    //y = H(m,u):
    //interpret seed into a point first for easier hashing
    EC_POINT *seed_point = bn2point(group, seed, ctx);
    //then use hash of points interface
    *randval = openssl_hash_points2bn(group, ctx, 2, seed_point, u);
    
    //nizk_dl_eq_prove(const EC_GROUP *group, const BIGNUM *exp, const EC_POINT *a, const EC_POINT *A, const EC_POINT *b, const EC_POINT *B, nizk_dl_eq_proof *pi, BN_CTX *ctx)
    nizk_dl_eq_prove(group, kp->priv, hash_seed_point, u, get0_generator(group), kp->pub, pi, ctx);
    
    //WE ARE NOW USING ONLY ONE HASH FUNCTION, INVESTIGATE SECURITY NEED FoR TWO
    
    
    point_free(seed_point);
    point_free(hash_seed_point);
    bn_free(hash_seed);
}

int verify_vrf(const EC_GROUP *group, BIGNUM *seed, BIGNUM *randval, EC_POINT *u, nizk_dl_eq_proof *pi, EC_POINT *pub_key, BN_CTX *ctx) {
    
    EC_POINT *seed_point = bn2point(group, seed, ctx); //optimize?
    BIGNUM *hash_seed = openssl_hash_bn2bn(seed);//optimize?
    EC_POINT *hash_seed_point = bn2point(group, hash_seed, ctx);//optimize?
    BIGNUM *rand_val_calc = openssl_hash_points2bn(group, ctx, 2, seed_point, u);
    
    if (0 != BN_cmp(randval, rand_val_calc)) {//cmp outputs 0 if equal
        return 1;//return false
    }
    
    int val_proof = nizk_dl_eq_verify(group, hash_seed_point, u, get0_generator(group), pub_key, pi, ctx);
    
    point_free(seed_point);
    bn_free(hash_seed);
    point_free(hash_seed_point);
    return val_proof;//returns 0 on successful validation
}
