//
//  SigSpeed.c
//  OpenSSL-for-iOS
//
//

#include "speed_test.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include "platform_measurement_utils.h"
#include "praos_vrf.h"

void handleErrors(const char *msg) {
    fprintf(stderr, "Error: %s\n", msg);
    exit(EXIT_FAILURE);
}


double ecdsa_speed(int num_reps) {
    
    // Create an EC_KEY structure for P-256 curve
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key) {
        handleErrors("Failed to create EC_KEY structure");
    }
    
    // Generate key pair
    if (EC_KEY_generate_key(ec_key) != 1) {
        handleErrors("Failed to generate key pair");
    }
    
    // Get the private key
    const BIGNUM *priv_key = EC_KEY_get0_private_key(ec_key);
    
    // Create the ECDSA signature context
    ECDSA_SIG *signature;
    
    // Message to be signed
    const char *message = "Hello, ECDSA!";
    size_t message_len = strlen(message);
    
    // Calculate the SHA-256 hash of the message
    unsigned char digest[32];
    SHA256((const unsigned char *)message, message_len, digest);
    
    platform_time_type start = platform_utils_get_wall_time();
    

    // Sign the message
    signature = ECDSA_do_sign(digest, sizeof(digest), ec_key);
    if (!signature) {
        handleErrors("Failed to sign the message");
    }
    
    for(int i = 0; i < num_reps; i++) {
        // Verify the signature
        if (ECDSA_do_verify(digest, sizeof(digest), signature, ec_key) != 1) {
            handleErrors("Failed to verify the signature");
        }
    }
    
    platform_time_type end = platform_utils_get_wall_time();
    double sig_speed = platform_utils_get_wall_time_diff(start, end);
    
    
    // Clean up
    ECDSA_SIG_free(signature);
    EC_KEY_free(ec_key);
    
    return sig_speed;
}

double praos_vrf_speed(int num_reps) {
    
    const EC_GROUP *group = get0_group();
    BN_CTX *ctx = BN_CTX_new();
    key_pair kp;
    
    key_pair_generate(group, &kp, ctx);
    BIGNUM *seed = bn_random(get0_order(group), ctx);
    BIGNUM *rand_val;// = bn_new();
    EC_POINT *u = point_new(group);
    nizk_dl_eq_proof pi;
    
    prove_vrf(group, seed, &rand_val, u, &pi, &kp, ctx);
    
    int ver;
    
    platform_time_type start = platform_utils_get_wall_time();
    for(int i = 0; i < num_reps; i++) {
        ver = verify_vrf(group, seed, rand_val, u, &pi, kp.pub, ctx);
    }
    
    platform_time_type end = platform_utils_get_wall_time();
    double vrf_speed = platform_utils_get_wall_time_diff(start, end);
    
    if (ver == 0){
        printf("VRF verified successfully!\n");
    } else {
        printf("VRF FAILED to verify!\n");
    }
    
    //    void dh_key_pair_free(dh_key_pair *kp);
    BN_CTX_free(ctx);
    point_free(u);
    bn_free(seed);
    bn_free(rand_val);
    nizk_dl_eq_proof_free(&pi);

    return vrf_speed;

}
