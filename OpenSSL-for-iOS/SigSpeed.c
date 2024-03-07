//
//  SigSpeed.c
//  OpenSSL-for-iOS
//
//  Created by Joakim Brorsson on 2024-03-07.
//  Copyright © 2024 Felix Schulze. All rights reserved.
//

#include "SigSpeed.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include "platform_measurement_utils.h"

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
    
    // Get the public key
    const EC_POINT *pub_key = EC_KEY_get0_public_key(ec_key);
    
    // Create the ECDSA signature context
    ECDSA_SIG *signature;
    
    // Message to be signed
    const char *message = "Hello, ECDSA!";
    size_t message_len = strlen(message);
    
    // Calculate the SHA-256 hash of the message
    unsigned char digest[32];
    SHA256((const unsigned char *)message, message_len, digest);
    
    platform_time_type start = platform_utils_get_wall_time();
    

    for(int i = 0; i < num_reps; i++) {
        // Sign the message
        signature = ECDSA_do_sign(digest, sizeof(digest), ec_key);
        if (!signature) {
            handleErrors("Failed to sign the message");
        }
    }
    
    platform_time_type end = platform_utils_get_wall_time();
    double sig_speed = platform_utils_get_wall_time_diff(start, end);
    
    // Verify the signature
    if (ECDSA_do_verify(digest, sizeof(digest), signature, ec_key) != 1) {
        handleErrors("Failed to verify the signature");
    } else {
        printf("Signature verified successfully!\n");
    }
    
    // Clean up
    ECDSA_SIG_free(signature);
    EC_KEY_free(ec_key);
    
    return sig_speed;
}
