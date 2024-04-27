//
//  SpeedTestWrapper.m
//  OpenSSL-for-iOS
//

#import <Foundation/Foundation.h>
#import "SpeedTestWrapper.h"
#import "speed_test.h"

@implementation SpeedTestWrapper


+ (void) performanceTest{
    NSLog(@"Sig ECDSA speed: %f", ecdsa_speed(10000));
    NSLog(@"VRF speed: %f", praos_vrf_speed(10000));
}

@end
