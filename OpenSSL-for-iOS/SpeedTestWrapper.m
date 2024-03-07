//
//  SpeedTestWrapper.m
//  OpenSSL-for-iOS
//
//  Created by Joakim Brorsson on 2024-03-06.
//  Copyright © 2024 Felix Schulze. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "SpeedTestWrapper.h"
#import "speed_test.h"

@implementation SpeedTestWrapper


+ (void) performanceTest{
    NSLog(@"Sig ECDSA speed: %f", ecdsa_speed(20000));
}

@end
