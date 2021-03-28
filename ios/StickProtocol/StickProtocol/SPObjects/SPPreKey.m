//
//  SPPreKey.m
//  STiiiCK
//
//  Created by Omar Basem on 10/08/2020.
//  Copyright © 2020 STiiiCK. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "SPPreKey.h"

@implementation SPPreKey

- (nullable instancetype)initWithKeyId:(uint32_t)keyId keyData:(NSData *)keyData {
    NSString *yapKey = [[self class] uniqueKeyForKeyId:keyId];
    if (self = [super initWithUniqueId:yapKey]) {
        self.keyId = keyId;
        self.keyData = keyData;
    }
    return self;
}

+ (NSString *)uniqueKeyForKeyId:(uint32_t)keyId
{
    return [NSString stringWithFormat:@"%d",keyId];
}

@end
