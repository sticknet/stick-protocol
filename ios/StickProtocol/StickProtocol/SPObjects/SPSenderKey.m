//
//  SPSenderKey.m
//  STiiiCK
//
//  Created by Omar Basem on 12/08/2020.
//  Copyright © 2020 STiiiCK. All rights reserved.
//


#import <Foundation/Foundation.h>
#import "SPSenderKey.h"

@implementation SPSenderKey

- (nullable instancetype)initWithAccountKey:(NSString *)accountKey keyId:(int32_t)keyId keyData:(NSData *)keyData {
    NSString *yapKey = [[self class] uniqueKeyForAccountKey:accountKey keyId:keyId];
    if (self = [super initWithUniqueId:yapKey]) {
        self.accountKey = accountKey;
        self.keyId = keyId;
        self.keyData = keyData;
    }
    return self;
}


+ (NSString *)uniqueKeyForAccountKey:(NSString *)accountKey keyId:(int32_t)keyId
{
    return [NSString stringWithFormat:@"%@-%d",accountKey,keyId];
}

@end
