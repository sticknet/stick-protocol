//
//  SPSignalSession.m
//  STiiiCK
//
//  Created by Omar Basem on 10/08/2020.
//  Copyright © 2020 STiiiCK. All rights reserved.
//

#import "SPSignalSession.h"

@implementation SPSignalSession

- (nullable instancetype)initWithAccountKey:(NSString *)accountKey name:(NSString *)name deviceId:(int32_t)deviceId sessionData:(NSData *)sessionData
{
    NSString *yapKey = [[self class] uniqueKeyForAccountKey:accountKey name:name deviceId:deviceId];
    if (self = [super initWithUniqueId:yapKey] ) {
        self.accountKey = accountKey;
        self.name = name;
        self.deviceId = deviceId;
        self.sessionData = sessionData;
    }
    return self;
}

+ (NSString *)uniqueKeyForAccountKey:(NSString *)accountKey name:(NSString *)name deviceId:(int32_t)deviceId
{
    return [NSString stringWithFormat:@"%@-%@-%d",accountKey,name,deviceId];
}

@end

