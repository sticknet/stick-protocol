//
//  SPSignalSession.h
//  STiiiCK
//
//  Created by Omar Basem on 10/08/2020.
//  Copyright © 2020 STiiiCK. All rights reserved.
//

#import "SPObject.h"

NS_ASSUME_NONNULL_BEGIN

@interface SPSignalSession : SPObject

@property (nonatomic, strong) NSString * name;
@property (nonatomic) int32_t deviceId;
@property (nonatomic, strong) NSData *sessionData;

- (nullable instancetype)initWithAccountKey:(NSString *)accountKey name:(NSString *)name deviceId:(int32_t)deviceId sessionData:(NSData *)sessionData;

+ (NSString *)uniqueKeyForAccountKey:(NSString *)accountKey name:(NSString *)name deviceId:(int32_t)deviceId;

@end

NS_ASSUME_NONNULL_END

