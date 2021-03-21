//
//  SPIdentity.h
//  STiiiCK
//
//  Created by Omar Basem on 09/08/2020.
//  Copyright © 2020 STiiiCK. All rights reserved.
//


#import "SPObject.h"
@class IdentityKeyPair;

NS_ASSUME_NONNULL_BEGIN

/** There should only be one SPIdentity in the database for an account */
@interface SPIdentity : SPObject

@property (nonatomic, strong) IdentityKeyPair *identityKeyPair;
@property (nonatomic) uint32_t registrationId;

- (nullable instancetype)initWithAccountKey:(NSString *)accountKey identityKeyPair:(IdentityKeyPair *)identityKeyPair registrationId:(uint32_t)registrationId;

@end
NS_ASSUME_NONNULL_END
