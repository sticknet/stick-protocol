//
//  SPIdentity.m
//  STiiiCK
//
//  Created by Omar Basem on 09/08/2020.
//  Copyright © 2020 STiiiCK. All rights reserved.
//



#import "SPIdentity.h"

@implementation SPIdentity

- (nullable instancetype)initWithAccountKey:(NSString *)accountKey identityKeyPair:(IdentityKeyPair *)identityKeyPair registrationId:(uint32_t)registrationId
{
    if (self = [super initWithUniqueId:accountKey]) {
        self.accountKey = accountKey;
        self.identityKeyPair = identityKeyPair;
        self.registrationId = registrationId;
    }
    return self;
}

@end

