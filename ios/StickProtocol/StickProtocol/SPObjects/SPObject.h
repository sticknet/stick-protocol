//
//  SPObject.h
//  STiiiCK
//
//  Created by Omar Basem on 09/08/2020.
//  Copyright © 2020 STiiiCK. All rights reserved.
//

#import "YapDatabaseObject.h"

NS_ASSUME_NONNULL_BEGIN

// Stick Protocol Object

@interface SPObject : YapDatabaseObject

@property (nonnull, strong) NSString *accountKey;

@end

NS_ASSUME_NONNULL_END

