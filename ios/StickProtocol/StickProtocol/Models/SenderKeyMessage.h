//
//  SenderKeyMessage.h
//  STiiiCK
//
//  Created by Omar Basem on 12/08/2020.
//  Copyright © 2020 STiiiCK. All rights reserved.
//

@import Foundation;
#import "SignalContext.h"

NS_ASSUME_NONNULL_BEGIN

@interface SenderKeyMessage : NSObject

- (nullable instancetype)initWithData:(NSData *)data
                              context:(SignalContext *)context
                                error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
