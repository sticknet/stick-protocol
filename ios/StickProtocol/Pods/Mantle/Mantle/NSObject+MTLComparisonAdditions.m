//
//  NSObject+MTLComparisonAdditions.m
//  Mantle
//
//  Created by Josh Vera on 10/26/12.
//  Copyright © 2012 GitHub. All rights reserved.
//
//  Portions copyright © 2011 Bitswift. All rights reserved.
//  See the LICENSE file for more information.
//

#import "NSObject+MTLComparisonAdditions.h"

BOOL MTLEqualObjects(id obj1, id obj2) {
	return (obj1 == obj2 || [obj1 isEqual:obj2]);
}
