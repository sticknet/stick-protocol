////
////  SetupDatabase.m
////  STiiiCK
////
////  Created by Omar Basem on 21/08/2020.
////  Copyright © 2020 STiiiCK. All rights reserved.
////
//
//#import <Foundation/Foundation.h>
//#import <YapDatabase/YapDatabase.h>
//#import "DatabaseSetup.h"
//
//@implementation DatabaseSetup : NSObject
//
//+ (NSString *)databasePath
//{
//  NSURL *fileManagerURL = [[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:@"group.com.stiiick"];
//  NSString *tmpPath = [NSString stringWithFormat:@"%@", fileManagerURL.path];
//  NSString *finalPath = [NSString stringWithFormat:@"%@",[tmpPath stringByAppendingString:@"/database.sqlite"]];
//  return finalPath;
//}
//
//+ (YapDatabase *)setupDatabase
//{
//  NSProcessInfo *processInfo = [NSProcessInfo processInfo];
//  NSString *processName = [processInfo processName];
//  if ([processName  isEqual: @"STiiiCK"]) {
//    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
//      NSString *baseDir = ([paths count] > 0) ? paths[0] : NSTemporaryDirectory();
//      NSString *initPath = [baseDir stringByAppendingPathComponent:@"/init.txt"];
//      NSString* content = [NSString stringWithContentsOfFile:initPath encoding:NSUTF8StringEncoding error:NULL];
//    if (content == NULL) {
//       [self deleteDatabase];
//    }
//  }
//  
//     
//    NSString *databasePath = [self databasePath];
//  
//  return [[YapDatabase alloc] initWithPath:[NSString stringWithFormat:@"file://%@", databasePath]];
//}
//
//+ (void)deleteDatabase
//{
//  NSLog(@"DELETING DATABASE");
//  NSString *databasePath = [self databasePath];
//  [[NSFileManager defaultManager] removeItemAtPath:databasePath error:NULL];
//}
//
//@end
//
//
