#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface AIVArchive : NSObject
/// Only data visible inside the injected app's sandbox / access groups is copied.
+ (nullable NSDictionary *)capture:(NSError **)error;
+ (nullable NSDictionary *)decode:(NSData *)plain error:(NSError **)error;
+ (NSDictionary *)restore:(NSDictionary *)archive error:(NSError **)error;
/// Streaming v2 helpers: enumerate paths without loading file contents into memory.
+ (nullable NSArray<NSDictionary *> *)fileDescriptorsWithWarnings:(NSMutableArray<NSString *> *)warnings
                                                             error:(NSError **)error;
+ (NSDictionary *)captureMetadata;
+ (nullable NSURL *)restoreDestinationForPath:(NSString *)path;
@end

NS_ASSUME_NONNULL_END
