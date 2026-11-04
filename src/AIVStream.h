#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// AIV3: password-free streaming records with SHA-256 corruption detection.
/// The archive is NOT encrypted: keep exported files in a private location.
@interface AIVStream : NSObject
+ (BOOL)createBackupAtURL:(NSURL *)url
                  progress:(nullable void (^)(NSString *stage))progress
                     error:(NSError **)error;
+ (nullable NSDictionary *)previewAtURL:(NSURL *)url error:(NSError **)error;
+ (nullable NSDictionary *)restoreAtURL:(NSURL *)url error:(NSError **)error;
@end

NS_ASSUME_NONNULL_END
