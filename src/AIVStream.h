#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// AIV2: encrypted, authenticated, streaming file records.
/// Files are processed in bounded chunks regardless of their total size.
@interface AIVStream : NSObject
+ (BOOL)createBackupAtURL:(NSURL *)url password:(NSString *)password error:(NSError **)error;
+ (nullable NSDictionary *)previewAtURL:(NSURL *)url password:(NSString *)password error:(NSError **)error;
+ (nullable NSDictionary *)restoreAtURL:(NSURL *)url password:(NSString *)password error:(NSError **)error;
@end

NS_ASSUME_NONNULL_END
