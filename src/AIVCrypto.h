#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Password-protected local container: AIV1 | salt | IV | HMAC | AES-CBC ciphertext.
/// This is an export format, not a substitute for iOS Data Protection.
@interface AIVCrypto : NSObject
+ (nullable NSData *)encrypt:(NSData *)plain password:(NSString *)password error:(NSError **)error;
+ (nullable NSData *)decrypt:(NSData *)packed password:(NSString *)password error:(NSError **)error;
@end

NS_ASSUME_NONNULL_END
