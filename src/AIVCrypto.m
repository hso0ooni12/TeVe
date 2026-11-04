#import "AIVCrypto.h"
#import <CommonCrypto/CommonCrypto.h>
#import <Security/Security.h>
#import <string.h>

static NSString *const AIVCryptoDomain = @"com.appidentityvault.crypto";
static const uint8_t kAIVMagic[] = {'A', 'I', 'V', '1'};
static const NSUInteger kAIVSaltSize = 16;
static const NSUInteger kAIVIVSize = 16;
static const NSUInteger kAIVMacSize = CC_SHA256_DIGEST_LENGTH;
static const unsigned kAIVIterations = 220000;

static NSError *AIVCryptoError(NSInteger code, NSString *message) {
    return [NSError errorWithDomain:AIVCryptoDomain code:code
                         userInfo:@{NSLocalizedDescriptionKey: message}];
}

static BOOL AIVDerive(NSString *password, const uint8_t *salt, uint8_t keys[64]) {
    NSData *pass = [password dataUsingEncoding:NSUTF8StringEncoding];
    return CCKeyDerivationPBKDF(kCCPBKDF2, pass.bytes, pass.length,
                               salt, kAIVSaltSize, kCCPRFHmacAlgSHA256,
                               kAIVIterations, keys, 64) == kCCSuccess;
}

static BOOL AIVConstantTimeEqual(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t result = 0;
    for (size_t i = 0; i < n; i++) result |= a[i] ^ b[i];
    return result == 0;
}

@implementation AIVCrypto

+ (NSData *)encrypt:(NSData *)plain password:(NSString *)password error:(NSError **)error {
    if (password.length < 8) {
        if (error) *error = AIVCryptoError(1, @"Use a password of at least 8 characters.");
        return nil;
    }
    uint8_t salt[16], iv[16], keys[64] = {0};
    if (SecRandomCopyBytes(kSecRandomDefault, sizeof(salt), salt) != errSecSuccess ||
        SecRandomCopyBytes(kSecRandomDefault, sizeof(iv), iv) != errSecSuccess ||
        !AIVDerive(password, salt, keys)) {
        if (error) *error = AIVCryptoError(2, @"Could not create an encryption key.");
        return nil;
    }
    NSMutableData *cipher = [NSMutableData dataWithLength:plain.length + kCCBlockSizeAES128];
    size_t cipherLength = 0;
    CCCryptorStatus status = CCCrypt(kCCEncrypt, kCCAlgorithmAES,
                                    kCCOptionPKCS7Padding, keys, kCCKeySizeAES256,
                                    iv, plain.bytes, plain.length,
                                    cipher.mutableBytes, cipher.length, &cipherLength);
    if (status != kCCSuccess) {
        memset(keys, 0, sizeof(keys));
        if (error) *error = AIVCryptoError(3, @"Encryption failed.");
        return nil;
    }
    cipher.length = cipherLength;
    NSMutableData *authenticated = [NSMutableData dataWithBytes:kAIVMagic length:sizeof(kAIVMagic)];
    [authenticated appendBytes:salt length:sizeof(salt)];
    [authenticated appendBytes:iv length:sizeof(iv)];
    [authenticated appendData:cipher];
    uint8_t mac[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, keys + 32, 32,
           authenticated.bytes, authenticated.length, mac);
    NSMutableData *result = [NSMutableData dataWithCapacity:authenticated.length + sizeof(mac)];
    [result appendBytes:authenticated.bytes length:sizeof(kAIVMagic) + kAIVSaltSize + kAIVIVSize];
    [result appendBytes:mac length:sizeof(mac)];
    [result appendBytes:(const uint8_t *)authenticated.bytes + sizeof(kAIVMagic) + kAIVSaltSize + kAIVIVSize
                  length:cipher.length];
    memset(keys, 0, sizeof(keys));
    return result;
}

+ (NSData *)decrypt:(NSData *)packed password:(NSString *)password error:(NSError **)error {
    const NSUInteger prefix = sizeof(kAIVMagic) + kAIVSaltSize + kAIVIVSize;
    if (packed.length < prefix + kAIVMacSize + kCCBlockSizeAES128 ||
        memcmp(packed.bytes, kAIVMagic, sizeof(kAIVMagic)) != 0) {
        if (error) *error = AIVCryptoError(4, @"Not a valid App Identity Vault backup.");
        return nil;
    }
    const uint8_t *bytes = packed.bytes;
    uint8_t keys[64] = {0};
    if (!AIVDerive(password, bytes + sizeof(kAIVMagic), keys)) {
        if (error) *error = AIVCryptoError(5, @"Could not derive the decryption key.");
        return nil;
    }
    const uint8_t *cipher = bytes + prefix + kAIVMacSize;
    size_t cipherLength = packed.length - prefix - kAIVMacSize;
    NSMutableData *authenticated = [NSMutableData dataWithBytes:bytes length:prefix];
    [authenticated appendBytes:cipher length:cipherLength];
    uint8_t mac[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, keys + 32, 32,
           authenticated.bytes, authenticated.length, mac);
    if (!AIVConstantTimeEqual(mac, bytes + prefix, kAIVMacSize)) {
        memset(keys, 0, sizeof(keys));
        if (error) *error = AIVCryptoError(6, @"Incorrect password or damaged backup.");
        return nil;
    }
    NSMutableData *plain = [NSMutableData dataWithLength:cipherLength + kCCBlockSizeAES128];
    size_t plainLength = 0;
    CCCryptorStatus status = CCCrypt(kCCDecrypt, kCCAlgorithmAES,
                                    kCCOptionPKCS7Padding, keys, kCCKeySizeAES256,
                                    bytes + sizeof(kAIVMagic) + kAIVSaltSize,
                                    cipher, cipherLength,
                                    plain.mutableBytes, plain.length, &plainLength);
    memset(keys, 0, sizeof(keys));
    if (status != kCCSuccess) {
        if (error) *error = AIVCryptoError(7, @"Decryption failed.");
        return nil;
    }
    plain.length = plainLength;
    return plain;
}
@end
