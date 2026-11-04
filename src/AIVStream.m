#import "AIVStream.h"
#import "AIVArchive.h"
#import "AIVCrypto.h"
#import <CommonCrypto/CommonCrypto.h>
#import <Security/Security.h>
#import <sqlite3.h>
#import <sys/stat.h>
#import <string.h>

static NSString *const AIVStreamDomain = @"com.appidentityvault.stream";
static const NSUInteger AIVChunk = 64 * 1024;
static const NSUInteger AIVHeaderSize = 4 + 16 + 16 + CC_SHA256_DIGEST_LENGTH;
static const uint8_t AIVMagic2[4] = {'A','I','V','2'};
static const uint8_t AIVMagic3[4] = {'A','I','V','3'};
static const NSUInteger AIVPlainHeaderSize = 4 + CC_SHA256_DIGEST_LENGTH;

static NSError *AIVSErr(NSInteger code, NSString *message) {
    return [NSError errorWithDomain:AIVStreamDomain code:code
                         userInfo:@{NSLocalizedDescriptionKey:message}];
}

static BOOL AIVKeys(NSString *password, const uint8_t *salt, uint8_t keys[64]) {
    NSData *data = [password dataUsingEncoding:NSUTF8StringEncoding];
    return CCKeyDerivationPBKDF(kCCPBKDF2, data.bytes, data.length, salt, 16,
            kCCPRFHmacAlgSHA256, 220000, keys, 64) == kCCSuccess;
}

static BOOL AIVSameMAC(const uint8_t *a, const uint8_t *b) {
    uint8_t diff = 0;
    for (NSUInteger i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) diff |= (a[i] ^ b[i]);
    return diff == 0;
}

static NSData *AIVRecordHeader(uint8_t type, uint32_t nameLength, uint64_t valueLength) {
    uint8_t header[13] = {0};
    header[0] = type;
    uint32_t nameBE = CFSwapInt32HostToBig(nameLength);
    uint64_t valueBE = CFSwapInt64HostToBig(valueLength);
    memcpy(header + 1, &nameBE, 4);
    memcpy(header + 5, &valueBE, 8);
    return [NSData dataWithBytes:header length:sizeof(header)];
}

// SQLite's -journal/-wal/-shm files are volatile, so copy the logical database
// through SQLite's online backup API, including committed transactions in WAL.
static BOOL AIVHasSQLiteHeader(NSFileHandle *handle) {
    if (!handle) return NO;
    NSData *prefix = [handle readDataOfLength:16];
    [handle seekToFileOffset:0];
    return prefix.length == 16 && memcmp(prefix.bytes, "SQLite format 3\0", 16) == 0;
}

static NSURL *AIVSQLiteSnapshot(NSURL *sourceURL, NSURL *directory, NSError **error) {
    NSURL *targetURL = [directory URLByAppendingPathComponent:
                        [NSUUID.UUID.UUIDString stringByAppendingString:@".sqlite"]];
    sqlite3 *source = NULL, *target = NULL;
    sqlite3_backup *backup = NULL;
    int result = sqlite3_open_v2(sourceURL.fileSystemRepresentation, &source,
                                 SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, NULL);
    if (result == SQLITE_OK) result = sqlite3_open_v2(targetURL.fileSystemRepresentation,
                    &target, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL);
    if (result == SQLITE_OK) {
        sqlite3_busy_timeout(source, 1000);
        sqlite3_busy_timeout(target, 1000);
        backup = sqlite3_backup_init(target, "main", source, "main");
        if (!backup) result = sqlite3_errcode(target);
    }
    if (backup) {
        NSUInteger retries = 0;
        do {
            result = sqlite3_backup_step(backup, 128);
            if (result == SQLITE_BUSY || result == SQLITE_LOCKED) {
                if (++retries > 30) break;
                sqlite3_sleep(100);
            } else retries = 0;
        } while (result == SQLITE_OK || result == SQLITE_BUSY || result == SQLITE_LOCKED);
        int finished = sqlite3_backup_finish(backup);
        if (result == SQLITE_DONE && finished == SQLITE_OK) result = SQLITE_OK;
        else if (result == SQLITE_DONE) result = finished;
    }
    if (source) sqlite3_close(source);
    if (target) sqlite3_close(target);
    if (result != SQLITE_OK) {
        if (error) *error = AIVSErr(27, [NSString stringWithFormat:
            @"Could not consistently snapshot the database %@ (SQLite %d).", sourceURL.lastPathComponent, result]);
        [NSFileManager.defaultManager removeItemAtURL:targetURL error:NULL];
        return nil;
    }
    return targetURL;
}

@protocol AIVRecordWriter <NSObject>
- (BOOL)append:(NSData *)plain error:(NSError **)error;
- (BOOL)finish:(NSError **)error;
@end

@protocol AIVRecordReader <NSObject>
- (nullable NSData *)readExactly:(NSUInteger)length error:(NSError **)error;
- (BOOL)atEnd:(NSError **)error;
@end

@interface AIVEncryptedWriter : NSObject <AIVRecordWriter> {
    CCCryptorRef _cryptor;
    CCHmacContext _hmac;
    uint8_t _keys[64];
}
@property (nonatomic, strong) NSFileHandle *file;
- (nullable instancetype)initWithURL:(NSURL *)url password:(NSString *)password error:(NSError **)error;
- (BOOL)append:(NSData *)plain error:(NSError **)error;
- (BOOL)finish:(NSError **)error;
@end

@implementation AIVEncryptedWriter
- (instancetype)initWithURL:(NSURL *)url password:(NSString *)password error:(NSError **)error {
    self = [super init];
    if (!self) return nil;
    if (password.length < 8) {
        if (error) *error = AIVSErr(1, @"Use a password with at least 8 characters.");
        return nil;
    }
    uint8_t salt[16], iv[16];
    if (SecRandomCopyBytes(kSecRandomDefault, 16, salt) != errSecSuccess ||
        SecRandomCopyBytes(kSecRandomDefault, 16, iv) != errSecSuccess ||
        !AIVKeys(password, salt, _keys)) {
        if (error) *error = AIVSErr(2, @"Could not generate an encryption key.");
        return nil;
    }
    if (![[NSFileManager defaultManager] createFileAtPath:url.path contents:nil attributes:nil]) {
        if (error) *error = AIVSErr(3, @"Could not create backup file. Check free storage.");
        return nil;
    }
    self.file = [NSFileHandle fileHandleForWritingToURL:url error:error];
    if (!self.file) return nil;
    if (CCCryptorCreate(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
                        _keys, kCCKeySizeAES256, iv, &_cryptor) != kCCSuccess) {
        if (error) *error = AIVSErr(4, @"Could not initialize encryption.");
        return nil;
    }
    uint8_t header[AIVHeaderSize];
    memcpy(header, AIVMagic2, 4);
    memcpy(header + 4, salt, 16);
    memcpy(header + 20, iv, 16);
    memset(header + 36, 0, CC_SHA256_DIGEST_LENGTH);
    CCHmacInit(&_hmac, kCCHmacAlgSHA256, _keys + 32, 32);
    CCHmacUpdate(&_hmac, header, 36);
    if (![self.file writeData:[NSData dataWithBytes:header length:sizeof(header)] error:error]) return nil;
    return self;
}

- (void)dealloc {
    if (_cryptor) CCCryptorRelease(_cryptor);
    memset(_keys, 0, sizeof(_keys));
    [self.file closeFile];
}

- (BOOL)append:(NSData *)plain error:(NSError **)error {
    if (plain.length == 0) return YES;
    NSMutableData *result = [NSMutableData dataWithLength:plain.length + kCCBlockSizeAES128];
    size_t written = 0;
    if (CCCryptorUpdate(_cryptor, plain.bytes, plain.length,
                        result.mutableBytes, result.length, &written) != kCCSuccess) {
        if (error) *error = AIVSErr(5, @"Encryption failed while streaming app data.");
        return NO;
    }
    result.length = written;
    if (written) {
        CCHmacUpdate(&_hmac, result.bytes, result.length);
        if (![self.file writeData:result error:error]) return NO;
    }
    return YES;
}

- (BOOL)finish:(NSError **)error {
    uint8_t tail[kCCBlockSizeAES128 * 2];
    size_t size = 0;
    if (CCCryptorFinal(_cryptor, tail, sizeof(tail), &size) != kCCSuccess) {
        if (error) *error = AIVSErr(6, @"Could not complete the encrypted archive.");
        return NO;
    }
    CCHmacUpdate(&_hmac, tail, size);
    if (![self.file writeData:[NSData dataWithBytes:tail length:size] error:error]) return NO;
    uint8_t mac[CC_SHA256_DIGEST_LENGTH];
    CCHmacFinal(&_hmac, mac);
    if (![self.file seekToOffset:36 error:error]) return NO;
    if (![self.file writeData:[NSData dataWithBytes:mac length:sizeof(mac)] error:error]) return NO;
    [self.file synchronizeFile];
    [self.file closeFile];
    self.file = nil;
    return YES;
}
@end

@interface AIVEncryptedReader : NSObject <AIVRecordReader> {
    CCCryptorRef _cryptor;
    uint8_t _keys[64];
    uint64_t _cipherRemaining;
    BOOL _finalized;
}
@property (nonatomic, strong) NSFileHandle *file;
@property (nonatomic, strong) NSMutableData *plainBuffer;
- (nullable instancetype)initWithURL:(NSURL *)url password:(NSString *)password error:(NSError **)error;
- (nullable NSData *)readExactly:(NSUInteger)length error:(NSError **)error;
- (BOOL)atEnd:(NSError **)error;
@end

@implementation AIVEncryptedReader
- (instancetype)initWithURL:(NSURL *)url password:(NSString *)password error:(NSError **)error {
    self = [super init];
    if (!self) return nil;
    self.file = [NSFileHandle fileHandleForReadingFromURL:url error:error];
    if (!self.file) return nil;
    NSNumber *length = nil;
    [url getResourceValue:&length forKey:NSURLFileSizeKey error:error];
    if (length.unsignedLongLongValue < AIVHeaderSize + 16) {
        if (error) *error = AIVSErr(7, @"The backup is incomplete.");
        return nil;
    }
    NSData *header = [self.file readDataOfLength:AIVHeaderSize];
    if (header.length != AIVHeaderSize || memcmp(header.bytes, AIVMagic2, 4) != 0) {
        if (error) *error = AIVSErr(8, @"Not an AIV2 backup.");
        return nil;
    }
    const uint8_t *p = header.bytes;
    if (!AIVKeys(password, p + 4, _keys)) {
        if (error) *error = AIVSErr(9, @"Cannot derive the decryption key.");
        return nil;
    }
    _cipherRemaining = length.unsignedLongLongValue - AIVHeaderSize;
    CCHmacContext context;
    CCHmacInit(&context, kCCHmacAlgSHA256, _keys + 32, 32);
    CCHmacUpdate(&context, p, 36);
    uint64_t toCheck = _cipherRemaining;
    while (toCheck) {
        NSData *chunk = [self.file readDataOfLength:(NSUInteger)MIN((uint64_t)AIVChunk, toCheck)];
        if (chunk.length == 0) {
            if (error) *error = AIVSErr(10, @"Truncated backup.");
            return nil;
        }
        CCHmacUpdate(&context, chunk.bytes, chunk.length);
        toCheck -= chunk.length;
    }
    uint8_t mac[CC_SHA256_DIGEST_LENGTH];
    CCHmacFinal(&context, mac);
    if (!AIVSameMAC(mac, p + 36)) {
        if (error) *error = AIVSErr(11, @"Incorrect password or corrupted backup.");
        return nil;
    }
    if (![self.file seekToOffset:AIVHeaderSize error:error]) return nil;
    if (CCCryptorCreate(kCCDecrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
                        _keys, kCCKeySizeAES256, p + 20, &_cryptor) != kCCSuccess) {
        if (error) *error = AIVSErr(12, @"Could not initialize decryption.");
        return nil;
    }
    self.plainBuffer = [NSMutableData data];
    return self;
}

- (void)dealloc {
    if (_cryptor) CCCryptorRelease(_cryptor);
    memset(_keys, 0, sizeof(_keys));
    [self.file closeFile];
}

- (BOOL)pump:(NSError **)error {
    if (_finalized) return YES;
    if (_cipherRemaining) {
        NSData *cipher = [self.file readDataOfLength:(NSUInteger)MIN((uint64_t)AIVChunk, _cipherRemaining)];
        if (!cipher.length) {
            if (error) *error = AIVSErr(13, @"Unexpected end of encrypted data.");
            return NO;
        }
        _cipherRemaining -= cipher.length;
        NSMutableData *plain = [NSMutableData dataWithLength:cipher.length + kCCBlockSizeAES128];
        size_t actual = 0;
        if (CCCryptorUpdate(_cryptor, cipher.bytes, cipher.length,
                            plain.mutableBytes, plain.length, &actual) != kCCSuccess) {
            if (error) *error = AIVSErr(14, @"Decryption failed.");
            return NO;
        }
        [self.plainBuffer appendBytes:plain.bytes length:actual];
    } else {
        uint8_t final[kCCBlockSizeAES128 * 2];
        size_t actual = 0;
        if (CCCryptorFinal(_cryptor, final, sizeof(final), &actual) != kCCSuccess) {
            if (error) *error = AIVSErr(15, @"Invalid encrypted padding.");
            return NO;
        }
        [self.plainBuffer appendBytes:final length:actual];
        _finalized = YES;
    }
    return YES;
}

- (NSData *)readExactly:(NSUInteger)length error:(NSError **)error {
    if (length == 0) return [NSData data];
    while (self.plainBuffer.length < length && !_finalized) {
        if (![self pump:error]) return nil;
    }
    if (self.plainBuffer.length < length) {
        if (error) *error = AIVSErr(16, @"The backup record is truncated.");
        return nil;
    }
    NSData *result = [self.plainBuffer subdataWithRange:NSMakeRange(0, length)];
    [self.plainBuffer replaceBytesInRange:NSMakeRange(0, length) withBytes:NULL length:0];
    return result;
}

- (BOOL)atEnd:(NSError **)error {
    while (!_finalized) if (![self pump:error]) return NO;
    if (self.plainBuffer.length != 0) {
        if (error) *error = AIVSErr(17, @"Unexpected trailing data in backup.");
        return NO;
    }
    return YES;
}
@end

// AIV3 intentionally has no password prompt. It is a plain archive whose hash
// detects accidental corruption; the hash is not an authentication signature.
@interface AIVPlainWriter : NSObject <AIVRecordWriter> {
    CC_SHA256_CTX _hash;
}
@property (nonatomic, strong) NSFileHandle *file;
- (nullable instancetype)initWithURL:(NSURL *)url error:(NSError **)error;
@end

@implementation AIVPlainWriter
- (instancetype)initWithURL:(NSURL *)url error:(NSError **)error {
    self = [super init];
    if (!self) return nil;
    if (![NSFileManager.defaultManager createFileAtPath:url.path contents:nil attributes:nil]) {
        if (error) *error = AIVSErr(31, @"Could not create a backup file. Check free storage.");
        return nil;
    }
    self.file = [NSFileHandle fileHandleForWritingToURL:url error:error];
    if (!self.file) return nil;
    uint8_t header[AIVPlainHeaderSize] = {0};
    memcpy(header, AIVMagic3, 4);
    CC_SHA256_Init(&_hash);
    if (![self.file writeData:[NSData dataWithBytes:header length:sizeof(header)] error:error]) return nil;
    return self;
}

- (void)dealloc { [self.file closeFile]; }

- (BOOL)append:(NSData *)plain error:(NSError **)error {
    if (!plain.length) return YES;
    if (![self.file writeData:plain error:error]) return NO;
    CC_SHA256_Update(&_hash, plain.bytes, (CC_LONG)plain.length);
    return YES;
}

- (BOOL)finish:(NSError **)error {
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(digest, &_hash);
    if (![self.file seekToOffset:4 error:error]) return NO;
    if (![self.file writeData:[NSData dataWithBytes:digest length:sizeof(digest)] error:error]) return NO;
    [self.file synchronizeFile];
    [self.file closeFile];
    self.file = nil;
    return YES;
}
@end

@interface AIVPlainReader : NSObject <AIVRecordReader> {
    uint64_t _remaining;
}
@property (nonatomic, strong) NSFileHandle *file;
- (nullable instancetype)initWithURL:(NSURL *)url error:(NSError **)error;
@end

@implementation AIVPlainReader
- (instancetype)initWithURL:(NSURL *)url error:(NSError **)error {
    self = [super init];
    if (!self) return nil;
    self.file = [NSFileHandle fileHandleForReadingFromURL:url error:error];
    if (!self.file) return nil;
    NSNumber *length = nil;
    if (![url getResourceValue:&length forKey:NSURLFileSizeKey error:error]) return nil;
    if (length.unsignedLongLongValue < AIVPlainHeaderSize + 13) {
        if (error) *error = AIVSErr(32, @"The backup file is incomplete.");
        return nil;
    }
    NSData *header = [self.file readDataOfLength:AIVPlainHeaderSize];
    if (header.length != AIVPlainHeaderSize || memcmp(header.bytes, AIVMagic3, 4) != 0) {
        if (error) *error = AIVSErr(33, @"This is not a password-free AIV3 backup. Create a new backup with the latest tool.");
        return nil;
    }
    const uint8_t *bytes = header.bytes;
    CC_SHA256_CTX context;
    CC_SHA256_Init(&context);
    uint64_t left = length.unsignedLongLongValue - AIVPlainHeaderSize;
    while (left) {
        NSData *part = [self.file readDataOfLength:(NSUInteger)MIN((uint64_t)AIVChunk, left)];
        if (!part.length) {
            if (error) *error = AIVSErr(34, @"The backup file ended unexpectedly.");
            return nil;
        }
        CC_SHA256_Update(&context, part.bytes, (CC_LONG)part.length);
        left -= part.length;
    }
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(digest, &context);
    if (!AIVSameMAC(digest, bytes + 4)) {
        if (error) *error = AIVSErr(35, @"The backup file is damaged or incomplete.");
        return nil;
    }
    if (![self.file seekToOffset:AIVPlainHeaderSize error:error]) return nil;
    _remaining = length.unsignedLongLongValue - AIVPlainHeaderSize;
    return self;
}

- (void)dealloc { [self.file closeFile]; }

- (NSData *)readExactly:(NSUInteger)length error:(NSError **)error {
    if (length > _remaining) {
        if (error) *error = AIVSErr(36, @"A backup record is truncated.");
        return nil;
    }
    NSMutableData *result = [NSMutableData dataWithCapacity:length];
    while (result.length < length) {
        NSData *chunk = [self.file readDataOfLength:MIN(AIVChunk, length - result.length)];
        if (!chunk.length) {
            if (error) *error = AIVSErr(37, @"The backup ended while reading a record.");
            return nil;
        }
        [result appendData:chunk];
    }
    _remaining -= length;
    return result;
}

- (BOOL)atEnd:(NSError **)error {
    if (_remaining == 0) return YES;
    if (error) *error = AIVSErr(38, @"Unexpected data after the backup terminator.");
    return NO;
}
@end

static BOOL AIVWriteRecord(id<AIVRecordWriter> writer, uint8_t type,
                           NSString *path, NSData *payload, NSError **error) {
    NSData *name = [path dataUsingEncoding:NSUTF8StringEncoding] ?: [NSData data];
    if (name.length > UINT32_MAX) {
        if (error) *error = AIVSErr(18, @"Backup path is too long.");
        return NO;
    }
    return [writer append:AIVRecordHeader(type, (uint32_t)name.length, payload.length) error:error] &&
           [writer append:name error:error] && [writer append:payload error:error];
}

static NSDictionary *AIVParse(id<AIVRecordReader> reader, BOOL restore, NSError **error) {
    NSDictionary *manifest = nil;
    NSUInteger files = 0, restored = 0;
    unsigned long long bytes = 0;
    NSMutableArray<NSString *> *warnings = [NSMutableArray array];
    NSFileManager *fm = NSFileManager.defaultManager;
    while (YES) {
        NSData *head = [reader readExactly:13 error:error];
        if (!head) return nil;
        const uint8_t *raw = head.bytes;
        uint32_t nbe;
        uint64_t vbe;
        memcpy(&nbe, raw + 1, 4);
        memcpy(&vbe, raw + 5, 8);
        uint32_t nameLength = CFSwapInt32BigToHost(nbe);
        uint64_t valueLength = CFSwapInt64BigToHost(vbe);
        if (raw[0] == 0) {
            if (nameLength || valueLength || !manifest || ![reader atEnd:error]) {
                if (error && !*error) *error = AIVSErr(19, @"Invalid backup terminator.");
                return nil;
            }
            break;
        }
        if (nameLength > 4096) {
            if (error) *error = AIVSErr(20, @"Invalid record path length.");
            return nil;
        }
        NSData *nameData = [reader readExactly:nameLength error:error];
        if (!nameData) return nil;
        NSString *path = [[NSString alloc] initWithData:nameData encoding:NSUTF8StringEncoding];
        if (!path) {
            if (error) *error = AIVSErr(21, @"Invalid file path encoding.");
            return nil;
        }
        if (raw[0] == 1) {
            if (manifest || nameLength || valueLength > 64ULL * 1024ULL * 1024ULL) {
                if (error) *error = AIVSErr(22, @"Invalid backup manifest.");
                return nil;
            }
            NSData *data = [reader readExactly:(NSUInteger)valueLength error:error];
            if (!data) return nil;
            id m = [NSPropertyListSerialization propertyListWithData:data
                             options:NSPropertyListImmutable format:NULL error:error];
            if (![m isKindOfClass:NSDictionary.class] ||
                ![m[@"format"] isEqual:@2] ||
                ![m[@"bundleID"] isEqualToString:NSBundle.mainBundle.bundleIdentifier ?: @""] ||
                ![m[@"keychain"] isKindOfClass:NSArray.class]) {
                if (error) *error = AIVSErr(23, @"Wrong app or invalid backup manifest.");
                return nil;
            }
            manifest = m;
            [warnings addObjectsFromArray:[m[@"warnings"] isKindOfClass:NSArray.class] ? m[@"warnings"] : @[]];
            continue;
        }
        if (raw[0] == 3) {
            if (!manifest || nameLength || valueLength > 2ULL * 1024ULL * 1024ULL) {
                if (error) *error = AIVSErr(28, @"Invalid backup warning record.");
                return nil;
            }
            NSData *data = [reader readExactly:(NSUInteger)valueLength error:error];
            if (!data) return nil;
            id additions = [NSPropertyListSerialization propertyListWithData:data
                options:NSPropertyListImmutable format:NULL error:error];
            if (![additions isKindOfClass:NSArray.class]) return nil;
            for (id warning in additions) if ([warning isKindOfClass:NSString.class]) [warnings addObject:warning];
            continue;
        }
        if (raw[0] != 2 || !manifest || nameLength == 0) {
            if (error) *error = AIVSErr(24, @"Invalid record sequence.");
            return nil;
        }
        files++;
        bytes += valueLength;
        NSURL *dest = restore ? [AIVArchive restoreDestinationForPath:path] : nil;
        NSURL *temporary = nil;
        NSFileHandle *output = nil;
        BOOL writeOK = (dest != nil);
        if (restore && writeOK) {
            NSError *fileError = nil;
            [fm createDirectoryAtURL:[dest URLByDeletingLastPathComponent]
                withIntermediateDirectories:YES attributes:nil error:&fileError];
            if (!fileError) {
                temporary = [[dest URLByDeletingLastPathComponent] URLByAppendingPathComponent:
                    [NSString stringWithFormat:@".%@.%@.aivtmp", dest.lastPathComponent, NSUUID.UUID.UUIDString]];
                if ([fm createFileAtPath:temporary.path contents:nil attributes:nil])
                    output = [NSFileHandle fileHandleForWritingToURL:temporary error:&fileError];
            }
            if (!output) {
                writeOK = NO;
                [warnings addObject:[NSString stringWithFormat:@"Could not prepare %@: %@", path,
                                     fileError.localizedDescription ?: @"write denied"]];
            }
        } else if (restore) {
            [warnings addObject:[NSString stringWithFormat:@"No access to %@", path]];
        }
        uint64_t remaining = valueLength;
        while (remaining) {
            NSData *part = [reader readExactly:(NSUInteger)MIN((uint64_t)AIVChunk, remaining) error:error];
            if (!part) { [output closeFile]; if (temporary) [fm removeItemAtURL:temporary error:NULL]; return nil; }
            remaining -= part.length;
            if (output && writeOK) {
                NSError *writeError = nil;
                if (![output writeData:part error:&writeError]) {
                    writeOK = NO;
                    [warnings addObject:[NSString stringWithFormat:@"Cannot write %@: %@", path,
                                         writeError.localizedDescription ?: @"unknown error"]];
                }
            }
        }
        [output closeFile];
        if (temporary) {
            if (writeOK) {
                NSError *replaceError = nil;
                BOOL exists = [fm fileExistsAtPath:dest.path];
                BOOL moved = exists ? ([fm replaceItemAtURL:dest withItemAtURL:temporary
                       backupItemName:nil options:0 resultingItemURL:NULL error:&replaceError] != nil) :
                       [fm moveItemAtURL:temporary toURL:dest error:&replaceError];
                if (moved) restored++;
                else [warnings addObject:[NSString stringWithFormat:@"Cannot replace %@: %@", path,
                                          replaceError.localizedDescription ?: @"unknown error"]];
            }
            [fm removeItemAtURL:temporary error:NULL];
        }
    }
    NSMutableDictionary *report = [manifest mutableCopy];
    report[@"fileCount"] = @(files);
    report[@"fileBytes"] = @(bytes);
    if (restore) {
        NSMutableDictionary *details = [manifest mutableCopy];
        details[@"files"] = @[];
        NSDictionary *keychainReport = [AIVArchive restore:details error:error];
        if (error && *error) return nil;
        [warnings addObjectsFromArray:keychainReport[@"warnings"] ?: @[]];
        report[@"files"] = @(restored);
        report[@"keychainRestored"] = keychainReport[@"keychain"] ?: @0;
        report[@"fcUUIDRestored"] = keychainReport[@"fcUUID"] ?: @NO;
        report[@"idfvOverride"] = keychainReport[@"idfvOverride"] ?: @NO;
        report[@"warnings"] = warnings;
    }
    if (!restore) report[@"warnings"] = warnings;
    return report;
}

@implementation AIVStream

+ (BOOL)createBackupAtURL:(NSURL *)url error:(NSError **)error {
    NSMutableArray<NSString *> *scanWarnings = [NSMutableArray array];
    NSArray<NSDictionary *> *descriptors = [AIVArchive fileDescriptorsWithWarnings:scanWarnings error:error];
    if (!descriptors) return NO;
    NSMutableDictionary *metadata = [[AIVArchive captureMetadata] mutableCopy];
    [scanWarnings addObjectsFromArray:metadata[@"warnings"] ?: @[]];
    metadata[@"warnings"] = scanWarnings;
    NSData *plist = [NSPropertyListSerialization dataWithPropertyList:metadata
                 format:NSPropertyListBinaryFormat_v1_0 options:0 error:error];
    if (!plist) return NO;
    NSString *snapshotPath = [NSTemporaryDirectory() stringByAppendingPathComponent:
        [NSString stringWithFormat:@"AppIdentityVault-%@", NSUUID.UUID.UUIDString]];
    NSURL *snapshotDirectory = [NSURL fileURLWithPath:snapshotPath isDirectory:YES];
    if (![NSFileManager.defaultManager createDirectoryAtURL:snapshotDirectory
        withIntermediateDirectories:YES attributes:nil error:error]) return NO;
    NSURL *partial = [url URLByAppendingPathExtension:@"part"];
    id<AIVRecordWriter> writer = [[AIVPlainWriter alloc] initWithURL:partial error:error];
    if (!writer) {
        [NSFileManager.defaultManager removeItemAtURL:snapshotDirectory error:NULL];
        [NSFileManager.defaultManager removeItemAtURL:partial error:NULL];
        return NO;
    }
    NSMutableArray<NSString *> *lateWarnings = [NSMutableArray array];
    BOOL ok = AIVWriteRecord(writer, 1, @"", plist, error);
    for (NSDictionary *entry in descriptors) {
        if (!ok) break;
        NSURL *fileURL = entry[@"url"];
        NSString *path = entry[@"path"];
        NSData *pathData = [path dataUsingEncoding:NSUTF8StringEncoding];
        if (!pathData.length || pathData.length > 4096) {
            if (error) *error = AIVSErr(25, @"App file path is too long.");
            ok = NO; break;
        }
        NSError *openError = nil;
        NSFileHandle *input = [NSFileHandle fileHandleForReadingFromURL:fileURL error:&openError];
        if (!input) {
            // Files deleted during enumeration were never backed up; continue
            // without inserting a malformed record into the encrypted stream.
            if (![NSFileManager.defaultManager fileExistsAtPath:fileURL.path]) {
                [lateWarnings addObject:[NSString stringWithFormat:@"Skipped a file removed during backup: %@", path]];
                continue;
            }
            if (error) *error = openError ?: AIVSErr(29, @"Unable to open an app file.");
            ok = NO; break;
        }
        NSURL *sqliteCopy = nil;
        if (AIVHasSQLiteHeader(input)) {
            [input closeFile];
            sqliteCopy = AIVSQLiteSnapshot(fileURL, snapshotDirectory, error);
            if (!sqliteCopy) { ok = NO; break; }
            input = [NSFileHandle fileHandleForReadingFromURL:sqliteCopy error:error];
            if (!input) { ok = NO; break; }
        }
        struct stat attributes;
        if (fstat(input.fileDescriptor, &attributes) != 0 || attributes.st_size < 0) {
            if (error) *error = AIVSErr(30, @"Could not determine the app file size.");
            [input closeFile]; ok = NO; break;
        }
        uint64_t currentSize = (uint64_t)attributes.st_size;
        ok = [writer append:AIVRecordHeader(2, (uint32_t)pathData.length,
                                            currentSize) error:error] &&
             [writer append:pathData error:error];
        uint64_t left = currentSize;
        while (ok && left) {
            NSData *chunk = [input readDataOfLength:(NSUInteger)MIN((uint64_t)AIVChunk, left)];
            if (!chunk.length) {
                if (error) *error = AIVSErr(26, @"A file changed during backup. Try again after closing app activity.");
                ok = NO; break;
            }
            ok = [writer append:chunk error:error];
            left -= chunk.length;
        }
        [input closeFile];
    }
    if (ok && lateWarnings.count) {
        NSData *warningPlist = [NSPropertyListSerialization dataWithPropertyList:lateWarnings
            format:NSPropertyListBinaryFormat_v1_0 options:0 error:error];
        ok = warningPlist && AIVWriteRecord(writer, 3, @"", warningPlist, error);
    }
    if (ok) ok = [writer append:AIVRecordHeader(0, 0, 0) error:error];
    if (ok) ok = [writer finish:error];
    writer = nil;
    if (ok) ok = [[NSFileManager defaultManager] moveItemAtURL:partial toURL:url error:error];
    if (!ok) [[NSFileManager defaultManager] removeItemAtURL:partial error:NULL];
    [NSFileManager.defaultManager removeItemAtURL:snapshotDirectory error:NULL];
    return ok;
}

+ (NSDictionary *)previewAtURL:(NSURL *)url error:(NSError **)error {
    AIVPlainReader *reader = [[AIVPlainReader alloc] initWithURL:url error:error];
    return reader ? AIVParse(reader, NO, error) : nil;
}

+ (NSDictionary *)restoreAtURL:(NSURL *)url error:(NSError **)error {
    AIVPlainReader *reader = [[AIVPlainReader alloc] initWithURL:url error:error];
    return reader ? AIVParse(reader, YES, error) : nil;
}
@end
