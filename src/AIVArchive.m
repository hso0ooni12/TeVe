#import "AIVArchive.h"
#import <Security/Security.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>

static NSString *const AIVArchiveDomain = @"com.appidentityvault.archive";
// Intentional memory bound for the first release. Larger apps need a streaming archive.
static const unsigned long long AIVMaxArchiveBytes = 96ULL * 1024ULL * 1024ULL;
static const unsigned long long AIVMaxSingleFileBytes = 32ULL * 1024ULL * 1024ULL;

static NSError *AIVError(NSInteger code, NSString *description) {
    return [NSError errorWithDomain:AIVArchiveDomain code:code
                         userInfo:@{NSLocalizedDescriptionKey:description}];
}

static id AIVSafePlistValue(id value) {
    if (!value || value == (id)kCFNull) return nil;
    if ([value isKindOfClass:NSString.class] ||
        [value isKindOfClass:NSNumber.class] ||
        [value isKindOfClass:NSData.class] ||
        [value isKindOfClass:NSDate.class]) return value;
    if ([value isKindOfClass:NSArray.class]) {
        NSMutableArray *array = [NSMutableArray array];
        for (id item in value) {
            id safe = AIVSafePlistValue(item);
            if (safe) [array addObject:safe];
        }
        return array;
    }
    if ([value isKindOfClass:NSDictionary.class]) {
        NSMutableDictionary *dict = [NSMutableDictionary dictionary];
        for (id key in value) {
            id safe = AIVSafePlistValue(value[key]);
            if ([key isKindOfClass:NSString.class] && safe) dict[key] = safe;
        }
        return dict;
    }
    return nil;
}

static NSArray<NSString *> *AIVAppGroups(void) {
    // Read only the entitlements already granted to the host app. No sandbox escape.
    typedef CFTypeRef (*TaskCreate)(CFAllocatorRef);
    typedef CFTypeRef (*EntitlementCopy)(CFTypeRef, CFStringRef, CFErrorRef *);
    TaskCreate create = (TaskCreate)dlsym(RTLD_DEFAULT, "SecTaskCreateFromSelf");
    EntitlementCopy copy = (EntitlementCopy)dlsym(RTLD_DEFAULT, "SecTaskCopyValueForEntitlement");
    if (!create || !copy) return @[];
    CFTypeRef task = create(kCFAllocatorDefault);
    if (!task) return @[];
    CFTypeRef value = copy(task, CFSTR("com.apple.security.application-groups"), NULL);
    CFRelease(task);
    if (!value) return @[];
    NSArray *groups = CFGetTypeID(value) == CFArrayGetTypeID() ?
                       [(__bridge NSArray *)value copy] : @[];
    CFRelease(value);
    NSMutableArray<NSString *> *valid = [NSMutableArray array];
    for (id group in groups) if ([group isKindOfClass:NSString.class]) [valid addObject:group];
    return valid;
}

static NSArray<NSDictionary *> *AIVKeychainSnapshot(NSMutableArray<NSString *> *warnings) {
    NSArray *classes = @[(__bridge id)kSecClassGenericPassword,
                         (__bridge id)kSecClassInternetPassword,
                         (__bridge id)kSecClassCertificate,
                         (__bridge id)kSecClassKey,
                         (__bridge id)kSecClassIdentity];
    NSMutableArray *all = [NSMutableArray array];
    for (id secClass in classes) {
        NSMutableDictionary *query = [@{(__bridge id)kSecClass:secClass,
                                        (__bridge id)kSecMatchLimit:(__bridge id)kSecMatchLimitAll,
                                        (__bridge id)kSecReturnAttributes:@YES,
                                        (__bridge id)kSecReturnData:@YES} mutableCopy];
        CFTypeRef found = NULL;
        OSStatus result = SecItemCopyMatching((__bridge CFDictionaryRef)query, &found);
        if (result == errSecItemNotFound) continue;
        if (result != errSecSuccess) {
            [warnings addObject:[NSString stringWithFormat:@"Keychain class %@: OSStatus %d", secClass, (int)result]];
            continue;
        }
        id matches = CFBridgingRelease(found);
        NSArray *items = [matches isKindOfClass:NSArray.class] ? matches : @[matches];
        for (id entry in items) {
            if (![entry isKindOfClass:NSDictionary.class]) continue;
            NSMutableDictionary *attributes = [entry mutableCopy];
            NSData *data = attributes[(__bridge id)kSecValueData];
            if (![data isKindOfClass:NSData.class]) continue; // Non-exportable hardware keys.
            [attributes removeObjectForKey:(__bridge id)kSecValueData];
            [attributes removeObjectForKey:(__bridge id)kSecAttrCreationDate];
            [attributes removeObjectForKey:(__bridge id)kSecAttrModificationDate];
            [attributes removeObjectForKey:(__bridge id)kSecAttrAccessControl];
            [attributes removeObjectForKey:(__bridge id)kSecValuePersistentRef];
            [all addObject:@{@"class":secClass,
                             @"attributes":(AIVSafePlistValue(attributes) ?: @{}),
                             @"value":data}];
        }
    }
    return all;
}

static BOOL AIVAddDirectory(NSURL *root, NSString *prefix,
                            NSMutableArray *files, unsigned long long *used,
                            NSMutableArray<NSString *> *warnings, NSError **error) {
    NSFileManager *fm = NSFileManager.defaultManager;
    NSArray *keys = @[NSURLIsRegularFileKey, NSURLIsSymbolicLinkKey, NSURLFileSizeKey];
    NSDirectoryEnumerator *enumerator = [fm enumeratorAtURL:root
                                includingPropertiesForKeys:keys
                                                   options:NSDirectoryEnumerationSkipsHiddenFiles
                                              errorHandler:^BOOL(NSURL *url, NSError *fileError) {
        [warnings addObject:[NSString stringWithFormat:@"Skipped %@: %@", url.lastPathComponent, fileError.localizedDescription]];
        return YES;
    }];
    for (NSURL *url in enumerator) {
        NSString *relative = [url.path substringFromIndex:root.path.length + 1];
        if ([relative isEqualToString:@"AppIdentityVault"] ||
            [relative hasPrefix:@"AppIdentityVault/"] ||
            [relative isEqualToString:@"Caches"] ||
            [relative hasPrefix:@"Caches/"] ||
            [relative isEqualToString:@"SplashBoard"] ||
            [relative hasPrefix:@"SplashBoard/"]) {
            [enumerator skipDescendants];
            continue;
        }
        NSNumber *isFile = nil, *isLink = nil, *size = nil;
        [url getResourceValue:&isFile forKey:NSURLIsRegularFileKey error:NULL];
        [url getResourceValue:&isLink forKey:NSURLIsSymbolicLinkKey error:NULL];
        [url getResourceValue:&size forKey:NSURLFileSizeKey error:NULL];
        if (!isFile.boolValue || isLink.boolValue) continue;
        if (size.unsignedLongLongValue > AIVMaxSingleFileBytes ||
            *used + size.unsignedLongLongValue > AIVMaxArchiveBytes) {
            if (error) *error = AIVError(1, @"App data exceeds the safe 96 MB backup limit. No incomplete backup was created.");
            return NO;
        }
        NSError *readError = nil;
        NSData *contents = [NSData dataWithContentsOfURL:url options:NSDataReadingMappedIfSafe error:&readError];
        if (!contents) {
            if (error) *error = readError ?: AIVError(2, @"Could not read an app file.");
            return NO;
        }
        *used += contents.length;
        [files addObject:@{@"path":[prefix stringByAppendingFormat:@"/%@", relative], @"data":contents}];
    }
    return YES;
}

static NSURL *AIVRestoreURL(NSString *path) {
    if (![path isKindOfClass:NSString.class] || [path hasPrefix:@"/"] ||
        [path containsString:@"\\"] || [path containsString:@"//"]) return nil;
    for (NSString *part in [path componentsSeparatedByString:@"/"]) {
        if (!part.length || [part isEqualToString:@"."] || [part isEqualToString:@".."])
            return nil;
    }
    NSString *home = NSHomeDirectory();
    if ([path hasPrefix:@"app/Documents/"] || [path hasPrefix:@"app/Library/"]) {
        return [NSURL fileURLWithPath:[home stringByAppendingPathComponent:[path substringFromIndex:4]]];
    }
    if ([path hasPrefix:@"group/"]) {
        NSArray *parts = [path componentsSeparatedByString:@"/"];
        if (parts.count < 3) return nil;
        NSString *groupID = parts[1];
        if (![AIVAppGroups() containsObject:groupID]) return nil;
        NSURL *groupURL = [NSFileManager.defaultManager containerURLForSecurityApplicationGroupIdentifier:groupID];
        if (!groupURL) return nil;
        NSString *rest = [[parts subarrayWithRange:NSMakeRange(2, parts.count - 2)] componentsJoinedByString:@"/"];
        return [groupURL URLByAppendingPathComponent:rest];
    }
    return nil;
}

static BOOL AIVPathHasSymlink(NSURL *destination) {
    NSFileManager *fm = NSFileManager.defaultManager;
    NSURL *current = destination;
    // Do not follow a pre-existing symbolic link when overwriting extracted files.
    while (current && current.path.length > NSHomeDirectory().length) {
        NSDictionary *attrs = [fm attributesOfItemAtPath:current.path error:NULL];
        if ([attrs[NSFileType] isEqual:NSFileTypeSymbolicLink]) return YES;
        current = [current URLByDeletingLastPathComponent];
    }
    return NO;
}

@implementation AIVArchive

+ (NSArray<NSDictionary *> *)fileDescriptors:(NSError **)error {
    NSFileManager *fm = NSFileManager.defaultManager;
    NSMutableArray<NSDictionary *> *descriptors = [NSMutableArray array];
    NSMutableDictionary<NSString *, NSURL *> *roots = [NSMutableDictionary dictionary];
    NSString *home = NSHomeDirectory();
    for (NSString *folder in @[@"Documents", @"Library"]) {
        NSURL *root = [NSURL fileURLWithPath:[home stringByAppendingPathComponent:folder]];
        if ([fm fileExistsAtPath:root.path]) roots[[@"app/" stringByAppendingString:folder]] = root;
    }
    for (NSString *group in AIVAppGroups()) {
        NSURL *root = [fm containerURLForSecurityApplicationGroupIdentifier:group];
        if (root) roots[[@"group/" stringByAppendingString:group]] = root;
    }
    NSArray *keys = @[NSURLIsRegularFileKey, NSURLIsSymbolicLinkKey, NSURLFileSizeKey];
    for (NSString *prefix in roots) {
        NSURL *root = roots[prefix];
        __block NSError *enumerationError = nil;
        NSDirectoryEnumerator *it = [fm enumeratorAtURL:root includingPropertiesForKeys:keys
                 options:NSDirectoryEnumerationSkipsHiddenFiles
            errorHandler:^BOOL(__unused NSURL *url, NSError *fileError) {
                enumerationError = fileError;
                return NO;
            }];
        for (NSURL *url in it) {
            NSString *relative = [url.path substringFromIndex:root.path.length + 1];
            if ([relative isEqualToString:@"AppIdentityVault"] ||
                [relative hasPrefix:@"AppIdentityVault/"] ||
                [relative isEqualToString:@"Caches"] ||
                [relative hasPrefix:@"Caches/"] ||
                [relative isEqualToString:@"SplashBoard"] ||
                [relative hasPrefix:@"SplashBoard/"]) {
                [it skipDescendants];
                continue;
            }
            NSNumber *regular = nil, *link = nil, *size = nil;
            [url getResourceValue:&regular forKey:NSURLIsRegularFileKey error:NULL];
            [url getResourceValue:&link forKey:NSURLIsSymbolicLinkKey error:NULL];
            [url getResourceValue:&size forKey:NSURLFileSizeKey error:NULL];
            if (!regular.boolValue || link.boolValue) continue;
            [descriptors addObject:@{@"url":url,
                                    @"path":[prefix stringByAppendingFormat:@"/%@", relative],
                                    @"size":size ?: @0}];
        }
        if (enumerationError) {
            if (error) *error = enumerationError;
            return nil;
        }
    }
    return descriptors;
}

+ (NSDictionary *)captureMetadata {
    NSMutableArray<NSString *> *warnings = [NSMutableArray array];
    NSArray *keychain = AIVKeychainSnapshot(warnings);
    NSUserDefaults *prefs = NSUserDefaults.standardUserDefaults;
    return @{@"format":@2,
             @"bundleID":NSBundle.mainBundle.bundleIdentifier ?: @"",
             @"appVersion":[NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"",
             @"created":[NSDate date],
             @"sourceIDFV":UIDevice.currentDevice.identifierForVendor.UUIDString ?: @"",
             @"fcUUID":[prefs stringForKey:@"fc_uuidForDevice"] ?: @"",
             @"groupIDs":AIVAppGroups(),
             @"keychain":keychain,
             @"warnings":warnings};
}

+ (NSURL *)restoreDestinationForPath:(NSString *)path {
    NSURL *url = AIVRestoreURL(path);
    return url && !AIVPathHasSymlink(url) ? url : nil;
}

+ (NSDictionary *)capture:(NSError **)error {
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *home = NSHomeDirectory();
    NSMutableArray *files = [NSMutableArray array];
    NSMutableArray<NSString *> *warnings = [NSMutableArray array];
    unsigned long long total = 0;
    for (NSString *folder in @[@"Documents", @"Library"]) {
        NSURL *url = [NSURL fileURLWithPath:[home stringByAppendingPathComponent:folder]];
        if (![fm fileExistsAtPath:url.path]) continue;
        if (!AIVAddDirectory(url, [@"app" stringByAppendingFormat:@"/%@", folder], files,
                             &total, warnings, error)) return nil;
    }
    NSArray<NSString *> *groups = AIVAppGroups();
    for (NSString *groupID in groups) {
        NSURL *url = [fm containerURLForSecurityApplicationGroupIdentifier:groupID];
        if (!url) {
            [warnings addObject:[NSString stringWithFormat:@"App Group not accessible: %@", groupID]];
            continue;
        }
        if (!AIVAddDirectory(url, [@"group" stringByAppendingFormat:@"/%@", groupID], files,
                             &total, warnings, error)) return nil;
    }
    NSArray *keychain = AIVKeychainSnapshot(warnings);
    NSString *bundleID = NSBundle.mainBundle.bundleIdentifier ?: @"";
    NSString *currentUUID = [UIDevice.currentDevice.identifierForVendor UUIDString] ?: @"";
    NSUserDefaults *prefs = NSUserDefaults.standardUserDefaults;
    NSString *fcUUID = [prefs stringForKey:@"fc_uuidForDevice"] ?: @"";
    return @{@"format":@1,
             @"bundleID":bundleID,
             @"appVersion":[NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"",
             @"created":[NSDate date],
             @"sourceIDFV":currentUUID,
             @"fcUUID":fcUUID,
             @"groupIDs":groups,
             @"files":files,
             @"keychain":keychain,
             @"warnings":warnings};
}

+ (NSDictionary *)decode:(NSData *)plain error:(NSError **)error {
    id value = [NSPropertyListSerialization propertyListWithData:plain
                                                        options:NSPropertyListImmutable
                                                         format:NULL error:error];
    if (![value isKindOfClass:NSDictionary.class] ||
        ![value[@"format"] isEqual:@1] ||
        ![value[@"bundleID"] isKindOfClass:NSString.class] ||
        ![value[@"files"] isKindOfClass:NSArray.class] ||
        ![value[@"keychain"] isKindOfClass:NSArray.class]) {
        if (error) *error = AIVError(3, @"The backup contents are not valid.");
        return nil;
    }
    if (![value[@"bundleID"] isEqualToString:NSBundle.mainBundle.bundleIdentifier ?: @""]) {
        if (error) *error = AIVError(4, @"Bundle ID mismatch. Restore only into the same app identity.");
        return nil;
    }
    return value;
}

+ (NSDictionary *)restore:(NSDictionary *)archive error:(NSError **)error {
    NSString *bundleID = NSBundle.mainBundle.bundleIdentifier ?: @"";
    if (![archive[@"bundleID"] isEqualToString:bundleID]) {
        if (error) *error = AIVError(5, @"Refusing to restore data into a different bundle ID.");
        return @{};
    }
    NSFileManager *fm = NSFileManager.defaultManager;
    NSUInteger restored = 0, keychainRestored = 0;
    NSMutableArray *warnings = [NSMutableArray arrayWithArray:
        [archive[@"warnings"] isKindOfClass:NSArray.class] ? archive[@"warnings"] : @[]];
    for (NSDictionary *entry in archive[@"files"]) {
        if (![entry isKindOfClass:NSDictionary.class] ||
            ![entry[@"data"] isKindOfClass:NSData.class]) continue;
        NSURL *dest = AIVRestoreURL(entry[@"path"]);
        if (!dest || AIVPathHasSymlink(dest)) {
            [warnings addObject:[NSString stringWithFormat:@"Unavailable path: %@", entry[@"path"] ?: @"?"]];
            continue;
        }
        NSError *fileError = nil;
        if (![fm createDirectoryAtURL:[dest URLByDeletingLastPathComponent]
          withIntermediateDirectories:YES attributes:nil error:&fileError] ||
            ![entry[@"data"] writeToURL:dest options:NSDataWritingAtomic error:&fileError]) {
            [warnings addObject:[NSString stringWithFormat:@"File restore failed: %@", fileError.localizedDescription]];
            continue;
        }
        restored++;
    }
    for (NSDictionary *entry in archive[@"keychain"]) {
        if (![entry isKindOfClass:NSDictionary.class]) continue;
        NSString *secClass = entry[@"class"];
        NSDictionary *attrs = entry[@"attributes"];
        NSData *data = entry[@"value"];
        if (![secClass isKindOfClass:NSString.class] ||
            ![attrs isKindOfClass:NSDictionary.class] ||
            ![data isKindOfClass:NSData.class]) continue;
        NSMutableDictionary *add = [attrs mutableCopy];
        add[(__bridge id)kSecClass] = secClass;
        add[(__bridge id)kSecValueData] = data;
        [add removeObjectForKey:(__bridge id)kSecAttrCreationDate];
        [add removeObjectForKey:(__bridge id)kSecAttrModificationDate];
        [add removeObjectForKey:(__bridge id)kSecValuePersistentRef];
        OSStatus result = SecItemAdd((__bridge CFDictionaryRef)add, NULL);
        if (result == errSecDuplicateItem) {
            // Update only items identified by the same keychain class/account/service.
            NSMutableDictionary *query = [NSMutableDictionary dictionaryWithObject:secClass forKey:(__bridge id)kSecClass];
            for (id key in @[(__bridge id)kSecAttrAccount, (__bridge id)kSecAttrService,
                             (__bridge id)kSecAttrServer, (__bridge id)kSecAttrAccessGroup]) {
                if (attrs[key]) query[key] = attrs[key];
            }
            BOOL uniqueEnough = attrs[(__bridge id)kSecAttrAccount] &&
                  (attrs[(__bridge id)kSecAttrService] || attrs[(__bridge id)kSecAttrServer]);
            if (uniqueEnough) {
                result = SecItemUpdate((__bridge CFDictionaryRef)query,
                                       (__bridge CFDictionaryRef)@{(__bridge id)kSecValueData:data});
            }
        }
        if (result == errSecSuccess) keychainRestored++;
        else [warnings addObject:[NSString stringWithFormat:@"Keychain record skipped (OSStatus %d).", (int)result]];
    }
    // Restore the FCUUID preference automatically as part of the single restore action.
    // Apps that read an older value from Keychain or cache it in memory may still differ.
    BOOL fcUUIDRestored = NO;
    NSString *fcUUID = archive[@"fcUUID"];
    if ([fcUUID isKindOfClass:NSString.class] && fcUUID.length) {
        NSPredicate *uuidCheck = [NSPredicate predicateWithFormat:@"SELF MATCHES[c] %@",
            @"([0-9a-f]{32}|[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12})"];
        if ([uuidCheck evaluateWithObject:fcUUID]) {
            [NSUserDefaults.standardUserDefaults setObject:fcUUID forKey:@"fc_uuidForDevice"];
            fcUUIDRestored = YES;
        } else {
            [warnings addObject:@"Stored FCUUID has an invalid format and was not restored."];
        }
    }
    // IDFV is generated by iOS. Recording it is not equivalent to restoring it.
    NSString *oldIDFV = archive[@"sourceIDFV"];
    NSString *currentIDFV = UIDevice.currentDevice.identifierForVendor.UUIDString;
    if ([oldIDFV isKindOfClass:NSString.class] && oldIDFV.length &&
        [oldIDFV caseInsensitiveCompare:(currentIDFV ?: @"")] != NSOrderedSame) {
        [warnings addObject:@"Apple identifierForVendor changed; the app cannot restore it with sandbox permissions."];
    }
    return @{@"files":@(restored), @"keychain":@(keychainRestored),
             @"fcUUID":@(fcUUIDRestored), @"warnings":warnings};
}

@end
