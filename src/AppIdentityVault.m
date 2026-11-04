#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#import <objc/runtime.h>
#import <stdlib.h>
#import "AIVArchive.h"
#import "AIVCrypto.h"
#import "AIVStream.h"

static NSString *AIVL(NSString *arabic, NSString *english) {
    NSString *lang = NSLocale.preferredLanguages.firstObject ?: @"en";
    return [lang hasPrefix:@"ar"] ? arabic : english;
}

// This alters only what calls inside the *injected application process* see.
// It cannot change the OS-provided vendor identity, code-signing Team ID, or App Attest.
static IMP AIVOriginalIDFV = NULL;
static NSUUID *AIVRestoredIDFV = nil;
static NSUUID *AIVIdentifierForVendor(id target, SEL selector) {
    if (AIVRestoredIDFV) return AIVRestoredIDFV;
    return AIVOriginalIDFV ? ((NSUUID *(*)(id, SEL))AIVOriginalIDFV)(target, selector) : nil;
}

static void AIVInstallIDFVOverride(void) {
    NSString *saved = [NSUserDefaults.standardUserDefaults
                        stringForKey:@"com.appidentityvault.override-idfv"];
    AIVRestoredIDFV = [[NSUUID alloc] initWithUUIDString:saved ?: @""];
    Method method = class_getInstanceMethod(UIDevice.class, @selector(identifierForVendor));
    if (method) AIVOriginalIDFV = method_setImplementation(method, (IMP)AIVIdentifierForVendor);
}

@interface AIVOverlay : NSObject <UIDocumentPickerDelegate>
@property (nonatomic, strong) UIButton *floatingButton;
@property (nonatomic, strong) UIDocumentPickerViewController *picker;
@end

@implementation AIVOverlay

+ (instancetype)shared {
    static AIVOverlay *instance;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ instance = [AIVOverlay new]; });
    return instance;
}

- (UIWindow *)activeWindow {
    UIApplication *app = UIApplication.sharedApplication;
    for (UIScene *scene in app.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class] ||
            scene.activationState != UISceneActivationStateForegroundActive) continue;
        for (UIWindow *window in ((UIWindowScene *)scene).windows) {
            if (window.isKeyWindow) return window;
        }
    }
    for (UIWindow *window in app.windows) if (window.isKeyWindow) return window;
    return nil;
}

- (UIViewController *)presenter {
    UIViewController *root = [self activeWindow].rootViewController;
    while (root.presentedViewController) root = root.presentedViewController;
    if ([root isKindOfClass:UINavigationController.class]) root = [(UINavigationController *)root visibleViewController];
    if ([root isKindOfClass:UITabBarController.class]) root = [(UITabBarController *)root selectedViewController];
    return root;
}

- (void)installButton {
    UIWindow *window = [self activeWindow];
    if (!window || !window.rootViewController) return;
    if (!self.floatingButton) {
        UIButton *button = [UIButton buttonWithType:UIButtonTypeCustom];
        [button setTitle:@"IV" forState:UIControlStateNormal];
        button.titleLabel.font = [UIFont boldSystemFontOfSize:14];
        button.backgroundColor = [UIColor colorWithRed:0.10 green:0.19 blue:0.36 alpha:0.95];
        button.layer.cornerRadius = 23;
        button.layer.borderWidth = 1;
        button.layer.borderColor = UIColor.systemTealColor.CGColor;
        button.layer.shadowColor = UIColor.blackColor.CGColor;
        button.layer.shadowRadius = 6;
        button.layer.shadowOpacity = 0.25;
        button.accessibilityLabel = @"App Identity Vault";
        [button addTarget:self action:@selector(showMenu) forControlEvents:UIControlEventTouchUpInside];
        self.floatingButton = button;
    }
    if (self.floatingButton.superview != window) {
        [self.floatingButton removeFromSuperview];
        self.floatingButton.frame = CGRectMake(MAX(8, window.bounds.size.width - 58), 180, 46, 46);
        self.floatingButton.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin;
        [window addSubview:self.floatingButton];
    }
    [window bringSubviewToFront:self.floatingButton];
}

- (void)message:(NSString *)title detail:(NSString *)detail {
    UIViewController *controller = [self presenter];
    if (!controller) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                 message:detail
                                                          preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:AIVL(@"حسنًا", @"OK")
                                             style:UIAlertActionStyleDefault handler:nil]];
    [controller presentViewController:alert animated:YES completion:nil];
}

- (void)showMenu {
    UIViewController *controller = [self presenter];
    if (!controller) return;
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"App Identity Vault"
            message:AIVL(@"اختر عملية واحدة. كل عملية تشمل الملفات وKeychain وApp Groups والمعرّفات الممكنة تلقائيًا.",
                         @"Choose an action. Each action includes accessible files, Keychain, App Groups, and identifiers automatically.")
            preferredStyle:UIAlertControllerStyleAlert];
    [sheet addAction:[UIAlertAction actionWithTitle:AIVL(@"نسخ الهوية", @"Copy identity")
                                              style:UIAlertActionStyleDefault
                                            handler:^(__unused UIAlertAction *action) { [self askBackupPassword]; }]];
    [sheet addAction:[UIAlertAction actionWithTitle:AIVL(@"لصق الهوية", @"Paste identity")
                                              style:UIAlertActionStyleDefault
                                            handler:^(__unused UIAlertAction *action) { [self chooseBackup]; }]];
    [controller presentViewController:sheet animated:YES completion:nil];
}

- (void)askBackupPassword {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:AIVL(@"تشفير النسخة", @"Encrypt backup")
        message:AIVL(@"ستتضمن النسخة بيانات محلية حساسة؛ احفظ كلمة المرور، فلن نستطيع استرجاعها.",
                     @"The backup may include sensitive local data. Store the password securely; it cannot be recovered.")
        preferredStyle:UIAlertControllerStyleAlert];
    for (NSString *hint in @[AIVL(@"كلمة المرور (8 رموز أو أكثر)", @"Password (8+ characters)"),
                             AIVL(@"تأكيد كلمة المرور", @"Confirm password")]) {
        [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
            field.secureTextEntry = YES; field.placeholder = hint;
            field.textContentType = UITextContentTypeNewPassword;
        }];
    }
    [alert addAction:[UIAlertAction actionWithTitle:AIVL(@"إلغاء", @"Cancel") style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:AIVL(@"إنشاء النسخة", @"Create backup")
                                             style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *action) {
        NSString *pass = alert.textFields[0].text ?: @"";
        NSString *again = alert.textFields[1].text ?: @"";
        if (pass.length < 8 || ![pass isEqualToString:again]) {
            [self message:AIVL(@"كلمة المرور غير صحيحة", @"Password error")
                     detail:AIVL(@"لازم 8 رموز على الأقل وكلمتا المرور متطابقتان.",
                                  @"Use 8+ characters and enter the same password twice.")];
            return;
        }
        [self createBackupWithPassword:pass];
    }]];
    [[self presenter] presentViewController:alert animated:YES completion:nil];
}

- (void)createBackupWithPassword:(NSString *)password {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSError *error = nil;
        NSString *folder = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/AppIdentityVault"];
        [[NSFileManager defaultManager] createDirectoryAtPath:folder
            withIntermediateDirectories:YES attributes:nil error:&error];
        NSString *timestamp = [NSString stringWithFormat:@"%.0f", NSDate.date.timeIntervalSince1970];
        NSString *path = [folder stringByAppendingPathComponent:
                          [NSString stringWithFormat:@"AppIdentityVault-%@.aiv", timestamp]];
        BOOL success = !error && [AIVStream createBackupAtURL:[NSURL fileURLWithPath:path]
                                                      password:password error:&error];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (error || !success) {
                [self message:AIVL(@"فشل النسخ", @"Backup failed")
                         detail:error.localizedDescription ?: @"Unknown error"];
                return;
            }
            NSURL *file = [NSURL fileURLWithPath:path];
            UIDocumentPickerViewController *exporter = [[UIDocumentPickerViewController alloc]
                                                        initForExportingURLs:@[file] asCopy:YES];
            UIViewController *controller = [self presenter];
            if (controller) [controller presentViewController:exporter animated:YES completion:nil];
            // The encrypted .aiv file stays in Documents until the user deletes it.
        });
    });
}

- (void)chooseBackup {
    UIDocumentPickerViewController *picker = [[UIDocumentPickerViewController alloc]
                                                   initForOpeningContentTypes:@[UTTypeData] asCopy:YES];
    picker.delegate = self;
    self.picker = picker;
    [[self presenter] presentViewController:picker animated:YES completion:nil];
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    NSURL *url = urls.firstObject;
    if (!url || ![url.pathExtension.lowercaseString isEqualToString:@"aiv"]) {
        [self message:AIVL(@"نوع ملف غير مدعوم", @"Unsupported file")
                 detail:@"Choose an AppIdentityVault .aiv file."];
        return;
    }
    [self askRestorePasswordForURL:url];
}

- (void)askRestorePasswordForURL:(NSURL *)url {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:AIVL(@"استعادة نسخة", @"Restore backup")
        message:AIVL(@"أدخل كلمة المرور لفك تشفير النسخة والتحقق منها.",
                     @"Enter the password to authenticate and decrypt this backup.")
        preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.placeholder = AIVL(@"كلمة المرور", @"Password");
        field.secureTextEntry = YES;
    }];
    [alert addAction:[UIAlertAction actionWithTitle:AIVL(@"إلغاء", @"Cancel") style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:AIVL(@"تحقق", @"Verify")
                                             style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *action) {
        NSString *pass = alert.textFields.firstObject.text ?: @"";
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            NSError *error = nil;
            NSDictionary *archive = [AIVStream previewAtURL:url password:pass error:&error];
            dispatch_async(dispatch_get_main_queue(), ^{
                if (!archive) {
                    [self message:AIVL(@"تعذرت الاستعادة", @"Cannot restore")
                             detail:error.localizedDescription ?: @"Invalid archive"];
                } else [self confirmRestorePreview:archive URL:url password:pass];
            });
        });
    }]];
    [[self presenter] presentViewController:alert animated:YES completion:nil];
}

- (void)confirmRestorePreview:(NSDictionary *)archive URL:(NSURL *)url password:(NSString *)password {
    NSString *detail = [NSString stringWithFormat:
        AIVL(@"النسخة: %@\nملفات: %lu — سجلات Keychain: %lu\nتحذيرات النسخ: %lu\n\nالاستعادة ستستبدل ملفات التطبيق الحالية، وقد تؤثر على تسجيل الدخول. هل أنت متأكد؟",
             @"Backup: %@\nFiles: %lu — Keychain records: %lu\nBackup warnings: %lu\n\nRestore overwrites current app files and may affect your login. Continue?"),
        archive[@"created"] ?: @"?", (unsigned long)[archive[@"fileCount"] unsignedIntegerValue],
        (unsigned long)[archive[@"keychain"] count], (unsigned long)[archive[@"warnings"] count]];
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:AIVL(@"تأكيد الاستعادة", @"Confirm restore")
                                                                message:detail preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:AIVL(@"إلغاء", @"Cancel") style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:AIVL(@"استعادة", @"Restore")
                                             style:UIAlertActionStyleDestructive handler:^(__unused UIAlertAction *action) {
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            NSError *error = nil;
            NSDictionary *report = [AIVStream restoreAtURL:url password:password error:&error];
            dispatch_async(dispatch_get_main_queue(), ^{
                NSUInteger issues = [report[@"warnings"] count];
                NSString *message = error.localizedDescription ?: [NSString stringWithFormat:
                    AIVL(@"تمت استعادة %@ ملف و%@ سجل Keychain. FCUUID: %@، IDFV: %@. تحذيرات: %lu. سيُغلق التطبيق الآن حتى تُحمَّل الهوية عند فتحه من جديد.",
                         @"Restored %@ files and %@ Keychain records. FCUUID: %@, IDFV: %@. Warnings: %lu. The app will close so the restored values are loaded next launch."),
                    report[@"files"] ?: @0, report[@"keychainRestored"] ?: @0,
                    [report[@"fcUUIDRestored"] boolValue] ? AIVL(@"نعم", @"yes") : AIVL(@"غير متاح", @"unavailable"),
                    [report[@"idfvOverride"] boolValue] ? AIVL(@"داخل التطبيق", @"in-app override") : AIVL(@"غير متاح", @"unavailable"),
                    (unsigned long)issues];
                if (issues) message = [message stringByAppendingFormat:@"\n%@",
                                     [[report[@"warnings"] subarrayWithRange:NSMakeRange(0, MIN(issues, 3))] componentsJoinedByString:@"\n"]];
                if (error || !report) {
                    [self message:AIVL(@"تعذرت الاستعادة", @"Restore failed") detail:message];
                } else {
                    UIAlertController *done = [UIAlertController alertControllerWithTitle:
                        AIVL(@"اكتملت عملية اللصق", @"Paste completed") message:message
                        preferredStyle:UIAlertControllerStyleAlert];
                    [done addAction:[UIAlertAction actionWithTitle:
                        AIVL(@"إغلاق التطبيق لتطبيق الهوية", @"Close app to apply identity")
                        style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *action) {
                            // iOS provides no supported API to relaunch a re-signed app automatically.
                            // Closing ensures cached UUID/session values are reloaded on next manual launch.
                            exit(0);
                        }]];
                    [[self presenter] presentViewController:done animated:YES completion:nil];
                }
            });
        });
    }]];
    [[self presenter] presentViewController:alert animated:YES completion:nil];
}

@end

__attribute__((constructor)) static void AIVBootstrap(void) {
    // Runs *inside* the host app when the library has been embedded and re-signed.
    // It does not gain jailbreak permissions or alter sandbox/Keychain entitlements.
    AIVInstallIDFVOverride();
    dispatch_async(dispatch_get_main_queue(), ^{
        AIVOverlay *overlay = [AIVOverlay shared];
        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification
            object:nil queue:NSOperationQueue.mainQueue usingBlock:^(__unused NSNotification *note) {
            [overlay installButton];
        }];
        [overlay installButton];
    });
}
