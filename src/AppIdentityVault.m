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
static IMP AIVOriginalFCUUID = NULL;
static NSString *AIVRestoredFCUUID = nil;
static NSUUID *AIVIdentifierForVendor(id target, SEL selector) {
    if (AIVRestoredIDFV) return AIVRestoredIDFV;
    return AIVOriginalIDFV ? ((NSUUID *(*)(id, SEL))AIVOriginalIDFV)(target, selector) : nil;
}

static id AIVFCUUIDForDevice(id target, SEL selector) {
    if (AIVRestoredFCUUID.length) return AIVRestoredFCUUID;
    return AIVOriginalFCUUID ? ((id (*)(id, SEL))AIVOriginalFCUUID)(target, selector) : nil;
}

static void AIVInstallIDFVOverride(void) {
    NSString *saved = [NSUserDefaults.standardUserDefaults
                        stringForKey:@"com.appidentityvault.override-idfv"];
    AIVRestoredIDFV = [[NSUUID alloc] initWithUUIDString:saved ?: @""];
    Method method = class_getInstanceMethod(UIDevice.class, @selector(identifierForVendor));
    if (method) AIVOriginalIDFV = method_setImplementation(method, (IMP)AIVIdentifierForVendor);
    NSString *fcUUID = [NSUserDefaults.standardUserDefaults stringForKey:@"fc_uuidForDevice"];
    if (fcUUID.length) {
        AIVRestoredFCUUID = fcUUID;
        Method fcMethod = class_getInstanceMethod(UIDevice.class, NSSelectorFromString(@"fc_uuidForDevice"));
        if (fcMethod) AIVOriginalFCUUID = method_setImplementation(fcMethod, (IMP)AIVFCUUIDForDevice);
    }
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
        [button addTarget:self action:@selector(buttonTouchDown:) forControlEvents:UIControlEventTouchDown];
        [button addTarget:self action:@selector(buttonTouchUp:) forControlEvents:
            UIControlEventTouchUpInside | UIControlEventTouchUpOutside | UIControlEventTouchCancel];
        UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc]
                                        initWithTarget:self action:@selector(dragButton:)];
        [button addGestureRecognizer:pan];
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

- (void)buttonTouchDown:(UIButton *)button {
    [UIView animateWithDuration:0.16 animations:^{ button.transform = CGAffineTransformMakeScale(0.93, 0.93); }];
}

- (void)buttonTouchUp:(UIButton *)button {
    [UIView animateWithDuration:0.2 delay:0 usingSpringWithDamping:0.65
          initialSpringVelocity:0.2 options:UIViewAnimationOptionBeginFromCurrentState
          animations:^{ button.transform = CGAffineTransformIdentity; } completion:nil];
}

- (void)dragButton:(UIPanGestureRecognizer *)gesture {
    UIView *button = gesture.view;
    UIWindow *window = [self activeWindow];
    if (!window || !button) return;
    CGPoint move = [gesture translationInView:window];
    CGPoint position = button.center;
    CGFloat margin = button.bounds.size.width * 0.5 + 8;
    position.x = MIN(MAX(position.x + move.x, margin), window.bounds.size.width - margin);
    position.y = MIN(MAX(position.y + move.y, window.safeAreaInsets.top + margin),
                     window.bounds.size.height - window.safeAreaInsets.bottom - margin);
    button.center = position;
    [gesture setTranslation:CGPointZero inView:window];
    if (gesture.state == UIGestureRecognizerStateEnded || gesture.state == UIGestureRecognizerStateCancelled) {
        BOOL right = position.x >= window.bounds.size.width / 2.0;
        position.x = right ? window.bounds.size.width - margin : margin;
        [UIView animateWithDuration:0.28 delay:0 usingSpringWithDamping:0.75
              initialSpringVelocity:0.1 options:UIViewAnimationOptionBeginFromCurrentState
              animations:^{ button.center = position; button.transform = CGAffineTransformIdentity; }
              completion:nil];
    }
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
    [[[UIImpactFeedbackGenerator alloc] initWithStyle:UIImpactFeedbackStyleLight] impactOccurred];
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"App Identity Vault"
            message:nil
            preferredStyle:UIAlertControllerStyleAlert];
    [sheet addAction:[UIAlertAction actionWithTitle:AIVL(@"نسخ الهوية", @"Copy identity")
                                              style:UIAlertActionStyleDefault
                                            handler:^(__unused UIAlertAction *action) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ [self beginBackup]; });
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:AIVL(@"لصق الهوية", @"Paste identity")
                                              style:UIAlertActionStyleDefault
                                            handler:^(__unused UIAlertAction *action) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ [self chooseBackup]; });
    }]];
    [controller presentViewController:sheet animated:YES completion:nil];
}

- (NSString *)backupStatusPath {
    return [NSHomeDirectory() stringByAppendingPathComponent:
            @"Documents/AppIdentityVault/last-backup-stage.txt"];
}

- (void)recordBackupStage:(NSString *)stage {
    NSString *safe = stage.length > 240 ? [stage substringToIndex:240] : stage;
    [safe writeToFile:[self backupStatusPath] atomically:YES
            encoding:NSUTF8StringEncoding error:NULL];
}

- (void)beginBackup {
    UIViewController *controller = [self presenter];
    if (!controller) return;
    UIAlertController *progress = [UIAlertController alertControllerWithTitle:
        AIVL(@"جاري النسخ…", @"Copying…")
        message:nil
        preferredStyle:UIAlertControllerStyleAlert];
    [controller presentViewController:progress animated:YES completion:nil];
    // Never make the actual backup depend on a modal presentation completion.
    // Some host apps block/delay presentation, which previously appeared as a
    // tap that did nothing at all.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.2 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
      dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSError *error = nil;
        NSString *folder = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/AppIdentityVault"];
        [[NSFileManager defaultManager] createDirectoryAtPath:folder
            withIntermediateDirectories:YES attributes:nil error:&error];
        NSString *timestamp = [NSString stringWithFormat:@"%.0f", NSDate.date.timeIntervalSince1970];
        NSString *path = [folder stringByAppendingPathComponent:
                          [NSString stringWithFormat:@"AppIdentityVault-%@.aiv", timestamp]];
        BOOL success = NO;
        NSNumber *size = nil;
        @try {
            if (!error) {
                [self recordBackupStage:@"Starting backup"]; 
                success = [AIVStream createBackupAtURL:[NSURL fileURLWithPath:path]
                    progress:^(NSString *stage) { [self recordBackupStage:stage]; }
                       error:&error];
            }
            if (success) {
                NSDictionary *attributes = [NSFileManager.defaultManager attributesOfItemAtPath:path error:&error];
                size = attributes[NSFileSize];
                success = size.unsignedLongLongValue > 36 && !error;
            }
        } @catch (NSException *exception) {
            error = [NSError errorWithDomain:@"com.appidentityvault.backup" code:1001
                userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:
                    @"File access exception: %@ (%@)", exception.name, exception.reason ?: @"unknown"]}];
            success = NO;
            [NSFileManager.defaultManager removeItemAtPath:[path stringByAppendingString:@".part"] error:NULL];
        }
        if (!success) [self recordBackupStage:[NSString stringWithFormat:@"Backup failed: %@",
                                 error.localizedDescription ?: @"Unknown file error"]];
        dispatch_async(dispatch_get_main_queue(), ^{
            void (^showResult)(void) = ^{
                if (!success) {
                    [self message:AIVL(@"فشل النسخ", @"Backup failed")
                             detail:error.localizedDescription ?: AIVL(@"تعذر إنشاء الملف. تحقق من المساحة المتوفرة.",
                                                                       @"Could not create the file. Check free storage.")];
                } else {
                    [self showBackupReady:[NSURL fileURLWithPath:path]];
                }
            };
            if (progress.presentingViewController) {
                [progress dismissViewControllerAnimated:YES completion:showResult];
            } else {
                showResult();
            }
        });
      });
    });
}

- (void)showBackupReady:(NSURL *)file {
    [[[UINotificationFeedbackGenerator alloc] init] notificationOccurred:UINotificationFeedbackTypeSuccess];
    UIAlertController *done = [UIAlertController alertControllerWithTitle:
        AIVL(@"تم النسخ ✅", @"Copied ✅")
        message:AIVL(@"وين تبي تحفظ النسخة؟", @"Where would you like to save it?")
        preferredStyle:UIAlertControllerStyleAlert];
    [done addAction:[UIAlertAction actionWithTitle:AIVL(@"اختيار مكان الحفظ", @"Choose location")
        style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *action) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ [self exportBackup:file]; });
        }]];
    [[self presenter] presentViewController:done animated:YES completion:nil];
}

- (void)exportBackup:(NSURL *)file {
    if (![NSFileManager.defaultManager fileExistsAtPath:file.path]) {
        [self message:AIVL(@"الملف غير موجود", @"File not found")
                 detail:AIVL(@"أعد عملية النسخ.", @"Please create the backup again.")];
        return;
    }
    UIDocumentPickerViewController *exporter = [[UIDocumentPickerViewController alloc]
                                                initForExportingURLs:@[file] asCopy:YES];
    UIViewController *controller = [self presenter];
    if (controller) [controller presentViewController:exporter animated:YES completion:nil];
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
        [self message:AIVL(@"ملف غير صالح", @"Invalid file")
                 detail:AIVL(@"اختر ملف هوية .aiv", @"Choose an .aiv identity file.")];
        return;
    }
    // Wait until the Files picker dismisses, then restore directly.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ [self restoreChosenFile:url]; });
}

- (void)restoreChosenFile:(NSURL *)url {
    UIViewController *controller = [self presenter];
    if (!controller) return;
    UIAlertController *progress = [UIAlertController alertControllerWithTitle:
        AIVL(@"جاري اللصق…", @"Pasting…") message:nil
        preferredStyle:UIAlertControllerStyleAlert];
    [controller presentViewController:progress animated:YES completion:nil];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.2 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            NSError *error = nil;
            NSDictionary *report = nil;
            @try {
                NSDictionary *preview = [AIVStream previewAtURL:url error:&error];
                if (preview && !error) report = [AIVStream restoreAtURL:url error:&error];
            } @catch (NSException *exception) {
                error = [NSError errorWithDomain:@"com.appidentityvault.restore" code:1002
                    userInfo:@{NSLocalizedDescriptionKey:exception.reason ?: @"Restore interrupted"}];
            }
            dispatch_async(dispatch_get_main_queue(), ^{
                void (^finish)(void) = ^{
                    if (!report || error) {
                        [[[UINotificationFeedbackGenerator alloc] init]
                            notificationOccurred:UINotificationFeedbackTypeError];
                        [self message:AIVL(@"تعذر اللصق", @"Paste failed")
                                 detail:AIVL(@"تأكد من ملف الهوية وجرّب مرة ثانية.",
                                             @"Check the identity file and try again.")];
                    } else {
                        [self showPasteCompleted];
                    }
                };
                if (progress.presentingViewController)
                    [progress dismissViewControllerAnimated:YES completion:finish];
                else finish();
            });
        });
    });
}

- (void)showPasteCompleted {
    [[[UINotificationFeedbackGenerator alloc] init]
        notificationOccurred:UINotificationFeedbackTypeSuccess];
    UIAlertController *done = [UIAlertController alertControllerWithTitle:
        AIVL(@"تم اللصق ✅", @"Pasted ✅")
        message:AIVL(@"افتح التطبيق مرة ثانية.", @"Open the app again.")
        preferredStyle:UIAlertControllerStyleAlert];
    [[self presenter] presentViewController:done animated:YES completion:nil];
    // Apply restored values on next launch; no extra confirmation/button.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ exit(0); });
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
