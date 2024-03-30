#include <assert.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/sysctl.h>
#import "AntiTamperingPlugin.h"

@implementation AntiTamperingPlugin

- (void)pluginInitialize{
    self.assetsHashes = @{};
    [self checkAndStopExecution];
}

-(void)checkAssetsIntegrity{
    [self.assetsHashes enumerateKeysAndObjectsUsingBlock:^(NSString* file, NSString* hash, BOOL* stop) {
        
        NSData* decodedFile = [[NSData alloc] initWithBase64EncodedString:file options:0];
        NSString* fileName = [[NSString alloc] initWithData:decodedFile encoding:NSUTF8StringEncoding];
        
        NSString* path = [[NSBundle mainBundle] pathForResource:[fileName stringByDeletingPathExtension] ofType:[fileName pathExtension] inDirectory:@"www"];
        if (path == nil) {
            @throw([NSException exceptionWithName:@"PathNotFoundException" reason:[@"No readable path retrieved for file " stringByAppendingString:fileName] userInfo:nil]);
        }
        NSData* fileData = [NSData dataWithContentsOfFile:path options:NSDataReadingUncached error:nil];
        
        unsigned char digest[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256( fileData.bytes, (CC_LONG)fileData.length, digest );
        NSMutableString* output = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
        for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
            [output appendFormat:@"%02x", digest[i]];
        }
        
        if (![output isEqualToString:hash]) {
            @throw([NSException exceptionWithName:@"HashNotMatchException" reason:[@"Hash doesn't match for file " stringByAppendingString:fileName] userInfo:nil]);
        }
        
    }];
}

-(void)debugDetection{
    int junk;
    int mib[4];
    struct kinfo_proc info;
    size_t size;
    info.kp_proc.p_flag = 0;
    // Initialize mib, which tells sysctl the info we want, in this case
    // we're looking for information about a specific process ID.
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();

    size = sizeof(info);
    junk = sysctl(mib, sizeof(mib) / sizeof(*mib), &info, &size, NULL, 0);
    assert(junk == 0);
    // We're being debugged if the P_TRACED flag is set.
    if ((info.kp_proc.p_flag & P_TRACED) != 0) {
        // A debugger was detected. Exit. exit(0);
        @throw([NSException exceptionWithName:@"DebugDetectedException" reason:@"App is running in Debug mode" userInfo:nil]);
    }

    NSString *fridaPath = @"/usr/bin/frida-server";
    if ([[NSFileManager defaultManager] fileExistsAtPath:fridaPath]) {
        @throw([NSException exceptionWithName:@"FridaDetectedException" reason:@"Frida detected on the device" userInfo:nil]);
    }

    #ifdef DEBUG
        @throw([NSException exceptionWithName:@"DebugDetectedException" reason:@"App running in Debug mode" userInfo:nil]);
    #endif
}

-(void)checkAndStopExecution{
    @try {
        [self debugDetection];
        [self checkAssetsIntegrity];
    } @catch (NSException *exception) {
        NSLog(@"Anti-Tampering check failed! %@: %@", [exception name], [exception reason]);
    }
}

-(void)verify:(CDVInvokedUrlCommand*)command{

    static CDVPluginResult* result = nil;

    [self.commandDelegate runInBackground:^{
        @try {
            [self debugDetection];
            [self checkAssetsIntegrity];
            NSDictionary* response = @{
                @"assets": @{
                    @"count": [NSNumber numberWithUnsignedInteger:[[self.assetsHashes allKeys] count]]
                }
            };
            result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:response];
        } @catch (NSException* exception) {
            result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:[@"AntiTampering failed: " stringByAppendingString:exception.reason]];
        } @finally {
            [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        }
    }];

}

@end
