#import "LowkeyEncryption.h"
#import <React/RCTLog.h>

#import "AsymmetricEncryption.h"
#import "AsymmetricECCEncryption.h"
#import "SymmetricEncryption.h"

@implementation LowkeyEncryption

RCT_EXPORT_MODULE()

#pragma mark - ASYMMETRIC ENCRYPTION

#pragma mark - Generating key pair

RCT_REMAP_METHOD(asymmetric_generateKeyPair,
                 asymmetric_generateKeyPairResolver:(RCTPromiseResolveBlock)resolve
                 rejecter:(RCTPromiseRejectBlock)reject)
{
    dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0ul);
    dispatch_async(queue, ^{
        [[AsymmetricECCEncryption alloc] generateKeyPair:resolve];
    });
}

#pragma mark - Encrypting a message with multiple public keys

RCT_EXPORT_METHOD(asymmetric_encryptGroup:(NSDictionary *)options
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    for (NSString* pk in options[@"publicKeys"]) {
        if ([pk length] == 0) {
            return reject(@"asymmetric_encrypt_failure_validation", @"Passed key/-s are not a valid key/-s", nil);
        }
    }
    if ([options[@"message"] length] == 0) {
        return reject(@"asymmetric_encrypt_failure_validation", @"Passed message is not a valid message", nil);
    }
        
    dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0ul);
    dispatch_async(queue, ^{
        [[AsymmetricECCEncryption alloc] encryptGroup:resolve props:options];
    });
    
}

#pragma mark - Decrypting a message with private key

RCT_EXPORT_METHOD(asymmetric_decryptGroup:(NSDictionary *)options
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    if ([options[@"privateKey"] length] == 0) {
        return reject(@"asymmetric_decrypt_failure_validation", @"Passed privateKey is not a valid private key", nil);
    }
    if ([options[@"publicKey"] length] == 0) {
        return reject(@"asymmetric_decrypt_failure_validation", @"Passed publicKey is not a valid public key", nil);
    }
    if (![options[@"messages"] isKindOfClass:[NSDictionary class]] || [options[@"messages"] count] == 0 ) {
        return reject(@"asymmetric_decrypt_failure_validation", @"Passed messages is not a valid message object", nil);
    }
    
    dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0ul);
    dispatch_async(queue, ^{
        [[AsymmetricECCEncryption alloc]  decryptGroup:resolve props:options error:^(NSError *err) {
            reject(@"asymmetric_decrypt_failure_validation", @"Corresponding fingerprint not found ", err);
        }];
    });
}

#pragma mark - SYMMETRIC ENCRYPTION


#pragma mark - Generating key pair

RCT_REMAP_METHOD(symmetric_generateSymmetricKey,
                 symmetric_generateSymmetricKeyResolver:(RCTPromiseResolveBlock)resolve
                 rejecter:(RCTPromiseRejectBlock)reject)
{
    dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0ul);
    dispatch_async(queue, ^{
        NSDictionary* key = [[SymmetricEncryption alloc] generateSymmetricKey];
        resolve(key);
    });
}

#pragma mark - Encrypting a message with public key

RCT_EXPORT_METHOD(symmetric_encryptStringWithSymmetricKey:(NSDictionary *)options
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    if ([options[@"symmetricKey"] length] == 0) {
        return reject(@"symmetric_encrypt_failure_validation", @"Passed symmetric key is not a valid key", nil);
    }
    if ([options[@"message"] length] == 0) {
        return reject(@"symmetric_encrypt_failure_validation", @"Passed message is not a valid message", nil);
    }
    
    dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0ul);
    dispatch_async(queue, ^{
        NSString *chiperString =[[SymmetricEncryption alloc] encryptStringWithSymmetricKey:options];
        return resolve(chiperString);
    });
    
}

#pragma mark - Decrypting a message with private key

RCT_EXPORT_METHOD(symmetric_decryptStringWithSymmetricKey:(NSDictionary *)options
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    if ([options[@"symmetricKey"] length] == 0) {
        return reject(@"symmetric_decrypt_failure_validation", @"Passed symmetric key is not a valid key", nil);
    }
    if ([options[@"message"] length] == 0) {
        return reject(@"symmetric_decrypt_failure_validation", @"Passed message is not a valid message", nil);
    }
    
    dispatch_queue_t queue  = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0ul);
    dispatch_async(queue, ^{
        NSString *clearString = [[SymmetricEncryption alloc] decryptStringWithSymmetricKey:options];
        resolve(clearString);
    });
}

@end
