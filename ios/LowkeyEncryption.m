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
    dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0ul);
    dispatch_async(queue, ^{
        [[AsymmetricECCEncryption alloc]  decryptGroup:resolve props:options];
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
    dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0ul);
    dispatch_async(queue, ^{
        NSString *chiperString =[[SymmetricEncryption alloc] encryptStringWithSymmetricKey:options];
        resolve(chiperString);
    });
    
}

#pragma mark - Decrypting a message with private key

RCT_EXPORT_METHOD(symmetric_decryptStringWithSymmetricKey:(NSDictionary *)options
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    dispatch_queue_t queue  = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0ul);
    dispatch_async(queue, ^{
        NSString *clearString = [[SymmetricEncryption alloc] decryptStringWithSymmetricKey:options];
        resolve(clearString);
    });
}

@end
