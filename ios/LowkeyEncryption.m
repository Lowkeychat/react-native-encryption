#import "LowkeyEncryption.h"
#import <React/RCTLog.h>

#import "AsymmetricEncryption.h"
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
        [[AsymmetricEncryption alloc] generateKeyPair:resolve];
    });
}

#pragma mark - Encrypting a message with public key

RCT_EXPORT_METHOD(asymmetric_encryptStringWithPublicKey:(NSDictionary *)options
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0ul);
    dispatch_async(queue, ^{
        [[AsymmetricEncryption alloc] encryptStringWithPublicKey:resolve props:options];
    });
    
}

#pragma mark - Decrypting a message with private key

RCT_EXPORT_METHOD(asymmetric_decryptStringWithPrivateKey:(NSDictionary *)options
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0ul);
    dispatch_async(queue, ^{
        [[AsymmetricEncryption alloc] decryptStringWithPrivateKey:resolve props:options];
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
        [[SymmetricEncryption alloc] generateSymmetricKey:resolve];
    });
}

#pragma mark - Encrypting a message with public key

RCT_EXPORT_METHOD(symmetric_encryptStringWithSymmetricKey:(NSDictionary *)options
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0ul);
    dispatch_async(queue, ^{
        [[SymmetricEncryption alloc] encryptStringWithSymmetricKey:resolve props:options];
    });
    
}

#pragma mark - Decrypting a message with private key

RCT_EXPORT_METHOD(symmetric_decryptStringWithSymmetricKey:(NSDictionary *)options
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0ul);
    dispatch_async(queue, ^{
        [[SymmetricEncryption alloc] decryptStringWithSymmetricKey:resolve props:options];
    });
}

@end
