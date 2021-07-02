#import <React/RCTLog.h>

#import "AsymmetricECCEncryption.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>

#import <Security/SecImportExport.h>

@implementation AsymmetricECCEncryption

#pragma mark - Generate key pair

- (void)generateKeyPair:(RCTPromiseResolveBlock)resolve {
    NSString *privateKeyBase64String;
    NSString *publicKeyBase64String;
    
    NSString *bundleIdentifier = [[NSBundle mainBundle] bundleIdentifier];
    bundleIdentifier = [bundleIdentifier stringByAppendingString:@".encryptionkeys"];
    
    NSData* tag = [bundleIdentifier dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary* attributes =
    @{ (id)kSecAttrKeyType:               (id)kSecAttrKeyTypeECSECPrimeRandom,
       (id)kSecAttrKeySizeInBits:         @256,
       (id)kSecPrivateKeyAttrs:
           @{ (id)kSecAttrIsPermanent:    @YES,
              (id)kSecAttrApplicationTag: tag,
           },
    };
    
    CFErrorRef error = NULL;
    SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes,
                                                 &error);
    if (!privateKey) {
        NSError *err = CFBridgingRelease(error);
        RCTFatal(err);
    }
    
    NSError *keyDataErr;
    NSData* privateKeyData = (NSData*)CFBridgingRelease(SecKeyCopyExternalRepresentation(privateKey, &error));
    
    
    if (!privateKeyData) {
        keyDataErr = CFBridgingRelease(error);
        RCTFatal(keyDataErr);
    }
    
    SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
    NSData* publicKeyData = (NSData*)CFBridgingRelease(SecKeyCopyExternalRepresentation(publicKey, &error));
    
    RCTLog(@"DATA %@", publicKeyData);
    
    if (!publicKeyData) {
        NSError *err = CFBridgingRelease(error);
        RCTFatal(err);
    }
    
    privateKeyBase64String = [privateKeyData base64EncodedStringWithOptions:0];
    publicKeyBase64String = [publicKeyData base64EncodedStringWithOptions:0];

    NSDictionary *keys = @{ @"privateKey" : privateKeyBase64String,  @"publicKey" : publicKeyBase64String};
    
    resolve(keys);
}

#pragma mark - Encrypt message with multiple public keys

- (void)encryptGroup:(RCTPromiseResolveBlock)resolve props:(NSDictionary*)props {
    
    NSMutableDictionary *encryptedObject = [[NSMutableDictionary alloc] init];
    
    if (@available(iOS 11.0, *)) {
        SecKeyAlgorithm algorithm = kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM;
        
        NSArray *publicKeysString = props[@"publicKeys"];
        NSString *message = props[@"message"];
        
        for (NSString* pk in publicKeysString) {
            NSString *fingerprint;
            RCTLog(@"pk ----> %@", pk);
            NSData *publicKeyData = [[NSData alloc] initWithBase64EncodedString:pk options:0];
        
            NSDictionary* options = @{(id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
                                      (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPublic,
                                      (id)kSecAttrKeySizeInBits: @256,
            };
            CFErrorRef error = NULL;
            
            RCTLog(@"publicKeyData ----> %@", publicKeyData);
            
            SecKeyRef publicKey = SecKeyCreateWithData((__bridge CFDataRef)publicKeyData,
                                                       (__bridge CFDictionaryRef)options,
                                                       &error);
            
            fingerprint = [self sha1:publicKeyData];
            
            if (!publicKey) {
                NSError *err = CFBridgingRelease(error);
                RCTFatal(err);
            }
            
            
            
            NSData* plainData = [message dataUsingEncoding:NSUTF8StringEncoding];
            BOOL canEncrypt = SecKeyIsAlgorithmSupported(publicKey,
                                                         kSecKeyOperationTypeEncrypt,
                                                         algorithm);
            
            NSData* cipherData = nil;
            
            if (canEncrypt) {
                CFErrorRef error = NULL;
                cipherData = (NSData*)CFBridgingRelease(
                                                        SecKeyCreateEncryptedData(publicKey,
                                                                                  algorithm,
                                                                                  (__bridge CFDataRef)plainData,
                                                                                  &error));
                if (publicKey) { CFRelease(publicKey); }
                
                if (!cipherData) {
                    NSError *err = CFBridgingRelease(error);
                    RCTFatal(err);
                }
                
                RCTLog(@"cipherData size 1 %lu", (unsigned long)[cipherData length]);
                NSString *chiperString = [cipherData base64EncodedStringWithOptions:0];
                [encryptedObject setValue:chiperString forKey:fingerprint];
                
            }
        }
    } else {
        // Fallback on earlier versions
    }
    resolve(encryptedObject);
    
}

- (void)decryptGroup:(RCTPromiseResolveBlock)resolve props:(NSDictionary*)props {
    
    SecKeyAlgorithm algorithm = kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM;
    
    
    NSString *privateKeyString = props[@"privateKey"];
    NSString *publicKeyString = props[@"publicKey"]; // [self cleanPublicKey:props[@"publicKey"]];
    NSDictionary *messages = props[@"messages"];
    
    
    NSData *publicKeyData = [[NSData alloc] initWithBase64EncodedString:publicKeyString options:0];
    NSString *fingerprint = [self sha1:publicKeyData];
    NSString *message = messages[fingerprint];
    
//    privateKeyString = [self cleanPrivateKey:privateKeyString];
    
    NSData *cipherData = [[NSData alloc] initWithBase64EncodedString:message options:0];
    
    RCTLog(@"cipherData size %lu", (unsigned long)[cipherData length]);
    
    NSData *privateKeyData = [[NSData alloc] initWithBase64EncodedString:privateKeyString options:0];
    NSDictionary* options = @{(id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
                              (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPrivate,
                              (id)kSecAttrKeySizeInBits: @256,
    };
    
    CFErrorRef error = NULL;
    SecKeyRef privateKey = SecKeyCreateWithData((__bridge CFDataRef)privateKeyData,
                                               (__bridge CFDictionaryRef)options,
                                                &error);
    if (!privateKey) {
        NSError *err = CFBridgingRelease(error);
        RCTFatal(err);
    }
    BOOL canDecrypt = SecKeyIsAlgorithmSupported(privateKey,
                                                    kSecKeyOperationTypeDecrypt,
                                                    algorithm);
    
//    canDecrypt &= ([cipherData length] == SecKeyGetBlockSize(privateKey));
    
    
    if (canDecrypt) {
        CFErrorRef error = NULL;
        
        NSData* clearData = (NSData*)CFBridgingRelease(
                             SecKeyCreateDecryptedData(privateKey,
                                                       algorithm,
                                                       (__bridge CFDataRef)cipherData,
                                                                                  &error));
        if (!clearData) {
            NSError *err = CFBridgingRelease(error);
            RCTLog(@"error!");
            RCTFatal(err);
        }
        if (privateKey) { CFRelease(privateKey); }
        
        NSString *clearString = [[NSString alloc] initWithData:clearData encoding:NSUTF8StringEncoding];
        
        resolve(clearString);
    } else {
        RCTLog(@"Cant decrypt");
    }
}

- (NSString*)sha1:(NSData *)data
{
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];

    CC_SHA1(data.bytes, (CC_LONG)data.length, digest);

    NSMutableString *output = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];

    for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++)
    {
        [output appendFormat:@"%02x", digest[i]];
    }

    return output;
}

@end
