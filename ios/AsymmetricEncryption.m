#import <React/RCTLog.h>

#import "AsymmetricEncryption.h"
#import <CommonCrypto/CommonCryptor.h>

#import <Security/SecImportExport.h>

@implementation AsymmetricEncryption

#pragma mark - Generate key pair

- (void)generateKeyPair:(RCTPromiseResolveBlock)resolve {
    NSString *privateKeyBase64String;
    NSString *publicKeyBase64String;
    
    // Creating attributes dictionary
    NSString *bundleIdentifier = [[NSBundle mainBundle] bundleIdentifier];
    bundleIdentifier = [bundleIdentifier stringByAppendingString:@".encryptionkeys"];
    
    NSData* tag = [bundleIdentifier dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary* attributes =
    @{ (id)kSecAttrKeyType:               (id)kSecAttrKeyTypeRSA,
       (id)kSecAttrKeySizeInBits:         @2048,
       (id)kSecPrivateKeyAttrs:
           @{ (id)kSecAttrIsPermanent:    @YES,
              (id)kSecAttrApplicationTag: tag,
           },
    };
    
    CFErrorRef error = NULL;
    
    // Generating private key
    SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes,
                                                 &error);
    // If key generation fail
    if (!privateKey) {
        NSError *err = CFBridgingRelease(error);
        RCTFatal(err);
    }
    
    NSError *keyDataErr;
    
    // Getting key data
    NSData* privateKeyData = (NSData*)CFBridgingRelease(  // ARC takes ownership
                                                        SecKeyCopyExternalRepresentation(privateKey, &error)
                                                        );
    
    if (!privateKeyData) {
        keyDataErr = CFBridgingRelease(error);  // ARC takes ownership
        RCTFatal(keyDataErr);
    }
    
    
    // Generating public key
    SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
    
    // Getting key data
    NSData* publicKeyData = (NSData*)CFBridgingRelease(  // ARC takes ownership
                                                       SecKeyCopyExternalRepresentation(publicKey, &error)
                                                       );
    
    if (!publicKeyData) {
        NSError *err = CFBridgingRelease(error);  // ARC takes ownership
        RCTFatal(err);
    }
    
    //*************************
    
    privateKeyBase64String = [privateKeyData base64EncodedStringWithOptions:0];
    publicKeyBase64String = [publicKeyData base64EncodedStringWithOptions:0];
    
    NSDictionary *keys = @{ @"privateKey" : privateKeyBase64String,  @"publicKey" : publicKeyBase64String};
    
    resolve(keys);
}

#pragma mark - Encrypt message

- (void)encryptStringWithPublicKey:(RCTPromiseResolveBlock)resolve props:(NSDictionary*)props {
    
    SecKeyAlgorithm algorithm = kSecKeyAlgorithmRSAEncryptionOAEPSHA512;
    
    //******************************************************
    
    NSString *publicKeyString = props[@"publicKey"];
    NSString *message = props[@"message"];
    
    //******************************************************
    
    NSData *publicKeyData = [[NSData alloc] initWithBase64EncodedString:publicKeyString options:0];
    NSDictionary* options = @{(id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
                              (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPublic,
                              (id)kSecAttrKeySizeInBits: @2048,
    };
    CFErrorRef error = NULL;
    SecKeyRef publicKey = SecKeyCreateWithData((__bridge CFDataRef)publicKeyData,
                                               (__bridge CFDictionaryRef)options,
                                               &error);
    if (!publicKey) {
        NSError *err = CFBridgingRelease(error);  // ARC takes ownership
        RCTFatal(err);
    }
    
    
    
    NSData* plainData = [message dataUsingEncoding:NSUTF8StringEncoding];
    
    BOOL canEncrypt = SecKeyIsAlgorithmSupported(publicKey,
                                                 kSecKeyOperationTypeEncrypt,
                                                 algorithm);
    canEncrypt &= ([plainData length] < (SecKeyGetBlockSize(publicKey)-130));
    
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
        
        NSString *chiperString = [cipherData base64EncodedStringWithOptions:0];
        
        resolve(chiperString);
    }
}

#pragma mark - Decrypt message

- (void)decryptStringWithPrivateKey:(RCTPromiseResolveBlock)resolve props:(NSDictionary*)props {
    
    SecKeyAlgorithm algorithm = kSecKeyAlgorithmRSAEncryptionOAEPSHA512;
    
    
    NSString *privateKeyString = props[@"privateKey"];
    NSString *message = props[@"message"];
    
    
    
    NSData *cipherData = [[NSData alloc] initWithBase64EncodedString:message options:0];
    
    
    NSData *privateKeyData = [[NSData alloc] initWithBase64EncodedString:privateKeyString options:0];
    NSDictionary* options = @{(id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
                              (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPrivate,
                              (id)kSecAttrKeySizeInBits: @2048,
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
    
    canDecrypt &= ([cipherData length] == SecKeyGetBlockSize(privateKey));
    
    
    if (canDecrypt) {
        CFErrorRef error = NULL;
        NSData *cipherData = [[NSData alloc] initWithBase64EncodedString:message options:0];
        
        NSData* clearData = (NSData*)CFBridgingRelease(
                             SecKeyCreateDecryptedData(privateKey,
                                                       algorithm,
                                                       (__bridge CFDataRef)cipherData,
                                                                                  &error));
        if (!clearData) {
            NSError *err = CFBridgingRelease(error);
            RCTFatal(err);
        }
        if (privateKey) { CFRelease(privateKey); }
        
        NSString *clearString = [[NSString alloc] initWithData:clearData encoding:NSUTF8StringEncoding];
        
        resolve(clearString);
    }
}

@end
