#import <React/RCTLog.h>

#import "AsymmetricEncryption.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>

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
    privateKeyBase64String = [@"-----BEGIN RSA PRIVATE KEY-----\n" stringByAppendingString:privateKeyBase64String];
    privateKeyBase64String = [privateKeyBase64String stringByAppendingString:@"\n-----END RSA PRIVATE KEY-----\n"];
    
    publicKeyBase64String = [publicKeyData base64EncodedStringWithOptions:0];
    publicKeyBase64String = [@"-----BEGIN RSA PUBLIC KEY-----\n" stringByAppendingString:publicKeyBase64String];
    publicKeyBase64String = [publicKeyBase64String stringByAppendingString:@"\n-----END RSA PUBLIC KEY-----\n"];
    
    NSDictionary *keys = @{ @"privateKey" : privateKeyBase64String,  @"publicKey" : publicKeyBase64String};
    
    resolve(keys);
}

#pragma mark - Encrypt messageencryptGroup

- (void)encryptStringWithPublicKey:(RCTPromiseResolveBlock)resolve props:(NSDictionary*)props {
    
    SecKeyAlgorithm algorithm = kSecKeyAlgorithmRSAEncryptionRaw;
    
    //******************************************************
    
    NSString *publicKeyString = props[@"publicKey"];
    NSString *message = props[@"message"];
    
    //******************************************************
    
    publicKeyString = [self cleanPublicKey:publicKeyString];
    
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


#pragma mark - Encrypt message with multiple public keys

- (void)encryptGroup:(RCTPromiseResolveBlock)resolve props:(NSDictionary*)props {
    
    NSMutableDictionary *encryptedObject = [[NSMutableDictionary alloc] init];
    
    SecKeyAlgorithm algorithm = kSecKeyAlgorithmRSAEncryptionRaw;
    
    NSArray *publicKeysString = props[@"publicKeys"];
    NSString *message = props[@"message"];
    
    for (NSString* pk in publicKeysString) {
        NSString *fingerprint;
        
        
        NSString *publicKeyString = [self cleanPublicKey:pk];
        NSData *publicKeyData = [[NSData alloc] initWithBase64EncodedString:publicKeyString options:0];
        
        NSDictionary* options = @{(id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
                                  (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPublic,
                                  (id)kSecAttrKeySizeInBits: @2048,
        };
        CFErrorRef error = NULL;
        
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
            [encryptedObject setValue:chiperString forKey:fingerprint];
                        
        }
    }
    resolve(encryptedObject);
    
}

#pragma mark - Decrypt message

- (void)decryptStringWithPrivateKey:(RCTPromiseResolveBlock)resolve props:(NSDictionary*)props {
    
    SecKeyAlgorithm algorithm = kSecKeyAlgorithmRSAEncryptionRaw;
    
    
    NSString *privateKeyString = props[@"privateKey"];
    NSString *message = props[@"message"];
    
    
    privateKeyString = [self cleanPrivateKey:privateKeyString];
    
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

- (void)decryptGroup:(RCTPromiseResolveBlock)resolve props:(NSDictionary*)props {
    
    SecKeyAlgorithm algorithm = kSecKeyAlgorithmRSAEncryptionRaw;
    
    
    NSString *privateKeyString = props[@"privateKey"];
    NSString *publicKeyString = [self cleanPublicKey:props[@"publicKey"]];
    NSDictionary *messages = props[@"messages"];
    
    
    NSData *publicKeyData = [[NSData alloc] initWithBase64EncodedString:publicKeyString options:0];
    NSString *fingerprint = [self sha1:publicKeyData];
    NSString *message = messages[fingerprint];
    
    privateKeyString = [self cleanPrivateKey:privateKeyString];
    
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

- (NSString *) cleanPublicKey:(NSString *)publicKeyBase64String {
    NSRange spos;
    NSRange epos;
    spos = [publicKeyBase64String rangeOfString:@"-----BEGIN RSA PUBLIC KEY-----"];
    if(spos.length > 0){
        epos = [publicKeyBase64String rangeOfString:@"-----END RSA PUBLIC KEY-----"];
    } else{
        spos = [publicKeyBase64String rangeOfString:@"-----BEGIN PUBLIC KEY-----"];
        epos = [publicKeyBase64String rangeOfString:@"-----END PUBLIC KEY-----"];
    }
    if(spos.location != NSNotFound && epos.location != NSNotFound){
        NSUInteger s = spos.location + spos.length;
        NSUInteger e = epos.location;
        NSRange range = NSMakeRange(s, e-s);
        publicKeyBase64String = [publicKeyBase64String substringWithRange:range];
    }
    publicKeyBase64String = [publicKeyBase64String stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    publicKeyBase64String = [publicKeyBase64String stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    publicKeyBase64String = [publicKeyBase64String stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    publicKeyBase64String = [publicKeyBase64String stringByReplacingOccurrencesOfString:@" "  withString:@""];
    
    return publicKeyBase64String;
}

- (NSString *) cleanPrivateKey:(NSString *)privateKeyBase64String {
    NSRange spos;
    NSRange epos;
    spos = [privateKeyBase64String rangeOfString:@"-----BEGIN RSA PRIVATE KEY-----"];
    if(spos.length > 0){
        epos = [privateKeyBase64String rangeOfString:@"-----END RSA PRIVATE KEY-----"];
    } else{
        spos = [privateKeyBase64String rangeOfString:@"-----BEGIN PRIVATE KEY-----"];
        epos = [privateKeyBase64String rangeOfString:@"-----END PRIVATE KEY-----"];
    }
    if(spos.location != NSNotFound && epos.location != NSNotFound){
        NSUInteger s = spos.location + spos.length;
        NSUInteger e = epos.location;
        NSRange range = NSMakeRange(s, e-s);
        privateKeyBase64String = [privateKeyBase64String substringWithRange:range];
    }
    privateKeyBase64String = [privateKeyBase64String stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    privateKeyBase64String = [privateKeyBase64String stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    privateKeyBase64String = [privateKeyBase64String stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    privateKeyBase64String = [privateKeyBase64String stringByReplacingOccurrencesOfString:@" "  withString:@""];
    
    return privateKeyBase64String;
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
