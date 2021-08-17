#import <CommonCrypto/CommonCryptor.h>
#import <React/RCTLog.h>

#import "SymmetricEncryption.h"

#import "NSString+AESCrypt.h"
#import "NSData+AESCrypt.h"

@implementation SymmetricEncryption

#pragma mark -

- (void)generateSymmetricKey:(RCTPromiseResolveBlock)resolve {
    NSString *keyString = [SymmetricEncryption generateSecureKey];
    
    NSDictionary *key = @{ @"symmetricKey" : keyString};
    resolve(key);

}
- (NSString *)generateSymmetricKeyString {
    NSString *keyString = [SymmetricEncryption generateSecureKey];
    
    return keyString;

}


#pragma mark -

- (void)encryptStringWithSymmetricKey:(RCTPromiseResolveBlock)resolve props:(NSDictionary*)props {
    NSString *symmetricKeyString = props[@"symmetricKey"];
    NSString *message = props[@"message"];
    
    NSString *chiperString = [message AES256EncryptWithKey:symmetricKeyString];
    
    resolve(chiperString);
    
}

- (NSString *)encryptStringWithSymmetricKeyWithReturn:(NSDictionary*)props {
    NSString *symmetricKeyString = props[@"symmetricKey"];
    NSString *message = props[@"message"];
    
    NSString *chiperString = [message AES256EncryptWithKey:symmetricKeyString];
    
    return chiperString;
    
}

#pragma mark -

- (void)decryptStringWithSymmetricKey:(RCTPromiseResolveBlock)resolve props:(NSDictionary*)props {
    NSString *symmetricKeyString = props[@"symmetricKey"];
    NSString *message = props[@"message"];
    
    NSString *clearString = [message AES256DecryptWithKey:symmetricKeyString];
    
    resolve(clearString);
}

- (NSString *)decryptStringWithSymmetricKeyWithReturn:(NSDictionary*)props {
    NSString *symmetricKeyString = props[@"symmetricKey"];
    NSString *message = props[@"message"];
    
    NSString *clearString = [message AES256DecryptWithKey:symmetricKeyString];
    
    return clearString;
}

#pragma mark -

+ (NSString *)generateSecureKey {
    NSMutableData *data = [NSMutableData dataWithLength:32];
    int result = SecRandomCopyBytes(kSecRandomDefault, 32, data.mutableBytes);
    if (result != noErr) {
        return nil;
    }
    return [data base64EncodedStringWithOptions:kNilOptions];
}


@end
