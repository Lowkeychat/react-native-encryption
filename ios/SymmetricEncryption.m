#import <CommonCrypto/CommonCryptor.h>
#import <React/RCTLog.h>

#import "SymmetricEncryption.h"

#import "NSString+AESCrypt.h"

@implementation SymmetricEncryption

#pragma mark -

- (void)generateSymmetricKey:(RCTPromiseResolveBlock)resolve {
    RCTLog(@"PULLI");
    NSString* symmetricKey = [SymmetricEncryption generateSecureKey];
    NSDictionary *key = @{ @"symmetricKey" : symmetricKey};
    
    resolve(key);

}


#pragma mark -

- (void)encryptStringWithSymmetricKey:(RCTPromiseResolveBlock)resolve props:(NSDictionary*)props {
    NSString *symmetricKeyString = props[@"symmetricKey"];
    NSString *message = props[@"message"];
    
    NSString *chiperString = [message AES256EncryptWithKey:symmetricKeyString];
    RCTLog(@"encrypted %@", chiperString);
    
    NSString *decrypted = [chiperString AES256DecryptWithKey:symmetricKeyString];
    RCTLog(@"decrypted %@", decrypted);
    
    resolve(chiperString);
    
}

#pragma mark -

- (void)decryptStringWithSymmetricKey:(RCTPromiseResolveBlock)resolve props:(NSDictionary*)props {
    NSString *symmetricKeyString = props[@"symmetricKey"];
    NSString *message = props[@"message"];
    
    NSString *clearString = [message AES256DecryptWithKey:symmetricKeyString];
    RCTLog(@"decrypted %@", clearString);
    
    resolve(clearString);
}

#pragma mark -

+ (NSString*)generateSecureKey
{
    NSMutableData *data = [NSMutableData dataWithLength:32];
    int result = SecRandomCopyBytes(kSecRandomDefault, 32, data.mutableBytes);
    if (result != noErr) {
        return nil;
    }
    return [data base64EncodedStringWithOptions:kNilOptions];
}

@end
