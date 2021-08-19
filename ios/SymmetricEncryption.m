#import <CommonCrypto/CommonCryptor.h>
#import <React/RCTLog.h>

#import "SymmetricEncryption.h"

#import "NSString+AESCrypt.h"
#import "NSData+AESCrypt.h"

#import "SymmetricEncryptionUtils.h"

@implementation SymmetricEncryption

#pragma mark -

- (NSDictionary *)generateSymmetricKey {
    NSString *keyString = [SymmetricEncryption generateSecureKey];
    
    NSDictionary *key = @{ @"symmetricKey" : keyString};
    return key;

}


#pragma mark -

- (NSString *)encryptStringWithSymmetricKey:(NSDictionary*)props {
    NSString *symmetricKeyString = props[@"symmetricKey"];
    NSString *message = props[@"message"];
    
    NSString *chiperString = [[SymmetricEncryptionUtils alloc] AES256EncryptWithKey:symmetricKeyString message:message];
    
    return chiperString;
    
}

#pragma mark -

- (NSString *)decryptStringWithSymmetricKey:(NSDictionary*)props {
    NSString *symmetricKeyString = props[@"symmetricKey"];
    NSString *message = props[@"message"];
    
    NSString *clearString = [[SymmetricEncryptionUtils alloc] AES256DecryptWithKey:symmetricKeyString message:message];
    
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
