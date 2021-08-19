#import <CommonCrypto/CommonCryptor.h>
#import "SymmetricEncryptionUtils.h"

@implementation SymmetricEncryptionUtils

#pragma mark - Encryption operations


- (NSString *)AES256EncryptWithKey:(NSString *)key message:(NSString *)message {
    NSData *plainData = [message dataUsingEncoding:NSUTF8StringEncoding];
    NSData *encryptedData = [self AES256EncryptWithKeyData:key data:plainData];
    NSString *encryptedString = [encryptedData base64EncodedStringWithOptions:0];
    return encryptedString;
}

- (NSString *)AES256DecryptWithKey:(NSString *)key message:(NSString *)message {
    NSData *encryptedData = [[NSData alloc] initWithBase64EncodedString:message options:0];
    NSData *plainData = [self AES256DecryptWithKeyData:key data:encryptedData];
    NSString *plainString = [[NSString alloc] initWithData:plainData encoding:NSUTF8StringEncoding];
    return plainString;
}

#pragma mark - Encryption operations on NSData


- (NSData *)AES256EncryptWithKeyData:(NSString *)key data:(NSData *)inputData {
    NSData *keyData = [[NSData alloc] initWithBase64EncodedString:key options:0];
    
    NSUInteger dataLength = [inputData length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesEncrypted = 0;

    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES,
                                              kCCOptionPKCS7Padding, keyData.bytes,
                                              kCCKeySizeAES256, NULL, [inputData bytes],
                                              dataLength, buffer, bufferSize, &numBytesEncrypted);
    if(cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
    }
    free(buffer);
    return nil;
}

- (NSData *)AES256DecryptWithKeyData:(NSString *)key data:(NSData *)inputData {
    NSData *keyData = [[NSData alloc] initWithBase64EncodedString:key options:0];
    
    NSUInteger dataLength = [inputData length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES,
                                          kCCOptionPKCS7Padding, keyData.bytes,
                                          kCCKeySizeAES256, NULL, [inputData bytes],
                                          dataLength, buffer, bufferSize, &numBytesDecrypted);
    if(cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    }
    free(buffer);
    return nil;
}

@end
