
#import <Foundation/Foundation.h>

@interface SymmetricEncryptionUtils : NSObject

- (NSString *)AES256EncryptWithKey:(NSString *)key message:(NSString *)message;
- (NSString *)AES256DecryptWithKey:(NSString *)key message:(NSString *)message;

- (NSData *)AES256EncryptWithKeyData:(NSString *)key data:(NSData *)inputData;
- (NSData *)AES256DecryptWithKeyData:(NSString *)key data:(NSData *)inputData;

@end
