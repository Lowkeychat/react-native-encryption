@interface SymmetricEncryption : NSObject

+ (NSString*)generateSecureKey;

- (NSDictionary *)generateSymmetricKey;
- (NSString *)encryptStringWithSymmetricKey:(NSDictionary*)props;
- (NSString *)decryptStringWithSymmetricKey:(NSDictionary*)props;


@end
