#import <React/RCTBridgeModule.h>

@interface AsymmetricEncryption : NSObject <RCTBridgeModule>

- (void)generateKeyPair:(RCTPromiseResolveBlock)resolve;

- (void)encryptStringWithPublicKey:(RCTPromiseResolveBlock)resolve props:(NSDictionary*)props;

- (void)decryptStringWithPrivateKey:(RCTPromiseResolveBlock)resolve                   props:(NSDictionary*)props;
    
@end
