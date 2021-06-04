import { NativeModules } from 'react-native';

type LowkeyEncryptionType = {
  multiply(a: number, b: number): Promise<number>;
  Asymmetric: {
    generateKeyPair(): Promise<{
      privateKey: string;
      publicKey: string;
    }>;
    encrypt(props: { message: string; publicKey: string }): Promise<string>;
    decrypt(props: { message: string; privateKey: string }): Promise<string>;
  };
  Symmetric: {
    generateKey(): Promise<{ key: string }>;
    encrypt(props: { message: string; symmetricKey: string }): Promise<string>;
    decrypt(props: { message: string; symmetricKey: string }): Promise<string>;
  };
};

const { LowkeyEncryption } = NativeModules;

const Encryption = {
  Asymmetric: {
    generateKeyPair: LowkeyEncryption.asymmetric_generateKeyPair,
    encrypt: LowkeyEncryption.asymmetric_encryptStringWithPublicKey,
    decrypt: LowkeyEncryption.asymmetric_decryptStringWithPrivateKey,
  },
  Symmetric: {
    generateKey: LowkeyEncryption.symmetric_generateSymmetricKey,
    encrypt: LowkeyEncryption.symmetric_encryptStringWithSymmetricKey,
    decrypt: LowkeyEncryption.symmetric_decryptStringWithSymmetricKey,
  },
};

export default Encryption as LowkeyEncryptionType;
