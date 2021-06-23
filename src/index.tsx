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
    encryptGroup(props: {
      message: string;
      publicKeys: string[];
    }): Promise<any>;
    decryptGroup(props: {
      messages: any;
      publicKey: string;
      privateKey: string;
    }): Promise<any>;
  };
  Symmetric: {
    generateKey(): Promise<{ symmetricKey: string }>;
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
    encryptGroup: LowkeyEncryption.asymmetric_encryptGroup,
    decryptGroup: LowkeyEncryption.asymmetric_decryptGroup,
  },
  Symmetric: {
    generateKey: LowkeyEncryption.symmetric_generateSymmetricKey,
    encrypt: LowkeyEncryption.symmetric_encryptStringWithSymmetricKey,
    decrypt: LowkeyEncryption.symmetric_decryptStringWithSymmetricKey,
  },
};

export default Encryption as LowkeyEncryptionType;
