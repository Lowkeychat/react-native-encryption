import { NativeModules } from 'react-native';

type LowkeyEncryptionType = {
  multiply(a: number, b: number): Promise<number>;
};

const { LowkeyEncryption } = NativeModules;

export default LowkeyEncryption as LowkeyEncryptionType;
