/* eslint-disable react-native/no-inline-styles */
import * as React from 'react';

import {
  StyleSheet,
  View,
  Text,
  TouchableOpacity,
  LayoutAnimation,
  TouchableWithoutFeedback,
  TextInput,
  Dimensions,
} from 'react-native';
import Encryption from '@lowkey/react-native-encryption';

const ENCRYPTION_TYPES = {
  SYMMETRIC: 'SYMMETRIC',
  ASYMMETRIC: 'ASYMMETRIC',
};

export default function App() {
  const [time, setTime] = React.useState(0);
  const [encryptionType, setEncryptionType] = React.useState(
    ENCRYPTION_TYPES.ASYMMETRIC
  );

  React.useEffect(() => {
    const interval = setInterval(() => setTime(time + 1), 1000);
    return () => {
      clearInterval(interval);
    };
  }, [time]);

  const [keys, setKeys] = React.useState({
    generated: false,
    publicKey: '',
    privateKey: '',
    symmetricKey: '',
  });

  const [message, setMessage] = React.useState({
    encrypted: false,
    decrypted: false,
    value: '',
  });

  const generateKeyPair = async () => {
    setKeys({
      ...keys,
      generated: false,
    });
    if (encryptionType === ENCRYPTION_TYPES.ASYMMETRIC) {
      const _keys = await Encryption.Asymmetric.generateKeyPair();
      console.log(_keys);
      LayoutAnimation.configureNext(LayoutAnimation.Presets.easeInEaseOut);
      setKeys({
        ...keys,
        ..._keys,
        generated: true,
      });
    } else if (encryptionType === ENCRYPTION_TYPES.SYMMETRIC) {
      const _key = await Encryption.Symmetric.generateKey();
      console.log('Encryption.Symmetric', _key);
      LayoutAnimation.configureNext(LayoutAnimation.Presets.easeInEaseOut);
      setKeys({
        ...keys,
        ..._key,
        generated: true,
      });
    }
  };

  const encryptString = async () => {
    const m = message.value;
    let encryptedMessage = '';

    if (encryptionType === ENCRYPTION_TYPES.ASYMMETRIC) {
      encryptedMessage = await Encryption.Asymmetric.encrypt({
        publicKey: keys.publicKey,
        message: m,
      });
    } else if (encryptionType === ENCRYPTION_TYPES.SYMMETRIC) {
      encryptedMessage = await Encryption.Symmetric.encrypt({
        symmetricKey: keys.symmetricKey,
        message: m,
      });
    }
    setMessage({
      encrypted: true,
      decrypted: false,
      value: encryptedMessage,
    });
  };

  const decryptString = async () => {
    const m = message.value;
    let decryptedMessage = '';

    if (encryptionType === ENCRYPTION_TYPES.ASYMMETRIC) {
      decryptedMessage = await Encryption.Asymmetric.decrypt({
        privateKey: keys.privateKey,
        message: m,
      });
    } else if (encryptionType === ENCRYPTION_TYPES.SYMMETRIC) {
      decryptedMessage = await Encryption.Symmetric.decrypt({
        symmetricKey: keys.symmetricKey,
        message: m,
      });
    }
    setMessage({
      encrypted: false,
      decrypted: true,
      value: decryptedMessage,
    });
  };

  const onChangeText = (m: string) => {
    setMessage({
      ...message,
      value: m,
    });
  };

  const reset = () => {
    setMessage({
      encrypted: false,
      decrypted: false,
      value: '',
    });
    setKeys({
      generated: false,
      publicKey: '',
      privateKey: '',
      symmetricKey: '',
    });
  };

  const changeEncryptionType = () => {
    setEncryptionType(
      encryptionType === ENCRYPTION_TYPES.ASYMMETRIC
        ? ENCRYPTION_TYPES.SYMMETRIC
        : ENCRYPTION_TYPES.ASYMMETRIC
    );
  };

  return (
    <View style={styles.container}>
      <View>
        <TouchableOpacity onPress={changeEncryptionType}>
          <View
            style={[
              styles.button,
              {
                backgroundColor: '#e9e9e9',
              },
            ]}
          >
            <Text
              style={{
                color: '#333',
              }}
            >
              Change Encryption type
            </Text>
          </View>
        </TouchableOpacity>
      </View>
      <TouchableOpacity onPress={generateKeyPair}>
        <View
          style={[
            styles.button,
            {
              backgroundColor: keys.generated ? '#3D854D' : '#e9e9e9',
            },
          ]}
        >
          <Text
            style={{
              color: keys.generated ? '#fefefe' : '#333',
            }}
          >
            Generate Keys {time}
          </Text>
        </View>
      </TouchableOpacity>
      <View style={styles.textInputContainer}>
        <View>
          <View style={styles.metaRow}>
            <Text style={styles.metaRowHeader}>Encryption Type:</Text>
            <Text style={styles.metaRowText}>
              {encryptionType === ENCRYPTION_TYPES.ASYMMETRIC
                ? 'ASYMMETRIC'
                : 'SYMMETRIC'}
            </Text>
          </View>
          <View style={styles.metaRow}>
            <Text style={styles.metaRowHeader}>Status:</Text>
            <Text style={styles.metaRowText}>
              {message.encrypted
                ? 'Encrypted'
                : message.decrypted
                ? 'Decrypted'
                : 'Plain'}
            </Text>
          </View>
        </View>
        <Text style={{ width: 300, textAlign: 'center' }} numberOfLines={1}>
          {message.value}
        </Text>
        <TextInput
          value={message.value}
          onChangeText={onChangeText}
          style={styles.textInput}
        />
        <View style={styles.buttonsContainer}>
          <TouchableWithoutFeedback onPress={encryptString}>
            <View
              style={[
                styles.button,
                {
                  backgroundColor: message.encrypted ? '#3D854D' : '#e9e9e9',
                },
              ]}
            >
              <Text
                style={{
                  color: message.encrypted ? '#fefefe' : '#333',
                }}
              >
                Encrypt
              </Text>
            </View>
          </TouchableWithoutFeedback>
          <TouchableWithoutFeedback onPress={reset}>
            <View
              style={[
                styles.button,
                {
                  backgroundColor: '#e9e9e9',
                },
              ]}
            >
              <Text
                style={{
                  color: '#333',
                }}
              >
                Reset
              </Text>
            </View>
          </TouchableWithoutFeedback>
          <TouchableWithoutFeedback onPress={decryptString}>
            <View
              style={[
                styles.button,
                {
                  backgroundColor: message.decrypted ? '#3D854D' : '#e9e9e9',
                },
              ]}
            >
              <Text
                style={{
                  color: message.decrypted ? '#fefefe' : '#333',
                }}
              >
                Dencrypt
              </Text>
            </View>
          </TouchableWithoutFeedback>
        </View>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  button: {
    paddingHorizontal: 30,
    paddingVertical: 20,
    marginVertical: 20,
    borderRadius: 15,
    alignItems: 'center',
    justifyContent: 'center',
  },
  textInputContainer: {
    flexDirection: 'column',
    justifyContent: 'center',
    alignItems: 'center',
    width: Dimensions.get('window').width,
    borderTopColor: '#e9e9e9',
    borderTopWidth: 1,
    borderStyle: 'solid',
    marginTop: 50,
    paddingTop: 50,
  },
  textInput: {
    width: 250,
    height: 60,
    borderColor: '#e9e9e9',
    borderWidth: 2,
    borderRadius: 15,
    padding: 20,
    marginTop: 20,
  },
  buttonsContainer: {
    width: Dimensions.get('window').width,
    flexDirection: 'row',
    justifyContent: 'space-evenly',
  },
  metaRow: {
    flexDirection: 'row',
    paddingVertical: 20,
  },
  metaRowHeader: {
    fontWeight: '700',
    marginRight: 10,
  },
  metaRowText: {
    fontWeight: '300',
  },
});
