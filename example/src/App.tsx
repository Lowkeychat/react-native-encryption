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
  ScrollView,
} from 'react-native';
import Encryption from '@lowkey/react-native-encryption';
import Clipboard from '@react-native-clipboard/clipboard';

const ENCRYPTION_TYPES = {
  SYMMETRIC: 'SYMMETRIC',
  ASYMMETRIC: 'ASYMMETRIC',
};

export default function App() {
  const [outgoingMessage, setOutgoingMessage] = React.useState('');
  const [incomingMessage, setIncomingMessage] = React.useState('');

  const [encryptionType, setEncryptionType] = React.useState(
    ENCRYPTION_TYPES.ASYMMETRIC
  );
  const [keys, setKeys] = React.useState({
    privateKey: '',
    publicKey: '',
  });

  const [symmetricKey, setSymmetricKey] = React.useState('');

  const [rKeys, setRKeys] = React.useState({
    privateKey: '',
    publicKey: '',
  });

  const [message, setMessage] = React.useState({
    encrypted: true,
    decrypted: false,
    value: '',
  });

  const [symmetricalMessage, setSymmetricalMessage] = React.useState('');
  const [symmetricalMessageOut, setSymmetricalMessageOut] = React.useState('');

  const generateKeyPair = async () => {
    setKeys({
      ...keys,
    });
    if (encryptionType === ENCRYPTION_TYPES.ASYMMETRIC) {
      const _keys = await Encryption.Asymmetric.generateKeyPair();
      console.log(_keys);
      LayoutAnimation.configureNext(LayoutAnimation.Presets.easeInEaseOut);
      setKeys({
        ...keys,
        ..._keys,
      });
    } else if (encryptionType === ENCRYPTION_TYPES.SYMMETRIC) {
      const _key = await Encryption.Symmetric.generateKey();
      LayoutAnimation.configureNext(LayoutAnimation.Presets.easeInEaseOut);
      setSymmetricKey(_key.symmetricKey);
    }
  };

  const encryptString = async () => {
    let encryptedMessage = '';

    if (encryptionType === ENCRYPTION_TYPES.ASYMMETRIC) {
      encryptedMessage = await Encryption.Asymmetric.encrypt({
        publicKey: rKeys.publicKey,
        message: outgoingMessage,
      });
      console.log(encryptedMessage);

      const encryptedMessage2 = await Encryption.Asymmetric.encryptGroup({
        publicKeys: [rKeys.publicKey],
        message: outgoingMessage,
      });

      setOutgoingMessage(JSON.stringify(encryptedMessage2));
    } else if (encryptionType === ENCRYPTION_TYPES.SYMMETRIC) {
      encryptedMessage = await Encryption.Symmetric.encrypt({
        symmetricKey: symmetricKey,
        message: symmetricalMessage,
      });
      console.log('LOOL', encryptedMessage);
      setSymmetricalMessage(encryptedMessage);
    }
  };

  const decryptString = async () => {
    let outgoingMessages2 = JSON.parse(incomingMessage);
    console.log('In decrypt', outgoingMessages2);
    let decryptedMessage = '';

    if (encryptionType === ENCRYPTION_TYPES.ASYMMETRIC) {
      // decryptedMessage = await Encryption.Asymmetric.decrypt({
      //   privateKey: keys.privateKey,
      //   message: incomingMessage,
      // });
      console.log('In ASYMMETRIC');
      let decryptedMessage2 = await Encryption.Asymmetric.decryptGroup({
        privateKey: keys.privateKey,
        publicKey: keys.publicKey,
        messages: outgoingMessages2,
      });
      console.log('decryptedMessage2', decryptedMessage2);
      setIncomingMessage(decryptedMessage2);

      // setIncomingMessage(decryptedMessage);
    } else if (encryptionType === ENCRYPTION_TYPES.SYMMETRIC) {
      decryptedMessage = await Encryption.Symmetric.decrypt({
        symmetricKey: symmetricKey,
        message: symmetricalMessageOut,
      });
      setSymmetricalMessageOut(decryptedMessage);
    }
  };

  const onChangeRPub = (m: string) => {
    setRKeys({
      ...rKeys,
      publicKey: m,
    });
  };
  const onChangeRPriv = (m: string) => {
    setRKeys({
      ...rKeys,
      privateKey: m,
    });
  };

  const onChangeText = (m: string) => {
    setMessage({
      ...message,
      value: m,
    });
  };

  const onChangeTextOut = (m: string) => {
    setOutgoingMessage(m);
  };

  const onChangeSymmetricalMessage = (m: string) => {
    setSymmetricalMessage(m);
  };

  const onChangeSymmetricalMessageOut = (m: string) => {
    setSymmetricalMessageOut(m);
  };

  const onChangeSymmetricalKey = (m: string) => {
    setSymmetricKey(m);
  };

  const onChangeTextIn = (m: string) => {
    setIncomingMessage(m);
  };

  const reset = () => {
    setMessage({
      encrypted: false,
      decrypted: false,
      value: '',
    });
    setKeys({
      publicKey: '',
      privateKey: '',
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
    <ScrollView style={styles.container} stickyHeaderIndices={[0]}>
      <View
        style={{
          backgroundColor: '#fff',
          paddingTop: 30,
          justifyContent: 'space-between',
          width: '100%',
          flexDirection: 'row',
        }}
      >
        <View
          style={[
            styles.button,
            {
              backgroundColor: '#e9e9e9',
              paddingHorizontal: 10,
              paddingVertical: 15,
            },
          ]}
        >
          <TouchableOpacity onPress={changeEncryptionType}>
            <Text
              style={{
                color: '#333',
              }}
            >
              Change Encryption type
            </Text>
          </TouchableOpacity>
        </View>
      </View>
      <View
        style={{
          width: '100%',
          borderTopColor: '#e9e9e9',
          borderTopWidth: 0.5,
          padding: 20,
        }}
      >
        <View
          style={{
            flexDirection: 'row',
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
        >
          <Text style={{ fontSize: 14, color: '#444', fontWeight: '700' }}>
            My Keys
          </Text>
          <TouchableOpacity onPress={generateKeyPair}>
            <View
              style={[
                styles.button,
                {
                  backgroundColor: '#e9e9e9',
                  paddingHorizontal: 10,
                  paddingVertical: 7.5,
                  borderRadius: 10,
                },
              ]}
            >
              <Text
                style={{
                  color: '#333',
                }}
              >
                Generate Keys
              </Text>
            </View>
          </TouchableOpacity>
        </View>
        {/* SYMMETRICAL KEYS */}
        {encryptionType === ENCRYPTION_TYPES.SYMMETRIC && (
          <View>
            <Text
              style={{
                fontSize: 12,
                color: '#444',
                fontWeight: '700',
                marginTop: 10,
              }}
            >
              Shared Secret:
            </Text>
            <View
              style={{
                flexDirection: 'row',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginTop: 10,
              }}
            >
              <TextInput
                numberOfLines={1}
                value={symmetricKey}
                onChangeText={onChangeSymmetricalKey}
                style={styles.textInput}
              />
              <TouchableOpacity
                style={{
                  backgroundColor: '#e9e9e9',
                  paddingHorizontal: 10,
                  paddingVertical: 5,
                  borderRadius: 10,
                }}
                onPress={() => Clipboard.setString(symmetricKey)}
              >
                <Text>Copy</Text>
              </TouchableOpacity>
            </View>
          </View>
        )}
        {/* ASYMMETRICAL KEYS */}
        {encryptionType === ENCRYPTION_TYPES.ASYMMETRIC && (
          <>
            <View>
              <Text
                style={{
                  fontSize: 12,
                  color: '#444',
                  fontWeight: '700',
                  marginTop: 10,
                }}
              >
                Public:
              </Text>
              <View
                style={{
                  flexDirection: 'row',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                }}
              >
                <Text
                  style={{
                    fontSize: 12,
                    color: '#444',
                    maxWidth: 300,
                    marginTop: 5,
                  }}
                  numberOfLines={1}
                >
                  {keys.publicKey}
                </Text>
                <TouchableOpacity
                  style={{
                    backgroundColor: '#e9e9e9',
                    paddingHorizontal: 10,
                    paddingVertical: 5,
                    borderRadius: 10,
                  }}
                  onPress={() => Clipboard.setString(keys.publicKey)}
                >
                  <Text>Copy</Text>
                </TouchableOpacity>
              </View>
            </View>
            <View>
              <Text
                style={{
                  fontSize: 12,
                  color: '#444',
                  fontWeight: '700',
                  marginTop: 10,
                }}
              >
                Private:
              </Text>
              <View
                style={{
                  flexDirection: 'row',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                }}
              >
                <Text
                  style={{
                    fontSize: 12,
                    color: '#444',
                    maxWidth: 300,
                    marginTop: 5,
                  }}
                  numberOfLines={1}
                >
                  {keys.privateKey}
                </Text>
                <TouchableOpacity
                  style={{
                    backgroundColor: '#e9e9e9',
                    paddingHorizontal: 10,
                    paddingVertical: 5,
                    borderRadius: 10,
                  }}
                  onPress={() => Clipboard.setString(keys.privateKey)}
                >
                  <Text>Copy</Text>
                </TouchableOpacity>
              </View>
            </View>
          </>
        )}
      </View>
      {encryptionType === ENCRYPTION_TYPES.ASYMMETRIC && (
        <View
          style={{
            width: '100%',
            borderTopColor: '#e9e9e9',
            borderTopWidth: 0.5,
            padding: 20,
          }}
        >
          <View
            style={{
              flexDirection: 'row',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}
          >
            <Text style={{ fontSize: 14, color: '#444', fontWeight: '700' }}>
              Recipient Keys
            </Text>
          </View>
          <View>
            <Text
              style={{
                fontSize: 12,
                color: '#444',
                fontWeight: '700',
                marginTop: 10,
              }}
            >
              Public:
            </Text>
            <View
              style={{
                flexDirection: 'row',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}
            >
              <TextInput
                style={{
                  fontSize: 12,
                  color: '#444',
                  maxWidth: 300,
                  marginTop: 5,
                  width: '100%',
                  height: 40,
                  borderColor: '#e9e9e9',
                  borderWidth: 1,
                  borderRadius: 10,
                }}
                numberOfLines={1}
                value={rKeys.publicKey}
                onChangeText={onChangeRPub}
              />
            </View>
          </View>
          <View>
            <Text
              style={{
                fontSize: 12,
                color: '#444',
                fontWeight: '700',
                marginTop: 10,
              }}
            >
              Private:
            </Text>
            <View
              style={{
                flexDirection: 'row',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}
            >
              <TextInput
                style={{
                  fontSize: 12,
                  color: '#444',
                  maxWidth: 300,
                  marginTop: 5,
                  width: '100%',
                  height: 40,
                  borderColor: '#e9e9e9',
                  borderWidth: 1,
                  borderRadius: 10,
                }}
                numberOfLines={1}
                value={rKeys.privateKey}
                onChangeText={onChangeRPriv}
              />
            </View>
          </View>
        </View>
      )}
      <View
        style={{
          width: '100%',
          borderTopColor: '#e9e9e9',
          borderTopWidth: 0.5,
          padding: 20,
        }}
      >
        <View
          style={{
            flexDirection: 'row',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: 20,
          }}
        >
          <Text style={{ fontSize: 14, color: '#444', fontWeight: '700' }}>
            Messages
          </Text>
        </View>
        {encryptionType === ENCRYPTION_TYPES.ASYMMETRIC && (
          <>
            <View>
              <View style={{ flexDirection: 'row', alignItems: 'center' }}>
                <Text
                  style={{
                    fontSize: 12,
                    color: '#444',
                    fontWeight: '700',
                    marginTop: 10,
                    marginBottom: 10,
                  }}
                >
                  Outgoing:
                </Text>
                <TouchableOpacity
                  style={{
                    backgroundColor: '#e9e9e9',
                    paddingHorizontal: 10,
                    borderRadius: 10,
                    justifyContent: 'center',
                    alignItems: 'center',
                    height: 20,
                    marginLeft: 10,
                  }}
                  onPress={() => Clipboard.setString(outgoingMessage)}
                >
                  <Text style={{ fontSize: 10 }}>Copy</Text>
                </TouchableOpacity>
              </View>
              <View
                style={{
                  flexDirection: 'row',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                }}
              >
                <TextInput
                  numberOfLines={1}
                  value={outgoingMessage}
                  onChangeText={onChangeTextOut}
                  style={styles.textInput}
                />
                <TouchableOpacity
                  style={{
                    backgroundColor: '#e9e9e9',
                    paddingHorizontal: 15,
                    paddingVertical: 15,
                    borderRadius: 10,
                  }}
                  onPress={encryptString}
                >
                  <Text>Encrypt</Text>
                </TouchableOpacity>
              </View>
            </View>
            <View>
              <View style={{ flexDirection: 'row', alignItems: 'center' }}>
                <Text
                  style={{
                    fontSize: 12,
                    color: '#444',
                    fontWeight: '700',
                    marginTop: 15,
                    marginBottom: 10,
                  }}
                >
                  Incoming:
                </Text>
                <TouchableOpacity
                  style={{
                    backgroundColor: '#e9e9e9',
                    paddingHorizontal: 10,
                    borderRadius: 10,
                    justifyContent: 'center',
                    alignItems: 'center',
                    height: 20,
                    marginLeft: 10,
                  }}
                  onPress={() => Clipboard.setString(incomingMessage)}
                >
                  <Text style={{ fontSize: 10 }}>Copy</Text>
                </TouchableOpacity>
              </View>
              <View
                style={{
                  flexDirection: 'row',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                }}
              >
                <TextInput
                  numberOfLines={1}
                  value={incomingMessage}
                  onChangeText={onChangeTextIn}
                  style={styles.textInput}
                />
                <TouchableOpacity
                  style={{
                    backgroundColor: '#e9e9e9',
                    paddingHorizontal: 15,
                    paddingVertical: 15,
                    borderRadius: 10,
                  }}
                  onPress={decryptString}
                >
                  <Text>Decrypt</Text>
                </TouchableOpacity>
              </View>
            </View>
          </>
        )}
        {encryptionType === ENCRYPTION_TYPES.SYMMETRIC && (
          <>
            <View>
              <View style={{ flexDirection: 'row', alignItems: 'center' }}>
                <Text
                  style={{
                    fontSize: 12,
                    color: '#444',
                    fontWeight: '700',
                    marginTop: 10,
                    marginBottom: 10,
                  }}
                >
                  Outgoing:
                </Text>
                <TouchableOpacity
                  style={{
                    backgroundColor: '#e9e9e9',
                    paddingHorizontal: 10,
                    borderRadius: 10,
                    justifyContent: 'center',
                    alignItems: 'center',
                    height: 20,
                    marginLeft: 10,
                  }}
                  onPress={() => Clipboard.setString(symmetricalMessage)}
                >
                  <Text style={{ fontSize: 10 }}>Copy</Text>
                </TouchableOpacity>
              </View>
              <View
                style={{
                  flexDirection: 'row',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                }}
              >
                <TextInput
                  numberOfLines={1}
                  value={symmetricalMessage}
                  onChangeText={onChangeSymmetricalMessage}
                  style={styles.textInput}
                />
                <TouchableOpacity
                  style={{
                    backgroundColor: '#e9e9e9',
                    paddingHorizontal: 15,
                    paddingVertical: 15,
                    borderRadius: 10,
                  }}
                  onPress={encryptString}
                >
                  <Text>Encrypt</Text>
                </TouchableOpacity>
              </View>
            </View>
            <View>
              <View style={{ flexDirection: 'row', alignItems: 'center' }}>
                <Text
                  style={{
                    fontSize: 12,
                    color: '#444',
                    fontWeight: '700',
                    marginTop: 10,
                    marginBottom: 10,
                  }}
                >
                  Incomming:
                </Text>
                <TouchableOpacity
                  style={{
                    backgroundColor: '#e9e9e9',
                    paddingHorizontal: 10,
                    borderRadius: 10,
                    justifyContent: 'center',
                    alignItems: 'center',
                    height: 20,
                    marginLeft: 10,
                  }}
                  onPress={() => Clipboard.setString(symmetricalMessageOut)}
                >
                  <Text style={{ fontSize: 10 }}>Copy</Text>
                </TouchableOpacity>
              </View>
              <View
                style={{
                  flexDirection: 'row',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                }}
              >
                <TextInput
                  numberOfLines={1}
                  value={symmetricalMessageOut}
                  onChangeText={onChangeSymmetricalMessageOut}
                  style={styles.textInput}
                />
                <TouchableOpacity
                  style={{
                    backgroundColor: '#e9e9e9',
                    paddingHorizontal: 15,
                    paddingVertical: 15,
                    borderRadius: 10,
                  }}
                  onPress={decryptString}
                >
                  <Text>Decrypt</Text>
                </TouchableOpacity>
              </View>
            </View>
          </>
        )}
      </View>

      <View style={styles.textInputContainer}>
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
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
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
    width: 275,
    height: 50,
    borderColor: '#e9e9e9',
    borderWidth: 2,
    borderRadius: 15,
    padding: 10,
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
