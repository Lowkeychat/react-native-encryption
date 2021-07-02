package com.reactnativelowkeyencryption

import android.os.Build
import android.util.Log
import androidx.annotation.RequiresApi
import com.facebook.react.bridge.*
import com.facebook.react.bridge.Arguments.toList
import java.util.*


@RequiresApi(Build.VERSION_CODES.O)
class LowkeyEncryptionModule(reactContext: ReactApplicationContext) : ReactContextBaseJavaModule(reactContext) {

    override fun getName(): String {
        return "LowkeyEncryption"
    }


    @ReactMethod
    fun asymmetric_generateKeyPair(promise: Promise) {
      val keys = AsymmetricECCEncryption().generateKeyPair();
      promise.resolve(keys)
    }

    @ReactMethod
    fun asymmetric_encryptGroup(props: ReadableMap, promise: Promise) {
      val publicKeys: ArrayList<String> = toList(props.getArray("publicKeys")) as ArrayList<String>;
      val message: String? = props.getString("message")
      val encryptedObject = AsymmetricECCEncryption().encryptGroup(publicKeys, message);

      promise.resolve(encryptedObject)

    }

    @ReactMethod
    fun asymmetric_decryptGroup(props: ReadableMap, promise: Promise) {
      val publicKey: String = props.getString("publicKey") as String
      val privateKey: String = props.getString("privateKey") as String
      val messages: ReadableMap = props.getMap("messages") as ReadableMap;

      val encryptedObject = AsymmetricECCEncryption().decryptGroup(publicKey, privateKey, messages);

      promise.resolve(encryptedObject)

    }



    @ReactMethod
    fun symmetric_generateSymmetricKey(promise: Promise) {
      val key = SymmetricEncryption().generateSymmetricKey();
      promise.resolve(key)
    }

    @ReactMethod
    fun symmetric_encryptStringWithSymmetricKey(props: ReadableMap, promise: Promise) {
      val symmetricKey: String? = props.getString("symmetricKey")
      val message: String? = props.getString("message")

      val chiperString = SymmetricEncryption().encryptStringWithSymmetricKey(symmetricKey, message);

      promise.resolve(chiperString)

    }

    @ReactMethod
    fun symmetric_decryptStringWithSymmetricKey(props: ReadableMap, promise: Promise) {
      val symmetricKey: String? = props.getString("symmetricKey")
      val message: String? = props.getString("message")

      val clearString = SymmetricEncryption().decryptStringWithSymmetricKey(symmetricKey, message);

      promise.resolve(clearString)

    }





}
