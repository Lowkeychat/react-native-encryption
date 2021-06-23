package com.reactnativelowkeyencryption

import PKCS1ToSubjectPublicKeyInfo
import android.os.Build
import android.util.Log
import androidx.annotation.RequiresApi
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.WritableMap
import java.io.Serializable
import java.security.*
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.Cipher


@RequiresApi(Build.VERSION_CODES.O)
class AsymmetricEncryption {
   private val algorithm = "RSA"

   fun generateKeyPair(): WritableMap {
      val kpg = KeyPairGenerator.getInstance(algorithm)
      kpg.initialize(2048)
      val keyPair = kpg.genKeyPair()

      val publicKey = publicKeyToPem(keyPair.public)
      val privateKey = privateKeyToPem(keyPair.private)

      val keys = Arguments.createMap()
      keys.putString("privateKey", privateKey)
      keys.putString("publicKey", publicKey)
      return keys
  }

  private fun publicKeyToPem(publicKey: PublicKey): String {
    val base64PubKey = Base64.getEncoder().withoutPadding().encodeToString(publicKey.encoded)
    return "-----BEGIN PUBLIC KEY-----\n" +
      base64PubKey.replace("(.{64})".toRegex(), "$1\n") +
      "\n-----END PUBLIC KEY-----\n"
  }


  private fun privateKeyToPem(privateKey: PrivateKey): String {
    val base64PrivateKey = Base64.getEncoder().encodeToString(privateKey.encoded)
    return "-----BEGIN PRIVATE KEY-----\n" + base64PrivateKey.replace("(.{64})".toRegex(), "$1\n") + "\n-----END PRIVATE KEY-----\n"
  }


  fun encrypt(publicKeyBase64: String?, inputString: String?): String {
    val decoder = Base64.getDecoder()
    val publicKey: PublicKey
    val cipher = Cipher.getInstance(algorithm)

    if(publicKeyBase64?.contains("-----BEGIN PUBLIC KEY-----", ignoreCase = true) == true) {

      val publicKeyBase64 = publicKeyBase64
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replace("\\s+".toRegex(), "")

      val publicKeyByteArray: ByteArray = decoder.decode(publicKeyBase64)

      val kf = KeyFactory.getInstance("RSA")
      publicKey = kf.generatePublic(X509EncodedKeySpec(publicKeyByteArray))

      cipher.init(Cipher.ENCRYPT_MODE, publicKey)

    } else if (publicKeyBase64?.contains("-----BEGIN RSA PUBLIC KEY-----", ignoreCase = true) == true) {

      val publicKeyBase64 = publicKeyBase64
        .replace("-----BEGIN RSA PUBLIC KEY-----", "")
        .replace("-----END RSA PUBLIC KEY-----", "")
        .replace("\\s+".toRegex(), "")

      val publicKeyByteArray: ByteArray = decoder.decode(publicKeyBase64)

      publicKey = PKCS1ToSubjectPublicKeyInfo().decodePKCS1PublicKey(publicKeyByteArray);

      cipher.init(Cipher.ENCRYPT_MODE, publicKey)

    }

    val inputData = inputString?.toByteArray()
    val chiperData = cipher.doFinal(inputData)

    return Base64.getEncoder().encodeToString(chiperData)
  }

  fun decrypt(privateKeyBase64: String?, inputString: String?): String {
    var privateKeyBaseString64: String? = privateKeyBase64;
    val decoder = Base64.getDecoder()
    if(privateKeyBaseString64?.contains("-----BEGIN PRIVATE KEY-----", ignoreCase = true) == true) {

      privateKeyBaseString64 = privateKeyBaseString64
              .replace("-----BEGIN PRIVATE KEY-----", "")
              .replace("-----END PRIVATE KEY-----", "")
              .replace("\\s+".toRegex(), "")

    } else if (privateKeyBaseString64?.contains("-----BEGIN RSA PRIVATE KEY-----", ignoreCase = true) == true) {
      privateKeyBaseString64 = privateKeyBaseString64
              .replace("-----BEGIN RSA PRIVATE KEY-----", "")
              .replace("-----END RSA PRIVATE KEY-----", "")
              .replace("\\s+".toRegex(), "")
    }

    val privateKey: ByteArray = decoder.decode(privateKeyBaseString64)

    val inputStringByteArray: ByteArray = decoder.decode(inputString)

    val key = KeyFactory.getInstance(algorithm)
      .generatePrivate(PKCS8EncodedKeySpec(privateKey))

    val cipher = Cipher.getInstance(algorithm)
    cipher.init(Cipher.DECRYPT_MODE, key)
    val decryptedByteArray = cipher.doFinal(inputStringByteArray)

    return String(decryptedByteArray, Charsets.UTF_8);
  }

  fun ByteArray.toHex(): String = joinToString(separator = "") { eachByte -> "%02x".format(eachByte) }

  fun encryptGroup(publicKeysBase64: ArrayList<String>, inputString: String?): WritableMap? {
    val list = Arguments.createMap()


    val decoder = Base64.getDecoder()
    val cipher = Cipher.getInstance(algorithm)

    for(publicKeyBase64 in publicKeysBase64) {
      val publicKeyInfo = getPublicKey(publicKeyBase64);

      val publicKey = publicKeyInfo["publicKey"] as PublicKey
      val fingerprint = publicKeyInfo["fingerprint"] as String

      Log.d("fingerprint", fingerprint)

      cipher.init(Cipher.ENCRYPT_MODE, publicKey)

      val inputData = inputString?.toByteArray()
      val chiperData = cipher.doFinal(inputData)

      list.putString(fingerprint, Base64.getEncoder().encodeToString(chiperData))
    }
   return list;
  }
  fun hex(bytes: ByteArray): String? {
    val result = StringBuilder()
    for (aByte in bytes) {
      result.append(String.format("%02x", aByte))
      // upper case
      // result.append(String.format("%02X", aByte));
    }
    return result.toString()
  }
  fun decryptGroup(publicKeyBase64: String, privateKeyBase64: String, messages: ReadableMap): String {
    var privateKeyBaseString64: String = privateKeyBase64;
    val decoder = Base64.getDecoder()

    val publicKeyInfo = getPublicKey(publicKeyBase64);

    val publicKey = publicKeyInfo["publicKey"]
    val fingerprint = publicKeyInfo["fingerprint"] as String

    val inputString = messages.getString(fingerprint)

    if(privateKeyBaseString64.contains("-----BEGIN PRIVATE KEY-----", ignoreCase = true)) {

      privateKeyBaseString64 = privateKeyBaseString64
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "")
        .replace("\\s+".toRegex(), "")

    } else if (privateKeyBaseString64?.contains("-----BEGIN RSA PRIVATE KEY-----", ignoreCase = true)) {
      privateKeyBaseString64 = privateKeyBaseString64
        .replace("-----BEGIN RSA PRIVATE KEY-----", "")
        .replace("-----END RSA PRIVATE KEY-----", "")
        .replace("\\s+".toRegex(), "")
    }

    val privateKey: ByteArray = decoder.decode(privateKeyBaseString64)

    val inputStringByteArray: ByteArray = decoder.decode(inputString)

    val key = KeyFactory.getInstance(algorithm)
      .generatePrivate(PKCS8EncodedKeySpec(privateKey))



    val cipher = Cipher.getInstance(algorithm)
    cipher.init(Cipher.DECRYPT_MODE, key)
    val decryptedByteArray = cipher.doFinal(inputStringByteArray)

    return String(decryptedByteArray, Charsets.UTF_8);
  }

  private fun getPublicKey(publicKeyBase64: String): Map<String, Serializable> {
    val decoder = Base64.getDecoder()
    val publicKey: PublicKey
    val cipher = Cipher.getInstance(algorithm)

    if(publicKeyBase64?.contains("-----BEGIN PUBLIC KEY-----", ignoreCase = true) == true) {

      val publicKeyBase64 = publicKeyBase64
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replace("\\s+".toRegex(), "")

      val publicKeyByteArray: ByteArray = decoder.decode(publicKeyBase64)

      Log.d("publicKey.encoded hex", hex(publicKeyByteArray))

      val kf = KeyFactory.getInstance("RSA")
      publicKey = kf.generatePublic(X509EncodedKeySpec(publicKeyByteArray))

      val md = MessageDigest.getInstance("SHA1")
      md.update(publicKeyByteArray)
      val fingerprint = md.digest().toHex()

      return mapOf("fingerprint" to fingerprint, "publicKey" to publicKey)


    }

    val publicKeyBase64 = publicKeyBase64
      .replace("-----BEGIN RSA PUBLIC KEY-----", "")
      .replace("-----END RSA PUBLIC KEY-----", "")
      .replace("\\s+".toRegex(), "")

    val publicKeyByteArray: ByteArray = decoder.decode(publicKeyBase64)

    Log.d("publicKey.encoded hex2", hex(publicKeyByteArray))

    publicKey = PKCS1ToSubjectPublicKeyInfo().decodePKCS1PublicKey(publicKeyByteArray);

    val md = MessageDigest.getInstance("SHA1")
    md.update(publicKeyByteArray)
    val fingerprint = md.digest().toHex()

    return mapOf("fingerprint" to fingerprint, "publicKey" to publicKey)
  }
}

